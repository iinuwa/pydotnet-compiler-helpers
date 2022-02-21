"""
Functionality to embed the managed app and its dependencies
into the host native binary.
"""
import base64
from enum import Enum, IntFlag
import hashlib
from io import SEEK_CUR
from mmap import mmap, ACCESS_READ, ACCESS_WRITE
import os
import platform
import shutil
import struct
import sys
from typing import BinaryIO, Optional, Sequence
import zlib


class OSPlatform(Enum):
    WINDOWS = 1
    OSX = 2
    LINUX = 4

    @staticmethod
    def os():
        platform_map = {
            "darwin":  OSPlatform.OSX,
            "linux":   OSPlatform.LINUX,
            "windows": OSPlatform.WINDOWS,
        }
        # TODO: Guard against unknown platforms
        return platform_map[platform.system().lower()]


class FileType(Enum):
    """Identifies the type of file embedded into the bundle.

    The bundler differentiates a few kinds of files via the manifest,
    with respect to the way in which they'll be used by the runtime.
    """
    Unknown = b'\x00'            # Type not determined.
    Assembly = b'\x01'           # IL and R2R Assemblies
    NativeBinary = b'\x02'       # NativeBinaries
    DepsJson = b'\x03'           # .deps.json configuration file
    RuntimeConfigJson = b'\x04'  # .runtimeconfig.json configuration file
    Symbols = b'\x05'            # PDB Files


class Architecture(Enum):
    X64 = 1
    X86 = 2
    ARM64 = 4
    ARM = 8

    @staticmethod
    def arch():
        arch_map = {
            "aarch64": Architecture.ARM64,
            "arm64":   Architecture.ARM64,
            "arm":     Architecture.ARM,
            "i386":    Architecture.X86,
            "i686":    Architecture.X86,
            "x86_64":  Architecture.X64,
        }
        # TODO: Guard against unknown architectures
        return arch_map[platform.machine()]


class BundleOptions(IntFlag):
    Default = 0
    BundleNativeBinaries = 1
    BundleAllContent = 2
    BundleSymbolFiles = 4
    EnableCompression = 8


class Version:
    def __init__(self, version_string):
        self.major: int = 0
        self.minor: int = 0
        self.build: int = 0
        self.revision: int = 0
        try:
            components = [int(c)
                          for c in version_string.split('.', maxsplit=4)]
        except ValueError:
            raise Exception(f"Invalid version string given: {version_string}")
        components.extend(0 for _ in range(4 - len(components)))
        [self.major, self.minor, self.build, self.revision] = components


class FileSpec:
    def __init__(self, source_path: str, relative_path: str):
        """Information about files to embed into the Bundle (input to the Bundler).

        @source_path: Path to the file to be bundled at compile time.
        @relative_path: Path where the file is expected at run time, relative
                        to the app DLL.
        """
        self.source_path = source_path
        self.bundle_relative_path = relative_path
        self.excluded = False

    def is_valid(self):
        return self.source_path and self.bundle_relative_path


class TargetInfo:
    """
    Information about the target for which the single-file bundle is built.

    Currently the TargetInfo only tracks:
      - the target operating system
      - the target architecture
      - the target framework
      - the default options for this target
      - the assembly alignment for this target
    """

    def __init__(self, target_os: Optional[OSPlatform],
                 target_arch: Optional[Architecture],
                 target_framework_version: Version):
        self.os = target_os if target_os else OSPlatform.os()
        self.arch = target_arch if target_arch else Architecture.arch()
        self.framework_version = target_framework_version if target_framework_version else Version(
            "6.0.0.0")
        self.bundle_major_version = target_framework_version.major

        assert(self.os == OSPlatform.LINUX or self.os ==
               OSPlatform.OSX or self.os == OSPlatform.WINDOWS)

        # TODO: Implement Version.compare_to
        if self.framework_version.major >= 6:
            self.bundle_major_version = 6
            self.default_options = BundleOptions.Default
        elif self.framework_version.major >= 5:
            self.bundle_major_version = 2
            self.default_options = BundleOptions.Default
        elif (self.framework_version.major == 3
                and (self.framework_version.minor == 0 or self.framework_version.minor == 1)):
            self.bundle_major_version = 1
            self.default_options = BundleOptions.BundleAllContent
        else:
            raise Exception(
                f"Invalid input: unsupported target framework version: {target_framework_version}")

        if self.os == OSPlatform.LINUX and self.arch == Architecture.ARM64:
            # We align assemblies in the bundle at 4K so that we can use mmap
            # on Linux without changing the page alignment of ARM64 R2R code.
            # This is only necessary for R2R assemblies, but we do it for all
            # assemblies for simplicity.
            # See https://github.com/dotnet/runtime/issues/41832.
            self.assembly_alignment = 4096
        elif self.os == OSPlatform.WINDOWS:
            # We align assemblies in the bundle at 4K - per requirements of
            # memory mapping API (MapViewOfFile3, et al).
            # This is only necessary for R2R assemblies, but we do it for all
            # assemblies for simplicity.
            self.assembly_alignment = 4096
        else:
            # Otherwise, assemblies are 64 bytes aligned, so that their
            # sections can be memory-mapped cache aligned.
            self.assembly_alignment = 64

        self.hostfxr = (
            "hostfxr.dll" if self.os == OSPlatform.WINDOWS
            else "libhostfxr.so" if self.os == OSPlatform.LINUX
            else "libhostfxr.dylib"
        )
        self.hostpolicy = (
            "hostpolicy.dll" if self.os == OSPlatform.WINDOWS
            else "libhostpolicy.so" if self.os == OSPlatform.LINUX
            else "libhostpolicy.dylib"
        )

    def should_exclude(self, relative_path: str) -> bool:
        """
        In .NET core 3.x, bundle processing happens within the AppHost.
        Therefore HostFxr and HostPolicy can be bundled within the single-file
        app. In .NET 5, bundle processing happens in HostFxr and HostPolicy
        libraries. Therefore, these libraries themselves cannot be bundled into
        the single-file app. This problem is mitigated by statically linking
        these host components with the AppHost.
        https://github.com/dotnet/runtime/issues/32823
        """
        return (
            self.framework_version.major != 3
            and (relative_path == self.hostfxr or relative_path == self.host_policy)
        )

    def target_specific_file_type(self, file_type: FileType) -> FileType:
        """
        The .NET core 3 apphost doesn't care about semantics of FileType -- all
        files are extracted at startup.
        However, the apphost checks that the FileType value is within expected
        bounds, so set it to the first enumeration.
        """
        return FileType.Unknown if self.bundle_major_version == 1 else file_type

    def get_assembly_name(self, host_name: str) -> str:
        # This logic to calculate assembly name from hostName should be removed
        # (and probably moved to test helpers) once the SDK can return the correct
        # assembly name.
        return os.path.splitext(host_name)[0] if OSPlatform.os() == OSPlatform.WINDOWS else host_name

    def is_native_binary(self, file_path: str) -> bool:
        if self.os == OSPlatform.LINUX:
            with open(file_path, 'rb') as f:
                file_len = os.stat(f.fileno()).st_size
                if file_len < 16:  # EI-NIDENT = 16
                    return False
                f.seek(0)
                e_ident = f.read(4)
                return e_ident == b'\x7fELF'

        if self.os == OSPlatform.OSX:
            class Magic(Enum):
                MH_MAGIC = 0xfeedface
                MH_CIGAM = 0xcefaedfe
                MH_MAGIC_64 = 0xfeedfacf
                MH_CIGAM_64 = 0xcffaedfe
            with open(file_path, 'rb') as f:
                file_len = os.stat(f.fileno()).st_size
                if file_len < 256:  # Header size
                    return False
                f.seek(0)
                magic = struct.unpack('<I', f.read(8))
                return any(magic == m for m in Magic)


class FileEntry:
    def __init__(self,
                 file_type: FileType,
                 relative_path: str,
                 offset: int,
                 size: int,
                 compressed_size: int,
                 bundle_major_version: int):
        self.bundle_major_version = bundle_major_version
        self.file_type = file_type
        self.relative_path = relative_path.replace('\\', '/')
        self.offset = offset
        self.size = size
        self.compressed_size = compressed_size

    def write(self, writer: BinaryIO):
        writer.write(struct.pack('<q', self.offset))
        writer.write(struct.pack('<q', self.size))
        if self.bundle_major_version >= 6:
            writer.write(struct.pack('<q', self.compressed_size))

        writer.write(struct.pack('c', self.file_type.value))
        print(struct.pack('c', self.file_type.value))

        # Write out an int 7 bits at a time. The high bit of the byte,
        # when on, tells reader to continue reading more bytes.
        #
        # Using the constants 0x7F and ~0x7F below offers smaller
        # codegen than using the constant 0x80.
        relative_path_len = len(self.relative_path)
        uvalue = relative_path_len
        print(uvalue)
        while (uvalue > 0x7f):
            writer.write((uvalue | ~0x7F).to_bytes(1, byteorder='little'))
            uvalue = uvalue >> 7

        writer.write(uvalue.to_bytes(1, byteorder='little'))
        writer.write(bytes(self.relative_path, encoding='utf-8'))


class BundleManifestHeaderFlags(IntFlag):
    DEFAULT = 0
    NETCOREAPP3_COMPAT_MODE = 1


class Manifest:
    """
    BundleManifest is a description of the contents of a bundle file.
    This class handles creation and consumption of bundle-manifests.

    Here is the description of the Bundle Layout:
    _______________________________________________
    AppHost


    ------------Embedded Files ---------------------
    The embedded files including the app, its
    configuration files, dependencies, and
    possibly the runtime.







    ------------ Bundle Header -------------
        MajorVersion
        MinorVersion
        NumEmbeddedFiles
        ExtractionID
        DepsJson Location [Version 2+]
           Offset
           Size
        RuntimeConfigJson Location [Version 2+]
           Offset
           Size
        Flags [Version 2+]
    - - - - - - Manifest Entries - - - - - - - - - - -
        Series of FileEntries (for each embedded file)
        [File Type, Name, Offset, Size information]



    _________________________________________________
    """
    BUNDLE_ID_LENGTH = 12
    # The Minor version is currently unused, and is always zero
    BUNDLE_MINOR_VERSION = 0

    def __init__(self, bundle_major_version: int, netcoreapp3_compat_mode: bool):
        self.bundle_major_version: int = bundle_major_version
        self.bundle_minor_version: int = 0
        self.files: Sequence[FileEntry] = []
        self.flags: BundleManifestHeaderFlags = (
            BundleManifestHeaderFlags.NETCOREAPP3_COMPAT_MODE if netcoreapp3_compat_mode
            else BundleManifestHeaderFlags.DEFAULT
        )
        self.bundle_hash = hashlib.sha256()
        self.deps_json_entry: FileEntry = None
        self.runtime_config_json_entry: FileEntry = None
        self.bundle_id: bytes = None

    def bundle_version(self):
        return f"{self.bundle_major_version}.{self.bundle_minor_version}"

    def add_entry(self, file_type: FileType, file_content: BinaryIO, relative_path: str, offset: int,
                  compressed_size: int, bundle_major_version: int) -> FileEntry:
        if self.bundle_hash is None:
            raise Exception("It is forbidden to change Manifest state after it was written or BundleId was obtained.")

        entry = FileEntry(file_type, relative_path, offset, os.fstat(
            file_content.fileno()).st_size, compressed_size, bundle_major_version)
        self.files.append(entry)
        file_content.seek(0)
        file_hash = hashlib.sha256(file_content.read())
        self.bundle_hash.update(file_hash.digest())

        if entry.file_type == FileType.DepsJson:
            self.deps_json_entry = entry
        elif entry.file_type == FileType.RuntimeConfigJson:
            self.runtime_config_json_entry = entry

        return entry

    def write(self, writer: BinaryIO) -> int:
        """
        Returns:
            Offset of data before writing
        """
        self.bundle_id = self.bundle_id if self.bundle_id else self.generate_deterministic_id()

        start_offset = writer.tell()
        writer.write(struct.pack('<I', self.bundle_major_version))
        writer.write(struct.pack('<I', self.bundle_minor_version))
        writer.write(struct.pack('<i', len(self.files)))
        writer.write(b'\x20')  # TODO: WHERE IS THIS COMING FROM?
        writer.write(self.bundle_id)

        if self.bundle_major_version >= 2:
            writer.write(struct.pack('<q', self.deps_json_entry.offset if self.deps_json_entry else 0))
            writer.write(struct.pack('<q', self.deps_json_entry.size if self.deps_json_entry else 0))

            writer.write(struct.pack(
                '<q',
                self.runtime_config_json_entry.offset if self.runtime_config_json_entry else 0)
            )
            writer.write(struct.pack(
                '<q',
                self.runtime_config_json_entry.size if self.runtime_config_json_entry else 0)
            )

            writer.write(struct.pack('<Q', self.flags))
            print(struct.pack('<Q', self.flags))

        for entry in self.files:
            entry.write(writer)

        return start_offset

    def generate_deterministic_id(self) -> bytes:
        final_bundle_hash = self.bundle_hash.digest()
        return base64.encodebytes(final_bundle_hash)[self.BUNDLE_ID_LENGTH:].replace(b'/', b'_')[:-1]


class Bundler:
    def __init__(self,
                 host_name: str,
                 output_dir: str,
                 options: BundleOptions = BundleOptions.Default,
                 target_os: Optional[OSPlatform] = None,
                 target_arch: Optional[Architecture] = None,
                 target_framework_version: Version = Version("6.0"),
                 diagnostic_output: bool = False,
                 app_assembly_name: Optional[str] = None,
                 macos_codesign: bool = True):

        # self.tracer = Trace(diagnostic_output)

        self.host_name = host_name
        self.output_dir = os.path.abspath(
            output_dir if output_dir else os.getcwd())
        self.target = TargetInfo(
            target_os, target_arch, target_framework_version)

        if (self.target.bundle_major_version < 6 and
           (options & BundleOptions.EnableCompression) != 0):
            raise Exception(
                "Compression requires framework version 6.0 or above")

        app_assembly_name = app_assembly_name if app_assembly_name else self.target.get_assembly_name(
            host_name)
        self.deps_json = f"{app_assembly_name}.deps.json"
        self.runtime_config_json = f"{app_assembly_name}.runtimeconfig.json"
        self.runtime_config_dev_json = f"{app_assembly_name}.runtimeconfig.dev.json"

        self.bundle_manifest = Manifest(
            self.target.bundle_major_version, netcoreapp3_compat_mode=(options & BundleOptions.BundleAllContent))
        self.options = self.target.default_options | options
        self.macos_codesign = macos_codesign

    def generate_bundle(self, file_specs: Sequence[FileSpec]) -> str:
        """Generate a bundle, given the specification of embedded files.

        @file_specs: An enumeration FileSpecs for the files to be embedded.
            Files in `file_specs` that are not bundled within the single file
            bundle and should be published as separate files are marked as
            "is_excluded" by this method.
            This doesn't include unbundled files that should be dropped, and
            not published as output.

        Returns the full path the the generated bundle file.
        Raises ValueError if input is invalid.
        `IOError`s and `ValueError`s from callee's flow to the caller.
        """
        if any([not f.is_valid() for f in file_specs]):
            raise ValueError("Invalid input specification: Found entry with "
                             "empty source-path or bundle-relative-path.")
        host_source = None
        for spec in file_specs:
            if spec.bundle_relative_path == self.host_name:
                host_source = spec.source_path
                break

        if not host_source:
            raise ValueError(
                "Invalid input specification: Must specify the host binary")

        bundle_path = os.path.join(self.output_dir, self.host_name)
        # if os.path.exists(bundle_path):
        #     self.tracer.log(f"Overwriting existing file: {bundle_path}")

        # Copy file
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

        shutil.copy(host_source, bundle_path)

        # if OSPlatform.os() == OSPlatform.OSX and HostModelUtils.is_codesign_available():
        #    remove_codesign_if_necessary(bundle_path)

        # Note: We're comparing file paths both on the OS we're running on as
        # well as on the target OS for the app.
        # We can't really make assumptions about the file systems (even on
        # Linux there can be case insensitive file systems and vice versa for
        # Windows). So it's safer to do case sensitive comparison everywhere.

        relative_path_to_spec: dict[str, FileSpec] = {}
        header_offset = 0
        with open(bundle_path, 'ab') as bundle_content:
            for file_spec in file_specs:
                relative_path: str = file_spec.bundle_relative_path
                if self.is_host(relative_path):
                    continue
                if self.should_ignore(relative_path):
                    continue

                file_type: FileType = self.infer_type(file_spec)

                if self.should_exclude(file_type, relative_path):
                    file_spec.excluded = True
                    continue

                if existing_file_spec := relative_path_to_spec.get(file_spec.bundle_relative_path):
                    if file_spec.source_path.lower() != existing_file_spec.source_path.lower():
                        raise Exception(
                            f"Invalid input specification: "
                            f"Found entries '{file_spec.source_path}' and '{existing_file_spec.source_path}' "
                            f"with the same bundle_relative_path '{file_spec.bundle_relative_path}'"
                        )
                    # Skip duplicates
                    continue
                else:
                    relative_path_to_spec[file_spec.bundle_relative_path] = file_spec

                with open(file_spec.source_path, 'rb') as file_to_write:
                    target_type: FileType = self.target.target_specific_file_type(
                        file_type)
                    (start_offset, compressed_size) = self.add_to_bundle(
                        bundle_content, file_to_write, target_type)
                    self.bundle_manifest.add_entry(target_type, file_to_write, relative_path,
                                                   start_offset, compressed_size, self.target.bundle_major_version)
                    # file_entry = self.bundle_manifest.add_entry(target_type, file_to_write, relative_path,
                    #                                             start_offset, compressed_size,
                    #                                             self.target.bundle_major_version)
                    # self.tracer.log(f"Embed: {file_entry}")

            header_offset = self.bundle_manifest.write(bundle_content)
        Bundler.set_as_bundle(bundle_path, header_offset)
        return bundle_path

    def is_host(self, relative_path) -> bool:
        return relative_path == self.host_name

    def should_ignore(self, relative_path) -> bool:
        return relative_path == self.runtime_config_dev_json

    def infer_type(self, file_spec: FileSpec) -> FileType:
        if file_spec.bundle_relative_path == self.deps_json:
            return FileType.DepsJson

        if file_spec.bundle_relative_path == self.runtime_config_json:
            return FileType.RuntimeConfigJson

        if os.path.splitext(file_spec.bundle_relative_path.lower())[1] == '.pdb':
            return FileType.Symbols

        (is_assembly, is_pe) = Bundler.is_assembly(file_spec.source_path)
        if is_assembly:
            return FileType.Assembly

        is_native_binary = is_pe if self.target.os == OSPlatform.WINDOWS else self.target.is_native_binary(
            file_spec.source_path)
        if is_native_binary:
            return FileType.NativeBinary

        return FileType.Unknown

    def should_exclude(self, file_type: FileType, relative_path: str) -> bool:
        if file_type in [FileType.Assembly, FileType.DepsJson, FileType.RuntimeConfigJson]:
            return False

        if file_type == FileType.NativeBinary:
            return (self.options & BundleOptions.BundleNativeBinaries) or self.target.should_exclude(relative_path)

        if file_type == FileType.Symbols:
            return self.options & BundleOptions.BundleSymbolFiles

        if file_type == FileType.Unknown:
            return self.options & BundleOptions.BundleSymbolFiles

        assert False, f"Exclusion rule not set for {file_type}."

    def set_as_bundle(app_host_path: str, bundle_header_offset: int):
        bundle_header_placeholder = (
            # 8 bytes represent the bundle header-offset
            # Zero for non-bundle apphosts (default).
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            # 32 bytes represent the bundle signature: SHA-256 for
            # ".NET Core bundle"
            b"\x8b\x12\x02\xb9\x6a\x61\x20\x38"
            b"\x72\x7b\x93\x02\x14\xd7\xa0\x32"
            b"\x13\xf5\xb9\xe6\xef\xae\x33\x18"
            b"\xee\x3b\x2d\xce\x24\xb3\x6a\xae"
        )

        # Re-write the estination apphost with the proper contents
        # TODO: Retry on IO error
        with open(app_host_path, "a+b") as f:
            # Why do I have to mmap this to effect writes?
            with mmap(f.fileno(), 0, access=ACCESS_WRITE) as m:
                m.seek(0)
                position = m.find(bundle_header_placeholder)
                if position < 0:
                    raise Exception(
                        f"Could not find placeholder value in apphost: {bundle_header_placeholder}.")
                m.seek(position)
                m.write(struct.pack('<L', bundle_header_offset))

                # TODO: MachOUtils.adjust_headers_for_bundle(app_host_path)

                # TODO: Retry on IO error
                os.utime(app_host_path)

        # if self.macos_codesign and OSPlatform.os() == OSPlatform.OSX and HostModelUtils.is_codesign_available():
        #     try:
        #         stderr = HostModelUtils.run_codesign(
        #             ['-s', '-'], app_host_destination_file_path)
        #     except Exception:
        #         raise Exception(f"Failed to codesign '{bundle_path}': {stderr}")

    @staticmethod
    def is_assembly(source_path) -> tuple[bool, bool]:
        # TODO: Test this
        with open(source_path, 'r') as f:
            with mmap(f.fileno(), 0, access=ACCESS_READ) as f:
                # Cheating on this a little based on info from
                # https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
                # and https://code.google.com/archive/p/corkami/wikis/PE.wiki.

                # To identify a PE file, the file should start with magic bytes
                # 'MZ' and contain an offset to the PE signature at 0x3c. The
                # four-byte PE signature should be equal to PE\0\0.
                try:
                    is_assembly = False
                    is_pe = False

                    e_magic = b'MZ'
                    if not f[:2] == e_magic:
                        return (False, False)

                    pe_signature_offset = f[0x3c]
                    pe_signature = b'PE\x00\x00'
                    is_pe = f[pe_signature_offset:pe_signature_offset +
                              4] == pe_signature
                    if is_pe:
                        coff_header_start = pe_signature_offset + 4
                        coff_header_size = 20
                        optional_header_start = coff_header_start + coff_header_size
                        (optional_header_size,) = struct.unpack(
                            '<H', f[coff_header_start + 16:coff_header_start + 16 + 2])
                        # The magic header values are specified as little endian,
                        # so we're reversing them here:
                        # https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-standard-fields-image-only
                        magic_value_length = 2
                        optional_header_magic_value = f[optional_header_start:
                                                        optional_header_start + magic_value_length]
                        # Data directory offset (relative to optional header)
                        # depends on whether this is a 32-bit (PE32) or 64-bit
                        # (PE32+) image
                        if optional_header_magic_value == b'\x0b\x01':  # PE32
                            data_directory_count_offset = optional_header_start + 92
                            clr_data_directory_entry_offset = optional_header_start + 208
                        # PE32+
                        elif optional_header_magic_value == b'\x0b\x02':
                            data_directory_count_offset = optional_header_start + 108
                            clr_data_directory_entry_offset = optional_header_start + 224
                        else:
                            return (is_assembly, is_pe)

                        # Validate that this entry actually exists
                        (data_directory_count,) = struct.unpack(
                            '<I', f[data_directory_count_offset:data_directory_count_offset + 4])
                        if not data_directory_count >= 15 or not data_directory_count <= 16:
                            return (is_assembly, is_pe)

                        clr_data_directory_entry = f[clr_data_directory_entry_offset:
                                                     clr_data_directory_entry_offset + 8]
                        (clr_data_directory_address, clr_data_directory_size) = struct.unpack(
                            '<II', clr_data_directory_entry)
                        # Sanity check
                        if clr_data_directory_size != 72:
                            return (is_assembly, is_pe)

                        # Find the virtual section that the clr directory lives in
                        section_entries_start = optional_header_start + optional_header_size
                        (section_entries_count,) = struct.unpack(
                            '<H', f[coff_header_start + 2:coff_header_start + 2 + 2])
                        section_entry_offset = section_entries_start
                        section_entry_size = 40
                        clr_data_directory_start = None
                        for _ in range(section_entries_count):
                            (section_virtual_size, section_address, section_size, section_offset) = struct.unpack(
                                '<IIII', f[section_entry_offset + 8:section_entry_offset + 8 + 4 * 4])
                            section_end = section_virtual_size + section_address
                            if clr_data_directory_address < section_end:
                                clr_data_directory_start = section_offset + \
                                    (clr_data_directory_address - section_address)
                                break
                            section_entry_offset += section_entry_size
                        if clr_data_directory_start is None:
                            return (is_assembly, is_pe)

                        # final sanity check: the CLR Data Directory/COR Header
                        # starts with the size of the header, which should match
                        # the value we already have
                        is_assembly = clr_data_directory_size == struct.unpack(
                            '<I', f[clr_data_directory_start:clr_data_directory_start + 4])[0]
                        return (is_assembly, is_pe)
                except Exception:
                    return (is_assembly, is_pe)

    def add_to_bundle(self, bundle: BinaryIO, file_to_bundle: BinaryIO, file_type: FileType) -> tuple[int, int]:
        """
        @bundle: The bundle file
        @file_to_bundle: The file to add to the bundle
        @file_type: The type of the file being added

        Returns:
            (start_offset, compressed_size) where
                start_offset is offset of the start 'file' within 'bundle', and
                compressed_size is the size of the compressed data, if entry was
                compressed, otherwise 0
        """
        start_offset = bundle.tell()
        if self.should_compress(file_type):
            file_length = len(file_to_bundle)
            file_to_bundle.seek(0)
            # We use DeflateStream here.
            # It uses ZLib algorithm, but with a trivial header that does not
            # contain file info.
            DEFLATE_DEFAULT_WINDOW_BITS = -15
            assert bundle.writable()
            compressor = zlib.compressobj(wbits=DEFLATE_DEFAULT_WINDOW_BITS)
            bundle.write(compressor.compress(file_to_bundle.read(-1)))
            compressed_size = bundle.tell() - start_offset
            if compressed_size < file_length * 0.75:
                return (start_offset, compressed_size)
            # compression rate was not good enough
            # roll back the bundle offset and let the uncompressed code path
            # take care of the entry.
            bundle.seek(start_offset)

        if file_type == FileType.Assembly:
            misalignment = bundle.tell() % self.target.assembly_alignment
            if misalignment != 0:
                padding = self.target.assembly_alignment - misalignment
                # bundle.seek(padding, SEEK_CUR)
                bundle.write(bytearray(padding))
        file_to_bundle.seek(0)
        start_offset = bundle.tell()
        bundle.write(file_to_bundle.read())
        return (start_offset, 0)

    def should_compress(self, file_type: FileType) -> bool:
        if not self.options & BundleOptions.EnableCompression:
            return False

        if file_type in [FileType.DepsJson, FileType.RuntimeConfigJson]:
            return False

        return True


class TaskItem:
    def __init__(self, item_spec: str, relative_path: str):
        self.item_spec = item_spec
        self.relative_path = relative_path


def execute(app_host_name: str,
            output_dir: str,
            runtime_identifier: str,
            target_framework_version: str,
            files_to_bundle: Sequence[TaskItem],
            include_native_libraries: bool = False,
            include_all_content: bool = False,
            include_symbols: bool = False,
            enable_compression_in_single_file: bool = False,
            show_diagnostic_output: bool = False) -> Sequence[FileSpec]:
    target_os: OSPlatform = (OSPlatform.WINDOWS if runtime_identifier.startswith("win")
                             else OSPlatform.OSX if runtime_identifier.startswith("osx")
                             else OSPlatform.LINUX)
    target_arch: Architecture = (
        Architecture.X64
        if runtime_identifier.endswith("-x64") or runtime_identifier.contains("-x64-") else Architecture.X86
        if runtime_identifier.endswith("-x86") or runtime_identifier.contains("-x86-") else Architecture.ARM64
        if runtime_identifier.endswith("-arm64") or runtime_identifier.contains("-arm64-") else Architecture.ARM
        if runtime_identifier.endswith("-arm") or runtime_identifier.contains("-arm-") else None)
    if target_arch is None:
        raise Exception(
            f"Runtime identifier not eligible for single-file bundles: {runtime_identifier}")

    options: BundleOptions = BundleOptions.Default
    options = options | BundleOptions.BundleNativeBinaries if include_native_libraries else BundleOptions.Default
    options = options | BundleOptions.BundleAllContent if include_all_content else BundleOptions.Default
    options = options | BundleOptions.BundleSymbolFiles if include_symbols else BundleOptions.Default
    options = options | BundleOptions.EnableCompression if enable_compression_in_single_file else BundleOptions.Default
    version: Version = Version(target_framework_version)
    bundler = Bundler(app_host_name, output_dir, options,
                      target_os, target_arch, version, show_diagnostic_output)

    file_specs: Sequence[FileSpec] = [
        FileSpec(i.item_spec, i.relative_path) for i in files_to_bundle]

    bundler.generate_bundle(file_specs)
    # Certain files are excluded from the bundle, based on BundleOptions.
    # For example:
    #    Native files and contents files are excluded by default.
    #    hostfxr and hostpolicy are excluded until singlefilehost is available.
    # Return the set of excluded files in ExcludedFiles, so that they can be
    # placed in the publish directory.

    excluded_files = [b for (b, f) in zip(
        files_to_bundle, file_specs) if f.excluded]
    return excluded_files


if __name__ == '__main__':
    args = sys.argv[1:]
    task_items = [(item := i.split('='), TaskItem(item[0], item[1]))[1]
                  for i in args[4:]]
    args[4] = task_items
    execute(*args)
