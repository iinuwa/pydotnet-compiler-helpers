"""
Functionality to embed the managed app and its dependencies
into the host native binary.
"""
from enum import Enum, auto
from mmap import mmap, ACCESS_READ
import os
import platform
import shutil
import struct
from typing import Optional, Sequence


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
        return platform_map[platform.system()]


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


class BundleOptions(Enum):
    Default = 0
    BundleNativeBinaries = 1
    BundleAllContent = 2
    BundleSymbolFiles = 4
    EnableCompression = 8


class Version:
    def init(self, version_string):
        self.major: int = 0
        self.minor: int = 0
        self.build: int = 0
        self.revision: int = 0
        try:
            components = [int(c) for c in version_string.split('.', maxsplit=4)]
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
        self.relative_path = relative_path
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
    def __init__(self, target_os: Optional[OSPlatform], target_arch: Optional[Architecture], target_framework_version: Version):
        self.os = target_os if target_os else OSPlatform.os()
        self.arch = target_arch if target_arch else Architecture.arch()
        self.framework_version = target_framework_version if target_framework_version else Version("6.0.0.0")
        self.bundle_major_version = target_framework_version.major

        assert(self.os == OSPlatform.LINUX or self.os == OSPlatform.OSX or self.os == OSPlatform.WINDOWS)

        # TODO: Implement Version.compare_to
        if self.framework_version.major >= 6:
            self.bundle_major_version = 6
            self.default_options = BundleOptions.Default
        elif self.framework_version.major >= 5:
            self.bundle_major_version = 2
            self.default_options = BundleOptions.Default
        elif self.framework_version.major == 3 and (self.framework_version.minor == 0 or self.framework_version.minor == 1):
            self.bundle_major_version = 1
            self.default_options = BundleOptions.BundleAllContent
        else:
            raise Exception(f"Invalid input: unsupported target framework version: {target_framework_version}")

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
        self.files: Sequence[FileEntry] = []
        self.flags: HeaderFlags = HeaderFlags.NETCOREAPP3_COMPAT_MODE if netcoreapp3_compat_mode else HeaderFlags.Default

    def bundle_version(self):
        return f"{self.bundle_major_version}.{self.bundle_minor_version}"


class FileType(Enum):
    """Identifies the type of file embedded into the bundle.

    The bundler differentiates a few kinds of files via the manifest,
    with respect to the way in which they'll be used by the runtime.
    """
    Unknown = auto()             # Type not determined.
    Assempbly = auto()           # IL and R2R Assemblies
    NativeBinary = auto()        # NativeBinaries
    DepsJson = auto()            # .deps.json configuration file
    RuntimeConfigJson, = auto()  # .runtimeconfig.json configuration file
    Symbols = auto()             # PDB Files


class Bundler:
    def __init__(self,
                 host_name: str,
                 output_dir: str,
                 options: BundleOptions = BundleOptions.Default,
                 target_os: Optional[OSPlatform] = None,
                 target_arch: Optional[Architecture] = None,
                 target_framework_version: Version = Version("6.0"),
                 diagnostic_output: bool = False,
                 app_assembly_name: Optional(str) = None,
                 macos_codesign: bool = True):

        # self.tracer = Trace(diagnostic_output)

        self.host_name = host_name
        self.output_dir = os.path.abspath(output_dir if output_dir else os.getcwd())
        self.target = TargetInfo(target_os, target_arch, target_framework_version)

        if (self.target.bundle_major_version < 6 and
           (options & BundleOptions.EnableCompression) != 0):
            raise Exception("Compression requires framework version 6.0 or above")

        app_assembly_name = app_assembly_name if not None else self.target.GetAssemblyName(host_name)
        self.deps_json = f"{app_assembly_name}.deps.json"
        self.runtime_config_json = f"{app_assembly_name}.runtimeconfig.json"
        self.runtime_config_dev_json = f"{app_assembly_name}.runtimeconfig.dev.json"

        self.bundle_manifest = Manifest(self.target.bundle_major_version, netcoreapp3_compat_mode=options & BundleOptions.BundleAllContent)
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
            raise ValueError("Invalid input specification: Must specify the host binary")

        bundle_path = os.path.join(self.output_dir, self.host_name)
        # if os.path.exists(bundle_path):
        #     self.tracer.log(f"Overwriting existing file: {bundle_path}")

        # Copy file
        if not os.path.exists(self.output_dir):
            os.mkdir(self.output_dir)

        shutil.copyfile(host_source, bundle_path)

        # if OSPlatform.os() == OSPlatform.OSX and HostModelUtils.is_codesign_available():
        #    remove_codesign_if_necessary(bundle_path)

        # Note: We're comparing file paths both on the OS we're running on as
        # well as on the target OS for the app.
        # We can't really make assumptions about the file systems (even on
        # Linux there can be case insensitive file systems and vice versa for
        # Windows). So it's safer to do case sensitive comparison everywhere.

        relative_path_to_spec: dict[str, FileSpec] = {}
        header_offset = 0
        with open(bundle_path, 'ab') as writer:
            for file_spec in file_specs:
                relative_path: str = file_spec.bundle_relative_path
                if self.is_host(relative_path):
                    continue
                if self.should_ignore(relative_path):
                    continue

                file_type: FileType = self.infer_type(file_spec)
    
    def is_host(self, relative_path) -> bool:
        return file_relative_path == self.host_name

    def should_ignore(self, relative_path) -> bool:
        return relative_path == self.runtime_config_dev_json
    
    def infer_type(self, file_spec: FileSpec) -> FileType:
        if file_spec.bundle_relative_path == self.deps_json:
            return FileType.DepsJson
        
        if file_spec.bundle_relative_path == self.runtime_config_json:
            return FileType.RuntimeConfigJson
        
        if os.path.splitext(file_spec.bundle_relative_path.lower())[1] == '.pdb':
            return FileType.Symbols
        
    def is_assembly(self, source_path) -> tuple[bool, bool]:
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
                    is_pe = f[pe_signature_offset:pe_signature_offset + 4] == pe_signature
                    if is_pe:
                        coff_header_start = pe_signature_offset + 4
                        coff_header_size = 20
                        optional_header_start = coff_header_start + coff_header_size
                        (optional_header_size,) = struct.unpack('<H', f[coff_header_start + 16:coff_header_start + 16 + 2])
                        # The magic header values are specified as little endian,
                        # so we're reversing them here:
                        # https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-standard-fields-image-only
                        magic_value_length = 4
                        optional_header_magic_value = f[optional_header_start:optional_header_start + magic_value_length]
                        # Data directory offset (relative to optional header)
                        # depends on whether this is a 32-bit (PE32) or 64-bit
                        # (PE32+) image
                        if optional_header_magic_value == b'\x0b\x01':  # PE32
                            data_directory_count_offset = optional_header_start + 92
                            data_directory_offset = optional_header_start + 96
                            clr_data_directory_entry_offset = optional_header_start + 208
                        elif optional_header_magic_value == b'\x0b\x02': # PE32+
                            data_directory_count_offset = optional_header_start + 108
                            data_directory_offset = optional_header_start + 112
                            clr_data_directory_entry_offset = optional_header_start + 224
                        else:
                            return (is_assembly, is_pe)
                        
                        # Validate that this entry actually exists
                        (data_directory_count,) = struct.unpack('<I', f[data_directory_count_offset:data_directory_count_offset + 4])
                        if not data_directory_count >= 15 or not data_directory_count <= 16:
                            return (is_assembly, is_pe)

                        clr_data_directory_entry = f[clr_data_directory_entry_offset:clr_data_directory_entry_offset + 8]
                        (clr_data_directory_address, clr_data_directory_size) = struct.unpack(clr_data_directory_entry)
                        # Sanity check
                        if clr_data_directory_size != 72:
                            return (is_assembly, is_pe)
                        
                        # Find the virtual section that the clr directory lives in
                        section_entries_start = optional_header_start + optional_header_size
                        (section_entries_count,) = struct.unpack('<H', f[coff_header_start + 2:coff_header_start + 2 + 2])
                        section_entry_offset = section_entries_start
                        section_entry_size = 40
                        clr_data_directory_start = None
                        for _ in range(section_entries_count):
                            (section_virtual_size, section_address, section_size, section_offset) = struct.unpack('<IIII', f[section_entry_offset + 8:section_entry_offset + 8 + 4 * 4])
                            section_end = section_virtual_size + section_address 
                            if clr_data_directory_address < section_end:
                                clr_data_directory_start = section_offset + (clr_data_directory_address - section_address)
                                break
                            section_entry_offset += section_entry_size
                        if clr_data_directory_start is None:
                            return (is_assembly, is_pe)
                        
                        # final sanity check: the CLR Data Directory/COR Header
                        # starts with the size of the header, which should match
                        # the value we already have
                        is_assembly = clr_data_directory_size == struct.unpack('<I', f[clr_data_directory_start:clr_data_directory_start + 4])[0]
                        return (is_assembly, is_pe)
                except:
                    return (is_assembly, is_pe)
                

        return (True, False)


class PEReader:
    def __init__(fp: BinaryIO):


def execute(app_host_name: str,
            output_dir: str,
            runtime_identifier: str,
            target_framework_version: str,
            files_to_bundle: Sequence[FileSpec],
            include_native_libraries: bool = False,
            include_all_content: bool = False,
            include_symbols: bool = False,
            enable_compression_in_single_file: bool = False,
            show_diagnostic_output: bool = False) -> ExcludedFiles:
    target_os: OSPlatform = (OSPlatform.WINDOWS if runtime_identifier.startswith("win")
                             else OSPlatform.OSX if runtime_identifier.startswith("osx")
                             else OSPlatform.LINUX)
    target_arch: Architecture = (Architecture.X64 if runtime_identifier.endswith("-x64") or runtime_identifier.contains("-x64-") else
                                 Architecture.X86 if runtime_identifier.endswith("-x86") or runtime_identifier.contains("-x86-") else
                                 Architecture.ARM64 if runtime_identifier.endswith("-arm64") or runtime_identifier.contains("-arm64-") else
                                 Architecture.ARM if runtime_identifier.endswith("-arm") or runtime_identifier.contains("-arm-") else
                                 None)
    if target_arch is None:
        raise Exception(
            f"Runtime identifier not eligible for single-file bundles: {runtime_identifier}")

    options: BundleOptions = BundleOptions.Default
    options |= BundleOptions.BundleNativeBinaries if include_native_libraries else BundleOptions.Default
    options |= BundleOptions.BundleAllContent if include_all_content else BundleOptions.Default
    options |= BundleOptions.BundleSymbolFiles if include_symbols else BundleOptions.Default
    options |= BundleOptions.EnableCompression if enable_compression_in_single_file else BundleOptions.Default
    version: Version = Version(target_framework_version)
    bundler = Bundler(app_host_name, output_dir, options, target_os, target_arch, version, show_diagnostic_output)
    
    file_spec: Sequence[FileSpec] = [FileSpec(f.item_spec, f.get_metadata()["relative_path"]) for f in files_to_bundle]

    bundler.generate_bundle(file_spec)
    # Certain files are excluded from the bundle, based on BundleOptions.
    # For example:
    #    Native files and contents files are excluded by default.
    #    hostfxr and hostpolicy are excluded until singlefilehost is available.
    # Return the set of excluded files in ExcludedFiles, so that they can be
    # placed in the publish directory.

    excluded_files = [b for (b, f) in zip(files_to_bundle, file_spec) if f.excluded]
    return excluded_files
