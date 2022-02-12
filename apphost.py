"""
Create an apphost executable based on a DLL. Based on the [original .NET
HostWriter implementation][host-writer-cs].

[host-writer-cs]: https://github.com/dotnet/runtime/blob/2cf48266341bafa60006ee2cd0f5696d63bb8151/src/installer/managed/Microsoft.NET.HostModel/AppHost/HostWriter.cs
"""
from mmap import mmap, ACCESS_COPY
import os
from os import chmod
from stat import S_IRUSR, S_IWUSR, S_IXUSR, S_IRGRP, S_IXGRP, S_IROTH, S_IXOTH
import platform
import sys
from typing import BinaryIO
# from typing import BinaryIO, Optional, Sequence
# import subprocess

# if platform.system() == 'Windows':
#     import ctypes
#     kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
# 
# 
# class HostModelUtils:
#     codesign_path = '/usr/bin/codesign'
# 
#     @staticmethod
#     def is_code_sign_available() -> bool:
#         return os.path.exists(HostModelUtils.codesign_path)
# 
#     @staticmethod
#     def run_code_sign(args: Sequence[str], app_host_path: str) -> tuple[Optional[int], Optional[str]]:
#         assert(platform.system() == 'Darwin')
#         assert(HostModelUtils.is_code_sign_available())
#         process = subprocess.run(
#             [HostModelUtils.codesign_path] + args, capture_output=True)
#         return (process.returncode, process.stderr)


# class BinaryUtils:
#     @staticmethod
#     def _binary_search_and_replace(
#             accessor: MemoryMappedViewAccessor,
#             search_pattern: bytes,
#             pattern_to_replace: bytes,
#             pad_zeroes: bool = True):
#         pass


# class PEUtils():
#     @staticmethod
#     def is_pe_image(accessor: MemoryMappedViewAccessor):
#         pass
#
#     def set_windows_gui_bit(accessor: MemoryMappedViewAccessor):
#         pass


APP_BINARY_PATH_PLACEHOLDER_SEARCH_VALUE = b"c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2"


# class ResourceUpdater():
#     def init(pe_file_path: str):
#         pass
# 
#     @staticmethod
#     def is_supported_os() -> bool:
#         """
#         Determines if the ResourceUpdater is supported by the current operating
#         system.  Some versions of Windows, such as Nano Server, do not support
#         the needed APIs.
#         """
#         if not platform.system() == 'Windows':
#             return False
#         try:
#             # TODO: UNTESTED
#             # On Nano Server 1709+, `BeginUpdateResource` is exported but
#             # returns a null handle with a zero error Try to call
#             # `BeginUpdateResource` with an invalid parameter; the error should
#             # be non-zero if supported On Nano Server 20213,
#             # `BeginUpdateResource` fails with ERROR_CALL_NOT_IMPLEMENTED
#             handle = kernel32.BeginUpdateResource('', False)
#             err = ctypes.get_last_error()
#             ERROR_CALL_NOT_IMPLEMENTED = 0x78
#             if not handle and (not err or err == ERROR_CALL_NOT_IMPLEMENTED):
#                 return False
#         except Exception:
#             # TODO: Test if EntryPointNotFound error
#             return False
#         return True
# 
#     def add_resources_from_pe_image(self, path: str):
#         return self


def create_app_host(
        app_host_source_file_path: str,
        app_host_destination_file_path: str,
        app_binary_file_path: str,
        windows_graphical_user_interface: bool = False,
        assembly_to_copy_resources_from: str = None,
        enable_macos_code_sign: bool = False):

    bytes_to_write = app_binary_file_path.encode('utf-8')
    PATH_NAME_REGION_SIZE = 1024
    if len(bytes_to_write) > PATH_NAME_REGION_SIZE:
        raise Exception(f"App name is too long: {app_binary_file_path}")

    # app_host_is_pe_image: bool = False

    def _rewrite_app_host(memory_mapped_file: BinaryIO):
        # Re-write the destination apphost with the proper contents.
        position = memory_mapped_file.find(
            APP_BINARY_PATH_PLACEHOLDER_SEARCH_VALUE)
        if position < 0:
            raise Exception(
                f"Could not find placeholder value in apphost: {APP_BINARY_PATH_PLACEHOLDER_SEARCH_VALUE}.")
        memory_mapped_file.seek(position)
        memory_mapped_file.write(bytes_to_write)
        diff = len(APP_BINARY_PATH_PLACEHOLDER_SEARCH_VALUE) - \
            len(bytes_to_write)
        if diff > 0:
            memory_mapped_file.write(bytearray(diff))
        # BinaryUtils.binary_search_and_replace(
        #     accessor, APP_BINARY_PATH_PLACEHOLDER_SEARCH_VALUE, bytes_to_write)
        # app_host_is_pe_image = PEUtils.is_pe_image(accessor)
        # if windows_graphical_user_interface:
        #     if not app_host_is_pe_image:
        #         raise Exception('Apphost is not a PE file')
        #     PEUtils.set_windows_gui_bit(accessor)

    # def update_resources():
    #     if assembly_to_copy_resources_from and app_host_is_pe_image:
    #         if ResourceUpdater._is_supported_os():
    #             (ResourceUpdater(app_host_destination_file_path)
    #                 .add_resources_from_pe_image(assembly_to_copy_resources_from)
    #                 .update())
    #         else:
    #             raise Exception(
    #                 'Apphost customization is not supported on this OS.')
    try:
        # Open the source host file.
        # TODO: retry on error
        with open(app_host_source_file_path, 'rb') as app_host_source_stream:
            with mmap(app_host_source_stream.fileno(), 0, access=ACCESS_COPY) as memory_mapped_file:
                # source_app_host_length = len(app_host_source_stream)
                _rewrite_app_host(memory_mapped_file)
                with open(app_host_destination_file_path, 'wb') as file_stream:
                    file_stream.write(memory_mapped_file)
                    # BinaryUtils.write_to_stream(
                    #   accessor, file_stream, source_app_host_length)
                    # if not app_host_is_pe_image:
                    #   MachOUtils.remove_signature(file_stream)

        # update_resources()  # TODO: Retry on error

        if not platform.system() == 'Windows':
            file_permission = S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH  # -rwxr-xr-x
            try:
                chmod(app_host_destination_file_path, file_permission)
            except Exception:
                raise Exception(
                    f"Could not set file permission {file_permission} for {app_host_destination_file_path}")

            # if enable_macos_code_sign and platform.system() == 'Darwin' and HostModelUtils.is_code_sign_available():
            #     try:
            #         HostModelUtils.run_code_sign(
            #             ['-s', '-'], app_host_destination_file_path)
            #     except Exception:
            #         raise Exception("Signing apphost executable failed")
    except Exception as e:
        try:
            os.remove(app_host_destination_file_path)
        except Exception as file_delete_ex:
            raise file_delete_ex from e
        raise e


create_app_host(sys.argv[1], sys.argv[2], sys.argv[3],
                assembly_to_copy_resources_from=sys.argv[4])
