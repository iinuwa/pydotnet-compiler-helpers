import os
import platform
import subprocess
import xml.etree.ElementTree as ET


def get_msbuild_metadata():
    dotnet_install_meta_path = '/etc/dotnet/install_location' if platform.system() == 'Linux' else None  # TODO: Determine location for non-Linux installs
    with open(dotnet_install_meta_path, 'r') as m:
        dotnet_root_dir = m.read().strip()
    dotnet_version = subprocess.run(['dotnet', '--version'], stdout=subprocess.PIPE).stdout.decode().strip()
    dotnet_props_path = os.path.join(dotnet_root_dir, 'sdk', dotnet_version, 'Microsoft.NETCoreSdk.BundledVersions.props')
    props = ET.parse(dotnet_props_path).getroot()
    host_runtime_identifier = props.find('./PropertyGroup/NETCoreSdkRuntimeIdentifier').text
    apphost_version = props.find('./PropertyGroup/BundledNETCoreAppPackageVersion').text
    native_apphost_path = os.path.join(dotnet_root_dir, 'packs', f'Microsoft.NETCore.App.Host.{host_runtime_identifier}', apphost_version, 'runtimes', host_runtime_identifier, 'native', 'apphost')
    return {
        'dotnet_version': dotnet_version,
        'dotnet_root_dir': dotnet_root_dir,
        'apphost_version': apphost_version,
        'host_runtime_identifier': host_runtime_identifier,
        'native_apphost_path': native_apphost_path,
    }
