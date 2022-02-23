import filecmp
import subprocess
import sys
import os
sys.path.append("..")
from apphost import create_app_host  # noqa: E402
from meta import get_msbuild_metadata  # noqa: E402


def test_apphost_is_same(tmp_path):
    test_file = os.environ['PYTEST_CURRENT_TEST'].split(':', maxsplit=1)[0]
    test_dir = os.path.dirname(test_file)
    cs_project_dir = os.path.join(test_dir, 'TestProj')
    dotnet_out_dir = os.path.join(tmp_path, 'dotnet_build')
    subprocess.run(['dotnet', 'build', '--nologo', cs_project_dir, '--output', dotnet_out_dir])
    dotnet_apphost_path = os.path.join(dotnet_out_dir, 'TestProj')
    pymsbuild_out_dir = os.path.join(tmp_path, 'python_build')
    metadata = get_msbuild_metadata()
    apphost_location = metadata['native_apphost_path']
    py_apphost_path = os.path.join(pymsbuild_out_dir, 'TestProj')
    create_app_host(apphost_location, py_apphost_path, 'TestProj.dll')
    assert filecmp.cmp(dotnet_apphost_path, py_apphost_path, shallow=False)
