#!/bin/sh

exit_with_error() {
  test_number=$1
  description=$2
  output=$3
  printf "not ok $test_number $description\n"
  printf "$output" | sed 's/^\(.*\)$/# \0/g'
  exit 1
}
printf "1..1\n"
test_1_description="Assert create_app_host() produces the same output as msbuild"
command="dotnet build --nologo TestProj"
output=$command
output=$(printf '%s' "$output\n$($command 2>&1)")
if [ $? -ne 0 ]; then
  exit_with_error 1 "$test_1_description" "$output"
fi
python ../apphost.py /usr/lib64/dotnet/packs/Microsoft.NETCore.App.Host.fedora.34-x64/6.0.0/runtimes/fedora.34-x64/native/apphost ./TestProj/bin/Debug/net6.0/pyapphost TestProj.dll TestProj
test_1_output=$(diff <(xxd TestProj/bin/Debug/net6.0/TestProj) <(xxd TestProj/bin/Debug/net6.0/pyapphost))
if [ $? -eq 0 ]; then
  echo ok 1 $test_1_description
else
  exit_with_error 1 $test_1_description $output
fi
