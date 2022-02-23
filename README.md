# Python .NET Compiler Helpers

Helper tools to perform some functions typically done by MSBuild with Python.
Aims to help with steps in the build process after compilation.

## Purpose

Hopefully, this can get integrated into another build system, like
[Meson](https://mesonbuild.com).

# Features

- [x] Produces framework-dependent executable (based on the [.NET HostWriter
      implementation][host-writer-cs])
- [x] Single-file application support

[host-writer-cs]: https://github.com/dotnet/runtime/blob/2cf48266341bafa60006ee2cd0f5696d63bb8151/src/installer/managed/Microsoft.NET.HostModel/AppHost/HostWriter.cs
# To do

- [ ] Add runtimeconfig.json generation
- [ ] Add deps.json generation
- [ ] Add self-contained application support
- [ ] Add Windows support
- [ ] Add Mac OS support
  - [ ] Add code signing support
- [ ] Add tests
  - [x] Integration test comparing that dotnet build and create_app_host() produce identical output
  - [ ] Others?
- [ ] Add create_app_host documentation, especially parameters
- [ ] Add CI
- [ ] Add "easy method" where you only need the DLL path
- [ ] Add "retry on error" functions from original .NET implementation
- [ ] Resolve NuGet references?
- [x] Add single-file support
