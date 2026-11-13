# Desktop releases

The desktop distribution opens the editor directly and includes its Python/Tk
runtime, HP family registry, 7z codecs, USB serial support and documentation.
Keep the complete `SPDTool` directory together when moving or distributing it.
No separate Python or pip installation is needed to run a frozen build.

## Launch

On Linux, extract the `.tar.gz` archive and run `./SPDTool/SPDTool`. The tar
archive preserves executable permissions. On Windows, a build made on Windows
starts with `SPDTool.exe`. An optional image filename opens that image directly.
Store collections and exports in a writable directory outside the application
folder. Preferences use the normal per-user configuration directory.

The supplied Linux build targets x86-64 and was built/tested on a glibc 2.41
system. Older distributions are not qualified; build from source on the oldest
distribution intended for deployment. This Linux artifact cannot run on Windows,
macOS, ARM or musl-based distributions. Windows/macOS require native builds;
the source package includes their build recipe, not prebuilt executables.

Every distribution includes `BUILD_INFO.json` with version, platform, dependency
versions and source hashes; `SHA256SUMS` covers the packaged files. Dependency
license texts are under `licenses/`. Hashes detect accidental changes; these
archives are unsigned and do not establish publisher authenticity.

## Diagnostics and command line

```sh
./SPDTool --version
./SPDTool --self-test --report check.json
./SPDTool --self-test --gui-check --report gui-check.json
./SPDTool --cli --help
./SPDTool --cli library-import --collection ./library --source ./Dumps
```

Run these commands inside the application directory, or use an absolute path
to the executable. On Windows, substitute `SPDTool.exe`; use `--report` for
diagnostics from a windowed build. Console command output on Windows requires a
build made with `packaging/build_desktop.py --console`, or the source Python CLI.
Self-tests create synthetic dumps in a
temporary directory and exercise conversion, 7z, SQLite, Unicode paths and open
bundles. The optional GUI check opens the editor and a read-only inspector.
They never enumerate hardware adapters, read DIMMs or program EEPROMs.

## Build from source

Create a clean Python environment on the target operating system:

```sh
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -r requirements-build.txt
python packaging/build_desktop.py
```

The default output is `dist/SPDTool/` (`dist/SPDTool.app` on macOS). Use
`--output /path/to/releases` to change the output parent. The build script
collects dynamic archive codecs and serial backends, includes the family
registry and documentation, and writes build provenance and checksums.
It replaces an existing output for the same application name.

Verify the executable from a different directory after moving its entire folder:

```sh
/path/to/SPDTool/SPDTool --self-test --gui-check --report /path/to/check.json
```

A release should be tested on each intended OS and architecture. A successful
offline self-test does not qualify USB drivers or physical programming. Native
host SMBus/I2C remains Linux-only. Windows uses the external serial bridge and
its board-specific driver; no Windows kernel SMBus driver is supplied. See the
[external bridge guide](EXTERNAL_BRIDGE.md) and
[PyInstaller documentation](https://pyinstaller.org/en/stable/operating-mode.html).
