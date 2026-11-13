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

Release packages target Linux x86-64 and Windows x64. The GitHub Linux workflow
builds on Ubuntu 22.04; each package records its actual build platform/libc in
`BUILD_INFO.json`. Older distributions are not qualified; build from source on
the oldest intended deployment system. Choose the package for the target OS:
Linux binaries cannot run on Windows, macOS, ARM or musl-based distributions.
macOS has a source build recipe but is outside the automated release matrix.

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
# Windows native SMBus assets (no driver installation):
# python packaging/fetch_windows_modules.py
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
offline self-test does not qualify USB drivers or physical programming. Linux
uses its native I2C stack; Windows uses signed PawnIO SMBus modules or the
external serial bridge. Install the PawnIO driver separately for native access.
See [Windows setup and controller limits](WINDOWS.md), the
[external bridge guide](EXTERNAL_BRIDGE.md) and
[PyInstaller documentation](https://pyinstaller.org/en/stable/operating-mode.html).

## GitHub Actions releases

`.github/workflows/desktop-releases.yml` tests and builds native x86-64 packages
on Ubuntu 22.04 and Windows Server 2022 with Python 3.12. Linux GUI tests use
Xvfb. Both builds run the relocated frozen-runtime GUI/CLI checks; these checks
never load a hardware driver or access DIMMs. Windows assets are downloaded
from fixed official URLs and verified before bundling, with corresponding
source/license files included.

Pushes to `main`, pull requests and **Actions → Desktop builds and releases →
Run workflow** produce downloadable workflow artifacts. To publish a release:

1. Update `VERSION` in `spd_version.py` and commit the source/workflow changes.
2. Push a matching tag, for example:

   ```sh
   git tag v2026.11.13.1
   git push origin v2026.11.13.1
   ```

The tag must equal `v` plus the source version. After both platforms pass, the
publish job creates/updates that GitHub release with Windows ZIP, Linux tar.gz
and SHA-256 files. Native packages contain the application/runtime/docs, not the
entire source checkout. GitHub supplies its usual tag source archives.
Manual/branch/PR builds do not publish a release.

Build jobs have read-only repository permissions. Only the tag publish job has
`contents: write`, using the repository's built-in `GITHUB_TOKEN`; no personal
token is required. Repository policy must permit Actions and release writes.
Action versions are pinned to commits. Archives/checksums are unsigned; no
Authenticode signing certificate or Windows kernel driver is distributed.
