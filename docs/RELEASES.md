# Desktop release builds

The file editor, collection database and USB serial bridge avoid Linux hardware
imports until that backend is selected. Native host SMBus/I2C access remains
Linux-only. Windows uses the external USB serial bridge and the serial driver
appropriate for the board; no Windows kernel SMBus driver is supplied.

A dedicated desktop launcher and optional PyInstaller build script are included:

```sh
python -m pip install -r requirements-build.txt
python packaging/build_desktop.py
```

Build on the target operating system and architecture. PyInstaller is not a
cross-compiler. The output is `dist/SPDTool/`; distribute the entire directory,
not just its executable. The desktop entry opens the GUI directly without CLI
arguments, and the build includes the HP family registry and optional serial
support. Source CLI commands remain available from a Python installation.

This build recipe is a release starting point, not a qualified Windows release.
Before publication, test on a clean Windows machine with no Python installation:
GUI startup/Tk assets, registry loading, collection imports and relocation,
non-ASCII paths, USB driver installation, disconnects and read/write failure
handling. Use a short writable collection directory outside the installation
folder; do not store user data in the bundle. Test the same hardware safeguards
used on Linux with a recoverable module.

A public release should add version metadata, icons, signed checksums, build
provenance and platform-specific signing/installer packaging. Keep software
installation separate from driver installation and physical fixture setup.
Do not advertise native Windows SMBus access or a tested executable until those
capabilities have been implemented and qualified.

See [PyInstaller operating modes](https://pyinstaller.org/en/stable/operating-mode.html)
and the [external bridge guide](EXTERNAL_BRIDGE.md).
