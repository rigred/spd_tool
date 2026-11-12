# SPDX-License-Identifier: MIT
"""Build on the target OS after installing requirements-build.txt."""
from pathlib import Path
import os
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
subprocess.run([sys.executable, '-m', 'PyInstaller', '--noconfirm', '--clean',
                '--windowed', '--onedir', '--name', 'SPDTool',
                '--add-data', str(root/'hp_families.json')+':.',
                str(root/'spd_desktop.py')], cwd=root, check=True)
