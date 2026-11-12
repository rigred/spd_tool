# SPDX-License-Identifier: MIT
"""Atomic, versioned desktop preferences; failures never create a collection."""
import json,os,tempfile
from pathlib import Path


def config_path():
    base=os.environ.get('SPD_TOOL_CONFIG_DIR') or os.environ.get('APPDATA') or os.environ.get('XDG_CONFIG_HOME') or str(Path.home()/'.config')
    return Path(base)/'spd-tool'/'settings.json'


def load(path=None):
    try:
        result=json.loads(Path(path or config_path()).read_text())
        if not isinstance(result,dict) or result.get('version')!=1:return {}
        if any(k in result and not isinstance(result[k],str) for k in ('catalog_path','search','sort','year_from','year_to')):return {}
        if 'autoload' in result and not isinstance(result['autoload'],bool):return {}
        if 'filters' in result and (not isinstance(result['filters'],dict) or any(not isinstance(v,str) for v in result['filters'].values())):return {}
        return result
    except (OSError,ValueError):return {}


def save(settings,path=None):
    path=Path(path or config_path());path.parent.mkdir(parents=True,exist_ok=True)
    fd,name=tempfile.mkstemp(prefix='.settings-',dir=path.parent)
    try:
        with os.fdopen(fd,'w') as stream:json.dump(dict(settings,version=1),stream,indent=2);stream.flush();os.fsync(stream.fileno())
        os.replace(name,path)
    finally:
        if os.path.exists(name):os.unlink(name)
