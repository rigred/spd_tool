# SPDX-License-Identifier: MIT
"""Desktop entry point, also exposing CLI commands and packaged diagnostics."""
import argparse
import json
from pathlib import Path
import sys
from spd_version import VERSION


def main(argv=None):
    argv=list(sys.argv[1:] if argv is None else argv)
    if argv[:1]==['--cli']:
        from spd_tool import main as cli_main
        previous=sys.argv
        try:sys.argv=[previous[0],*argv[1:]];return cli_main()
        finally:sys.argv=previous
    parser=argparse.ArgumentParser(description='SPD Tool desktop editor and library')
    parser.add_argument('image',nargs='?',help='Optional supported SPD image to open')
    parser.add_argument('--version',action='version',version='SPD Tool '+VERSION)
    parser.add_argument('--self-test',action='store_true',help='Check bundled dependencies and temporary-file workflows; no hardware access')
    parser.add_argument('--gui-check',action='store_true',help='Also exercise Tk windows during --self-test')
    parser.add_argument('--report',help='Save --self-test results as JSON')
    args=parser.parse_args(argv)
    if (args.gui_check or args.report) and not args.self_test:parser.error('--gui-check and --report require --self-test')
    if args.self_test:
        from spd_release_check import self_test
        try:report=self_test(gui=args.gui_check)
        except Exception as exc:
            import traceback
            report=dict(status='FAILED',error=str(exc),traceback=traceback.format_exc(),version=VERSION)
        text=json.dumps(report,indent=2)+'\n'
        if args.report:Path(args.report).write_text(text,encoding='utf-8')
        if sys.stdout is not None:sys.stdout.write(text)
        return 0 if report['status']=='PASS' else 1
    from spd_editor import main as editor_main
    editor_main(args.image)
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
