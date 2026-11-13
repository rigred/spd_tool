# SPDX-License-Identifier: MIT
"""Compact import summaries with a complete, separately exportable record."""
from collections import Counter


def import_report(rows,errors):
    return dict(accepted=len(rows),unique_images=len({r['sha256'] for r in rows}),
                editable=sum(r.get('editable',True) for r in rows),
                archived=sum(not r.get('editable',True) for r in rows),
                invalid_integrity=sum(r['integrity']=='INVALID' for r in rows),
                unknown_integrity=sum(r['integrity']=='UNKNOWN' for r in rows),
                by_format=dict(Counter(r['import_format'] for r in rows)),
                by_memory=dict(Counter(r['memory'] for r in rows)),
                error_groups=dict(Counter(e['error'] for e in errors)),errors=errors,
                images=[{k:r.get(k) for k in ('source','sha256','memory','part','editable','support','integrity','warnings')} for r in rows])


def report_preview(report):
    lines=[f"Imported {report['accepted']} source images ({report['unique_images']} distinct images).",
           f"Editable: {report['editable']} | Read-only archive: {report['archived']} | Rejected: {len(report['errors'])}",
           f"Invalid SPD integrity: {report['invalid_integrity']} | Unknown integrity: {report['unknown_integrity']}",
           'Counts refer to source images; identical decoded bytes share one collection entry.',
           'No source images were repaired. Read-only images can be inspected and exported.',
           '\nMemory types: '+', '.join(f'{k}: {v}' for k,v in sorted(report['by_memory'].items())),
           'Formats: '+', '.join(f'{k}: {v}' for k,v in sorted(report['by_format'].items()))]
    if report['errors']:
        lines.append('\nRejection groups:')
        lines.extend(f'{count} × {reason}' for reason,count in sorted(report['error_groups'].items(),key=lambda x:-x[1])[:20])
        lines.append('\nFirst 20 rejected inputs:')
        lines.extend(e.get('path','')+': '+e['error'] for e in report['errors'][:20])
    lines.append('\nExport → Last import report saves the complete JSON record, including every source and rejection.')
    return '\n'.join(lines)
