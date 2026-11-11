#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline Tk SPD editor. Run `python spd_editor.py [image]`."""
import argparse
import json
import os
from pathlib import Path
import tempfile
from spd_library import SPD, load_spd_file, hexdiff
from spd_integrity import repair_integrity


class EditorDocument:
    """Display-independent editor model; every successful operation is undoable."""
    def __init__(self, data, path=''):
        self.spd = SPD(data, path)
        self.path = str(path)
        self.saved = self.spd.data
        self.undo_stack = []
        self.redo_stack = []

    @property
    def dirty(self):
        return self.spd.data != self.saved

    def replace(self, data):
        candidate = SPD(data, self.path)
        if candidate.mem_type != self.spd.mem_type or len(data) != len(self.spd.data):
            raise ValueError('Editing cannot change the memory generation or image length')
        if candidate.data != self.spd.data:
            self.undo_stack.append(self.spd.data)
            self.redo_stack.clear()
            self.spd = candidate

    def edit(self, offset, values):
        values = bytes(values)
        if not values or not 0 <= offset < offset + len(values) <= len(self.spd.data):
            raise ValueError('Byte edit is empty or outside this image')
        candidate = bytearray(self.spd.data)
        candidate[offset:offset + len(values)] = values
        self.replace(candidate)

    def set_part_number(self, value):
        offset = 128 if self.spd.mem_type == 0x0B else 73
        if self.spd.mem_type not in (0x08, 0x0B):
            raise ValueError('Structured edits require DDR2 or DDR3')
        value = value.encode('ascii')
        if len(value) > 18 or any(b < 32 or b > 126 for b in value):
            raise ValueError('Part number must contain at most 18 printable ASCII characters')
        self.edit(offset, value.ljust(18, b' '))

    def set_serial(self, value):
        offset = 122 if self.spd.mem_type == 0x0B else 95
        if self.spd.mem_type not in (0x08, 0x0B):
            raise ValueError('Structured edits require DDR2 or DDR3')
        value = bytes.fromhex(value)
        if len(value) != 4:
            raise ValueError('Serial must contain exactly four hex bytes, in SPD byte order')
        self.edit(offset, value)

    def undo(self):
        if self.undo_stack:
            previous = self.undo_stack.pop()
            self.redo_stack.append(self.spd.data)
            self.spd = SPD(previous, self.path)

    def redo(self):
        if self.redo_stack:
            following = self.redo_stack.pop()
            self.undo_stack.append(self.spd.data)
            self.spd = SPD(following, self.path)

    def repair(self):
        self.replace(repair_integrity(self.spd.data))

    def save(self, path, fix_integrity=True):
        """Atomic file replacement; failed writes leave document and destination intact."""
        data = repair_integrity(self.spd.data) if fix_integrity else self.spd.data
        destination = Path(path)
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as stream:
                temp_path = stream.name
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_path, destination)
        finally:
            if temp_path and os.path.exists(temp_path):
                os.unlink(temp_path)
        self.replace(data)
        self.path = str(destination)
        self.spd.path = self.path
        self.saved = data


class SPDEditor:
    def __init__(self, root):
        import tkinter as tk
        from tkinter import ttk
        from tkinter.scrolledtext import ScrolledText
        self.root, self.document = root, None
        root.title('SPD Editor')
        root.geometry('1100x780')
        toolbar = ttk.Frame(root, padding=8)
        toolbar.pack(fill='x')
        for label, callback in [('Open...', self.open), ('Save', self.save), ('Save As...', self.save_as),
                                ('Undo', self.undo), ('Redo', self.redo), ('Repair integrity', self.repair),
                                ('Compare...', self.compare), ('Export JSON...', self.export)]:
            ttk.Button(toolbar, text=label, command=lambda f=callback: self.run(f)).pack(side='left', padx=2)
        self.fix_on_save = tk.BooleanVar(value=True)
        ttk.Checkbutton(root, text='Repair checksum / CRC on save', variable=self.fix_on_save).pack(anchor='w', padx=12)
        self.status = tk.StringVar(value='Open a binary or hex-text SPD image to begin.')
        ttk.Label(root, textvariable=self.status, padding=8).pack(fill='x')
        book = ttk.Notebook(root)
        book.pack(fill='both', expand=True, padx=10, pady=5)
        decoded = ttk.Frame(book)
        book.add(decoded, text='Decoded data')
        self.decoded = ScrolledText(decoded, wrap='none', font='TkFixedFont')
        self.decoded.pack(fill='both', expand=True)
        raw = ttk.Frame(book)
        book.add(raw, text='Byte editor')
        self.bytes_view = ttk.Treeview(raw, columns=('offset', 'value', 'original', 'field'), show='headings', selectmode='browse')
        for key, label, width in [('offset', 'Offset', 100), ('value', 'Hex', 80),
                                  ('original', 'Opened / saved', 110), ('field', 'Field', 560)]:
            self.bytes_view.heading(key, text=label)
            self.bytes_view.column(key, width=width)
        scroll = ttk.Scrollbar(raw, orient='vertical', command=self.bytes_view.yview)
        self.bytes_view.configure(yscrollcommand=scroll.set)
        scroll.pack(side='right', fill='y')
        self.bytes_view.pack(fill='both', expand=True)
        self.bytes_view.tag_configure('changed', background='#fff1bd')
        self.bytes_view.bind('<Double-1>', lambda event: self.run(self.edit_selected))
        edits = ttk.Frame(raw, padding=8)
        edits.pack(fill='x')
        for label, cb in [('Edit selected byte...', self.edit_selected), ('Write hex range...', self.edit_range),
                          ('Part number...', self.edit_part), ('Serial number...', self.edit_serial)]:
            ttk.Button(edits, text=label, command=lambda f=cb: self.run(f)).pack(side='left', padx=3)
        self.diff = ScrolledText(book, wrap='none', font='TkFixedFont')
        book.add(self.diff, text='Comparison')
        self.book = book
        self.diff.configure(state='disabled')
        root.protocol('WM_DELETE_WINDOW', lambda: self.run(self.close))
        for key, action in [('<Control-o>', self.open), ('<Control-s>', self.save),
                            ('<Control-z>', self.undo), ('<Control-y>', self.redo)]:
            root.bind(key, lambda event, f=action: self.run(f))

    def run(self, callback):
        from tkinter import messagebox
        try:
            callback()
        except (OSError, ValueError, NotImplementedError, UnicodeError) as exc:
            messagebox.showerror('SPD Editor', str(exc), parent=self.root)

    def require_document(self):
        if self.document is None:
            raise ValueError('Open an SPD image first')
        return self.document

    def confirm_discard(self):
        from tkinter import messagebox
        if self.document and self.document.dirty:
            decision = messagebox.askyesnocancel('Unsaved changes', 'Save changes before continuing?', parent=self.root)
            if decision is None:
                return False
            if decision:
                return self.save()
        return True

    def open_path(self, path):
        spd = load_spd_file(path)
        self.document = EditorDocument(spd.data, path)
        self.set_text(self.diff, '')
        self.refresh()

    def open(self):
        from tkinter import filedialog
        if not self.confirm_discard():
            return
        path = filedialog.askopenfilename(parent=self.root, filetypes=[('SPD images', '*.bin *.spd *.txt *.hex'), ('All files', '*')])
        if path:
            self.open_path(path)

    @staticmethod
    def set_text(widget, text):
        widget.configure(state='normal')
        widget.delete('1.0', 'end')
        widget.insert('1.0', text)
        widget.configure(state='disabled')

    def refresh(self):
        doc = self.require_document()
        spd = doc.spd
        self.root.title(f'{"* " if doc.dirty else ""}{Path(doc.path).name or "Untitled"} - SPD Editor')
        crc = spd.decoded_data['crc_info']
        self.status.set(f'{spd.mem_type_name} | {len(spd.data)} bytes | Integrity: {crc["status"]} | '
                        f'{len(hexdiff(doc.saved, spd.data))} changed bytes')
        self.set_text(self.decoded, json.dumps(spd.decoded_data, indent=2, default=lambda x: bytes(x).hex()))
        selected = self.bytes_view.selection()
        self.bytes_view.delete(*self.bytes_view.get_children())
        from ddr2_decoder import DDR2_FIELDS
        from ddr3_decoder import DDR3_FIELDS
        fields = DDR2_FIELDS if spd.mem_type == 8 else DDR3_FIELDS if spd.mem_type == 11 else []
        for offset, value in enumerate(spd.data):
            field = next((name for start, end, name in fields if start <= offset <= end), 'Reserved / raw byte')
            changed = value != doc.saved[offset]
            self.bytes_view.insert('', 'end', iid=str(offset), values=(f'{offset:03d} / 0x{offset:02X}',
                                   f'{value:02X}', f'{doc.saved[offset]:02X}', field), tags=('changed',) if changed else ())
        if selected and self.bytes_view.exists(selected[0]):
            self.bytes_view.selection_set(selected[0])
            self.bytes_view.see(selected[0])

    def edit_selected(self):
        from tkinter import simpledialog
        doc = self.require_document()
        selected = self.bytes_view.selection()
        if not selected:
            raise ValueError('Select a byte to edit')
        offset = int(selected[0])
        text = simpledialog.askstring('Edit byte', f'Hex value at offset {offset}:', initialvalue=f'{doc.spd.data[offset]:02X}', parent=self.root)
        if text is not None:
            data = bytes.fromhex(text)
            if len(data) != 1:
                raise ValueError('Enter exactly one hex byte')
            doc.edit(offset, data)
            self.refresh()

    def edit_range(self):
        from tkinter import simpledialog
        doc = self.require_document()
        offset = simpledialog.askinteger('Write range', 'Starting offset (decimal):', minvalue=0, maxvalue=len(doc.spd.data)-1, parent=self.root)
        if offset is None:
            return
        text = simpledialog.askstring('Write range', 'Hex bytes (for example: 01 02 FF):', parent=self.root)
        if text is not None:
            doc.edit(offset, bytes.fromhex(text))
            self.refresh()

    def edit_part(self):
        from tkinter import simpledialog
        doc = self.require_document()
        value = simpledialog.askstring('Part number', 'Part number (18 ASCII characters maximum):',
                  initialvalue=doc.spd.decoded_data['manufacturing'].get('module_part_number', ''), parent=self.root)
        if value is not None:
            doc.set_part_number(value)
            self.refresh()

    def edit_serial(self):
        from tkinter import simpledialog
        doc = self.require_document()
        value = simpledialog.askstring('Serial number', 'Four hex bytes, in SPD byte order:',
                  initialvalue=doc.spd.decoded_data['manufacturing'].get('serial_number', ''), parent=self.root)
        if value is not None:
            doc.set_serial(value)
            self.refresh()

    def undo(self):
        self.require_document().undo()
        self.refresh()

    def redo(self):
        self.require_document().redo()
        self.refresh()

    def repair(self):
        self.require_document().repair()
        self.refresh()

    def save(self):
        doc = self.require_document()
        if not doc.path:
            return self.save_as()
        doc.save(doc.path, self.fix_on_save.get())
        self.refresh()
        return True

    def save_as(self):
        from tkinter import filedialog
        doc = self.require_document()
        path = filedialog.asksaveasfilename(parent=self.root, defaultextension='.bin', filetypes=[('Binary SPD', '*.bin'), ('All files', '*')])
        if not path:
            return False
        doc.save(path, self.fix_on_save.get())
        self.refresh()
        return True

    def compare(self):
        from tkinter import filedialog
        doc = self.require_document()
        path = filedialog.askopenfilename(parent=self.root)
        if not path:
            return
        other = load_spd_file(path)
        diffs = hexdiff(doc.spd.data, other.data)
        fmt = lambda value: '--' if value is None else f'{value:02X}'
        self.set_text(self.diff, f'Current image vs {path}\n{len(diffs)} differing bytes\n\nOffset   Current   Comparison\n' +
                      '\n'.join(f'{offset:04X}     {fmt(a)}        {fmt(b)}' for offset, a, b in diffs))
        self.book.select(self.diff)

    def export(self):
        from tkinter import filedialog
        doc = self.require_document()
        path = filedialog.asksaveasfilename(parent=self.root, defaultextension='.json', filetypes=[('JSON', '*.json')])
        if path:
            Path(path).write_text(json.dumps(doc.spd.decoded_data, indent=2, default=lambda x: bytes(x).hex()) + '\n', encoding='utf-8')

    def close(self):
        if self.confirm_discard():
            self.root.destroy()


def main(path=None):
    import tkinter as tk
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        raise ValueError(f'A graphical display and Tk are required: {exc}') from exc
    app = SPDEditor(root)
    if path:
        app.run(lambda: app.open_path(path))
    root.mainloop()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', nargs='?')
    args = parser.parse_args()
    try:
        main(args.image)
    except (ImportError, ValueError) as exc:
        parser.exit(1, f'{exc}\n')
