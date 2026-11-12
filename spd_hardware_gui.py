# SPDX-License-Identifier: MIT
"""Asynchronous Tk acquisition and reviewed programming workflow."""
import json
from pathlib import Path
import queue
import sys
import threading

from spd_hardware import (LinuxBackend, ExternalBackend, digest,
                          prepare_programming, execute_programming)


class HardwarePanel:
    def __init__(self, editor, parent):
        import tkinter as tk
        from tkinter import ttk
        from tkinter.scrolledtext import ScrolledText
        self.editor, self.root, self.parent = editor, editor.root, parent
        viewport = tk.Canvas(parent, highlightthickness=0, background='#EEF2F7')
        outer_scroll = ttk.Scrollbar(parent, orient='vertical', command=viewport.yview)
        viewport.configure(yscrollcommand=outer_scroll.set)
        outer_scroll.pack(side='right', fill='y')
        viewport.pack(fill='both', expand=True)
        content = ttk.Frame(viewport)
        window = viewport.create_window(0, 0, window=content, anchor='nw')
        content.bind('<Configure>', lambda event:viewport.configure(scrollregion=viewport.bbox('all')))
        viewport.bind('<Configure>', lambda event:viewport.itemconfigure(window, width=max(event.width, 990), height=max(event.height, 680)))
        parent = content
        self.busy = False
        self.writing = False
        self.events = queue.Queue()
        self.cancel_event = threading.Event()
        self.images = {}
        self.backend = None
        self.scan_config = None
        self.plan = None
        self.mode = tk.StringVar(value='Linux I2C / SMBus' if sys.platform.startswith('linux') else 'USB serial bridge')
        self.adapter = tk.StringVar()
        self.active = tk.BooleanVar(value=False)
        self.repair = tk.BooleanVar(value=True)
        self.start = tk.StringVar(value='0')
        self.end = tk.StringVar(value='255')
        self.state = tk.StringVar(value='Discover adapters, choose one, then scan for SPD devices.')
        controls = ttk.LabelFrame(parent, text='Connection', padding=10)
        controls.pack(fill='x', padx=10, pady=8)
        ttk.Combobox(controls, textvariable=self.mode, values=('Linux I2C / SMBus', 'USB serial bridge'), state='readonly', width=22).grid(row=0, column=0, padx=4)
        self.adapter_box = ttk.Combobox(controls, textvariable=self.adapter, width=32)
        self.adapter_box.grid(row=0, column=1, padx=4)
        ttk.Button(controls, text='Discover adapters', command=lambda:self.safe(self.discover)).grid(row=0, column=2, padx=4)
        ttk.Button(controls, text='Scan selected adapter', command=lambda:self.safe(self.scan)).grid(row=0, column=3, padx=4)
        ttk.Checkbutton(controls, text='Probe unregistered SPD addresses (0x50–0x57)', variable=self.active).grid(row=1, column=0, columnspan=3, sticky='w', pady=8)
        self.mode.trace_add('write', self.connection_changed)
        ttk.Label(parent, textvariable=self.state, padding=8, wraplength=1100).pack(fill='x')
        table = ttk.Frame(parent)
        table.pack(fill='x', padx=10)
        self.devices = ttk.Treeview(table, columns=('address','memory','capacity','rate','identity','size','integrity'), show='headings', selectmode='browse', height=4)
        for key, title, width in [('address','Address',75),('memory','Type',85),('capacity','Capacity',95),('rate','MT/s',75),('identity','Part number',220),('size','Bytes',65),('integrity','Acquisition / integrity',300)]:
            self.devices.heading(key, text=title)
            self.devices.column(key, width=width)
        scrollbar = ttk.Scrollbar(table, orient='vertical', command=self.devices.yview)
        self.devices.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side='right', fill='y'); self.devices.pack(fill='both', expand=True)
        self.devices.bind('<<TreeviewSelect>>', lambda event:self.show_selected())
        actions = ttk.Frame(parent, padding=8); actions.pack(fill='x')
        for title, callback in [('Read into editor', self.load), ('Save selected dump…', self.save_dump), ('Select best available image', self.select_best)]:
            ttk.Button(actions, text=title, command=lambda cb=callback:self.safe(cb)).pack(side='left', padx=4)
        self.cancel_button = ttk.Button(actions, text='Cancel read / scan', command=self.cancel)
        self.cancel_button.pack(side='right', padx=4)
        programming = ttk.LabelFrame(parent, text='Program the selected device from the editor image', padding=10)
        programming.pack(fill='x', padx=10, pady=8)
        ttk.Label(programming, text='Inclusive range:').pack(side='left')
        ttk.Entry(programming, textvariable=self.start, width=6).pack(side='left', padx=4)
        ttk.Label(programming, text='to').pack(side='left')
        ttk.Entry(programming, textvariable=self.end, width=6).pack(side='left', padx=4)
        ttk.Checkbutton(programming, text='Repair integrity in programming copy', variable=self.repair).pack(side='left', padx=8)
        ttk.Button(programming, text='Review changes…', command=lambda:self.safe(self.prepare)).pack(side='left', padx=4)
        ttk.Button(programming, text='Back up, program and verify…', command=lambda:self.safe(self.program)).pack(side='left', padx=4)
        self.details = ScrolledText(parent, height=8, wrap='none', font='TkFixedFont')
        self.details.pack(fill='both', expand=True, padx=10, pady=4)
        self.log = ScrolledText(parent, height=3, wrap='word', font='TkFixedFont')
        self.log.pack(fill='x', padx=10, pady=4)
        self.editor.set_text(self.details, 'Read images are ranked by valid integrity, editor support and completeness.\nThis does not select compatible timings or identify a physical DIMM slot.')
        self.editor.set_text(self.log, '')
        self.poll_job = self.root.after(50, self.poll)
        self.parent.bind('<Destroy>', self.destroyed, add='+')

    def destroyed(self, event):
        if event.widget == self.parent:
            self.cancel_event.set()
            if self.poll_job:
                self.root.after_cancel(self.poll_job)
                self.poll_job = None

    def connection_changed(self, *args):
        self.adapter.set('')
        self.adapter_box.configure(values=())
        self.plan = None

    def safe(self, callback):
        self.editor.run(callback)

    def idle(self):
        if self.busy:
            raise ValueError('A hardware operation is already running')

    def config(self):
        return self.mode.get(), self.adapter.get().strip()

    def selected(self):
        self.idle()
        if self.config() != self.scan_config:
            raise ValueError('Connection changed; scan the selected adapter again')
        selection = self.devices.selection()
        if not selection or selection[0] not in self.images:
            raise ValueError('Select a readable SPD device')
        return self.images[selection[0]]

    def append_log(self, message):
        self.log.configure(state='normal')
        self.log.insert('end', message + '\n')
        self.log.see('end'); self.log.configure(state='disabled')

    def start_job(self, label, work, done, writing=False):
        from tkinter import ttk
        self.idle()
        self.busy, self.writing = True, writing
        self.cancel_event = threading.Event()
        self.state.set(label)
        self.cancel_button.configure(state='disabled' if writing else 'normal')
        self.frozen_controls = []
        def freeze(parent):
            for child in parent.winfo_children():
                if child is not self.cancel_button and isinstance(child, (ttk.Button, ttk.Entry, ttk.Combobox, ttk.Checkbutton)):
                    self.frozen_controls.append((child, child.cget('state')))
                    child.configure(state='disabled')
                freeze(child)
        freeze(self.parent)
        def run():
            try:
                self.events.put(('done', (done, work())))
            except Exception as exc:
                self.events.put(('error', str(exc)))
        threading.Thread(target=run, daemon=True).start()

    def poll(self):
        from tkinter import messagebox
        try:
            while True:
                kind, value = self.events.get_nowait()
                if kind == 'log':
                    self.append_log(value)
                else:
                    was_writing = self.writing
                    self.busy = self.writing = False
                    for widget, state in self.frozen_controls:
                        widget.configure(state=state)
                    if kind == 'done':
                        callback, result = value
                        self.safe(lambda:callback(result))
                    else:
                        self.plan = None
                        detail = value + ('\nProgramming stopped; the target may be partially modified. Retain the backup and read it again.' if was_writing else '')
                        self.state.set(detail)
                        self.append_log(detail)
                        messagebox.showerror('SPD hardware', detail, parent=self.root)
        except queue.Empty:
            pass
        self.poll_job = self.root.after(50, self.poll)

    def cancel(self):
        if self.busy and not self.writing:
            self.cancel_event.set()
            self.state.set('Cancelling after the current bounded transaction…')

    def discover(self):
        mode = self.mode.get()
        def work():
            if mode == 'USB serial bridge':
                from spd_bridge import list_ports
                return [f'{port} — {description}' for port, description in list_ports()]
            if not sys.platform.startswith('linux'):
                raise ValueError('Local I2C / SMBus discovery requires Linux')
            from spd_smbus import inventory
            return [f'{r["bus"]} — {r["name"]}' for r in inventory()]
        def done(values):
            if self.mode.get() != mode:
                return
            self.adapter_box.configure(values=values)
            self.adapter.set(values[0] if values else '')
            self.state.set(f'{len(values)} adapters found. Select one and scan. A port can also be entered manually.')
        self.start_job('Discovering adapters…', work, done)

    def scan(self):
        self.idle()
        configuration = self.config()
        mode, value = configuration
        name = value.split(' — ', 1)[0]
        if not name:
            raise ValueError('Select an adapter or serial port first')
        backend = ExternalBackend(name) if mode == 'USB serial bridge' else LinuxBackend(int(name, 0))
        self.plan = None
        active = self.active.get()
        def work():
            return backend.scan(active, self.cancel_event, lambda m:self.events.put(('log',m)))
        def done(result):
            if self.config() != configuration:
                self.state.set('Connection changed during scan; scan again.')
                return
            self.backend, self.scan_config = backend, configuration
            images, errors = result
            self.devices.delete(*self.devices.get_children())
            self.images = {str(i): image for i, image in enumerate(images)}
            for key, image in self.images.items():
                item = image.summary()
                self.devices.insert('', 'end', iid=key, values=(item['address'],item['memory'],item['capacity'],item['data_rate_MTps'],item['identity'],item['length'],item['integrity']))
            for i, error in enumerate(errors):
                self.devices.insert('', 'end', iid=f'error-{i}', values=('', '', '', '', '', '', error))
                self.append_log(error)
            self.state.set(f'{len(images)} readable devices. {len(errors)} unsuccessful addresses. Select a device to inspect or read.')
            if images:
                self.devices.selection_set('0'); self.show_selected()
        self.start_job('Scanning selected adapter…', work, done)

    def show_selected(self):
        selection = self.devices.selection()
        if selection and selection[0] in self.images:
            self.editor.set_text(self.details, json.dumps(self.images[selection[0]].summary(), indent=2))

    def select_best(self):
        self.idle()
        if self.config() != self.scan_config:
            raise ValueError('Connection changed; scan the selected adapter again')
        if self.images:
            self.devices.selection_set('0'); self.show_selected()
            self.state.set('Selected the best available read by integrity and completeness; verify the target identity.')

    def load(self):
        image = self.selected()
        if not image.editable:
            raise ValueError('This generation can be saved as a dump but is not supported by the editor')
        if not self.editor.confirm_discard():
            return
        backend = self.backend
        def done(result):
            from spd_editor import EditorDocument
            self.editor.document = EditorDocument(result.data)
            self.editor.set_text(self.editor.diff, '')
            self.editor.refresh()
            self.end.set(str(len(result.data)-1))
            self.plan = None
            self.state.set(f'Loaded a fresh, matching-snapshot read from {result.target} / 0x{result.address:02X}. Save As preserves it on disk.')
            self.editor.book.select(self.editor.overview_tab)
        self.start_job('Reading selected SPD into editor…', lambda:backend.read(image.address, self.cancel_event), done)

    def save_dump(self):
        from tkinter import filedialog
        image = self.selected()
        path = filedialog.asksaveasfilename(parent=self.root, title='Save acquired SPD image', defaultextension='.bin')
        if path:
            # Exclusive creation protects both source files and earlier acquisitions.
            with Path(path).open('xb') as handle:
                handle.write(image.data)
            self.state.set(f'Saved the exact scanned image to {path}')

    def prepare(self):
        image = self.selected()
        document = self.editor.require_document()
        data = bytes(document.spd.data)
        start, end, repair = int(self.start.get(), 0), int(self.end.get(), 0), self.repair.get()
        self.plan = None
        backend = self.backend
        def done(plan):
            from spd_hardware import DeviceImage
            self.plan = plan
            self.prepared_repair = repair
            target = DeviceImage(plan.target,plan.address,plan.original,'programmer').summary()
            lines = [f'TARGET: {plan.target} / 0x{plan.address:02X}',
                     f'Part: {target["identity"]}; serial: {target["serial"]}; {target["capacity"]}',
                     f'Range: {plan.start}..{plan.end}; {len(plan.changes)} changed bytes',
                     f'Target SHA-256: {digest(plan.original)}', f'Result SHA-256: {digest(plan.expected)}',
                     f'Full {len(plan.original)}-byte target backup and full read-back verification are mandatory.', '', 'Offset    Target → Result']
            lines += [f'{n:3d} / 0x{n:02X}    {a:02X} → {b:02X}' for n,a,b in plan.changes]
            self.editor.set_text(self.details, '\n'.join(lines))
            self.state.set('Review prepared. Check target identity and exact changes before programming.')
        self.start_job('Reading target and preparing programming review…', lambda:prepare_programming(backend, image.address, data, start, end, repair), done)

    def program(self):
        from tkinter import filedialog, messagebox
        image = self.selected()
        plan = self.plan
        if plan is None:
            raise ValueError('Prepare and review the programming changes first')
        doc = self.editor.require_document()
        if (plan.target != self.backend.target or plan.address != image.address
                or plan.editor_hash != digest(doc.spd.data)
                or self.repair.get() != self.prepared_repair
                or plan.start != int(self.start.get(), 0) or plan.end != int(self.end.get(), 0)):
            self.plan = None
            raise ValueError('Image, target or range changed; prepare a new review')
        if not plan.changes:
            raise ValueError('The target already contains the requested data')
        backup = filedialog.asksaveasfilename(parent=self.root, title='New file for mandatory original SPD backup', defaultextension='.bin')
        if not backup:
            return
        if Path(backup).exists() or Path(str(backup)+'.json').exists():
            raise ValueError('Choose a new backup filename; existing files cannot be replaced')
        if not messagebox.askyesno('Program SPD', f'Program {plan.target} / 0x{plan.address:02X}?\n\n{len(plan.changes)} changed bytes in range {plan.start}..{plan.end}.\nBackup: {backup}\n\nA failed write can leave the module unusable until restored.\nProceed with backup, programming and full verification?', parent=self.root, default='no'):
            return
        backend = self.backend
        self.plan = None
        def done(report):
            self.state.set('Programming complete. Two full read-backs match the reviewed result. Scan again before further operations.')
            self.append_log(self.state.get())
            self.scan_config = None
            self.editor.set_text(self.details, json.dumps(report, indent=2))
        self.start_job('Backing up, programming and verifying. Keep the device connected…',
                       lambda:execute_programming(backend, plan, backup, lambda m:self.events.put(('log',m))), done, writing=True)
