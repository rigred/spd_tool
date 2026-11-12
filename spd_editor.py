#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline Tk SPD editor. Run `python spd_editor.py [image]`."""
import hashlib
import argparse
import json
import os
from pathlib import Path
import tempfile
from spd_library import SPD, load_spd_file, hexdiff
from spd_integrity import repair_integrity
from spd_fields import module_fields, field_by_key, edit_field


class EditorDocument:
    """Display-independent editor model; every successful operation is undoable."""
    def __init__(self, data, path=''):
        self.spd = SPD(data, path)
        self.path = str(path)
        self.saved = self.spd.data
        self.undo_stack = []
        self.redo_stack = []
        self._vendor_profile_provenance = {}

    @property
    def vendor_profile_application(self):
        return self._vendor_profile_provenance.get(hashlib.sha256(self.spd.data).hexdigest())

    @vendor_profile_application.setter
    def vendor_profile_application(self, report):
        sha=hashlib.sha256(self.spd.data).hexdigest()
        if report.get('result_sha256')!=sha:
            raise ValueError('Profile provenance does not match the editor image')
        self._vendor_profile_provenance[sha]=report

    @property
    def dirty(self):
        return self.spd.data != self.saved

    def replace(self, data):
        candidate = SPD(data, self.path)
        if candidate.mem_type != self.spd.mem_type or len(data) != len(self.spd.data):
            raise ValueError('Editing cannot change the memory generation or image length')
        if candidate.data != self.spd.data:
            report=self.vendor_profile_application
            sha=hashlib.sha256(candidate.data).hexdigest()
            if report and sha!=report.get('target_sha256') and sha not in self._vendor_profile_provenance:
                self._vendor_profile_provenance[sha]=dict(report,result_sha256=sha,modified_after_profile=True)
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
        if self.spd.mem_type not in (0x04, 0x07, 0x08, 0x0B):
            raise ValueError('Structured edits require SDR, DDR, DDR2 or DDR3')
        value = value.encode('ascii')
        if len(value) > 18 or any(b < 32 or b > 126 for b in value):
            raise ValueError('Part number must contain at most 18 printable ASCII characters')
        self.edit(offset, value.ljust(18, b' '))

    def set_serial(self, value):
        offset = 122 if self.spd.mem_type == 0x0B else 95
        if self.spd.mem_type not in (0x04, 0x07, 0x08, 0x0B):
            raise ValueError('Structured edits require SDR, DDR, DDR2 or DDR3')
        value = bytes.fromhex(value)
        if len(value) != 4:
            raise ValueError('Serial must contain exactly four hex bytes, in SPD byte order')
        self.edit(offset, value)

    def set_module_field(self, key, value):
        self.replace(edit_field(self.spd.data, key, value))

    def copy_module_settings(self, source_data):
        from types import SimpleNamespace
        from spd_integrity import patch_image
        source = SPD(source_data)
        if self.spd.mem_type == 11:
            if (self.spd.data[3] & 15) not in (1,5,9,11):
                raise ValueError('Register/buffer settings require a DDR3 RDIMM or LRDIMM')
            ranges = ['60:116']
        elif self.spd.mem_type in (4,7):
            ranges = ['21:22']
        else:
            raise ValueError('Module settings copy supports SDR, DDR and DDR3 registered layouts')
        self.replace(patch_image(self.spd.data,source.data,SimpleNamespace(copy_range=ranges)))

    def set_hpt(self, code):
        if self.spd.mem_type != 11 or len(self.spd.data)<184:
            raise ValueError('HPT editing requires DDR3 with bytes 176-183 present')
        code = bytes.fromhex(code) if isinstance(code,str) else bytes(code)
        if len(code)!=4:
            raise ValueError('HPT code requires exactly four bytes in SPD byte order')
        self.edit(176,b'HPT\0'+code)

    def hp_info(self, registry=None):
        from hp_smartmemory_ident import load_registry
        registry = load_registry(str(Path(__file__).with_name('hp_families.json'))) if registry is None else registry
        if self.spd.mem_type != 11 or len(self.spd.data)<184:
            return dict(available=False, matches=[])
        data=self.spd.data
        serial=int.from_bytes(data[122:126],'big')
        present=data[176:180]==b'HPT\0'
        code=int.from_bytes(data[180:184],'big')
        matches=[]
        if present:
            for key,family in registry.items():
                try:
                    a,b,k=(int(family[x],16) for x in ('A','B','K'))
                    if (a*serial+b*code)&0xFFFFFFFF == k:
                        matches.append(dict(key=key,name=family.get('name',key),equivalents=family.get('equivalents',[])))
                except (KeyError,TypeError,ValueError):
                    continue
        return dict(available=True,present=present,serial=f'{serial:08X}',hpt=f'{code:08X}',matches=matches,
                    note='Registry matches are learned relationships, not cryptographic authentication. Serial/part edits do not automatically rewrite HPT.')

    def hpt_candidates(self, family_key, registry=None):
        from hp_smartmemory_ident import load_registry, compute_hpt_solutions
        registry=load_registry(str(Path(__file__).with_name('hp_families.json'))) if registry is None else registry
        info=self.hp_info(registry)
        if not info['available']:
            raise ValueError('HPT editing requires a full DDR3 customer block')
        if family_key not in registry:
            raise ValueError('Unknown HP family')
        family=registry[family_key]
        try:
            b=int(family['B'],16)
        except (KeyError,ValueError) as exc:
            raise ValueError('Family lacks valid coefficients') from exc
        count=(b & -b) if b else 0
        if not b or count>1024:
            raise ValueError('Family is underdetermined; refusing to enumerate more than 1024 candidates')
        return [f'{code:08X}' for code in compute_hpt_solutions(int(info['serial'],16),family)]

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
        self._active_dialog = None
        self._configure_style()
        root.configure(background='#EEF2F7')
        root.title('SPD Editor')
        root.geometry('1240x920')
        root.minsize(1024,720)
        header = tk.Frame(root,background='#14283F',padx=20,pady=14)
        header.pack(fill='x')
        tk.Label(header,text='SPD TOOL',font=('DejaVu Sans',18,'bold'),foreground='white',background='#14283F').pack(side='left')
        tk.Label(header,text='MODULE CONFIGURATION',font=('DejaVu Sans',10),foreground='#B5C8DC',background='#14283F').pack(side='left',padx=20)
        self.document_name=tk.StringVar(value='No image loaded')
        tk.Label(header,textvariable=self.document_name,foreground='#DCE8F5',background='#14283F',anchor='e').pack(side='right')
        toolbar = ttk.Frame(root, padding=(12,8))
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
        self.overview_tab=ttk.Frame(book)
        book.add(self.overview_tab,text='Overview')
        self._build_overview(self.overview_tab)
        decoded = ttk.Frame(book)
        book.add(decoded, text='Decoded JSON')
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
        self.bytes_view.bind('<Double-1>',lambda event:self._edit_tree_row(event,self.bytes_view,self.edit_selected))
        edits = ttk.Frame(raw, padding=8)
        edits.pack(fill='x')
        for label, cb in [('Edit selected byte...', self.edit_selected), ('Write hex range...', self.edit_range),
                          ('Part number...', self.edit_part), ('Serial number...', self.edit_serial)]:
            ttk.Button(edits, text=label, command=lambda f=cb: self.run(f)).pack(side='left', padx=3)
        module_tab = ttk.Frame(book)
        self.module_tab=module_tab
        book.add(module_tab, text='Registers / buffers')
        filters = ttk.Frame(module_tab,padding=6)
        filters.pack(fill='x')
        self.field_group = tk.StringVar(value='All groups')
        self.group_selector = ttk.Combobox(filters,textvariable=self.field_group,state='readonly',width=32)
        self.group_selector.pack(side='left',padx=3)
        self.group_selector.bind('<<ComboboxSelected>>',lambda event:self.refresh_module_fields())
        self.field_search = tk.StringVar()
        ttk.Label(filters,text='Filter:').pack(side='left',padx=3)
        ttk.Entry(filters,textvariable=self.field_search,width=22).pack(side='left')
        self.show_expert = tk.BooleanVar(value=False)
        ttk.Checkbutton(filters,text='Show raw control/personality words',variable=self.show_expert,
                        command=self.refresh_module_fields).pack(side='left',padx=6)
        self.field_search.trace_add('write',lambda *args:self.refresh_module_fields())
        self.module_view=ttk.Treeview(module_tab,columns=('group','name','value','raw','location'),show='headings',selectmode='browse')
        for key,label,width in [('group','Group',210),('name','Setting',300),('value','Meaning',230),('raw','Code',65),('location','Byte / bits',105)]:
            self.module_view.heading(key,text=label)
            self.module_view.column(key,width=width)
        module_scroll=ttk.Scrollbar(module_tab,orient='vertical',command=self.module_view.yview)
        self.module_view.configure(yscrollcommand=module_scroll.set)
        module_scroll.pack(side='right',fill='y')
        self.module_view.pack(fill='both',expand=True)
        self.module_view.bind('<Double-1>',lambda event:self._edit_tree_row(event,self.module_view,self.edit_module_field))
        self.module_view.bind('<<TreeviewSelect>>',self.show_field_note)
        self.field_note=tk.StringVar(value='Select a setting for its description. Raw personality words require the buffer vendor datasheet.')
        ttk.Label(module_tab,textvariable=self.field_note,wraplength=1000,padding=6).pack(fill='x')
        buttons=ttk.Frame(module_tab,padding=6)
        buttons.pack(fill='x')
        ttk.Button(buttons,text='Edit selected setting...',command=lambda:self.run(self.edit_module_field)).pack(side='left')
        ttk.Button(buttons,text='Copy module settings from file...',command=lambda:self.run(self.copy_module_settings)).pack(side='left',padx=8)
        hp_tab=ttk.Frame(book)
        book.add(hp_tab,text='HP SmartMemory')
        self.hp_text=ScrolledText(hp_tab,wrap='word',font='TkFixedFont')
        self.hp_text.pack(fill='both',expand=True)
        hp_buttons=ttk.Frame(hp_tab,padding=8)
        hp_buttons.pack(fill='x')
        ttk.Button(hp_buttons,text='Set HPT bytes...',command=lambda:self.run(self.edit_hpt)).pack(side='left')
        ttk.Button(hp_buttons,text='Compute HPT from known family...',command=lambda:self.run(self.compute_hpt)).pack(side='left',padx=8)
        self.diff = ScrolledText(book, wrap='none', font='TkFixedFont')
        book.add(self.diff, text='Comparison')
        self.book = book
        from spd_hardware_gui import HardwarePanel
        self.hardware_tab = ttk.Frame(book)
        book.add(self.hardware_tab, text='Hardware / programmer')
        self.hardware = HardwarePanel(self, self.hardware_tab)
        from spd_catalog_gui import CatalogPanel
        self.catalog_tab = ttk.Frame(book)
        book.add(self.catalog_tab, text='SPD library')
        self.catalog = CatalogPanel(self, self.catalog_tab)
        self.diff.configure(state='disabled')
        root.protocol('WM_DELETE_WINDOW', lambda: self.run(self.close))
        for key, action in [('<Control-o>', self.open), ('<Control-s>', self.save),
                            ('<Control-z>', self.undo), ('<Control-y>', self.redo)]:
            root.bind(key, lambda event, f=action: self.run(f))

    def _configure_style(self):
        from tkinter import ttk
        style=ttk.Style(self.root)
        if 'clam' in style.theme_names():style.theme_use('clam')
        style.configure('.',font=('DejaVu Sans',10))
        style.configure('TFrame',background='#EEF2F7')
        style.configure('TLabel',background='#EEF2F7',foreground='#22364D')
        style.configure('TButton',padding=(10,6))
        style.configure('TCheckbutton',background='#EEF2F7')
        style.configure('TNotebook',background='#EEF2F7',borderwidth=0)
        style.configure('TNotebook.Tab',padding=(14,8))
        style.map('TNotebook.Tab',background=[('selected','#FFFFFF')],foreground=[('selected','#135FAB')])
        style.configure('Treeview',rowheight=27,background='white',fieldbackground='white',foreground='#22364D')
        style.configure('Treeview.Heading',background='#DFE7F0',foreground='#243951',padding=(8,6),font=('DejaVu Sans',10,'bold'))
        style.map('Treeview',background=[('selected','#D5E7F8')],foreground=[('selected','#102F52')])
        style.configure('Card.TFrame',background='white',relief='solid',borderwidth=1)
        style.configure('Card.TLabel',background='white',foreground='#22364D')
        style.configure('Section.TLabel',background='white',foreground='#135FAB',font=('DejaVu Sans',11,'bold'))
        style.configure('Metric.TLabel',background='white',foreground='#14283F',font=('DejaVu Sans',17,'bold'))
        style.configure('Muted.TLabel',background='white',foreground='#62758B')

    def _build_overview(self,parent):
        import tkinter as tk
        from tkinter import ttk
        canvas=tk.Canvas(parent,background='#EEF2F7',highlightthickness=0)
        scroll=ttk.Scrollbar(parent,orient='vertical',command=canvas.yview)
        canvas.configure(yscrollcommand=scroll.set)
        scroll.pack(side='right',fill='y');canvas.pack(fill='both',expand=True)
        body=ttk.Frame(canvas,padding=14)
        item=canvas.create_window((0,0),window=body,anchor='nw')
        canvas.bind('<Configure>',lambda event:canvas.itemconfigure(item,width=event.width))
        body.bind('<Configure>',lambda event:canvas.configure(scrollregion=canvas.bbox('all')))
        self.overview_title=tk.StringVar(value='Open an SPD image')
        ttk.Label(body,textvariable=self.overview_title,font=('DejaVu Sans',16,'bold')).pack(anchor='w',pady=(0,10))
        metrics=ttk.Frame(body);metrics.pack(fill='x')
        self.overview_metrics={}
        for column,(key,label) in enumerate((('capacity','USABLE CAPACITY'),('family','MEMORY FAMILY'),('speed','SPD MAXIMUM RATE'),('integrity','IMAGE INTEGRITY'))):
            metrics.columnconfigure(column,weight=1,uniform='metrics')
            card=ttk.Frame(metrics,style='Card.TFrame',padding=12)
            card.grid(row=0,column=column,sticky='nsew',padx=(0,8) if column<3 else 0)
            ttk.Label(card,text=label,style='Muted.TLabel').pack(anchor='w')
            variable=tk.StringVar(value='--');self.overview_metrics[key]=variable
            ttk.Label(card,textvariable=variable,style='Metric.TLabel').pack(anchor='w',pady=(6,0))
        grid=ttk.Frame(body);grid.pack(fill='x',pady=12)
        self.overview_values={}
        for index,(section,labels) in enumerate((
            ('Module identity',('Part number','Module manufacturer','DRAM manufacturer','Serial / SPD byte order','Manufacturing date','SPD revision')),
            ('Organization',('Memory family','Module type','Usable capacity','Ranks','SDRAM device width','Data / checking width','Banks per device','Operating voltage')),
            ('Operating point',('SPD maximum data rate','Clock at tCKmin','Minimum clock period','CL - tRCD - tRP - tRAS','Bandwidth designation','Module thermal sensor')),
            ('Register / buffer',('Component manufacturer','Component revision','Register devices','DRAM package rows','Buffer orientation','Component family','Registered address/control')))):
            grid.columnconfigure(index%2,weight=1,uniform='sections')
            card=ttk.Frame(grid,style='Card.TFrame',padding=12)
            card.grid(row=index//2,column=index%2,sticky='nsew',padx=(0,8) if index%2==0 else 0,pady=(0,8))
            ttk.Label(card,text=section.upper(),style='Section.TLabel').grid(row=0,column=0,columnspan=2,sticky='w',pady=(0,8))
            card.columnconfigure(1,weight=1)
            for row,label in enumerate(labels,1):
                ttk.Label(card,text=label,style='Muted.TLabel').grid(row=row,column=0,sticky='nw',padx=(0,14),pady=3)
                variable=tk.StringVar(value='--');self.overview_values[(section,label)]=variable
                ttk.Label(card,textvariable=variable,style='Card.TLabel',wraplength=330).grid(row=row,column=1,sticky='nw',pady=3)
        lower=ttk.Frame(body);lower.pack(fill='x')
        for index in (0,1):lower.columnconfigure(index,weight=1,uniform='tables')
        self.overview_trees={}
        for index,(key,title,columns) in enumerate((('timings','TIMING LIMITS',('Parameter','Limit')),('profiles','OPERATING PROFILES',('Rate / profile','CL-tRCD-tRP-tRAS','Value','Source')))):
            card=ttk.Frame(lower,style='Card.TFrame',padding=12)
            card.grid(row=0,column=index,sticky='nsew',padx=(0,8) if index==0 else 0)
            ttk.Label(card,text=title,style='Section.TLabel').pack(anchor='w',pady=(0,8))
            tree=ttk.Treeview(card,columns=columns,show='headings',height=6)
            for column in columns:
                tree.heading(column,text=column);tree.column(column,width=110,minwidth=65)
            scrollbar=ttk.Scrollbar(card,orient='vertical',command=tree.yview)
            tree.configure(yscrollcommand=scrollbar.set);scrollbar.pack(side='right',fill='y');tree.pack(fill='both',expand=True)
            self.overview_trees[key]=tree
        integrity=ttk.Frame(body,style='Card.TFrame',padding=12);integrity.pack(fill='x',pady=12)
        ttk.Label(integrity,text='INTEGRITY & DIAGNOSTICS',style='Section.TLabel').pack(anchor='w')
        self.integrity_summary=tk.StringVar(value='No image loaded')
        ttk.Label(integrity,textvariable=self.integrity_summary,style='Card.TLabel',wraplength=1060).pack(anchor='w',pady=8)
        self.overview_warnings=tk.Text(integrity,height=3,wrap='word',background='#F7F9FC',foreground='#7D4B09',relief='flat',font=('DejaVu Sans',10))
        self.overview_warnings.pack(fill='x')
        ttk.Label(body,text='SPD capability data; configured host speed and memory-training results are not measured.',foreground='#62758B').pack(anchor='w',pady=(0,8))

    def _refresh_overview(self):
        from spd_overview import module_overview
        view=module_overview(self.document.spd,self.document.hp_info())
        self.overview_title.set(view['title'])
        for key,variable in self.overview_metrics.items():variable.set(view[key])
        for variable in self.overview_values.values():variable.set('Not specified')
        for section,rows in view['sections'].items():
            for label,value in rows:
                variable=self.overview_values.get((section,label))
                if variable is not None:variable.set(value)
        for key,tree in self.overview_trees.items():
            tree.delete(*tree.get_children())
            for row in view[key]:tree.insert('','end',values=row)
        self.integrity_summary.set('   |   '.join(f'{key}: {value}' for key,value in view['integrity_fields']))
        self.set_text(self.overview_warnings,'\n'.join(view['warnings']) or 'No decoder warnings. Hardware validation is separate.')

    def _edit_tree_row(self,event,tree,callback):
        row=tree.identify_row(event.y)
        if row and tree.identify_region(event.x,event.y) in ('cell','tree'):
            tree.selection_set(row);tree.focus(row)
            # Defer until the current button event has completed.
            self.root.after_idle(lambda:self.run(callback))
        return 'break'

    def _new_dialog(self,title):
        import tkinter as tk
        active=self._active_dialog
        if active is not None and active.winfo_exists():
            active.lift();return None
        dialog=tk.Toplevel(self.root)
        dialog.withdraw()
        dialog.title(title)
        dialog.transient(self.root)
        self._active_dialog=dialog
        def closed(event):
            if event.widget is dialog:
                pending=getattr(dialog,'_activation_job',None)
                if pending:
                    self.root.after_cancel(pending)
                    dialog._activation_job=None
                if self._active_dialog is dialog:self._active_dialog=None
        dialog.bind('<Destroy>',closed,add='+')
        return dialog

    def _present_dialog(self,dialog,focus=None):
        import tkinter as tk
        def acquire(event=None):
            if event is not None and event.widget is not dialog:return
            if not dialog.winfo_exists() or not dialog.winfo_viewable():return
            try:
                if dialog.grab_current() is dialog:return
                dialog.grab_set()
                if focus is not None:focus.focus_set()
            except tk.TclError as exc:
                # A window can be unmapped while the WM processes a transition.
                # Its next Map/Visibility event will retry without an early grab.
                if dialog.winfo_exists() and dialog.winfo_viewable():
                    dialog.destroy()
                    from tkinter import messagebox
                    messagebox.showerror('SPD Editor',f'Cannot activate dialog: {exc}',parent=self.root)
        dialog.bind('<Map>',acquire,add='+')
        dialog.bind('<Visibility>',acquire,add='+')
        dialog.update_idletasks()
        dialog.deiconify()
        def deferred_acquire():
            dialog._activation_job=None
            acquire()
        dialog._activation_job=self.root.after_idle(deferred_acquire)

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
        self.hardware.plan = None
        self.hardware.end.set(str(len(spd.data)-1))
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
        self.document_name.set(Path(doc.path).name or 'Untitled image')
        self._refresh_overview()
        crc = spd.decoded_data['crc_info']
        self.status.set(f'{spd.mem_type_name} | {len(spd.data)} bytes | Integrity: {crc["status"]} | '
                        f'{len(hexdiff(doc.saved, spd.data))} changed bytes')
        self.set_text(self.decoded, json.dumps(spd.decoded_data, indent=2, default=lambda x: bytes(x).hex()))
        selected = self.bytes_view.selection()
        self.bytes_view.delete(*self.bytes_view.get_children())
        from ddr2_decoder import DDR2_FIELDS
        from ddr3_decoder import DDR3_FIELDS
        from legacy_decoder import LEGACY_FIELDS
        fields = DDR2_FIELDS if spd.mem_type == 8 else DDR3_FIELDS if spd.mem_type == 11 else LEGACY_FIELDS
        for offset, value in enumerate(spd.data):
            field = next((name for start, end, name in fields if start <= offset <= end), 'Reserved / raw byte')
            changed = value != doc.saved[offset]
            self.bytes_view.insert('', 'end', iid=str(offset), values=(f'{offset:03d} / 0x{offset:02X}',
                                   f'{value:02X}', f'{doc.saved[offset]:02X}', field), tags=('changed',) if changed else ())
        groups=['All groups']+sorted({f.group for f in module_fields(spd.data)})
        self.group_selector.configure(values=groups)
        if self.field_group.get() not in groups:self.field_group.set('All groups')
        self.refresh_module_fields()
        hp=doc.hp_info()
        if hp.get('available'):
            rows=['HP SMARTMEMORY','',f"Serial (SPD order)  {hp['serial']}",f"HPT marker          {'Present' if hp['present'] else 'Absent'}",f"HPT code            {hp['hpt']}",'', 'LEARNED FAMILY MATCHES']
            rows.extend(item['name']+'  '+', '.join(item['equivalents']) for item in hp['matches'])
            if not hp['matches']:rows.append('No matching family in the registry')
            rows.extend(['',hp['note']])
            self.set_text(self.hp_text,'\n'.join(rows))
        else:self.set_text(self.hp_text,'HP HPT requires a DDR3 image containing bytes 176-183.')
        if selected and self.bytes_view.exists(selected[0]):
            self.bytes_view.selection_set(selected[0])
            self.bytes_view.see(selected[0])

    def refresh_module_fields(self):
        if not self.document:return
        self.module_view.delete(*self.module_view.get_children())
        search=self.field_search.get().lower()
        for f in module_fields(self.document.spd.data):
            if f.expert and not self.show_expert.get():continue
            if self.field_group.get() not in ('All groups',f.group):continue
            if search and search not in f'{f.key} {f.group} {f.label}'.lower():continue
            self.module_view.insert('','end',iid=f.key,values=(f.group,f.label,f.display(self.document.spd.data),
                                    f'0x{f.raw(self.document.spd.data):X}',f'{f.offset} / {f.shift+f.bits-1}:{f.shift}'))
        if not module_fields(self.document.spd.data):
            self.field_note.set('No registered-module layout applies to this image. Use the byte editor for other fields.')

    def show_field_note(self,event=None):
        selected=self.module_view.selection()
        if selected and self.document:
            f=field_by_key(self.document.spd.data,selected[0])
            self.field_note.set(f'{f.key}: {f.note or "Only the selected bitfield is changed; adjacent bits are preserved."}')

    def edit_module_field(self):
        import tkinter as tk
        from tkinter import ttk
        from fractions import Fraction
        doc=self.require_document()
        selected=self.module_view.selection()
        if not selected:raise ValueError('Select a module setting to edit')
        f=field_by_key(doc.spd.data,selected[0])
        dialog=self._new_dialog(f.label)
        if dialog is None:return
        body=ttk.Frame(dialog,padding=16);body.pack(fill='both',expand=True)
        ttk.Label(body,text=f'{f.label} - byte {f.offset}, bits {f.shift+f.bits-1}:{f.shift}').pack(anchor='w')
        ttk.Label(body,text=f.note or 'Adjacent bits are preserved.',wraplength=540).pack(anchor='w',pady=8)
        value=tk.StringVar()
        if f.choices is not None:
            options=[f'{code}: {meaning}' for code,meaning in f.choices.items()]
            entry=ttk.Combobox(body,textvariable=value,values=options,state='readonly',width=56)
            current=f.raw(doc.spd.data)
            if current in f.choices:value.set(f'{current}: {f.choices[current]}')
        else:
            value.set(str(Fraction(f.raw(doc.spd.data))*Fraction(str(f.scale))))
            entry=ttk.Entry(body,textvariable=value,width=36)
            ttk.Label(body,text=f'Units: {f.unit or "encoded integer"}; step {f.scale}. Fractions are accepted; 0x-prefixed integers specify raw encoded counts.').pack(anchor='w')
        entry.pack(fill='x',pady=8)
        def apply():
            raw=value.get().split(':',1)[0] if f.choices is not None else value.get()
            doc.set_module_field(f.key,raw)
            dialog.destroy()
            self.refresh()
        buttons=ttk.Frame(body);buttons.pack(fill='x',pady=8)
        ttk.Button(buttons,text='Apply',command=lambda:self.run(apply)).pack(side='left')
        ttk.Button(buttons,text='Cancel',command=dialog.destroy).pack(side='left',padx=8)
        dialog.bind('<Escape>',lambda event:dialog.destroy())
        self._present_dialog(dialog,entry)

    def copy_module_settings(self):
        from tkinter import filedialog
        doc=self.require_document()
        path=filedialog.askopenfilename(parent=self.root,title='Select compatible donor SPD')
        if path:
            doc.copy_module_settings(load_spd_file(path).data)
            self.refresh()

    def edit_hpt(self):
        from tkinter import simpledialog
        doc=self.require_document()
        info=doc.hp_info()
        if not info['available']:raise ValueError('HPT editing requires DDR3 bytes 176-183')
        code=simpledialog.askstring('HP HPT','Four HPT bytes in SPD byte order (big-endian registry integer):',
                                    initialvalue=info['hpt'],parent=self.root)
        if code is not None:
            doc.set_hpt(code)
            self.refresh()

    def compute_hpt(self):
        import tkinter as tk
        from tkinter import ttk
        from hp_smartmemory_ident import load_registry
        doc=self.require_document()
        if not doc.hp_info()['available']:raise ValueError('HPT computation requires DDR3 bytes 176-183')
        registry=load_registry(str(Path(__file__).with_name('hp_families.json')))
        families={f'{fam.get("name",key)} [{key}]':key for key,fam in registry.items() if all(x in fam for x in ('A','B','K'))}
        if not families:raise ValueError('No learned HP families in hp_families.json')
        dialog=self._new_dialog('Compute HP HPT')
        if dialog is None:return
        body=ttk.Frame(dialog,padding=16);body.pack()
        ttk.Label(body,text='Select a learned family, then calculate candidates for the current serial.').pack()
        choice=tk.StringVar(value=next(iter(families)))
        ttk.Combobox(body,textvariable=choice,values=list(families),state='readonly',width=60).pack(fill='x',pady=8)
        candidate=tk.StringVar()
        picker=ttk.Combobox(body,textvariable=candidate,state='readonly',width=20);picker.pack(pady=8)
        def calculate():
            candidate.set('')
            picker.configure(values=[])
            values=doc.hpt_candidates(families[choice.get()],registry)
            picker.configure(values=values)
            if not values:raise ValueError('No HPT solution for this serial and family')
            candidate.set(values[0])
        def apply():
            if candidate.get() not in doc.hpt_candidates(families[choice.get()],registry):raise ValueError('Calculate and select a candidate for the current family first')
            doc.set_hpt(candidate.get());dialog.destroy();self.refresh()
        # Changing families invalidates a previously computed candidate.
        def clear_candidates(*args):
            candidate.set('');picker.configure(values=[])
        choice.trace_add('write',clear_candidates)
        ttk.Button(body,text='Calculate candidates',command=lambda:self.run(calculate)).pack(pady=4)
        ttk.Button(body,text='Apply selected HPT',command=lambda:self.run(apply)).pack(pady=4)
        ttk.Button(body,text='Cancel',command=dialog.destroy).pack(pady=4)
        dialog.bind('<Escape>',lambda event:dialog.destroy())
        self._present_dialog(dialog,picker)

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
        if self.hardware.busy:
            raise ValueError('Wait for the hardware operation to finish before closing; reads and scans can be cancelled')
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
