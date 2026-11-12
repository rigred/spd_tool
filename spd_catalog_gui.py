# SPDX-License-Identifier: MIT
"""Integrated catalog UI; network submission remains an explicit future capability."""
import json
from pathlib import Path
from spd_catalog import Catalog


class CatalogPanel:
    def __init__(self, editor, parent):
        import tkinter as tk
        from tkinter import ttk
        from tkinter.scrolledtext import ScrolledText
        self.editor, self.root, self.catalog = editor, editor.root, None
        self.location = tk.StringVar(value='Choose a collection folder to open or create its database.')
        self.search = tk.StringVar()
        top=ttk.Frame(parent,padding=8); top.pack(fill='x')
        for label,callback in [('Open / create collection…',self.choose),('Add SPD files…',self.import_files),('Import folder…',self.import_folder),('Add editor image',self.add_editor)]:
            ttk.Button(top,text=label,command=lambda cb=callback:editor.run(cb)).pack(side='left',padx=3)
        ttk.Label(parent,textvariable=self.location,padding=8).pack(fill='x')
        search=ttk.Frame(parent,padding=8); search.pack(fill='x')
        ttk.Label(search,text='Search manufacturer, model, serial or hash:').pack(side='left')
        ttk.Entry(search,textvariable=self.search,width=45).pack(side='left',padx=8)
        self.search.trace_add('write',lambda *args:self.refresh())
        self.table=ttk.Treeview(parent,columns=('memory','manufacturer','part','serial','integrity'),show='headings',selectmode='extended')
        for key,title,width in [('memory','Type',70),('manufacturer','Manufacturer',250),('part','Model',260),('serial','Serial',130),('integrity','Integrity',100)]:
            self.table.heading(key,text=title); self.table.column(key,width=width)
        scroll=ttk.Scrollbar(parent,orient='vertical',command=self.table.yview)
        self.table.configure(yscrollcommand=scroll.set)
        scroll.pack(side='right',fill='y'); self.table.pack(fill='both',expand=True,padx=8)
        buttons=ttk.Frame(parent,padding=8); buttons.pack(fill='x')
        for label,callback in [('Open selected in editor',self.open_selected),('Analyze HPT family',self.analyze),('Compute HPT for editor serial',lambda:self.analyze(True)),('Prepare public submission…',self.submission)]:
            ttk.Button(buttons,text=label,command=lambda cb=callback:editor.run(cb)).pack(side='left',padx=3)
        self.details=ScrolledText(parent,height=12,wrap='word',font='TkFixedFont'); self.details.pack(fill='both',expand=True,padx=8,pady=8)
        editor.set_text(self.details,'Imports preserve source files and deduplicate by SHA-256.\nPublic submission exports a reviewable bundle; no public service is configured and no data is uploaded.')

    def require(self):
        if self.catalog is None: raise ValueError('Open or create a collection first')
        return self.catalog

    def choose(self):
        from tkinter import filedialog
        self.editor.hardware.idle()
        path=filedialog.askdirectory(parent=self.root,title='Open or create SPD collection')
        if path:
            self.catalog=Catalog(path); self.location.set(str(self.catalog.root)); self.refresh()

    def refresh(self):
        self.table.delete(*self.table.get_children())
        if self.catalog:
            for r in self.catalog.rows(self.search.get()):
                self.table.insert('','end',iid=r['sha256'],values=tuple(r[k] for k in ('memory','manufacturer','part','serial','integrity')))

    def selected(self):
        self.require()
        selected=self.table.selection()
        if len(selected)!=1: raise ValueError('Select exactly one catalog image')
        return selected[0]

    def import_paths(self, paths):
        catalog=self.require()
        def done(result):
            rows,errors=result
            self.refresh()
            self.editor.set_text(self.details,json.dumps(dict(collection=str(catalog.root),accepted=len(rows),errors=errors),indent=2))
        self.editor.hardware.start_job('Importing SPD files into collection…',lambda:catalog.import_files(paths),done)

    def import_files(self):
        from tkinter import filedialog
        self.require()
        paths=filedialog.askopenfilenames(parent=self.root,title='Add SPD images',filetypes=[('SPD images','*.bin *.spd *.hex *.txt'),('All files','*')])
        if paths:self.import_paths(paths)

    def import_folder(self):
        from tkinter import filedialog
        self.require()
        path=filedialog.askdirectory(parent=self.root,title='Import SPD directory (sources are retained)')
        if path:
            paths=[]
            for p in Path(path).rglob('*'):
                if p.is_file() and not p.is_symlink() and p.suffix.lower() in ('.bin','.spd','.hex','.txt'):
                    paths.append(p)
                    if len(paths)>10000: raise ValueError('Folder exceeds 10,000 candidate files; import smaller folders')
            self.import_paths(paths)

    def add_editor(self):
        catalog=self.require(); doc=self.editor.require_document()
        catalog.add(doc.spd.data,'editor snapshot'); self.refresh()

    def open_selected(self):
        from spd_editor import EditorDocument
        data=self.require().data(self.selected())
        if not self.editor.confirm_discard(): return
        self.editor.document=EditorDocument(data)
        self.editor.hardware.plan=None
        self.editor.hardware.end.set(str(len(data)-1))
        self.editor.set_text(self.editor.diff,''); self.editor.refresh()
        self.editor.book.select(self.editor.overview_tab)

    def analyze(self, for_editor=False):
        catalog=self.require(); sha=self.selected()
        serial=None
        if for_editor:
            doc=self.editor.require_document()
            if doc.spd.mem_type!=11: raise ValueError('HPT computation requires a DDR3 editor image')
            serial=int.from_bytes(doc.spd.data[122:126],'big')
        self.editor.hardware.start_job('Analyzing HPT family evidence…',lambda:catalog.hp_analysis(sha,serial),
                                      lambda result:self.editor.set_text(self.details,json.dumps(result,indent=2)))

    def submission(self):
        from tkinter import filedialog,messagebox
        catalog=self.require(); hashes=self.table.selection()
        if not hashes:raise ValueError('Select catalog images to submit')
        if not messagebox.askyesno('Prepare public submission','The bundle contains raw SPD images, including module serial numbers and vendor data.\nOriginal source paths are omitted.\n\nPrepare an offline bundle for review? Nothing will be uploaded.',parent=self.root,default='no'):return
        path=filedialog.asksaveasfilename(parent=self.root,title='New public submission bundle',defaultextension='.zip')
        if path:
            result=catalog.export_submission(hashes,path)
            self.editor.set_text(self.details,json.dumps(result,indent=2)+'\n\nPrepared for review. Public upload is not yet available.')
