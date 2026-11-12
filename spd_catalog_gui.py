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
        viewport=tk.Canvas(parent,highlightthickness=0,background='#EEF2F7')
        outer=ttk.Scrollbar(parent,orient='vertical',command=viewport.yview)
        outer.pack(side='right',fill='y');viewport.configure(yscrollcommand=outer.set);viewport.pack(fill='both',expand=True)
        content=ttk.Frame(viewport);window=viewport.create_window(0,0,window=content,anchor='nw')
        content.bind('<Configure>',lambda event:viewport.configure(scrollregion=viewport.bbox('all')))
        viewport.bind('<Configure>',lambda event:viewport.itemconfigure(window,width=max(990,event.width),height=max(680,event.height)))
        parent=content
        self.location = tk.StringVar(value='Choose a collection folder to open or create its database.')
        self.search = tk.StringVar()
        top=ttk.Frame(parent,padding=8); top.pack(fill='x')
        for label,callback in [('Open / create collection…',self.choose),('Add SPD files…',self.import_files),('Import folder…',self.import_folder),('Add editor image',self.add_editor),('Editor OEM details…',lambda:self.edit_oem(True))]:
            ttk.Button(top,text=label,command=lambda cb=callback:editor.run(cb)).pack(side='left',padx=3)
        ttk.Label(parent,textvariable=self.location,padding=8).pack(fill='x')
        search=ttk.Frame(parent,padding=8); search.pack(fill='x')
        ttk.Label(search,text='Search manufacturer, model, serial or hash:').pack(side='left')
        ttk.Entry(search,textvariable=self.search,width=45).pack(side='left',padx=8)
        self.search.trace_add('write',lambda *args:self.refresh())
        self.filters={};self.filter_boxes={}
        facets=ttk.LabelFrame(parent,text='Collection filters',padding=6);facets.pack(fill='x',padx=8)
        fields=[('oem_name','OEM'),('manufacturer','Vendor'),('dram_manufacturer','DRAM vendor'),('memory','Memory'),('module_type','Module type'),
                ('capacity_mib','Capacity MiB'),('data_rate_MTps','Speed MT/s'),('ranks','Ranks'),('ecc','ECC'),
                ('integrity','Integrity'),('hpt_present','HPT tag'),('length','Bytes'),('manufacture_year','Mfg year')]
        for i,(key,title) in enumerate(fields):
            var=tk.StringVar(value='All');self.filters[key]=var
            frame=ttk.Frame(facets);frame.grid(row=i//4,column=i%4,sticky='ew',padx=3,pady=2)
            ttk.Label(frame,text=title,width=11).pack(side='left')
            box=ttk.Combobox(frame,textvariable=var,values=('All',),state='readonly',width=13);box.pack(side='left')
            self.filter_boxes[key]=box;box.bind('<<ComboboxSelected>>',lambda event:self.refresh())
        dates=ttk.Frame(parent,padding=6);dates.pack(fill='x')
        self.year_from=tk.StringVar(value='Any');self.year_to=tk.StringVar(value='Any');self.sort=tk.StringVar(value='Model')
        self.year_boxes=[]
        for title,var in [('Manufactured from year',self.year_from),('to year',self.year_to)]:
            ttk.Label(dates,text=title).pack(side='left',padx=3)
            box=ttk.Combobox(dates,textvariable=var,values=('Any',),state='readonly',width=8);box.pack(side='left')
            box.bind('<<ComboboxSelected>>',lambda event:self.refresh());self.year_boxes.append(box)
        ttk.Label(dates,text='Sort').pack(side='left',padx=8)
        sort=ttk.Combobox(dates,textvariable=self.sort,state='readonly',width=13,values=('Model','Vendor','Date oldest','Date newest','Capacity','Speed','Serial'))
        sort.pack(side='left');sort.bind('<<ComboboxSelected>>',lambda event:self.refresh())
        ttk.Button(dates,text='Clear filters',command=self.clear_filters).pack(side='left',padx=8)
        mining=ttk.Frame(parent,padding=4);mining.pack(fill='x')
        ttk.Button(mining,text='Mine HPT families…',command=lambda:editor.run(self.mine)).pack(side='left',padx=4)
        ttk.Button(mining,text='Export saved families…',command=lambda:editor.run(self.export_families)).pack(side='left',padx=4)
        ttk.Button(mining,text='Vendor data / profiles…',command=lambda:editor.run(self.vendor_dialog)).pack(side='left',padx=4)
        self.count=tk.StringVar();ttk.Label(mining,textvariable=self.count,padding=4).pack(side='right')
        table_frame=ttk.Frame(parent);table_frame.pack(fill='x',padx=8)
        self.table=ttk.Treeview(table_frame,columns=('memory','manufacturer','part','oem_part_number','serial','integrity'),show='headings',selectmode='extended',height=4)
        for key,title,width in [('memory','Type',70),('manufacturer','Manufacturer',250),('part','Model',210),('oem_part_number','OEM part / HP family',190),('serial','Serial',130),('integrity','Integrity',100)]:
            self.table.heading(key,text=title); self.table.column(key,width=width)
        scroll=ttk.Scrollbar(table_frame,orient='vertical',command=self.table.yview)
        self.table.configure(yscrollcommand=scroll.set)
        scroll.pack(side='right',fill='y'); self.table.pack(fill='both',expand=True)
        buttons=ttk.Frame(parent,padding=8); buttons.pack(fill='x')
        for label,callback in [('OEM sticker details…',self.edit_oem),('Open selected in editor',self.open_selected),('Analyze HPT family',self.analyze),('Compute HPT for editor serial',lambda:self.analyze(True)),('Prepare public submission…',self.submission)]:
            ttk.Button(buttons,text=label,command=lambda cb=callback:editor.run(cb)).pack(side='left',padx=3)
        self.details=ScrolledText(parent,height=6,wrap='word',font='TkFixedFont'); self.details.pack(fill='both',expand=True,padx=8,pady=8)
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

    def clear_filters(self):
        for var in self.filters.values():var.set('All')
        self.year_from.set('Any');self.year_to.set('Any');self.search.set('');self.sort.set('Model');self.refresh()

    def refresh(self):
        self.table.delete(*self.table.get_children())
        if self.catalog:
            facets=self.catalog.facets()
            for key,box in self.filter_boxes.items():box.configure(values=['All',*facets[key]])
            years=[str(v) for v in sorted({r['manufacture_year'] for r in self.catalog.rows() if r.get('manufacture_year') is not None})]
            for box in self.year_boxes:box.configure(values=['Any',*years])
            try:
                rows=self.catalog.rows(self.search.get(),{k:v.get() for k,v in self.filters.items()},
                                       None if self.year_from.get()=='Any' else self.year_from.get(),
                                       None if self.year_to.get()=='Any' else self.year_to.get(),self.sort.get())
            except ValueError as exc:
                self.count.set(str(exc));return
            for r in rows:
                self.table.insert('','end',iid=r['sha256'],values=(r['memory'],r['manufacturer'],r['part'],r.get('hp_family_part_number') or r.get('oem_part_number',''),r['serial'],r['integrity']))
            self.count.set(f'{len(rows)} shown / {len(self.catalog.rows())} total images')

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
        self.capture_editor(); self.refresh()

    def open_selected(self):
        from spd_editor import EditorDocument
        data=self.require().data(self.selected())
        if not self.editor.confirm_discard(): return
        self.editor.document=EditorDocument(data)
        self.editor.document.catalog_oem=(str(self.catalog.root),self.selected())
        source=next(r for r in self.catalog.rows() if r['sha256']==self.selected())
        if source.get('vendor_profile_application'):
            self.editor.document.vendor_profile_application=source['vendor_profile_application']
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

    def mine(self):
        catalog=self.require()
        def done(report):
            self.editor.set_text(self.details,json.dumps(report,indent=2))
            self.show_mining(catalog,report)
        self.editor.hardware.start_job('Mining collection HPT evidence…',catalog.mine_families,done)

    def show_mining(self,catalog,report):
        import tkinter as tk
        from tkinter import ttk,messagebox,simpledialog
        from tkinter.scrolledtext import ScrolledText
        dialog=tk.Toplevel(self.root);dialog.title('Collection HPT family evaluation');dialog.geometry('1000x650')
        dialog.transient(self.root)
        ttk.Label(dialog,text='Select a group to inspect evidence. Saved families remain collection-local.',padding=8).pack(fill='x')
        tree=ttk.Treeview(dialog,columns=('part','status','serials','evaluation','saved'),show='headings',selectmode='browse',height=8)
        for key,title,width in [('part','Model',280),('status','Evaluation',160),('serials','Distinct serials',100),('evaluation','Evidence level',220),('saved','Saved',70)]:
            tree.heading(key,text=title);tree.column(key,width=width)
        tree.pack(fill='both',expand=True,padx=8)
        text=ScrolledText(dialog,height=12,wrap='word');text.pack(fill='both',expand=True,padx=8,pady=8)
        groups={str(i):r for i,r in enumerate(report['groups'])}
        for key,r in groups.items():tree.insert('','end',iid=key,values=(r['part'],r['status'],r['distinct_serials'],r.get('evaluation',''),r['saved']))
        def selected():
            ids=tree.selection()
            if not ids:raise ValueError('Select a family group')
            return groups[ids[0]]
        def show(event=None):
            if tree.selection():self.editor.set_text(text,json.dumps(selected(),indent=2))
        tree.bind('<<TreeviewSelect>>',show)
        def save():
            candidate=selected(); selected_id=tree.selection()[0]
            if candidate['status']!='candidate':raise ValueError('This group does not have an eligible relation')
            name=simpledialog.askstring('Family label','Family name or known HP spare part number (no identity is inferred):',initialvalue=candidate['part'],parent=dialog)
            if not name:return
            if not messagebox.askyesno('Save empirical HPT family',f"Save {candidate['evaluation']} relation from {candidate['distinct_serials']} serials?\n\nThis is not authentication or proof of an HP family identity. Evidence is rechecked before saving.",parent=dialog,default='no'):return
            def saved(record):
                if dialog.winfo_exists():
                    candidate['saved']=True;tree.set(selected_id,'saved',True)
                    self.editor.set_text(text,json.dumps(record,indent=2))
            self.editor.hardware.start_job('Rechecking and saving HPT family…',lambda:catalog.save_family(candidate,name),saved)
        ttk.Button(dialog,text='Save reviewed family to collection',command=lambda:self.editor.run(save)).pack(pady=8)
        if groups:tree.selection_set('0');show()

    def export_families(self):
        from tkinter import filedialog
        records=self.require().saved_families()
        if not records:raise ValueError('No saved collection families')
        registry={r['id']:dict(r['family'],equivalents=sorted({r['part'],*(m['part_number'] for m in r.get('members',[]))}),scope=r.get('scope'),evaluation=r['evaluation'],evidence_sha256=r['evidence_sha256']) for r in records}
        path=filedialog.asksaveasfilename(parent=self.root,title='New family registry export',defaultextension='.json')
        if path:
            with Path(path).open('x',encoding='utf-8') as handle:json.dump(registry,handle,indent=2)

    def capture_editor(self):
        catalog=self.require();doc=self.editor.require_document()
        row=catalog.add(doc.spd.data,'editor snapshot')
        report=getattr(doc,'vendor_profile_application',None)
        if report:
            if report['result_sha256']!=row['sha256']:
                from spd_vendor import sha256
                report=dict(report,result_sha256=sha256(doc.spd.data),modified_after_profile=True)
            catalog.mark_profile_generated(row['sha256'],report)
        context=getattr(doc,'catalog_oem',None)
        if context and context[0]==str(catalog.root) and context[1]!=row['sha256'] and not catalog.oem_details(row['sha256']):
            fields=('oem_name','part_number','spare_number','assembly_number','model','hp_family_part_number','notes')
            old=catalog.oem_details(context[1])
            if old:catalog.set_oem_details(row['sha256'],{k:v for k,v in old.items() if k in fields})
        doc.catalog_oem=(str(catalog.root),row['sha256'])
        return row['sha256']

    def edit_oem(self, for_editor=False):
        import tkinter as tk
        from tkinter import ttk
        from tkinter.scrolledtext import ScrolledText
        self.editor.hardware.idle();catalog=self.require()
        sha=self.capture_editor() if for_editor else self.selected()
        existing=catalog.oem_details(sha)
        dialog=tk.Toplevel(self.root);dialog.title('OEM sticker details');dialog.geometry('720x540');dialog.transient(self.root)
        ttk.Label(dialog,text='Manual collection metadata; raw SPD bytes are not changed.\nEntries with identical SPD bytes share these annotations.',padding=10).pack(fill='x')
        fields=ttk.Frame(dialog,padding=8);fields.pack(fill='x');variables={}
        for row,(key,title) in enumerate([('oem_name','OEM name (HP, HPE, Dell, Lenovo, …)'),('part_number','OEM part number'),('spare_number','Spare / replacement number'),('assembly_number','Assembly number'),('model','OEM model / product'),('hp_family_part_number','HP HPT family PN (optional)')]):
            ttk.Label(fields,text=title).grid(row=row,column=0,sticky='w',pady=4)
            var=tk.StringVar(value=existing.get(key,''));variables[key]=var
            ttk.Entry(fields,textvariable=var,width=44).grid(row=row,column=1,sticky='ew',padx=8)
        ttk.Label(dialog,text='HP/HPE HPT grouping uses the explicit family PN, or the OEM part number if omitted.\nOther OEMs retain their own details and are not treated as HP.',padding=8).pack(fill='x')
        ttk.Label(dialog,text='Sticker notes / provenance',padding=4).pack(anchor='w')
        notes=ScrolledText(dialog,height=5,wrap='word');notes.pack(fill='both',expand=True,padx=10);notes.insert('1.0',existing.get('notes',''))
        def save():
            self.editor.hardware.idle()
            details={key:var.get() for key,var in variables.items()};details['notes']=notes.get('1.0','end-1c')
            record=catalog.set_oem_details(sha,details)
            self.refresh();self.editor.set_text(self.details,json.dumps(dict(sha256=sha,oem=record),indent=2));dialog.destroy()
        ttk.Button(dialog,text='Save OEM details (blank fields clear previous values)',command=lambda:self.editor.run(save)).pack(pady=10)

    def vendor_dialog(self):
        from spd_vendor_gui import VendorProfileDialog
        self.editor.hardware.idle();self.require()
        return VendorProfileDialog(self)
