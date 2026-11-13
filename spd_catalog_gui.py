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
        self.editor,self.root,self.catalog=editor,editor.root,None
        self.display_rows={}
        self.last_import_report=None
        self.location=tk.StringVar(value='Choose a collection folder to open or create its database.');self.search=tk.StringVar()
        top=ttk.Frame(parent,padding=8);top.pack(fill='x')
        for label,callback in [('Open / create collection…',self.choose),('Add SPD files / archives…',self.import_files),('Import folder…',self.import_folder),('Add editor image',self.add_editor),('Editor OEM details…',lambda:self.edit_oem(True))]:
            ttk.Button(top,text=label,command=lambda cb=callback:editor.run(cb)).pack(side='left',padx=3)
        ttk.Label(parent,textvariable=self.location,padding=(10,2)).pack(fill='x')
        preferences=ttk.Frame(parent,padding=6);preferences.pack(fill='x')
        self.autoload=tk.BooleanVar(value=False)
        ttk.Checkbutton(preferences,text='Load this collection at startup',variable=self.autoload).pack(side='left')
        ttk.Button(preferences,text='Save preferences',command=lambda:editor.run(self.save_settings)).pack(side='left',padx=6)
        ttk.Button(preferences,text='Refresh source files / index',command=lambda:editor.run(self.refresh_sources)).pack(side='left',padx=6)
        search=ttk.Frame(parent,padding=8);search.pack(fill='x');self.search_bar=search
        ttk.Label(search,text='Search').pack(side='left')
        ttk.Entry(search,textvariable=self.search,width=35).pack(side='left',padx=6,fill='x',expand=True)
        self.search.trace_add('write',lambda *args:self.refresh())
        self.sort=tk.StringVar(value='Model');ttk.Label(search,text='Sort').pack(side='left')
        box=ttk.Combobox(search,textvariable=self.sort,state='readonly',width=13,values=('Model','Vendor','Date oldest','Date newest','Capacity','Speed','Serial'));box.pack(side='left',padx=4);box.bind('<<ComboboxSelected>>',lambda event:self.refresh())
        self.show_filters=tk.BooleanVar(value=False);self.show_details=tk.BooleanVar(value=False)
        ttk.Checkbutton(search,text='Filters',variable=self.show_filters,command=self.toggle_filters).pack(side='left',padx=4)
        ttk.Checkbutton(search,text='Details / log',variable=self.show_details,command=self.toggle_details).pack(side='left',padx=4)
        self.count=tk.StringVar();ttk.Label(search,textvariable=self.count).pack(side='right',padx=6)
        self.filters_container=ttk.Frame(parent);self.filters={};self.filter_boxes={}
        facets=ttk.LabelFrame(self.filters_container,text='Collection filters',padding=6);facets.pack(fill='x',padx=8)
        fields=[('oem_name','OEM'),('manufacturer','Vendor'),('dram_manufacturer','DRAM vendor'),('memory','Memory'),('module_type','Module type'),('capacity_mib','Capacity MiB'),('data_rate_MTps','Speed MT/s'),('ranks','Ranks'),('ecc','ECC'),('integrity','Integrity'),('hpt_present','HPT tag'),('length','Bytes'),('manufacture_year','Mfg year'),('support','Support')]
        for i,(key,title) in enumerate(fields):
            var=tk.StringVar(value='All');self.filters[key]=var
            frame=ttk.Frame(facets);frame.grid(row=i//4,column=i%4,sticky='ew',padx=3,pady=2)
            ttk.Label(frame,text=title,width=11).pack(side='left');box=ttk.Combobox(frame,textvariable=var,values=('All',),state='readonly',width=13);box.pack(side='left')
            self.filter_boxes[key]=box;box.bind('<<ComboboxSelected>>',lambda event:self.refresh())
        dates=ttk.Frame(self.filters_container,padding=6);dates.pack(fill='x');self.year_from=tk.StringVar(value='Any');self.year_to=tk.StringVar(value='Any');self.year_boxes=[]
        for title,var in [('Manufactured from year',self.year_from),('to year',self.year_to)]:
            ttk.Label(dates,text=title).pack(side='left',padx=3);box=ttk.Combobox(dates,textvariable=var,values=('Any',),state='readonly',width=8);box.pack(side='left');box.bind('<<ComboboxSelected>>',lambda event:self.refresh());self.year_boxes.append(box)
        ttk.Button(dates,text='Clear filters',command=self.clear_filters).pack(side='left',padx=8)
        actions=ttk.Frame(parent,padding=6);actions.pack(fill='x')
        for title,items in [('Module actions',[('Open / inspect selected',self.open_selected),('OEM sticker details…',self.edit_oem),('Analyze HPT family',self.analyze),('Compute HPT for editor serial',lambda:self.analyze(True))]),('HP tools',[('Mine HPT families…',self.mine),('Vendor data / profiles…',self.vendor_dialog)]),('Export',[('Selected raw binary…',self.export_binary),('Open SPD bundle…',self.export_bundle),('Last import report…',self.export_import_report),('Public submission…',self.submission),('Saved HPT families…',self.export_families)])]:
            button=ttk.Menubutton(actions,text=title);menu=tk.Menu(button,tearoff=False)
            for label,callback in items:menu.add_command(label=label,command=lambda cb=callback:editor.run(cb))
            button.configure(menu=menu);button.pack(side='left',padx=3)
        ttk.Button(actions,text='Remove selected…',command=lambda:editor.run(self.remove_selected)).pack(side='left',padx=5)
        ttk.Button(actions,text='Clean missing references…',command=lambda:editor.run(self.cleanup_missing)).pack(side='left',padx=5)
        ttk.Button(actions,text='Collection trash…',command=lambda:editor.run(self.show_trash)).pack(side='left',padx=5)
        self.summary=tk.StringVar(value='Select a module to inspect it; double-click to open it in the workbench.')
        ttk.Label(parent,textvariable=self.summary,padding=(10,4),wraplength=1150).pack(fill='x')
        self.panes=ttk.Panedwindow(parent,orient='vertical');self.panes.pack(fill='both',expand=True,padx=8,pady=(0,8))
        table_frame=ttk.Frame(self.panes);self.panes.add(table_frame,weight=8)
        self.table=ttk.Treeview(table_frame,columns=('memory','manufacturer','part','oem_part_number','serial','integrity','support'),show='headings',selectmode='extended',height=18)
        for key,title,width in [('memory','Type',70),('manufacturer','Manufacturer',230),('part','Model / part number',260),('oem_part_number','OEM part / HP family',200),('serial','Serial',125),('integrity','Integrity',95),('support','Support',140)]:self.table.heading(key,text=title);self.table.column(key,width=width,minwidth=60)
        scroll=ttk.Scrollbar(table_frame,orient='vertical',command=self.table.yview);scroll.pack(side='right',fill='y')
        horizontal=ttk.Scrollbar(table_frame,orient='horizontal',command=self.table.xview);horizontal.pack(side='bottom',fill='x')
        self.table.configure(yscrollcommand=scroll.set,xscrollcommand=horizontal.set);self.table.pack(fill='both',expand=True)
        self.table.bind('<<TreeviewSelect>>',lambda event:self.selection_summary())
        self.table.bind('<Double-1>',lambda event:editor.run(self.open_selected) if self.table.identify_row(event.y) else None)
        self.details_frame=ttk.Frame(self.panes);self.details=ScrolledText(self.details_frame,height=8,wrap='word',font='TkFixedFont');self.details.pack(fill='both',expand=True)
        editor.set_text(self.details,'Imports preserve source files and deduplicate by SHA-256. Open bundles verify every payload before import. Public submission remains an offline export.')

    def toggle_filters(self):
        if self.show_filters.get():self.filters_container.pack(fill='x',after=self.search_bar)
        else:self.filters_container.pack_forget()

    def toggle_details(self):
        if self.show_details.get():
            if str(self.details_frame) not in self.panes.panes():self.panes.add(self.details_frame,weight=2)
        elif str(self.details_frame) in self.panes.panes():self.panes.forget(self.details_frame)

    def selection_summary(self):
        selection=self.table.selection()
        if len(selection)!=1:self.summary.set(f'{len(selection)} images selected');return
        row=self.display_rows.get(selection[0])
        if row:self.summary.set(f"{row['memory']} | {row['manufacturer']} | {row['part']} | {row.get('capacity_mib') or '?'} MiB | {row.get('ranks') or '?'} ranks | {row['integrity']} | {row.get('support','Editable')} | SHA-256 {row['sha256'][:16]}…")

    def remove_selected(self):
        import tkinter as tk
        from tkinter import ttk
        self.editor.hardware.idle();catalog=self.require();plan=catalog.removal_plan(self.table.selection())
        dialog=tk.Toplevel(self.root);dialog.title('Review collection removal');dialog.geometry('1000x600');dialog.transient(self.root)
        counts=plan['dependents'];message=f"Remove {len(plan['hashes'])} images from the active collection. {len(plan['files'])} managed file paths will be quarantined in collection trash.\nDependent profiles: {counts['vendor_profiles']}; recipes: {counts['merge_recipes']}; learned families: {counts['families']}.\nExternal source files and the open editor buffer remain untouched."
        ttk.Label(dialog,text=message,wraplength=950,padding=12).pack(fill='x')
        tree=ttk.Treeview(dialog,columns=('part','serial','path'),show='headings',height=12)
        for key,title,width in [('part','Part number',250),('serial','Serial',130),('path','Managed file',570)]:tree.heading(key,text=title);tree.column(key,width=width)
        scroll=ttk.Scrollbar(dialog,command=tree.yview);scroll.pack(side='right',fill='y');tree.configure(yscrollcommand=scroll.set);tree.pack(fill='both',expand=True,padx=8)
        for row in plan['tables']['images']:
            metadata=json.loads(row['metadata']);tree.insert('','end',values=(metadata['part'],metadata['serial'],row['path']))
        include=tk.BooleanVar(value=False)
        ttk.Checkbutton(dialog,text='Also remove the listed dependent profiles, recipes and learned families (restorable from trash)',variable=include).pack(anchor='w',padx=10,pady=8)
        def apply():
            self.editor.hardware.idle();report=catalog.remove_images(plan,include.get());self.editor.factory.discovery_key=None;self.refresh();self.editor.set_text(self.details,json.dumps(report,indent=2));dialog.destroy();self.location.set(f"{catalog.root} — removed {report['removed']} images; restore them through Collection trash")
        ttk.Button(dialog,text='Move reviewed images to collection trash',command=lambda:self.editor.run(apply)).pack(pady=10)
        return dialog

    def cleanup_missing(self):
        import tkinter as tk
        from tkinter import ttk
        self.editor.hardware.idle();catalog=self.require();review=catalog.missing_references()
        dialog=tk.Toplevel(self.root);dialog.title('Review missing external references');dialog.geometry('1050x600');dialog.transient(self.root)
        ttk.Label(dialog,text=f"{len(review['missing'])} missing external file references; {len(review['unreadable'])} unreadable/ambiguous references retained.\nThis removes stale pointers only. Managed binary snapshots, retained originals, profiles and external files are not deleted.",wraplength=1000,padding=12).pack(fill='x')
        tree=ttk.Treeview(dialog,columns=('sha','source'),show='headings',height=16)
        for key,title,width in [('sha','Image SHA-256',200),('source','Missing external file',800)]:tree.heading(key,text=title);tree.column(key,width=width)
        scroll=ttk.Scrollbar(dialog,command=tree.yview);scroll.pack(side='right',fill='y');tree.configure(yscrollcommand=scroll.set);tree.pack(fill='both',expand=True,padx=8)
        for row in review['missing']:tree.insert('','end',values=(row['sha'][:16],row['source']))
        def apply():
            self.editor.hardware.idle();result=catalog.cleanup_references(review);self.editor.set_text(self.details,json.dumps(dict(result,retained=review['unreadable']),indent=2));dialog.destroy();self.location.set(f"{catalog.root} — cleaned {result['references_removed']} stale references; all managed images retained")
        ttk.Button(dialog,text='Remove reviewed missing references',command=lambda:self.editor.run(apply)).pack(pady=10)
        return dialog

    def show_trash(self):
        import tkinter as tk
        from tkinter import ttk,messagebox
        self.editor.hardware.idle();catalog=self.require();dialog=tk.Toplevel(self.root);dialog.title('Collection trash');dialog.geometry('800x520');dialog.transient(self.root)
        ttk.Label(dialog,text='Removal packages contain managed files and metadata. Restore a package or explicitly delete it permanently. External source files are never included.',padding=10,wraplength=760).pack(fill='x')
        tree=ttk.Treeview(dialog,columns=('id','images','files'),show='headings',selectmode='extended')
        for key,title,width in [('id','Removal package',450),('images','Images',100),('files','Quarantined files',160)]:tree.heading(key,text=title);tree.column(key,width=width)
        tree.pack(fill='both',expand=True,padx=8)
        def refresh():
            tree.delete(*tree.get_children())
            for row in catalog.trash_entries():tree.insert('','end',iid=row['id'],values=(row['id'],row['images'],row['files']))
        def restore():
            self.editor.hardware.idle();selected=tree.selection()
            if len(selected)!=1:raise ValueError('Select one removal package to restore')
            catalog.restore_trash(selected[0]);self.editor.factory.discovery_key=None;self.refresh();refresh()
        def empty():
            self.editor.hardware.idle();selected=tree.selection()
            if not selected:raise ValueError('Select removal packages to delete permanently')
            if messagebox.askyesno('Permanently delete collection trash',f'Permanently delete {len(selected)} selected removal packages and their quarantined files? This cannot be undone.',parent=dialog,default='no'):catalog.empty_trash(selected);refresh()
        buttons=ttk.Frame(dialog,padding=8);buttons.pack(fill='x')
        ttk.Button(buttons,text='Restore selected package',command=lambda:self.editor.run(restore)).pack(side='left',padx=4)
        ttk.Button(buttons,text='Permanently empty selected packages…',command=lambda:self.editor.run(empty)).pack(side='left',padx=4)
        refresh();return dialog

    def require(self):
        if self.catalog is None: raise ValueError('Open or create a collection first')
        return self.catalog

    def choose(self):
        from tkinter import filedialog
        self.editor.hardware.idle()
        path=filedialog.askdirectory(parent=self.root,title='Open or create SPD collection')
        if path:
            self.catalog=Catalog(path);self.location.set(str(self.catalog.root));self.refresh();self.save_settings()
            if self.catalog.migration_warnings:
                self.show_details.set(True);self.toggle_details();self.editor.set_text(self.details,json.dumps(dict(unreadable_catalog_artifacts=self.catalog.migration_warnings),indent=2))

    def save_settings(self):
        from spd_settings import save
        settings=dict(catalog_path=str(self.require().root),autoload=self.autoload.get(),filters={k:v.get() for k,v in self.filters.items()},search=self.search.get(),sort=self.sort.get(),year_from=self.year_from.get(),year_to=self.year_to.get())
        save(settings);self.location.set(str(self.catalog.root)+' — preferences saved')

    def restore_settings(self):
        from spd_settings import load
        settings=load();self.autoload.set(settings.get('autoload') is True)
        path=settings.get('catalog_path')
        if not path:return
        if not self.autoload.get():self.location.set('Saved collection: '+path+' (automatic loading disabled)');return
        if not (Path(path)/'library.sqlite3').is_file():self.location.set('Saved collection unavailable: '+path);return
        def done(catalog):
            self.catalog=catalog
            for k,var in self.filters.items():var.set(settings.get('filters',{}).get(k,'All'))
            for key in ('sort','year_from','year_to','search'):
                if isinstance(settings.get(key),str):getattr(self,key).set(settings[key])
            self.location.set(str(catalog.root));self.refresh()
        self.editor.hardware.start_job('Loading saved SPD collection…',lambda:Catalog(path),done)

    def refresh_sources(self):
        catalog=self.require()
        def done(result):
            self.refresh();self.location.set(f"{catalog.root} — checked {result['checked']} source files; {len(result['errors'])} errors, {len(result['missing'])} unavailable paths")
            self.editor.set_text(self.details,json.dumps(result,indent=2))
        self.editor.hardware.start_job('Refreshing immutable source snapshots…',catalog.refresh_sources,done)

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
            self.display_rows={r['sha256']:r for r in rows}
            for r in rows:
                self.table.insert('','end',iid=r['sha256'],values=(r['memory'],r['manufacturer'],r['part'],r.get('hp_family_part_number') or r.get('oem_part_number',''),r['serial'],r['integrity'],r.get('support','Editable')))
            self.count.set(f'{len(rows)} shown / {len(self.catalog.rows())} total images')
            if hasattr(self.editor,'factory'):self.editor.factory.refresh()

    def selected(self):
        self.require()
        selected=self.table.selection()
        if len(selected)!=1: raise ValueError('Select exactly one catalog image')
        return selected[0]

    def import_paths(self, paths):
        catalog=self.require()
        def done(result):
            from spd_import_report import import_report,report_preview
            rows,errors=result
            self.editor.factory.discovery_key=None;self.refresh()
            self.last_import_report=dict(import_report(rows,errors),collection=str(catalog.root))
            report=self.last_import_report
            self.location.set(f"{catalog.root} — imported {len(rows)} sources; {report['archived']} read-only; {len(errors)} rejected")
            if errors or report['archived'] or report['invalid_integrity']:self.show_details.set(True);self.toggle_details()
            self.editor.set_text(self.details,report_preview(report))
        self.editor.hardware.start_job('Importing SPD files into collection…',lambda:catalog.import_files(paths),done)

    def import_files(self):
        from tkinter import filedialog
        self.require()
        paths=filedialog.askopenfilenames(parent=self.root,title='Add SPD images',filetypes=[('SPD images','*.bin *.spd *.thp *.rw *.hex *.txt *.spdz *.zip *.7z'),('All files','*')])
        if paths:self.import_paths(paths)

    def import_folder(self):
        from tkinter import filedialog
        self.require()
        path=filedialog.askdirectory(parent=self.root,title='Import SPD directory (sources are retained)')
        if path:self.import_paths([path])

    def add_editor(self):
        catalog=self.require(); doc=self.editor.require_document()
        self.capture_editor(); self.refresh()

    def open_selected(self):
        from spd_editor import EditorDocument
        catalog=self.require();sha=self.selected();data=catalog.data(sha)
        source=next(r for r in catalog.rows() if r['sha256']==sha)
        if not source.get('editable',True):return self.inspect_archive(source,data)
        if not self.editor.confirm_discard(): return
        self.editor.document=EditorDocument(data)
        self.editor.document.catalog_oem=(str(self.catalog.root),self.selected())
        if source.get('vendor_profile_application'):
            self.editor.document.vendor_profile_application=source['vendor_profile_application']
            self.editor.document.engineering_history=json.loads(json.dumps(source['vendor_profile_application'].get('engineering_history',[])))
        self.editor.hardware.plan=None
        self.editor.hardware.end.set(str(len(data)-1))
        self.editor.set_text(self.editor.diff,''); self.editor.refresh()
        self.editor.book.select(self.editor.overview_tab)

    def inspect_archive(self,row,data):
        import tkinter as tk
        from tkinter import ttk
        from tkinter.scrolledtext import ScrolledText
        dialog=tk.Toplevel(self.root);dialog.title(row['memory']+' — read-only SPD archive');dialog.geometry('900x650');dialog.transient(self.root)
        ttk.Label(dialog,text=row['memory']+'  •  '+row['part'],font='TkHeadingFont',padding=12).pack(anchor='w')
        ttk.Label(dialog,text='Read-only collection image. Binary and open-bundle export preserve every byte.\nTiming editing and EEPROM programming for this image are unavailable.',padding=(12,0)).pack(anchor='w')
        book=ttk.Notebook(dialog);book.pack(fill='both',expand=True,padx=12,pady=12)
        overview=ttk.Frame(book,padding=10);book.add(overview,text='Identity / integrity')
        for i,(title,value) in enumerate([('Manufacturer',row['manufacturer']),('Part number',row['part']),('Serial',row['serial']),('Manufactured',row['manufacture_date'] or 'Unknown'),('Module type',row['module_type']),('Image length',str(len(data))+' bytes'),('SPD integrity',row['integrity']),('CRC coverage',row.get('integrity_details',{}).get('scope','See metadata')),('SHA-256',row['sha256'])]):
            ttk.Label(overview,text=title+':').grid(row=i,column=0,sticky='nw',padx=(0,15),pady=3)
            ttk.Label(overview,text=value,wraplength=640).grid(row=i,column=1,sticky='w',pady=3)
        ttk.Label(overview,text='\n'.join(row.get('warnings',[])),wraplength=740).grid(row=9,column=0,columnspan=2,sticky='nw',pady=12)
        for title,text in [('Exact bytes','\n'.join(f'{i:04X}: '+' '.join(f'{v:02X}' for v in data[i:i+16]) for i in range(0,len(data),16))),('Metadata',json.dumps(row,indent=2))]:
            view=ScrolledText(book,wrap='none',font='TkFixedFont');view.insert('1.0',text);view.configure(state='disabled');book.add(view,text=title)
        ttk.Button(dialog,text='Close',command=dialog.destroy).pack(anchor='e',padx=12,pady=(0,12))
        return dialog

    def export_binary(self):
        from tkinter import filedialog
        from spd_containers import exclusive_output
        data=self.require().data(self.selected())
        path=filedialog.asksaveasfilename(parent=self.root,title='Export exact SPD bytes (no repair)',defaultextension='.bin',filetypes=[('Raw SPD binary','*.bin')])
        if path:
            if Path(path).suffix.lower() in ('.thp','.rw','.zip','.spdz','.7z'):raise ValueError('Choose a binary filename, not a container extension')
            exclusive_output(path,data)

    def export_import_report(self):
        from tkinter import filedialog
        from spd_containers import exclusive_output
        if self.last_import_report is None:raise ValueError('Import files first to generate a report')
        path=filedialog.asksaveasfilename(parent=self.root,title='Save complete import report',defaultextension='.json',filetypes=[('JSON report','*.json')])
        if path:exclusive_output(path,(json.dumps(self.last_import_report,indent=2)+'\n').encode('utf-8'))

    def analyze(self, for_editor=False):
        catalog=self.require(); sha=self.selected()
        serial=None
        if for_editor:
            doc=self.editor.require_document()
            if doc.spd.mem_type!=11: raise ValueError('HPT computation requires a DDR3 editor image')
            serial=int.from_bytes(doc.spd.data[122:126],'big')
        self.editor.hardware.start_job('Analyzing HPT family evidence…',lambda:catalog.hp_analysis(sha,serial),
                                      lambda result:self.editor.set_text(self.details,json.dumps(result,indent=2)))

    def export_bundle(self):
        from tkinter import filedialog
        catalog=self.require();hashes=self.table.selection()
        if not hashes:raise ValueError('Select catalog images to export')
        path=filedialog.asksaveasfilename(parent=self.root,title='New open SPD bundle',defaultextension='.spdz',filetypes=[('Open SPD bundle','*.spdz'),('ZIP','*.zip')])
        if path:
            catalog.export_bundle(hashes,path)
            self.editor.set_text(self.details,f'Exported {len(hashes)} images with a UTF-8 manifest and verified SHA-256 payloads. Raw images retain their original SPD integrity status.')

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
        source=getattr(doc,'source_import',None)
        if source:catalog.retain_import(row['sha256'],dict(source,data=doc.spd.data,metadata={}))
        report=getattr(doc,'vendor_profile_application',None)
        if report:
            if report['result_sha256']!=row['sha256']:
                from spd_vendor import sha256
                report=dict(report,result_sha256=sha256(doc.spd.data),modified_after_profile=True)
            report=dict(report,engineering_history=doc.engineering_history)
            catalog.mark_profile_generated(row['sha256'],report)
        context=getattr(doc,'catalog_oem',None)
        if context and context[0]==str(catalog.root) and context[1]!=row['sha256'] and not catalog.oem_details(row['sha256']):
            fields=('oem_name','part_number','spare_number','assembly_number','model','hp_family_part_number','dram_chip_part_number','pcb_revision','register_part_number','notes')
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
        dialog=tk.Toplevel(self.root);dialog.title('OEM sticker details');dialog.geometry('800x700');dialog.transient(self.root)
        ttk.Label(dialog,text='Manual collection metadata; raw SPD bytes are not changed.\nEntries with identical SPD bytes share these annotations.',padding=10).pack(fill='x')
        fields=ttk.Frame(dialog,padding=8);fields.pack(fill='x');variables={}
        for row,(key,title) in enumerate([('oem_name','OEM name (HP, HPE, Dell, Lenovo, …)'),('part_number','OEM part number'),('spare_number','Spare / replacement number'),('assembly_number','Assembly number'),('model','OEM model / product'),('hp_family_part_number','HP HPT family PN (optional)'),('dram_chip_part_number','DRAM chip part number (observed)'),('pcb_revision','PCB revision (observed)'),('register_part_number','Register IC part number (observed)')]):
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
