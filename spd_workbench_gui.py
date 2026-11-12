# SPDX-License-Identifier: MIT
"""Integrated engineering pages. All apply actions edit memory, never a bus."""
import hashlib,json
from pathlib import Path
import tkinter as tk
from tkinter import ttk,filedialog,messagebox,simpledialog
from spd_library import SPD,load_spd_file,hexdiff
from spd_native import native_timings,encode_native,promote_xmp
from spd_merge import elements,merge,digest,replay
from spd_compatibility import assess
from spd_timing_analysis import configuration,schedule


def button(parent,label,callback,editor):
    b=ttk.Button(parent,text=label,command=lambda:editor.run(callback));b.pack(side='left',padx=3,pady=3);return b


def table(parent,columns,height=8):
    frame=ttk.Frame(parent);frame.pack(fill='both',expand=True,padx=8,pady=4)
    tree=ttk.Treeview(frame,columns=[c[0] for c in columns],show='headings',height=height,selectmode='extended')
    for key,title,width in columns:tree.heading(key,text=title);tree.column(key,width=width,minwidth=55)
    y=ttk.Scrollbar(frame,command=tree.yview);y.pack(side='right',fill='y');tree.configure(yscrollcommand=y.set)
    x=ttk.Scrollbar(frame,orient='horizontal',command=tree.xview);x.pack(side='bottom',fill='x');tree.configure(xscrollcommand=x.set)
    tree.pack(fill='both',expand=True);return tree


def viewport(parent):
    canvas=tk.Canvas(parent,highlightthickness=0,background='#EEF2F7');bar=ttk.Scrollbar(parent,command=canvas.yview)
    bar.pack(side='right',fill='y');canvas.pack(fill='both',expand=True);canvas.configure(yscrollcommand=bar.set)
    body=ttk.Frame(canvas);item=canvas.create_window(0,0,window=body,anchor='nw')
    body.bind('<Configure>',lambda e:canvas.configure(scrollregion=canvas.bbox('all')))
    canvas.bind('<Configure>',lambda e:canvas.itemconfigure(item,width=max(e.width,900)))
    return body


class Preview:
    def __init__(self,editor,parent):
        self.editor=editor;self.proposal=None
        self.note=tk.StringVar(value='Preview a proposal. Applying changes the in-memory image only.')
        ttk.Label(parent,textvariable=self.note,wraplength=1000,padding=8).pack(fill='x')
        self.tree=table(parent,[('offset','Offset',90),('field','Field',270),('before','Target',170),('after','Proposed',170)],5)
        row=ttk.Frame(parent);row.pack(fill='x');button(row,'Apply reviewed changes',self.apply,editor)
        button(row,'Export proposal / audit…',self.export,editor)
    def set(self,data,report):
        target=self.editor.require_document().spd.data
        self.proposal=(digest(target),bytes(data),report)
        self.tree.delete(*self.tree.get_children());fields=elements(target)
        for off,before,after in hexdiff(target,data):
            names=[f['label'] for f in fields.values() if off in f['masks']]
            self.tree.insert('','end',values=(f'{off} / {off:02X}',', '.join(names) or 'Timing / integrity',f'{before:02X}',f'{after:02X}'))
        self.note.set(f'{len(hexdiff(target,data))} changed bytes. Base integrity repaired; hardware compatibility and verified operation remain separate. '+report.get('note',''))
    def apply(self):
        self.editor.hardware.idle();doc=self.editor.require_document()
        if not self.proposal or digest(doc.spd.data)!=self.proposal[0]:raise ValueError('Preview is missing or stale; rebuild it for the current target')
        old,data,report=self.proposal;doc.replace(data)
        doc.record_engineering(dict(report,target_sha256=old,result_sha256=digest(data)))
        doc.vendor_profile_application=dict(report,kind=report.get('kind','engineering-operation'),generated=True,target_sha256=old,result_sha256=digest(data))
        self.proposal=None;self.editor.refresh()
    def export(self):
        if not self.proposal:raise ValueError('Build a preview first')
        path=filedialog.asksaveasfilename(parent=self.editor.root,defaultextension='.json',title='Export reviewed proposal and audit')
        if path:Path(path).write_text(json.dumps(dict(target_sha256=self.proposal[0],image_hex=self.proposal[1].hex(),audit=self.proposal[2]),indent=2))


class FactoryPanel:
    def __init__(self,editor,parent):
        self.editor=editor;self.donors={};self.selections=[];self.resolutions={};self.recipe=None;self.discovery_key=None;self._discovery_job=None
        def cleanup(event):
            if event.widget is editor.root and self._discovery_job:
                try:editor.root.after_cancel(self._discovery_job)
                except tk.TclError:pass
        editor.root.bind('<Destroy>',cleanup,add='+')
        parent=viewport(parent)
        self.identity=tk.StringVar();ttk.Label(parent,textvariable=self.identity,wraplength=1000,padding=10,font=('DejaVu Sans',11,'bold')).pack(fill='x')
        row=ttk.Frame(parent);row.pack(fill='x');self.search=tk.StringVar();self.show_incompatible=tk.BooleanVar()
        ttk.Label(row,text='Donor search').pack(side='left');ttk.Entry(row,textvariable=self.search,width=35).pack(side='left')
        button(row,'Find catalog donors',self.discover,editor);button(row,'Add donor file…',self.add_donor,editor)
        ttk.Checkbutton(row,text='Include incompatible',variable=self.show_incompatible,command=lambda:editor.run(self.discover)).pack(side='left')
        self.donor_tree=table(parent,[('class','Compatibility',180),('part','Manufacturer PN',220),('type','Generation / module',160),('source','Source / SHA-256',350)],5)
        self.donor_tree.bind('<<TreeviewSelect>>',lambda e:editor.run(self.inspect))
        self.explanation=tk.StringVar();ttk.Label(parent,textvariable=self.explanation,wraplength=1000,padding=8).pack(fill='x')
        row=ttk.Frame(parent);row.pack(fill='x');self.preset=tk.StringVar(value='Vendor-specific data only')
        ttk.Combobox(row,textvariable=self.preset,state='readonly',values=('OEM identity only','Manufacturer metadata only','Vendor-specific data only','Preserve target hardware configuration','Transfer selected timing configuration','Custom field selection'),width=38).pack(side='left',padx=8)
        button(row,'Select preset',self.preset_select,editor);button(row,'Analyze donor timings',self.analyze,editor)
        self.fields=table(parent,[('group','Category',150),('field','Field / dependency',300),('location','Byte masks',210),('target','Target raw',180),('donor','Donor raw',180)],7)
        override=ttk.LabelFrame(parent,text='Operation-specific review evidence (blank keeps the restriction)',padding=6);override.pack(fill='x',padx=8)
        self.overrides={}
        for i,(key,label) in enumerate([('hardware_equivalence','Chip / PCB equivalence'),('register_equivalence','Register equivalence'),('timing','Timing import / test basis'),('opaque','Opaque payload review'),('identity','Identity replacement reason')]):
            var=tk.StringVar();self.overrides[key]=var;ttk.Label(override,text=label).grid(row=i,column=0,sticky='w');ttk.Entry(override,textvariable=var,width=95).grid(row=i,column=1,sticky='ew')
        override.columnconfigure(1,weight=1)
        row=ttk.Frame(parent);row.pack(fill='x')
        for label,cb in [('Queue selected fields',self.queue),('Clear composition',self.clear),('Preview composition',self.build),('Save reusable recipe…',self.save_recipe),('Replay recipe…',self.load_recipe)]:button(row,label,cb,editor)
        saved=ttk.Frame(parent);saved.pack(fill='x')
        self.saved_recipe=tk.StringVar();self.saved_recipes={}
        self.saved_recipe_box=ttk.Combobox(saved,textvariable=self.saved_recipe,state='readonly',width=55);self.saved_recipe_box.pack(side='left',padx=8)
        button(saved,'Preview saved catalog recipe',self.load_catalog_recipe,editor)
        self.queue_note=tk.StringVar(value='Composition empty');ttk.Label(parent,textvariable=self.queue_note,padding=6,wraplength=1000).pack(fill='x')
        self.preview=Preview(editor,parent)
        hp=ttk.LabelFrame(parent,text='HP SmartMemory — compute separately for target serial',padding=6);hp.pack(fill='x',padx=8,pady=8)
        self.hp_profile=tk.StringVar();self.hp_candidate=tk.StringVar();self.hp_profiles={}
        self.hp_profile_box=ttk.Combobox(hp,textvariable=self.hp_profile,state='readonly',width=36);self.hp_profile_box.pack(side='left')
        button(hp,'Find HP profiles',self.find_hp,editor)
        self.hp_candidate_box=ttk.Combobox(hp,textvariable=self.hp_candidate,state='readonly',width=12);self.hp_candidate_box.pack(side='left')
        button(hp,'Compute candidates',self.hp_options,editor);button(hp,'Preview target HPT',self.hp_preview,editor)
        extra=ttk.Frame(parent,padding=6);extra.pack(fill='x')
        hp=extra
        button(hp,'Compute target HPT from known family…',editor.compute_hpt,editor)
        button(hp,'Catalog HPT families / donor profiles…',editor.catalog.vendor_dialog,editor)
        button(hp,'Edit target OEM sticker details…',lambda:editor.catalog.edit_oem(True),editor)
        ttk.Label(parent,text='HPT equation matches and transplanted metadata do not certify HP server acceptance. Target identity and timings are preserved unless explicitly selected.',wraplength=1000,padding=8).pack(fill='x')
    def refresh(self):
        if not self.editor.document:return
        spd=self.editor.document.spd;d=spd.decoded_data;m=d['manufacturing']
        self.identity.set(f"TARGET  •  {spd.mem_type_name}  •  {m.get('module_mfg_id','Unknown')}  •  {m.get('module_part_number','Unknown')}\n{d.get('general',{}).get('module_type','')}  |  {d.get('ranks','?')} ranks  |  {d.get('data_width_bits','?')} data bits  |  ECC {d.get('ecc_bits','?')}  |  {d.get('timings_ns',{}).get('tCKmin','?')} ns tCK\nIntegrity: {d['crc_info']['status']}  |  HPT: {self.editor.document.hp_info().get('hpt','not present')}")
        from spd_vendor import vendor_metadata
        vendor=vendor_metadata(spd.data,d)
        oem={}
        context=getattr(self.editor.document,'catalog_oem',None)
        cat=self.editor.catalog.catalog
        if context and cat and context[0]==str(cat.root):oem=cat.oem_details(context[1])
        self.identity.set(self.identity.get()+f"\nDRAM: {m.get('dram_mfg_id','Unknown')}  |  OEM: {oem.get('oem_name',vendor.get('possible_oem') or 'not established')} / {oem.get('part_number','not annotated')}  |  chip PN: {oem.get('dram_chip_part_number','not established')}")
        if cat:
            self.saved_recipes={row['name']+' / '+row['id'][:12]:row['bundle'] for row in cat.recipes()}
            self.saved_recipe_box.configure(values=list(self.saved_recipes))
        key=(digest(spd.data),str(cat.root) if cat else None)
        if cat and key!=self.discovery_key:
            self.discovery_key=key
            if self._discovery_job:self.editor.root.after_cancel(self._discovery_job)
            def discover_later():
                if self.editor.hardware.busy:
                    self._discovery_job=self.editor.root.after(100,discover_later);return
                self._discovery_job=None;self.editor.run(self.discover)
            self._discovery_job=self.editor.root.after_idle(discover_later)

    def discover(self):
        cat=self.editor.catalog.require();target=self.editor.require_document().spd.data
        rows=cat.rows(self.search.get());include=self.show_incompatible.get()
        def collect():
            results=[];errors=[]
            for row in rows:
                if len(rows)>200 and self.editor.hardware.cancel_event.is_set():break
                try:data=cat.data(row['sha256']);report=assess(data,target)
                except (ValueError,OSError,NotImplementedError) as exc:errors.append(str(exc));continue
                if report['classification']=='Incompatible' and not include:continue
                results.append((data,str(cat.root)+' / '+row['sha256'][:12],report))
            return results,errors
        def done(result):
            if not self.editor.document or digest(self.editor.document.spd.data)!=digest(target) or self.editor.catalog.catalog is not cat:return
            self.donors={};self.donor_tree.delete(*self.donor_tree.get_children())
            for data,source,report in result[0]:self.insert(data,source,report)
            self.explanation.set(f'{len(result[0])} donor candidates; {len(result[1])} unreadable/invalid catalog entries. Select a donor to inspect its compatibility reasons.')
        if len(rows)>200:self.editor.hardware.start_job('Evaluating catalog donor compatibility…',collect,done)
        else:done(collect())
    def insert(self,data,source,report=None):
        sha=digest(data);self.donors[sha]=data;d=SPD(data);m=d.decoded_data['manufacturing'];report=report or assess(data,self.editor.require_document().spd.data)
        if self.donor_tree.exists(sha):self.donor_tree.delete(sha)
        self.donor_tree.insert('','end',iid=sha,values=(report['classification'],m.get('module_part_number',''),d.mem_type_name+' / '+d.decoded_data['general']['module_type'],source))
    def add_donor(self):
        path=filedialog.askopenfilename(parent=self.editor.root,title='Choose donor SPD')
        if path:self.insert(load_spd_file(path).data,path)
    def donor(self):
        selected=self.donor_tree.selection()
        if len(selected)!=1:raise ValueError('Select one donor')
        return self.donors[selected[0]]
    def inspect(self):
        if len(self.donor_tree.selection())!=1:return
        donor=self.donor();target=self.editor.require_document().spd.data;r=assess(donor,target)
        self.explanation.set(' • '.join([r['classification']]+r['hard']+r['matches']+r['warnings']+['Required review: '+', '.join(r['required_overrides'])]))
        self.fields.delete(*self.fields.get_children())
        for key,f in elements(donor).items():
            offsets=list(f['masks']);raw=lambda data:' '.join(f'{data[i]&f["masks"][i]:02X}' for i in offsets if i<len(data))
            target_raw=raw(target);donor_raw=raw(donor)
            if key.startswith('timing:'):
                target_raw=str(native_timings(target).get(key[7:],'Unavailable'));donor_raw=str(native_timings(donor).get(key[7:],'Unavailable'))
            if key=='native_timings':target_raw='Target complete timing set';donor_raw='Donor complete timing set + CAS'
            self.fields.insert('','end',iid=key,values=(f['group'],f['label']+(' — '+f['dependencies'] if f['dependencies'] else ''),', '.join(f'{i}:{m:02X}' for i,m in f['masks'].items()),target_raw,donor_raw))
    def preset_select(self):
        keys=list(elements(self.donor()));p=self.preset.get()
        wanted={'OEM identity only':['part_number','revision'],'Manufacturer metadata only':['manufacturer','dram_manufacturer'],'Vendor-specific data only':['manufacturer_payload'],'Preserve target hardware configuration':['manufacturer_payload','customer_payload'],'Transfer selected timing configuration':['native_timings'],'Custom field selection':[]}[p]
        self.fields.selection_set([k for k in wanted if k in keys])
    def queue(self):
        keys=list(self.fields.selection())
        if not keys:raise ValueError('Select fields to queue')
        self.selections.append(dict(data=self.donor(),keys=keys,overrides={k:v.get().strip() for k,v in self.overrides.items() if v.get().strip()}))
        self.queue_note.set(' | '.join(digest(s['data'])[:12]+': '+', '.join(s['keys']) for s in self.selections))
        self.recipe=None
    def clear(self):
        self.selections=[];self.resolutions={};self.recipe=None;self.preview.proposal=None;self.queue_note.set('Composition empty')
    def build(self):
        if not self.selections:raise ValueError('Queue at least one donor field')
        result=merge(self.editor.require_document().spd.data,self.selections,self.resolutions)
        if result['conflicts']:
            conflicts=result['conflicts'];sources=sorted({digest(s['data']) for s in self.selections})
            text='\n'.join(s[:12] for s in sources)
            answer=simpledialog.askstring('Resolve donor conflict',f'{len(conflicts)} unresolved conflicts. Choose donor SHA prefix for this preview:\n{text}',parent=self.editor.root)
            if not answer:return
            chosen=[s for s in sources if s.startswith(answer.strip())]
            if len(chosen)!=1:raise ValueError('Choose a unique donor SHA prefix')
            for c in conflicts:
                if 'field' in c:self.resolutions[c['field']]=chosen[0]
                elif any(v[0]==chosen[0] for v in c['sources']):self.resolutions[f"{c['offset']}:{c['bit']}"]=chosen[0]
            result=merge(self.editor.require_document().spd.data,self.selections,self.resolutions)
            if result['conflicts']:raise ValueError('Other conflicts remain; preview again and select their source')
        self.recipe=result['recipe'];self.preview.set(result['data'],dict(operation='Multi-donor merge',recipe=self.recipe,note='Target serial preserved unless explicitly selected.'))
    def save_recipe(self):
        if not self.recipe or digest(self.editor.require_document().spd.data)!=self.recipe['target_sha256']:raise ValueError('Build a conflict-free preview before applying or changing the target')
        path=filedialog.asksaveasfilename(parent=self.editor.root,defaultextension='.json',title='Save reproducible merge recipe')
        if path:
            bundle=dict(recipe=self.recipe,target_hex=self.editor.require_document().spd.data.hex(),sources={digest(s['data']):s['data'].hex() for s in self.selections})
            Path(path).write_text(json.dumps(bundle,indent=2))
            if self.editor.catalog.catalog:self.editor.catalog.catalog.save_recipe(Path(path).stem,bundle);self.editor.catalog.refresh()
    def load_recipe(self):
        path=filedialog.askopenfilename(parent=self.editor.root,filetypes=[('Merge recipe','*.json')])
        if not path:return
        if Path(path).stat().st_size>8*1024*1024:raise ValueError('Recipe exceeds 8 MiB')
        bundle=json.loads(Path(path).read_text())
        if not isinstance(bundle,dict) or not isinstance(bundle.get('recipe'),dict) or not isinstance(bundle.get('sources'),dict):raise ValueError('Not a merge recipe bundle')
        result=replay(self.editor.require_document().spd.data,bundle['recipe'],{k:bytes.fromhex(v) for k,v in bundle['sources'].items()})
        self.recipe=result['recipe'];self.preview.set(result['data'],dict(operation='Recipe replay',recipe=self.recipe))
    def load_catalog_recipe(self):
        if self.saved_recipe.get() not in self.saved_recipes:raise ValueError('Select a saved catalog recipe; load its original target image before replay')
        bundle=self.saved_recipes[self.saved_recipe.get()]
        result=replay(self.editor.require_document().spd.data,bundle['recipe'],{k:bytes.fromhex(v) for k,v in bundle['sources'].items()})
        self.recipe=result['recipe'];self.preview.set(result['data'],dict(operation='Saved catalog recipe replay',recipe=self.recipe))

    def find_hp(self):
        catalog=self.editor.catalog.require();target=self.editor.require_document().spd.data;self.hp_profiles={}
        for profile in catalog.vendor_profiles():
            try:
                donor=catalog.data(profile['donor_sha256']);report=assess(donor,target)
                if report['allowed']:self.hp_profiles[profile['name']+' / '+profile['id'][:12]]=profile['id']
            except (ValueError,OSError):continue
        self.hp_profile_box.configure(values=list(self.hp_profiles));self.hp_profile.set(next(iter(self.hp_profiles),''));self.hp_candidate.set('')
        self.explanation.set(f'{len(self.hp_profiles)} viable saved HP profiles. Compute candidates for the target serial, then preview. Create profiles through catalog HPT families / donor profiles if none are saved.')
    def hp_options(self):
        if self.hp_profile.get() not in self.hp_profiles:raise ValueError('Find and select an HP profile first')
        options=self.editor.catalog.require().hp_profile_options(self.hp_profiles[self.hp_profile.get()],self.editor.require_document().spd.data)
        self.hp_candidate_box.configure(values=options['candidates']);self.hp_candidate.set(options['candidates'][0] if len(options['candidates'])==1 else '')
        self.explanation.set(f"Target serial {options['target_serial']}: {len(options['candidates'])} empirical solutions. Select one explicitly. "+options['warning'])
    def hp_preview(self):
        if self.hp_profile.get() not in self.hp_profiles or not self.hp_candidate.get():raise ValueError('Compute and select an HPT candidate first')
        catalog=self.editor.catalog.require();profile_id=self.hp_profiles[self.hp_profile.get()]
        replace=messagebox.askyesno('HPT customer data','Permit replacing existing non-HPT data at bytes 176–183? Review all changed bytes before applying.',parent=self.editor.root,default='no')
        data,report=catalog.preview_hp_profile(profile_id,self.editor.require_document().spd.data,self.hp_candidate.get(),replace)
        self.preview.set(data,dict(report,operation='Computed target-serial HPT',note=report['warning']))

    def analyze(self):
        self.editor.timing.load_data(self.donor(),'Donor');self.editor.book.select(self.editor.timing_tab)


class PerformancePanel:
    def __init__(self,editor,parent):
        self.editor=editor;self.fingerprint=None;self.family=None;self.native_vars={};self.epp_vars={}
        self.book=ttk.Notebook(parent);self.book.pack(fill='both',expand=True)
        self.native_page=ttk.Frame(self.book);self.book.add(self.native_page,text='Native SPD timing configuration')
        native=viewport(self.native_page);self.summary=tk.StringVar();ttk.Label(native,textvariable=self.summary,padding=10,wraplength=1000).pack(fill='x')
        self.form=ttk.LabelFrame(native,text='Generation-specific native timings (ns)',padding=8);self.form.pack(fill='x',padx=8)
        row=ttk.Frame(native);row.pack(fill='x');self.cas=tk.StringVar()
        ttk.Label(row,text='Supported CAS list').pack(side='left',padx=8);ttk.Entry(row,textvariable=self.cas,width=40).pack(side='left')
        button(row,'Reload target timings',self.reload,editor);button(row,'Preview native encoding',self.build_native,editor);button(row,'Analyze edited timings',self.analyze,editor)
        self.preview=Preview(editor,native)
        self.epp_page=ttk.Frame(self.book);self.book.add(self.epp_page,text='DDR2 EPP')
        epp=viewport(self.epp_page);row=ttk.Frame(epp);row.pack(fill='x');self.epp_format=tk.StringVar(value='full');self.slot=tk.StringVar(value='0');self.optimal=tk.StringVar(value='0')
        for label,var,values in [('Format',self.epp_format,('full','abbreviated')),('Slot',self.slot,('0','1','2','3')),('Optimal',self.optimal,('0','1','2','3'))]:
            ttk.Label(row,text=label).pack(side='left',padx=4);ttk.Combobox(row,textvariable=var,values=values,state='readonly',width=13).pack(side='left')
        for label,cb in [('Load',self.load_epp),('Seed from native',self.seed_epp),('Duplicate selected…',self.duplicate)]:button(row,label,cb,editor)
        self.enabled=tk.BooleanVar(value=True);self.replace=tk.BooleanVar()
        ttk.Checkbutton(epp,text='Enable this profile',variable=self.enabled).pack(anchor='w',padx=8)
        ttk.Checkbutton(epp,text='Permit replacing manufacturer data or changing EPP format (bytes 99–127)',variable=self.replace).pack(anchor='w',padx=8)
        form=ttk.LabelFrame(epp,text='EPP parameters — full-only controls ignored for abbreviated profiles',padding=8);form.pack(fill='x',padx=8)
        keys=['voltage_V','command_rate','cas','tCKmin','tRCDmin','tRPmin','tRASmin','tWRmin','tRCmin','address_drive','cs_drive','clock_drive','data_drive','dqs_drive','address_delay','address_setup','cs_delay','cs_setup']
        for i,key in enumerate(keys):
            row,col=divmod(i,3);var=tk.StringVar();self.epp_vars[key]=var
            ttk.Label(form,text=key).grid(row=row,column=col*2,sticky='w');ttk.Entry(form,textvariable=var,width=15).grid(row=row,column=col*2+1,padx=8,pady=3)
        ttk.Label(epp,text='Drive codes: address/CS 0–3 = 1/1.25/1.5/2×; clock/data/DQS 0–3 = .75/1/1.25/1.5×. Delay codes 0–31 in 1/64 tCK; setup 0 = ½ tCK, 1 = 1 tCK. Published format scope: DDR2 UDIMM.',wraplength=1000,padding=8).pack(fill='x')
        row=ttk.Frame(epp);row.pack(fill='x');button(row,'Preview EPP encoding',self.build_epp,editor);button(row,'Analyze EPP candidate',self.analyze_epp,editor)
        self.epp_preview=Preview(editor,epp)
        self.xmp_page=ttk.Frame(self.book);self.book.add(self.xmp_page,text='XMP / evidence / timing-bin planner')
        from spd_xmp_gui import XMPDialog
        self.xmp=XMPDialog(editor,viewport(self.xmp_page))
        danger=ttk.LabelFrame(native,text='DANGER ZONE — XMP → primary DDR3 timing configuration',padding=8);danger.pack(fill='x',padx=8,pady=8)
        self.xmp_slot=tk.StringVar(value='1');ttk.Combobox(danger,textvariable=self.xmp_slot,values=('1','2'),state='readonly',width=6).pack(side='left')
        self.ack=tk.BooleanVar();ttk.Checkbutton(danger,text='I tested these settings on the target hardware and reviewed voltage requirements',variable=self.ack).pack(side='left')
        button(danger,'Preview native conversion',self.convert,editor)
        ttk.Label(native,text='Native fields cannot request arbitrary XMP voltage, CWL, command rate or controller behavior. Apply requires acknowledgment; Undo restores the prior image. Profile editing never programs physical hardware.',wraplength=1000,padding=8).pack(fill='x')
    def data(self):return self.editor.require_document().spd.data
    def refresh(self):
        if not self.editor.document:return
        data=self.data()
        if self.family!=data[2]:
            self.family=data[2]
            voltage={0:'5',1:'3.3',2:'1.5',3:'3.3',4:'2.5'}.get(data[8],'') if data[2] in (4,7) else '1.8' if data[2]==8 and data[8]==5 else '1.5' if data[2]==11 and not data[6]&1 else '1.35' if data[2]==11 and data[6]&2 else '1.25' if data[2]==11 and data[6]&4 else ''
            self.xmp.voltage.set(voltage)
            rate=SPD(data).decoded_data.get('max_data_rate_MTps')
            self.xmp.rates.set(str(rate or 100))
        if self.fingerprint!=digest(data):self.reload()
        self.book.tab(self.epp_page,state='normal' if data[2]==8 else 'disabled')
    def reload(self):
        data=self.data();self.fingerprint=digest(data);self.native_vars={}
        for child in self.form.winfo_children():child.destroy()
        for i,(key,value) in enumerate(native_timings(data).items()):
            row,col=divmod(i,3);var=tk.StringVar(value=str(value));self.native_vars[key]=var
            ttk.Label(self.form,text=key).grid(row=row,column=col*2,sticky='w');ttk.Entry(self.form,textvariable=var,width=17).grid(row=row,column=col*2+1,padx=6,pady=3)
        self.cas.set(','.join(str(c) for c in SPD(data).decoded_data.get('cas_latencies_supported',[])))
        self.summary.set(f'{SPD(data).mem_type_name}: semantic encoders preserve non-timing bytes and repair base integrity. Minimum timings round upward to their representable units. Changing the legacy CAS bitmap invalidates stale lower-CAS points.')
    def build_native(self):self.preview.set(encode_native(self.data(),{k:v.get() for k,v in self.native_vars.items()},self.cas.get().split(',')),dict(operation='Native timing edit',classification='manually configured'))
    def analyze(self):
        config=configuration(self.data());config['label']='Edited native candidate';config['parameters'].update({k.removesuffix('min'):float(v.get()) for k,v in self.native_vars.items() if k!='tACmax'})
        config['parameters']['tCK']=float(self.native_vars['tCKmin'].get());config['parameters']['CL']=max(float(v) for v in self.cas.get().split(','))
        self.editor.timing.use(config);self.editor.book.select(self.editor.timing_tab)
    def set_epp(self,p):
        for key,var in self.epp_vars.items():var.set(str(p.get('timings_ns',{}).get(key,p.get(key,0))))
        self.enabled.set(p.get('enabled',True))
    def load_epp(self):
        from spd_epp import decode_epp
        p=decode_epp(self.data())
        if not p or p['format']=='unknown':raise ValueError('No supported EPP extension; seed a new configuration')
        self.epp_format.set(p['format']);self.optimal.set(str(p['optimal']));
        if int(self.slot.get())>=len(p['profiles']):raise ValueError('Slot is absent in this EPP format')
        self.set_epp(p['profiles'][int(self.slot.get())])
    def seed_epp(self):
        data=self.data()
        if data[2]!=8:raise ValueError('EPP requires DDR2')
        times=native_timings(data);self.set_epp(dict(enabled=True,voltage_V=1.8,command_rate=2,cas=max(SPD(data).decoded_data['cas_latencies_supported']),timings_ns=times))
    def epp_candidate(self):
        from spd_epp import encode_epp
        values={k:v.get() for k,v in self.epp_vars.items()};times={k:values.pop(k) for k in list(values) if k.startswith('t')}
        return encode_epp(self.data(),int(self.slot.get()),dict(values,enabled=self.enabled.get(),timings_ns=times),self.epp_format.get(),self.replace.get(),int(self.optimal.get()))
    def build_epp(self):self.epp_preview.set(self.epp_candidate(),dict(operation='EPP edit',format=self.epp_format.get(),slot=self.slot.get(),parameters={k:v.get() for k,v in self.epp_vars.items()}))
    def duplicate(self):
        from spd_epp import duplicate_epp
        dest=simpledialog.askinteger('Duplicate EPP','Destination slot (0 based)',parent=self.editor.root,minvalue=0,maxvalue=3)
        if dest is not None:self.epp_preview.set(duplicate_epp(self.data(),int(self.slot.get()),dest),dict(operation='EPP duplication',source=self.slot.get(),destination=dest))
    def analyze_epp(self):
        self.editor.timing.use(configuration(self.epp_candidate(),'EPP',int(self.slot.get())));self.editor.book.select(self.editor.timing_tab)
    def convert(self):
        data,report=promote_xmp(self.data(),int(self.xmp_slot.get()),self.ack.get())
        self.preview.set(data,dict(report,operation='XMP to native',tested_acknowledgment=self.ack.get()))


class TimingPanel:
    def __init__(self,editor,parent):
        self.editor=editor;self.current=None;self.reference=None;self.params={};parent=viewport(parent)
        row=ttk.Frame(parent);row.pack(fill='x');self.source=tk.StringVar(value='Native');self.units=tk.StringVar(value='Cycles');self.burst=tk.StringVar(value='4');self.cr=tk.StringVar(value='1');self.zoom=tk.StringVar(value='9')
        ttk.Combobox(row,textvariable=self.source,values=('Native','XMP 1','XMP 2','EPP 0','EPP 1','EPP 2','EPP 3'),state='readonly',width=15).pack(side='left')
        button(row,'Load configuration',self.load,editor);button(row,'Pin as comparison',self.pin,editor)
        for label,var,values in [('View',self.units,('Cycles','ns')),('BL',self.burst,('1','2','4','8')),('CR',self.cr,('1','2')),('Zoom',self.zoom,('4','9','18','30'))]:
            ttk.Label(row,text=label).pack(side='left',padx=4);box=ttk.Combobox(row,textvariable=var,values=values,width=7,state='readonly');box.pack(side='left');box.bind('<<ComboboxSelected>>',lambda e:editor.run(self.draw))
        self.title=tk.StringVar(value='Load a native, XMP, EPP, donor or generated configuration.');ttk.Label(parent,textvariable=self.title,padding=8).pack(fill='x')
        self.form=ttk.LabelFrame(parent,text='Interactive operating parameters — ns except CL (cycles)',padding=6);self.form.pack(fill='x',padx=8)
        row=ttk.Frame(parent);row.pack(fill='x');button(row,'Add timing / controller assumption…',self.add_parameter,editor);button(row,'Recalculate timeline',self.draw,editor);button(row,'Export analysis…',self.export,editor)
        self.messages=tk.StringVar();ttk.Label(parent,textvariable=self.messages,wraplength=1000,padding=8).pack(fill='x')
        frame=ttk.Frame(parent);frame.pack(fill='both',expand=True);self.canvas=tk.Canvas(frame,height=520,background='white',highlightthickness=0)
        scroll=ttk.Scrollbar(frame,orient='horizontal',command=self.canvas.xview);scroll.pack(side='bottom',fill='x');self.canvas.configure(xscrollcommand=scroll.set);self.canvas.pack(fill='both',expand=True)
        self.details=tk.StringVar(value='Click a command or timing window for its scheduling constraint.');ttk.Label(parent,textvariable=self.details,wraplength=1000,padding=8).pack(fill='x')
    def load(self):
        source=self.source.get();kind=source.split()[0];index=int(source.split()[1])-(1 if kind=='XMP' else 0) if ' ' in source else 0
        self.use(configuration(self.editor.require_document().spd.data,kind,index))
    def load_data(self,data,label):
        config=configuration(data);config['label']=label;self.use(config)
    def use(self,config):
        self.current=config;self.title.set(f"{SPD(self.editor.require_document().spd.data).mem_type_name} • {config['label']} • illustrative independent command workloads")
        for child in self.form.winfo_children():child.destroy()
        self.params={}
        for i,(key,value) in enumerate(config['parameters'].items()):
            row,col=divmod(i,5);var=tk.StringVar(value=str(value));self.params[key]=var
            ttk.Label(self.form,text=key).grid(row=row,column=col*2,sticky='w');entry=ttk.Entry(self.form,textvariable=var,width=10);entry.grid(row=row,column=col*2+1,padx=4,pady=2)
            entry.bind('<Return>',lambda e:self.editor.run(self.draw));entry.bind('<FocusOut>',lambda e:self.editor.run(self.draw))
        self.draw()
    def add_parameter(self):
        if not self.current:self.load()
        allowed=['tCWL','tWR','tWTR','tRTP','tRFC','tRC','tRAS','tRP','tRCD','tRRD','tCCD','tREFI']
        if self.current['generation']!=11:allowed.remove('tCWL')
        if self.current['generation'] in (8,11):allowed.append('tFAW')
        key=simpledialog.askstring('Timing parameter','Name: '+', '.join(allowed),parent=self.editor.root)
        if not key:return
        if key not in allowed:raise ValueError('Parameter is not applicable to this generation/model')
        value=simpledialog.askfloat('Operating assumption',key+' in ns (from datasheet/controller setting)',parent=self.editor.root,minvalue=.001)
        if value is not None:
            config=dict(self.current,parameters={k:float(v.get()) for k,v in self.params.items()});config['parameters'][key]=value;self.use(config)
    def pin(self):
        self.draw();self.reference=(self.current['label'],self.result);self.draw()
    def draw(self):
        if not self.current:return
        values={k:float(v.get()) for k,v in self.params.items()};self.result=schedule(self.current['generation'],values,int(self.burst.get()),int(self.cr.get()),self.current.get('bank_count'))
        self.messages.set(' | '.join(self.result['violations']+['Unknown / not modeled: '+', '.join(self.result['missing'])]+self.result['assumptions']))
        self.canvas.delete('all');scale=float(self.zoom.get());ns=self.units.get()=='ns';tck=values['tCK']
        sets=[('Candidate',self.result,'#135FAB')]+([(self.reference[0],self.reference[1],'#A35E1E')] if self.reference else [])
        lanes=list(dict.fromkeys(e['lane'] for _,result,_ in sets for e in result['events']));lane_height=140 if self.reference else 100;position=lambda cycle,period=tck:210+cycle*period*scale if ns else 210+cycle*scale
        maximum=max([e['ns'] if ns else e['cycle'] for _,r,_ in sets for e in r['events']]+[1]);width=max(1000,210+maximum*scale+180)
        self.canvas.create_text(8,12,anchor='nw',text='Blue: candidate\nBrown: '+(self.reference[0] if self.reference else 'no pinned comparison'),font=('DejaVu Sans',8))
        step=max(1,int(60/scale))
        for tick in range(0,int(maximum)+1,step):
            x=210+tick*scale;self.canvas.create_text(x,12,text=str(tick),anchor='n',fill='#61758B')
        self.canvas.create_text(210,30,text='Nanoseconds' if ns else 'Clock cycles',anchor='nw',fill='#61758B')
        for i,lane in enumerate(lanes):
            y=65+i*lane_height;self.canvas.create_text(8,y,anchor='w',text=lane,font=('DejaVu Sans',9,'bold'));self.canvas.create_line(205,y,width,y,fill='#CBD5DF')
        for label,result,color in sets:
            delta=60 if label!='Candidate' else 0
            for w in result['windows']:
                y=65+lanes.index(w['lane'])*lane_height+delta;item=self.canvas.create_line(position(w['start'],result['tCK_ns']),y-17,position(w['end'],result['tCK_ns']),y-17,fill=color,width=5 if w['critical'] else 2)
                self.canvas.tag_bind(item,'<Button-1>',lambda e,w=w:self.details.set(f"{w['name']}: {w['end']-w['start']:g} cycles; highlighted window is a scheduling boundary, not measured latency."))
            for event in result['events']:
                y=65+lanes.index(event['lane'])*lane_height+delta;x=position(event['cycle'],result['tCK_ns']);self.canvas.create_line(x,y-9,x,y+9,fill=color,width=2)
                item=self.canvas.create_text(x,y+12,anchor='n',text=f"{event['command']}\n{event['ns'] if ns else event['cycle']:g}",fill=color,font=('DejaVu Sans',8))
                self.canvas.tag_bind(item,'<Button-1>',lambda e,event=event:self.details.set(event['command']+': '+event['reason']))
        self.canvas.configure(height=max(520,len(lanes)*lane_height+100),scrollregion=(0,0,width,max(520,len(lanes)*lane_height+100)))
    def export(self):
        self.draw()
        if not self.current:raise ValueError('Load a configuration first')
        path=filedialog.asksaveasfilename(parent=self.editor.root,defaultextension='.json',title='Export timing assumptions and schedule')
        if path:Path(path).write_text(json.dumps(dict(configuration=dict(self.current,parameters={k:float(v.get()) for k,v in self.params.items()}),analysis=self.result,comparison=self.reference),indent=2))


class HistoryPanel:
    def __init__(self,editor,parent):
        self.editor=editor
        ttk.Label(parent,text='Operation history is retained for this document session. Export the audit or archive the editor image in the collection to retain provenance. Undo/Redo changes the active image without deleting the audit.',wraplength=1000,padding=8).pack(fill='x')
        self.tree=table(parent,[('time','UTC time',210),('operation','Operation',260),('source','Original image',150),('result','Result image',150),('active','Current result',120)],14)
        self.detail=tk.StringVar();ttk.Label(parent,textvariable=self.detail,wraplength=1000,padding=8).pack(fill='x')
        self.tree.bind('<<TreeviewSelect>>',lambda e:self.inspect())
        row=ttk.Frame(parent);row.pack(fill='x');button(row,'Export complete audit…',self.export,editor)
    def refresh(self):
        self.tree.delete(*self.tree.get_children())
        if not self.editor.document:return
        doc=self.editor.document;current=digest(doc.spd.data)
        for index,record in enumerate(doc.engineering_history):
            self.tree.insert('','end',iid=str(index),values=(record.get('recorded_at',''),record.get('operation',record.get('kind','Edit')),record.get('target_sha256','')[:12],record.get('result_sha256','')[:12],'Yes' if record.get('result_sha256')==current else 'No'))
    def inspect(self):
        if not self.tree.selection():return
        record=self.editor.document.engineering_history[int(self.tree.selection()[0])]
        self.detail.set(' • '.join(str(record.get(k,'')) for k in ('operation','note','classification'))+'\n'+str(len(record.get('changes',[])))+' recorded byte changes. Full donor and override records are included in audit export.')
    def export(self):
        doc=self.editor.require_document();path=filedialog.asksaveasfilename(parent=self.editor.root,title='Export operation history',defaultextension='.json')
        if path:Path(path).write_text(json.dumps(dict(schema='spd-tool-history/1',active_image_sha256=digest(doc.spd.data),operations=doc.engineering_history),indent=2))
