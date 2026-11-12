# SPDX-License-Identifier: MIT
"""XMP profile authoring and auditable timing proposals; never programs hardware."""
import hashlib
import json
import tkinter as tk
from tkinter import ttk,filedialog,messagebox
from tkinter.scrolledtext import ScrolledText
from spd_xmp import TIMINGS,RAW_FIELDS,encode_profile,read_profile,number,integer
from spd_timing_planner import plan_bins,evidence_template,validate_evidence
from spd_library import SPD
from ddr3_xmp_decoder import decode_xmp


def digest(data):return hashlib.sha256(data).hexdigest()


class XMPDialog:
    def __init__(self,editor,parent=None):
        self.editor=editor;self.root=editor.root;self.preview=None;self.evidence={};self.plans=[];self.proposal_lineage=None;self._populating=False
        if parent is None:
            self.dialog=tk.Toplevel(self.root);self.dialog.title('DDR3 XMP / timing planner');self.dialog.geometry('1100x880');self.dialog.transient(self.root)
        else:self.dialog=parent
        book=ttk.Notebook(self.dialog);book.pack(fill='both',expand=True)
        profiles=ttk.Frame(book);planner=ttk.Frame(book);book.add(profiles,text='DDR3 XMP profiles');book.add(planner,text='Timing-bin planner (SDR through DDR3)')
        self.book=book;self.profile_page=profiles
        top=ttk.Frame(profiles,padding=8);top.pack(fill='x')
        self.slot=tk.StringVar(value='1');ttk.Label(top,text='Profile').pack(side='left')
        ttk.Combobox(top,textvariable=self.slot,values=('1','2'),state='readonly',width=4).pack(side='left',padx=4)
        for title,cb in [('Load existing',self.load),('Seed from JEDEC',self.seed),('Import profile JSON',self.import_profile),('Export profile JSON',self.export_profile)]:
            ttk.Button(top,text=title,command=lambda f=cb:self.safe(f)).pack(side='left',padx=3)
        self.enabled=tk.BooleanVar(value=True);self.replace=tk.BooleanVar(value=False)
        ttk.Checkbutton(profiles,text='Profile enabled',variable=self.enabled).pack(anchor='w',padx=10)
        ttk.Checkbutton(profiles,text='Permit replacing non-XMP customer data (HP HPT and XMP cannot coexist here)',variable=self.replace).pack(anchor='w',padx=10)
        general=ttk.Frame(profiles,padding=8);general.pack(fill='x');self.values={};self.field_entries={}
        fields=[('voltage_V','VDD (V)','1.5'),('dimms_per_channel','DIMMs/channel','1'),('cas_latencies','CAS list','11'),('mtb_dividend','MTB dividend','1'),('mtb_divisor','MTB divisor','8')]
        for i,(key,label,value) in enumerate(fields):
            ttk.Label(general,text=label).grid(row=0,column=i,padx=3)
            var=tk.StringVar(value=value);self.values[key]=var;entry=ttk.Entry(general,textvariable=var,width=15);entry.grid(row=1,column=i,padx=3);self.field_entries[key]=entry
        timing=ttk.LabelFrame(profiles,text='Timing minima in ns; tREFI is a MAXIMUM interval',padding=8);timing.pack(fill='x',padx=8,pady=4)
        self.timings={}
        for i,key in enumerate(TIMINGS):
            row=i%7;col=(i//7)*2
            ttk.Label(timing,text=key,width=18).grid(row=row,column=col,sticky='w')
            var=tk.StringVar();self.timings[key]=var;entry=ttk.Entry(timing,textvariable=var,width=24);entry.grid(row=row,column=col+1,padx=6,pady=2);self.field_entries[key]=entry
        raw=ttk.LabelFrame(profiles,text='Expert raw fields — preserve unless their encoding is established',padding=6);raw.pack(fill='x',padx=8,pady=4)
        self.raw={}
        for i,key in enumerate(RAW_FIELDS):
            var=tk.StringVar(value='0');self.raw[key]=var
            ttk.Label(raw,text=key).grid(row=i//3,column=(i%3)*2,padx=3)
            entry=ttk.Entry(raw,textvariable=var,width=8);entry.grid(row=i//3,column=(i%3)*2+1,padx=3);self.field_entries[key]=entry
        clock=ttk.LabelFrame(profiles,text='Clock selection and live feasibility',padding=6);clock.pack(fill='x',padx=8)
        self.target_rate=tk.StringVar(value='1600');self.clock_unit=tk.StringVar(value='MT/s');self.generation_source=tk.StringVar(value='Current profile')
        row=ttk.Frame(clock);row.pack(fill='x')
        ttk.Label(row,text='Target clock / rate').pack(side='left');self.target_entry=ttk.Entry(row,textvariable=self.target_rate,width=12);self.target_entry.pack(side='left',padx=4)
        ttk.Combobox(row,textvariable=self.clock_unit,values=('MT/s','MHz'),state='readonly',width=7).pack(side='left')
        ttk.Combobox(row,textvariable=self.generation_source,values=('Current profile','SPD / loaded evidence'),state='readonly',width=24).pack(side='left',padx=5)
        ttk.Button(row,text='Generate timing draft at this speed',command=lambda:self.safe(self.generate_at_clock)).pack(side='left')
        self.clock_status=tk.StringVar();ttk.Label(clock,textvariable=self.clock_status,wraplength=1000,padding=4).pack(fill='x')
        self.validation_tree=ttk.Treeview(clock,columns=('field','status','reason'),show='headings',height=4)
        for key,title,width in [('field','Field',130),('status','Status',100),('reason','Reason / encoded value',750)]:self.validation_tree.heading(key,text=title);self.validation_tree.column(key,width=width)
        bar=ttk.Scrollbar(clock,command=self.validation_tree.yview);bar.pack(side='right',fill='y');self.validation_tree.configure(yscrollcommand=bar.set);self.validation_tree.pack(fill='x')
        self.idiot_override=tk.BooleanVar(value=False);self.override_reason=tk.StringVar()
        ttk.Checkbutton(clock,text='Idiot override — permit inconsistent timing combinations (encoding limits still apply)',variable=self.idiot_override).pack(anchor='w')
        row=ttk.Frame(clock);row.pack(fill='x');ttk.Label(row,text='Override reason / intent').pack(side='left');ttk.Entry(row,textvariable=self.override_reason,width=90).pack(side='left',padx=4)
        actions=ttk.Frame(profiles,padding=8);actions.pack(fill='x')
        self.preview_button=ttk.Button(actions,text='Preview encoded profile',command=lambda:self.safe(self.build_preview));self.preview_button.pack(side='left',padx=4)
        self.apply_button=ttk.Button(actions,text='Apply reviewed profile to editor',command=lambda:self.safe(self.apply));self.apply_button.pack(side='left',padx=4)
        self.output=ScrolledText(profiles,height=9,wrap='word',font='TkFixedFont');self.output.pack(fill='both',expand=True,padx=8,pady=6)
        self.editor.set_text(self.output,'Load a profile or seed one from JEDEC. New profiles use XMP 1.3.\nJEDEC/identity bytes remain unchanged. Unknown/reserved fields in existing profiles are retained.')
        config=ttk.Frame(planner,padding=8);config.pack(fill='x')
        self.rates=tk.StringVar(value='1600,1866,2133');self.voltage=tk.StringVar(value='1.5');self.refresh_ns=tk.StringVar(value='7800');self.cwl=tk.StringVar()
        for i,(title,var) in enumerate([('Target rates MT/s',self.rates),('VDD V',self.voltage),('Refresh MAX ns',self.refresh_ns),('CWL cycles (blank=reference)',self.cwl)]):
            ttk.Label(config,text=title).grid(row=0,column=i,padx=4)
            ttk.Entry(config,textvariable=var,width=24 if i==0 else 18).grid(row=1,column=i,padx=4)
        anchors=ttk.Frame(planner,padding=8);anchors.pack(fill='x');self.anchor=tk.StringVar(value='JEDEC SPD')
        self.anchor_picker=ttk.Combobox(anchors,textvariable=self.anchor,state='readonly',values=('JEDEC SPD',),width=50);self.anchor_picker.pack(side='left')
        for title,callback in [('Evidence template…',self.save_template),('Load evidence JSON…',self.load_evidence),('Generate proposals',self.generate)]:
            ttk.Button(anchors,text=title,command=lambda f=callback:self.safe(f)).pack(side='left',padx=3)
        evidence_options=ttk.Frame(planner,padding=6);evidence_options.pack(fill='x')
        self.datasheet_anchor=tk.BooleanVar(value=False)
        ttk.Checkbutton(evidence_options,text='Use transcribed datasheet timings as anchor (replace only supplied fields)',variable=self.datasheet_anchor).pack(side='left')
        ttk.Button(evidence_options,text='Edit evidence JSON…',command=lambda:self.safe(self.edit_evidence)).pack(side='left',padx=4)
        ttk.Button(evidence_options,text='Clear external evidence',command=self.clear_evidence).pack(side='left',padx=8)
        ttk.Label(planner,text='Proposals preserve absolute timing minima at faster clocks. Refresh is not scaled upward.\nEvidence is manually supplied and module-hash bound; no automatic voltage increase or hardware testing occurs.',padding=8).pack(fill='x')
        self.table=ttk.Treeview(planner,columns=('rate','clock','cl','source','status'),show='headings',height=7,selectmode='browse')
        for key,label,width in [('rate','MT/s',100),('clock','MHz',110),('cl','CL',65),('source','Anchor',220),('status','Proposal status',480)]:
            self.table.heading(key,text=label);self.table.column(key,width=width)
        self.table.pack(fill='both',expand=True,padx=8)
        self.table.bind('<<TreeviewSelect>>',lambda event:self.show_plan())
        tools=ttk.Frame(planner,padding=8);tools.pack(fill='x')
        ttk.Button(tools,text='Use selected proposal in XMP editor',command=lambda:self.safe(self.use_plan)).pack(side='left',padx=3)
        ttk.Button(tools,text='Analyze proposal',command=lambda:self.safe(self.analyze_plan)).pack(side='left',padx=3)
        ttk.Button(tools,text='Preview native SPD proposal',command=lambda:self.safe(self.native_plan)).pack(side='left',padx=3)
        ttk.Button(tools,text='Export proposals JSON…',command=lambda:self.safe(self.export_plans)).pack(side='left',padx=3)
        self.plan_text=ScrolledText(planner,height=12,wrap='word',font='TkFixedFont');self.plan_text.pack(fill='both',expand=True,padx=8,pady=8)
        self.editor.set_text(self.plan_text,'Any faster-clock proposal is untested until validated on the intended module/platform.\nEnter refresh requirements for the intended temperature; 7800 ns is an operator default, not a datasheet assertion.')

        style=ttk.Style(self.root);style.configure('Invalid.TEntry',fieldbackground='#FFE1E1');style.configure('Warning.TEntry',fieldbackground='#FFF0C4')
        for var in [*self.values.values(),*self.timings.values(),*self.raw.values(),self.slot,self.replace,self.idiot_override,self.override_reason,self.target_rate,self.clock_unit]:var.trace_add('write',lambda *args:self.live_validate())
        self.live_validate()

    def safe(self,callback):self.editor.run(callback)
    def data(self):return self.editor.require_document().spd.data
    def slot_number(self):return integer(self.slot.get(),1,2,'Profile')

    def set_profile(self,profile):
        if not isinstance(profile,dict) or any(k not in profile for k in self.values) or not isinstance(profile.get('timings_ns'),dict) or any(k not in profile['timings_ns'] for k in TIMINGS):raise ValueError('Incomplete XMP profile JSON')
        if not isinstance(profile.get('cas_latencies'),list):raise ValueError('CAS latencies must be a list')
        if not isinstance(profile.get('enabled',True),bool):raise ValueError('Profile enabled must be true/false')
        self._populating=True
        self.preview=None;self.proposal_lineage=None;self.enabled.set(profile.get('enabled',True))
        for key,var in self.values.items():
            value=profile[key];var.set(','.join(str(v) for v in value) if key=='cas_latencies' else str(value))
        for key,var in self.timings.items():var.set(str(profile['timings_ns'][key]))
        for key,var in self.raw.items():var.set(str(profile.get(key,0)))
        self._populating=False;self.live_validate()

    def parameters(self):
        return dict(enabled=self.enabled.get(),voltage_V=self.values['voltage_V'].get(),
                    dimms_per_channel=self.values['dimms_per_channel'].get(),
                    mtb_dividend=self.values['mtb_dividend'].get(),mtb_divisor=self.values['mtb_divisor'].get(),
                    cas_latencies=[integer(x.strip(),4,18,'CAS') for x in self.values['cas_latencies'].get().split(',')],
                    timings_ns={k:v.get() for k,v in self.timings.items()},**{k:integer(v.get(),0,255,k) for k,v in self.raw.items()})

    def load(self):
        profile=read_profile(self.data(),self.slot_number());self.set_profile(profile)
        self.editor.set_text(self.output,json.dumps(profile,indent=2))

    def seed(self):
        data=self.data();spd=SPD(data)
        if spd.mem_type!=11:raise ValueError('XMP authoring is DDR3-only; other families can use the timing planner')
        rate=spd.decoded_data.get('max_data_rate_MTps')
        rows=plan_bins(data,[rate],self.voltage.get(),self.refresh_ns.get(),cwl_cycles=self.cwl.get() or None)
        if rows[0]['profile'] is None:raise ValueError(rows[0]['profile_error'] or 'Could not seed a complete profile')
        self.set_profile(rows[0]['profile']);self.proposal_lineage=rows[0];self.editor.set_text(self.output,json.dumps(rows[0],indent=2))

    def signature(self):return json.dumps([self.slot_number(),self.parameters(),self.replace.get(),self.idiot_override.get(),self.override_reason.get()],sort_keys=True)

    def build_preview(self):
        self.editor.hardware.idle();data=self.data();params=self.parameters()
        if self.evidence:validate_evidence(data,self.evidence)
        diagnostics=self.live_validate()
        if diagnostics and not diagnostics['logical_valid'] and not self.idiot_override.get():raise ValueError('Resolve highlighted timing / evidence conflicts, or explicitly enable the idiot override')
        if self.idiot_override.get() and not self.override_reason.get().strip():raise ValueError('Record a reason / intent for the idiot override')
        encoded=encode_profile(data,self.slot_number(),params,self.replace.get(),allow_inconsistent=self.idiot_override.get())
        report=dict(idiot_override=self.idiot_override.get(),override_reason=self.override_reason.get().strip(),live_diagnostics=self.live_validate(),kind='ddr3-xmp',generated=True,target_sha256=digest(data),result_sha256=digest(encoded),
                    profile_number=self.slot_number(),requested_profile=params,evidence=self.evidence,timing_proposal=self.proposal_lineage,
                    encoded_profile=read_profile(encoded,self.slot_number()),
                    changes=[dict(offset=i,before=a,after=b) for i,(a,b) in enumerate(zip(data,encoded)) if a!=b],
                    note='Untested custom profile. Base JEDEC bytes preserved; base CRC does not protect XMP.')
        self.preview=(self.editor.document,encoded,report,self.signature());self.live_validate()
        self.editor.set_text(self.output,json.dumps(report,indent=2))

    def apply(self):
        self.editor.hardware.idle()
        if not self.preview:raise ValueError('Preview the encoded profile first')
        doc,encoded,report,signature=self.preview
        if doc is not self.editor.document or digest(self.data())!=report['target_sha256'] or signature!=self.signature():
            self.preview=None;raise ValueError('Image or profile changed; preview again')
        if not report['changes']:raise ValueError('No changes to apply')
        override_notice='IDIOT OVERRIDE ENABLED: timing/evidence conflicts have been deliberately bypassed.\nReason: '+report.get('override_reason','')+'\n\n' if report.get('idiot_override') else ''
        if not messagebox.askyesno('Apply custom XMP',override_notice+f"Apply {len(report['changes'])} byte changes to the editor?\n\nThis is an untested profile, not a certified speed bin.\nExisting JEDEC settings are retained. Hardware programming is separate.",parent=self.dialog,default='no'):return
        doc.replace(encoded);doc.vendor_profile_application=report;doc.record_engineering(dict(report,operation='DDR3 XMP edit'))
        self.editor.refresh();self.preview=None
        self.editor.set_text(self.output,'Applied as one undoable editor operation. Save As or archive the generated snapshot, then use the separate hardware review to program it.\n\n'+json.dumps(report,indent=2))

    def write_json(self,title,value):
        path=filedialog.asksaveasfilename(parent=self.dialog,title=title,defaultextension='.json')
        if path:
            with open(path,'x',encoding='utf-8') as handle:json.dump(value,handle,indent=2)

    def read_json(self,title):
        path=filedialog.askopenfilename(parent=self.dialog,title=title,filetypes=[('JSON','*.json')])
        if not path:return None
        with open(path,'rb') as handle:raw=handle.read(1024*1024+1)
        if len(raw)>1024*1024:raise ValueError('JSON input exceeds 1 MiB')
        value=json.loads(raw)
        if not isinstance(value,dict):raise ValueError('JSON input must be an object')
        return value

    def import_profile(self):
        value=self.read_json('Import XMP profile')
        if value is None:return
        if value.get('schema')!='spd-tool-xmp-profile/1' or value.get('module_sha256')!=digest(self.data()):raise ValueError('Profile schema or module hash mismatch')
        self.set_profile(value['profile'])

    def export_profile(self):self.write_json('New XMP profile JSON',dict(schema='spd-tool-xmp-profile/1',module_sha256=digest(self.data()),profile=self.parameters()))
    def save_template(self):self.write_json('New timing evidence template',evidence_template(self.data()))

    def load_evidence(self):
        value=self.read_json('Load module timing evidence')
        if value is None:return
        self.use_evidence(value)

    def use_evidence(self,value):
        self.evidence=validate_evidence(self.data(),value);self.preview=None
        choices=['JEDEC SPD']+[f"Test {i}: {p['reference']}" for i,p in enumerate(value.get('tested_points',[]))]
        self.anchor_picker.configure(values=choices);self.anchor.set('JEDEC SPD');self.plans=[];self.live_validate()
        self.table.delete(*self.table.get_children())
        self.editor.set_text(self.plan_text,json.dumps(self.evidence,indent=2))

    def edit_evidence(self):
        dialog=tk.Toplevel(self.dialog);dialog.title('Timing evidence JSON');dialog.geometry('850x650');dialog.transient(self.root)
        ttk.Label(dialog,text='Enter transcribed datasheet constraints and/or user-reported tests.\nUse canonical timing names (tAAmin for CL cycles). The module hash must match the intended image.',padding=8).pack(fill='x')
        text=ScrolledText(dialog,wrap='none',font='TkFixedFont');text.pack(fill='both',expand=True,padx=8)
        text.insert('1.0',json.dumps(self.evidence or evidence_template(self.data()),indent=2))
        def save():
            value=json.loads(text.get('1.0','end'))
            self.use_evidence(value);dialog.destroy()
        ttk.Button(dialog,text='Validate and use evidence',command=lambda:self.safe(save)).pack(pady=8)

    def generate(self):
        index=None if self.anchor.get()=='JEDEC SPD' else int(self.anchor.get().split(':',1)[0].split()[1])
        self.plans=plan_bins(self.data(),[r.strip() for r in self.rates.get().split(',')],self.voltage.get(),self.refresh_ns.get(),self.evidence,index,self.cwl.get() or None,self.datasheet_anchor.get())
        self.table.delete(*self.table.get_children())
        for i,row in enumerate(self.plans):
            status='; '.join(row['violations']) or row['profile_error'] or 'Untested proposal'
            self.table.insert('','end',iid=str(i),values=(row['rate_MTps'],round(row['clock_MHz'],3),row['cycles'].get('tAAmin'),row['anchor'],status))
        if self.plans:self.table.selection_set('0');self.show_plan()

    def selected_plan(self):
        selected=self.table.selection()
        if not selected or not self.plans:raise ValueError('Generate and select a proposal')
        row=self.plans[int(selected[0])]
        if row['module_sha256']!=digest(self.data()):raise ValueError('Editor image changed; regenerate proposals')
        return row

    def show_plan(self):
        if self.table.selection():self.editor.set_text(self.plan_text,json.dumps(self.plans[int(self.table.selection()[0])],indent=2))

    def use_plan(self):
        row=self.selected_plan()
        if not row['profile']:raise ValueError(row['profile_error'] or '; '.join(row['violations']) or 'XMP is only supported for DDR3')
        self.set_profile(row['profile']);self.proposal_lineage=row;self.book.select(self.profile_page)
        self.editor.set_text(self.output,json.dumps(row,indent=2)+'\n\nPreview to check actual encodable timings and quantization before applying.')

    def export_plans(self):
        if not self.plans:raise ValueError('Generate proposals first')
        self.write_json('New timing proposals JSON',dict(schema='spd-tool-timing-proposals/1',evidence=self.evidence,proposals=self.plans))

    def clear_evidence(self):
        self.evidence={};self.plans=[];self.preview=None
        self.anchor_picker.configure(values=('JEDEC SPD',));self.anchor.set('JEDEC SPD');self.datasheet_anchor.set(False)
        self.table.delete(*self.table.get_children());self.editor.set_text(self.plan_text,'External evidence cleared.');self.live_validate()

    def analyze_plan(self):
        from spd_timing_analysis import configuration
        row=self.selected_plan();config=configuration(self.data());config['label']=row['anchor']+' / extrapolated'
        config['parameters'].update({k.removesuffix('min'):v for k,v in row['timings_ns'].items() if k.endswith('min')})
        config['parameters']['tCK']=row['timings_ns']['tCKmin'];config['parameters']['CL']=row['cycles']['tAAmin']
        self.editor.timing.use(config);self.editor.book.select(self.editor.timing_tab)

    def native_plan(self):
        from spd_native import encode_native,native_timings
        row=self.selected_plan()
        if row['violations']:raise ValueError('; '.join(row['violations']))
        timings={k:v for k,v in row['timings_ns'].items() if k in native_timings(self.data())}
        data=encode_native(self.data(),timings,[row['cycles']['tAAmin']])
        self.editor.performance.preview.set(data,dict(operation='Generated native timing proposal',proposal=row,evidence=self.evidence,classification='extrapolated; not hardware verified'))
        self.editor.book.select(self.editor.performance_tab);self.editor.performance.book.select(self.editor.performance.native_page)

    def draft_parameters(self):
        return dict({k:v.get() for k,v in self.values.items()},cas_latencies=[x.strip() for x in self.values['cas_latencies'].get().split(',')],enabled=self.enabled.get(),timings_ns={k:v.get() for k,v in self.timings.items()})

    def live_validate(self):
        if self._populating:return None
        from spd_profile_validation import validate_xmp
        if not self.editor.document or self.editor.document.spd.mem_type!=11:
            self.clock_status.set('XMP authoring requires a DDR3 target. Other generations use native timings / the timing-bin planner.')
            self.preview_button.configure(state='disabled');self.apply_button.configure(state='disabled');return None
        data=self.data();report=validate_xmp(data,self.slot_number(),self.draft_parameters(),self.replace.get(),self.evidence)
        try:
            target=number(self.target_rate.get())*(2 if self.clock_unit.get()=='MHz' else 1)
            if not 1<=target<=10000:raise ValueError('Target rate must be 1–10000 MT/s')
            self.target_entry.configure(style='TEntry')
        except ValueError:
            self.target_entry.configure(style='Invalid.TEntry')
        for key,var in self.raw.items():
            try:integer(var.get(),0,255,key)
            except ValueError as exc:report['errors'][key]=[str(exc)]
        for key,entry in self.field_entries.items():entry.configure(style='Invalid.TEntry' if key in report['errors'] else 'Invalid.TEntry' if not report['logical_valid'] and key in report['warnings'] and any('Needs CL' in m or 'tRC is below' in m for m in report['warnings'][key]) and not self.idiot_override.get() else 'Warning.TEntry' if key in report['warnings'] else 'TEntry')
        self.validation_tree.delete(*self.validation_tree.get_children())
        for category,title in [('errors','Cannot encode'),('warnings','Warning')]:
            for key,messages in report[category].items():
                for message in messages:
                    status=title if category=='errors' or message.startswith('Encoded as') else 'Bypassed' if self.idiot_override.get() else 'Conflict'
                    self.validation_tree.insert('','end',values=(key,status,message))
        envelope=report['clock_envelope'];text=''
        if 'tCKmin' in report['actual_ns']:
            period=report['actual_ns']['tCKmin'];text=f'Encoded draft: {1000/period:.3f} MHz / {2000/period:.3f} MT/s; tCK {period:g} ns. '
        if envelope:text+=f"With current CAS/tAA: {envelope['min_clock_MHz']:.3f}–{envelope['max_clock_MHz']:.3f} MHz ({envelope['min_rate_MTps']:.3f}–{envelope['max_rate_MTps']:.3f} MT/s). "
        text+='Encoding/CAS envelope only; not a tested chip, board or controller speed range.'
        if self.idiot_override.get():text+=' IDIOT OVERRIDE: logical warnings will not block encoding; unrepresentable values still do.'
        self.clock_status.set(text)
        valid=not report['errors'] and (report['logical_valid'] or self.idiot_override.get()) and (not self.idiot_override.get() or bool(self.override_reason.get().strip()))
        self.preview_button.configure(state='normal' if valid else 'disabled');self.apply_button.configure(state='normal' if valid and self.preview else 'disabled')
        return report

    def generate_at_clock(self):
        from spd_profile_validation import generate_xmp_at_rate
        rate=number(self.target_rate.get())*(2 if self.clock_unit.get()=='MHz' else 1)
        source='SPD' if self.generation_source.get()=='SPD / loaded evidence' else 'current'
        profile,lineage=generate_xmp_at_rate(self.data(),self.slot_number(),self.draft_parameters(),rate,self.evidence,source,self.idiot_override.get())
        # Preserve vendor-specific expert fields; generated timings do not invent them.
        profile.update({k:integer(v.get(),0,255,k) for k,v in self.raw.items()})
        self.set_profile(profile);self.proposal_lineage=lineage
        self.editor.set_text(self.output,'Generated an editable, untested timing draft. Review highlighted values and preview before applying.\n\n'+json.dumps(lineage,indent=2))
