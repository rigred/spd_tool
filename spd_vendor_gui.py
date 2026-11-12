# SPDX-License-Identifier: MIT
"""Reviewed HP donor profiles. Applying a profile edits a buffer, never hardware."""
import json
import tkinter as tk
from tkinter import ttk,messagebox,simpledialog
from tkinter.scrolledtext import ScrolledText
from spd_vendor import sha256,vendor_metadata


class VendorProfileDialog:
    def __init__(self,panel):
        self.panel=panel;self.editor=panel.editor;self.catalog=panel.require()
        self.dialog=tk.Toplevel(panel.root);self.dialog.title('Vendor metadata and HP donor profiles');self.dialog.geometry('1060x760')
        self.dialog.transient(panel.root)
        self.profile=tk.StringVar();self.hpt=tk.StringVar();self.replace=tk.BooleanVar(value=False)
        self.preview=None
        controls=ttk.Frame(self.dialog,padding=8);controls.pack(fill='x')
        ttk.Button(controls,text='Inspect selected library image',command=lambda:self.safe(self.inspect_donor)).pack(side='left',padx=3)
        ttk.Button(controls,text='Inspect loaded editor image',command=lambda:self.safe(self.inspect_editor)).pack(side='left',padx=3)
        ttk.Button(controls,text='Create profile from selected donor…',command=lambda:self.safe(self.create)).pack(side='left',padx=3)
        profiles=ttk.Frame(self.dialog,padding=8);profiles.pack(fill='x')
        ttk.Label(profiles,text='Saved profile').pack(side='left')
        self.profiles=ttk.Combobox(profiles,textvariable=self.profile,state='readonly',width=65);self.profiles.pack(side='left',padx=8)
        ttk.Button(profiles,text='Find target HPT solutions',command=lambda:self.safe(self.options)).pack(side='left')
        target=ttk.Frame(self.dialog,padding=8);target.pack(fill='x')
        ttk.Label(target,text='Target HPT').pack(side='left')
        self.codes=ttk.Combobox(target,textvariable=self.hpt,state='readonly',width=15);self.codes.pack(side='left',padx=8)
        ttk.Checkbutton(target,text='Permit replacement of existing non-HPT customer data',variable=self.replace).pack(side='left')
        actions=ttk.Frame(self.dialog,padding=8);actions.pack(fill='x')
        ttk.Button(actions,text='Preview changes',command=lambda:self.safe(self.build_preview)).pack(side='left',padx=4)
        ttk.Button(actions,text='Apply reviewed changes to editor',command=lambda:self.safe(self.apply)).pack(side='left',padx=4)
        ttk.Label(self.dialog,text='Target serial, manufacturer IDs, dates, part number, revisions and functional settings are preserved.\nHardware programming remains a separate reviewed operation. Server acceptance is not guaranteed.',padding=8).pack(fill='x')
        self.text=ScrolledText(self.dialog,wrap='word',font='TkFixedFont');self.text.pack(fill='both',expand=True,padx=8,pady=8)
        self.refresh_profiles()
        self.show('Select a library donor to inspect its observed vendor data, or load a saved profile for the current editor image.\nProfiles require a matching manufacturer PN, matching functional bytes and a family that validates the donor HPT.')

    def safe(self,callback):self.editor.run(callback)
    def show(self,value):self.editor.set_text(self.text,value if isinstance(value,str) else json.dumps(value,indent=2))

    def refresh_profiles(self):
        self.records={f"{p['name']} — {p['id'][:12]}":p for p in self.catalog.vendor_profiles()}
        self.profiles.configure(values=list(self.records))
        if self.profile.get() not in self.records:self.profile.set('')

    def selected_profile(self):
        record=self.records.get(self.profile.get())
        if not record:raise ValueError('Choose a saved vendor profile')
        return record

    def inspect_donor(self):self.show(self.catalog.vendor_observations(self.panel.selected()))
    def inspect_editor(self):self.show(vendor_metadata(self.editor.require_document().spd.data))

    def create(self):
        self.editor.hardware.idle()
        donor=self.panel.selected();analysis=self.catalog.hp_analysis(donor)
        raw=self.catalog.data(donor)
        valid=[f for f in analysis['families'] if not f.get('error') and raw[180:184].hex().upper() in f.get('candidates',[])]
        if not valid:raise ValueError('No validated donor family. Add its OEM family PN or mine/save the family evidence first')
        child=tk.Toplevel(self.dialog);child.title('Create HP donor profile');child.geometry('840x340');child.transient(self.dialog)
        ttk.Label(child,text='Choose a family that validates this donor. Multiple families are not selected automatically.',padding=8).pack(fill='x')
        choices={f"{f['family'].get('name',f['key'])} — {f['origin']} — {f['key']}":f['key'] for f in valid}
        family=tk.StringVar(value=next(iter(choices)) if len(choices)==1 else '')
        ttk.Combobox(child,textvariable=family,values=list(choices),state='readonly',width=100).pack(padx=8,pady=8)
        name=tk.StringVar(value='HP HPT donor profile')
        ttk.Entry(child,textvariable=name,width=70).pack(padx=8,pady=8)
        opaque=tk.BooleanVar(value=False)
        ttk.Checkbutton(child,text='Expert: also copy opaque donor bytes 150–175 and 184–255',variable=opaque).pack(anchor='w',padx=8,pady=8)
        ttk.Label(child,text='Default changes HPT only. Opaque bytes may contain undocumented identifiers/checksums.\nCopying them is an explicit template operation, not a decoded vendor conversion.',padding=8).pack(fill='x')
        def save():
            if family.get() not in choices:raise ValueError('Select a donor family explicitly')
            record=self.catalog.create_hp_profile(donor,choices[family.get()],name.get(),opaque.get())
            self.refresh_profiles()
            self.profile.set(next(label for label,p in self.records.items() if p['id']==record['id']))
            self.preview=None;self.show(record);child.destroy()
        ttk.Button(child,text='Save reviewed profile',command=lambda:self.safe(save)).pack(pady=8)

    def options(self):
        self.editor.hardware.idle();self.preview=None
        options=self.catalog.hp_profile_options(self.selected_profile()['id'],self.editor.require_document().spd.data)
        self.codes.configure(values=options['candidates'])
        self.hpt.set(options['candidates'][0] if len(options['candidates'])==1 else '')
        self.show(options)

    def build_preview(self):
        self.editor.hardware.idle()
        data=self.editor.require_document().spd.data
        result,report=self.catalog.preview_hp_profile(self.selected_profile()['id'],data,self.hpt.get(),self.replace.get())
        self.preview=(result,report,self.replace.get())
        self.show(report)

    def apply(self):
        self.editor.hardware.idle()
        if not self.preview:raise ValueError('Preview the changes first')
        result,report,replace=self.preview;doc=self.editor.require_document()
        if (sha256(doc.spd.data)!=report['target_sha256'] or self.selected_profile()['id']!=report['profile']['id']
                or self.hpt.get().upper()!=report['chosen_hpt'] or replace!=self.replace.get()):
            self.preview=None;raise ValueError('Editor image or profile options changed; build a new preview')
        # Check the donor/family again before changing the editor.
        checked,fresh=self.catalog.preview_hp_profile(report['profile']['id'],doc.spd.data,report['chosen_hpt'],replace)
        if checked!=result:raise ValueError('Profile result changed; preview again')
        if not report['changes']:raise ValueError('The editor already contains this profile result')
        if not messagebox.askyesno('Apply HP profile to editor',f"Apply {len(report['changes'])} byte changes to the editor?\n\nTarget serial: {report['target_serial']}\nChosen HPT: {report['chosen_hpt']}\n\nThis does not certify the module or program hardware.",parent=self.dialog,default='no'):return
        doc.replace(result);doc.vendor_profile_application=fresh
        self.editor.refresh();self.preview=None
        self.show(dict(applied_to_editor=True,report=fresh,next_step='Save As or add the generated snapshot to the library. Use Hardware / programmer for a separate backup/write/verify review.'))
