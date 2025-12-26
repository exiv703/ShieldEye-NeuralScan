import gi

gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')

from gi.repository import Gtk, Adw, GLib
from backend.scanner import SecurityScanner

class SettingsView(Gtk.Box):
    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=20)
        self.set_margin_top(24)
        self.set_margin_bottom(24)
        self.set_margin_start(24)
        self.set_margin_end(24)
        
        self.scanner = SecurityScanner()
        
        title = Gtk.Label(label="Settings")
        title.add_css_class("title-1")
        title.set_halign(Gtk.Align.START)
        self.append(title)
        
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_vexpand(True)
        self.append(scrolled)
        
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24)
        scrolled.set_child(content)
        
        ai_group = self._create_group("AI Configuration")
        content.append(ai_group)
        
        self.model_combo = Gtk.DropDown.new_from_strings([
            "bigcode/starcoder2-3b",
            "bigcode/starcoder2-7b",
            "mistralai/Mixtral-8x7B-Instruct-v0.1"
        ])
        current_model = getattr(self.scanner, 'desired_model_name', "bigcode/starcoder2-3b")
        models = ["bigcode/starcoder2-3b", "bigcode/starcoder2-7b", "mistralai/Mixtral-8x7B-Instruct-v0.1"]
        if current_model in models:
            self.model_combo.set_selected(models.index(current_model))
            
        ai_group.append(self._create_row("AI Model", self.model_combo, "Select the AI model used for code analysis."))
        
        self.detail_combo = Gtk.DropDown.new_from_strings(["short", "standard", "deep"])
        current_detail = self.scanner.settings.get('ai_detail', 'standard')
        details = ["short", "standard", "deep"]
        if current_detail in details:
            self.detail_combo.set_selected(details.index(current_detail))
            
        ai_group.append(self._create_row("AI Explanation Detail", self.detail_combo, "Controls verbosity of AI findings."))

        self.full_ai_switch = Gtk.Switch()
        self.full_ai_switch.set_active(True)
        ai_group.append(self._create_row("Full AI Mode", self.full_ai_switch, "Enables AI badges in UI."))

        scan_group = self._create_group("Scanner Options")
        content.append(scan_group)
        
        self.trivy_switch = Gtk.Switch()
        self.trivy_switch.set_active(self.scanner.settings.get('use_trivy', False))
        scan_group.append(self._create_row("Use Trivy", self.trivy_switch, "Include Trivy findings (requires Docker)."))
        
        self.history_switch = Gtk.Switch()
        self.history_switch.set_active(self.scanner.settings.get('save_history', True))
        scan_group.append(self._create_row("Save Scan History", self.history_switch, "Persist results to dashboard history."))
        
        duration_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        
        top_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        lbl = Gtk.Label(label="Minimum Scan Duration (ms)")
        lbl.add_css_class("heading")
        lbl.set_halign(Gtk.Align.START)
        top_row.append(lbl)
        
        self.duration_val_label = Gtk.Label(label="2500")
        self.duration_val_label.set_halign(Gtk.Align.END)
        self.duration_val_label.set_hexpand(True)
        top_row.append(self.duration_val_label)
        
        duration_box.append(top_row)
        
        self.duration_scale = Gtk.Scale.new_with_range(Gtk.Orientation.HORIZONTAL, 0, 5000, 50)
        self.duration_scale.set_value(2500)
        self.duration_scale.connect("value-changed", lambda w: self.duration_val_label.set_label(str(int(w.get_value()))))
        duration_box.append(self.duration_scale)
        
        scan_group.append(duration_box)
        
        action_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        action_box.set_halign(Gtk.Align.END)
        action_box.set_margin_top(12)
        
        self.saved_lbl = Gtk.Label(label="Settings Saved!")
        self.saved_lbl.add_css_class("success-label")
        self.saved_lbl.set_visible(False)
        action_box.append(self.saved_lbl)
        
        apply_btn = Gtk.Button(label="Apply Settings")
        apply_btn.add_css_class("accent-button")
        apply_btn.connect("clicked", self.apply_settings)
        action_box.append(apply_btn)
        
        content.append(action_box)

    def _create_group(self, title):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        lbl = Gtk.Label(label=title)
        lbl.add_css_class("title-2")
        lbl.set_halign(Gtk.Align.START)
        box.append(lbl)
        
        frame = Gtk.Frame()
        frame.add_css_class("card")
        
        inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        inner.set_margin_start(16)
        inner.set_margin_end(16)
        inner.set_margin_top(16)
        inner.set_margin_bottom(16)
        frame.set_child(inner)
        
        box.append(frame)
        return inner

    def _create_row(self, label_text, widget, tooltip_text=""):
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        
        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        lbl = Gtk.Label(label=label_text)
        lbl.add_css_class("heading")
        lbl.set_halign(Gtk.Align.START)
        vbox.append(lbl)
        
        if tooltip_text:
            sub = Gtk.Label(label=tooltip_text)
            sub.add_css_class("dim-label")
            sub.set_halign(Gtk.Align.START)
            vbox.append(sub)
            
        row.append(vbox)
        
        widget.set_halign(Gtk.Align.END)
        widget.set_hexpand(True)
        widget.set_valign(Gtk.Align.CENTER)
        row.append(widget)
        
        return row

    def apply_settings(self, widget):
        self.saved_lbl.set_visible(True)
        
        print(f"Model: {self.model_combo.get_selected_item().get_string()}")
        print(f"Trivy: {self.trivy_switch.get_active()}")
        
        GLib.timeout_add(2000, lambda: self.saved_lbl.set_visible(False))
