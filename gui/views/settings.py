import gi
import json
from pathlib import Path

gi.require_version('Gtk', '4.0')

from gi.repository import Gtk, GLib

CONFIG_FILE = Path('data') / 'config.json'
MODEL_OPTIONS = [
    "bigcode/starcoder2-3b",
    "bigcode/starcoder2-7b",
    "mistralai/Mixtral-8x7B-Instruct-v0.1"
]

class SettingsView(Gtk.Box):
    def __init__(self, main_window=None):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=20)
        self.main_window = main_window
        self.set_margin_top(24)
        self.set_margin_bottom(24)
        self.set_margin_start(24)
        self.set_margin_end(24)
        self.settings = self._load_config()
        
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
        
        self.model_combo = Gtk.DropDown.new_from_strings(MODEL_OPTIONS)
        current_model = self.settings.get('ai_model', MODEL_OPTIONS[0])
        if current_model in MODEL_OPTIONS:
            self.model_combo.set_selected(MODEL_OPTIONS.index(current_model))
            
        ai_group.append(self._create_row("AI Model", self.model_combo, "Select the AI model used for code analysis."))
        
        self.detail_combo = Gtk.DropDown.new_from_strings(["short", "standard", "deep"])
        current_detail = self.settings.get('ai_detail', 'standard')
        details = ["short", "standard", "deep"]
        if current_detail in details:
            self.detail_combo.set_selected(details.index(current_detail))
            
        ai_group.append(self._create_row("AI Explanation Detail", self.detail_combo, "Controls verbosity of AI findings."))

        self.full_ai_switch = Gtk.Switch()
        self.full_ai_switch.set_active(self.settings.get('ai_enabled', True))
        ai_group.append(self._create_row("Full AI Mode", self.full_ai_switch, "Enables AI badges in UI."))

        scan_group = self._create_group("Scanner Options")
        content.append(scan_group)
        
        self.trivy_switch = Gtk.Switch()
        self.trivy_switch.set_active(self.settings.get('use_trivy', False))
        scan_group.append(self._create_row("Use Trivy", self.trivy_switch, "Include Trivy findings (requires Docker)."))
        
        self.history_switch = Gtk.Switch()
        self.history_switch.set_active(self.settings.get('save_history', True))
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
        current_timeout = int(self.settings.get('scan_timeout', 2500))
        self.duration_scale.set_value(current_timeout)
        self.duration_val_label.set_label(str(current_timeout))
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

    def _load_config(self):
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                loaded = json.load(f)
                if isinstance(loaded, dict):
                    return loaded
        except (json.JSONDecodeError, OSError):
            pass

        return {}

    def apply_settings(self, widget):
        selected_model_item = self.model_combo.get_selected_item()
        selected_detail_item = self.detail_combo.get_selected_item()

        self.settings.update({
            'ai_model': selected_model_item.get_string() if selected_model_item else MODEL_OPTIONS[0],
            'ai_detail': selected_detail_item.get_string() if selected_detail_item else 'standard',
            'ai_enabled': self.full_ai_switch.get_active(),
            'use_trivy': self.trivy_switch.get_active(),
            'save_history': self.history_switch.get_active(),
            'scan_timeout': int(self.duration_scale.get_value())
        })

        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(self.settings, f, indent=4)

        # Push the new settings into the running scanner so no restart is needed.
        if hasattr(self, 'main_window'):
            scanner = getattr(getattr(getattr(self, 'main_window', None), 'scan_view', None), 'scanner', None)
            if scanner:
                scanner.reload_config()

        self.saved_lbl.set_visible(True)

        GLib.timeout_add(2000, lambda: self.saved_lbl.set_visible(False))
