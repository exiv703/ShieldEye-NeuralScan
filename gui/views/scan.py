import gi
import threading
import os
import time
from gi.repository import Gtk, GLib, Gio, Pango
from backend import SecurityScanner
from utils.file_handler import save_scan_history, load_scan_history

class ScanView(Gtk.Box):
    def __init__(self, window):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.window = window
        self.scanner = SecurityScanner()
        self.current_scan_path = None
        self.scan_start_time = None
        
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scrolled.set_vexpand(True)
        
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=20)
        content.set_margin_top(24)
        content.set_margin_bottom(24)
        content.set_margin_start(24)
        content.set_margin_end(24)
        
        header_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        header_label = Gtk.Label(label="Scan Target")
        header_label.add_css_class("title-1")
        header_label.set_halign(Gtk.Align.START)
        header_box.append(header_label)
        
        subtitle = Gtk.Label(label="Select a file to analyze for security vulnerabilities")
        subtitle.add_css_class("dim-label")
        subtitle.set_halign(Gtk.Align.START)
        header_box.append(subtitle)
        content.append(header_box)
        
        options_card = self._build_options_card()
        content.append(options_card)
        
        self.drop_zone = Gtk.Button()
        self.drop_zone.add_css_class("scan-drop-zone")
        self.drop_zone.connect("clicked", self._on_select_file)
        
        drop_content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        drop_content.set_halign(Gtk.Align.CENTER)
        drop_content.set_valign(Gtk.Align.CENTER)
        
        icon = Gtk.Image.new_from_icon_name("folder-open-symbolic")
        icon.set_pixel_size(64)
        icon.add_css_class("scan-icon")
        drop_content.append(icon)
        
        lbl = Gtk.Label(label="Click to Select File")
        lbl.add_css_class("heading")
        drop_content.append(lbl)
        
        sub = Gtk.Label(label="Supported: .py, .js, .sh, Dockerfile")
        sub.add_css_class("dim-label")
        drop_content.append(sub)
        
        self.drop_zone.set_child(drop_content)
        self.drop_zone.set_size_request(-1, 300)
        content.append(self.drop_zone)
        
        self.progress_card = self._build_progress_card()
        self.progress_card.set_visible(False)
        content.append(self.progress_card)
        
        self.recent_card = self._build_recent_files_card()
        content.append(self.recent_card)
        
        scrolled.set_child(content)
        self.append(scrolled)
    
    def _build_options_card(self):
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        card.add_css_class("card")
        
        # Title
        title = Gtk.Label(label="Scan Options")
        title.add_css_class("heading")
        title.set_halign(Gtk.Align.START)
        card.append(title)
        
        detail_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        detail_box.set_halign(Gtk.Align.START)
        
        detail_label = Gtk.Label(label="Detail Level:")
        detail_label.set_width_chars(15)
        detail_label.set_xalign(0)
        detail_box.append(detail_label)
        
        self.detail_quick = Gtk.CheckButton(label="Quick")
        self.detail_standard = Gtk.CheckButton(label="Standard")
        self.detail_deep = Gtk.CheckButton(label="Deep")
        
        self.detail_standard.set_group(self.detail_quick)
        self.detail_deep.set_group(self.detail_quick)
        self.detail_standard.set_active(True)
        
        detail_box.append(self.detail_quick)
        detail_box.append(self.detail_standard)
        detail_box.append(self.detail_deep)
        
        card.append(detail_box)
        
        help_text = Gtk.Label()
        help_text.set_markup(
            "<small><b>Quick:</b> Fast heuristic scan only\n"
            "<b>Standard:</b> Heuristics + AI analysis (recommended)\n"
            "<b>Deep:</b> Comprehensive analysis with detailed explanations</small>"
        )
        help_text.set_halign(Gtk.Align.START)
        help_text.add_css_class("dim-label")
        card.append(help_text)
        
        return card
    
    def _build_progress_card(self):
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        card.add_css_class("card")
        
        header_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        
        self.progress_icon = Gtk.Spinner()
        self.progress_icon.set_size_request(24, 24)
        header_box.append(self.progress_icon)
        
        self.progress_title = Gtk.Label(label="Scanning...")
        self.progress_title.add_css_class("heading")
        self.progress_title.set_halign(Gtk.Align.START)
        self.progress_title.set_hexpand(True)
        header_box.append(self.progress_title)
        
        card.append(header_box)
        
        self.progress_bar = Gtk.ProgressBar()
        self.progress_bar.set_show_text(True)
        card.append(self.progress_bar)
        
        self.progress_status = Gtk.Label(label="Initializing...")
        self.progress_status.add_css_class("dim-label")
        self.progress_status.set_halign(Gtk.Align.START)
        card.append(self.progress_status)
        
        stats_grid = Gtk.Grid()
        stats_grid.set_column_spacing(24)
        stats_grid.set_row_spacing(8)
        
        elapsed_label = Gtk.Label(label="Elapsed:")
        elapsed_label.add_css_class("dim-label")
        elapsed_label.set_halign(Gtk.Align.START)
        stats_grid.attach(elapsed_label, 0, 0, 1, 1)
        
        self.elapsed_value = Gtk.Label(label="0s")
        self.elapsed_value.set_halign(Gtk.Align.START)
        stats_grid.attach(self.elapsed_value, 1, 0, 1, 1)
        
        findings_label = Gtk.Label(label="Findings:")
        findings_label.add_css_class("dim-label")
        findings_label.set_halign(Gtk.Align.START)
        stats_grid.attach(findings_label, 2, 0, 1, 1)
        
        self.findings_value = Gtk.Label(label="0")
        self.findings_value.set_halign(Gtk.Align.START)
        stats_grid.attach(self.findings_value, 3, 0, 1, 1)
        
        card.append(stats_grid)
        
        return card
    
    def _build_recent_files_card(self):
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        card.add_css_class("card")
        
        title = Gtk.Label(label="Recent Scans")
        title.add_css_class("heading")
        title.set_halign(Gtk.Align.START)
        card.append(title)
        
        self.recent_list = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        card.append(self.recent_list)
        
        self._update_recent_files()
        
        return card
    
    def _update_recent_files(self):
        while self.recent_list.get_first_child():
            self.recent_list.remove(self.recent_list.get_first_child())
        
        history = load_scan_history()
        if not history:
            no_files = Gtk.Label(label="No recent scans")
            no_files.add_css_class("dim-label")
            no_files.set_halign(Gtk.Align.START)
            self.recent_list.append(no_files)
            return
        
        for entry in history[-5:][::-1]:
            stored_file_name = entry.get('file', '')
            stored_file_path = entry.get('file_path', '')
            
            file_path = stored_file_path or stored_file_name or ''
            display_name = stored_file_name or os.path.basename(stored_file_path) or 'Unknown file'

            threats = entry.get('threats', 0)
            date = entry.get('date', '')
            
            row = Gtk.Button()
            row.add_css_class("flat")
            row.connect("clicked", lambda w, p=file_path: self._start_scan(p))
            
            row_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
            row_box.set_margin_top(4)
            row_box.set_margin_bottom(4)
            row_box.set_margin_start(8)
            row_box.set_margin_end(8)
            
            icon = Gtk.Image.new_from_icon_name("document-open-symbolic")
            icon.set_pixel_size(16)
            row_box.append(icon)
            
            name_label = Gtk.Label(label=display_name)
            name_label.set_halign(Gtk.Align.START)
            name_label.set_hexpand(True)
            name_label.set_ellipsize(Pango.EllipsizeMode.END)
            name_label.set_xalign(0)  
            name_label.set_max_width_chars(40)
            row_box.append(name_label)
            
            if threats > 0:
                badge = Gtk.Label(label=str(threats))
                badge.add_css_class("badge")
                if threats >= 10:
                    badge.add_css_class("badge-high")
                elif threats >= 5:
                    badge.add_css_class("badge-medium")
                else:
                    badge.add_css_class("badge-low")
                row_box.append(badge)
            
            row.set_child(row_box)
            self.recent_list.append(row)

    def _on_select_file(self, widget):
        dialog = Gtk.FileDialog()
        dialog.set_title("Select File to Scan")
        dialog.open(self.window, None, self._on_file_selected)

    def _on_file_selected(self, dialog, result):
        try:
            file = dialog.open_finish(result)
            if file:
                path = file.get_path()
                self._start_scan(path)
        except Exception as e:
            print(f"Error selecting file: {e}")

    def _start_scan(self, path):
        if not os.path.exists(path):
            self._show_error(f"File not found: {path}")
            return
        
        try:
            normalized_path = os.path.realpath(path)
            if not os.path.isfile(normalized_path):
                self._show_error(f"Path is not a file: {path}")
                return
            path = normalized_path
        except (OSError, ValueError) as e:
            self._show_error(f"Invalid file path: {e}")
            return
        
        self.current_scan_path = path
        self.scan_start_time = time.time()
        
        self.drop_zone.set_visible(False)
        self.progress_card.set_visible(True)
        self.progress_icon.start()
        self.progress_title.set_label(f"Scanning {os.path.basename(path)}")
        self.progress_bar.set_fraction(0.0)
        self.progress_bar.set_text("Starting...")
        self.progress_status.set_label("Initializing scanner...")
        self.elapsed_value.set_label("0s")
        self.findings_value.set_label("0")
        
        if self.detail_quick.get_active():
            detail = 'quick'
        elif self.detail_deep.get_active():
            detail = 'deep'
        else:
            detail = 'standard'
        
        GLib.timeout_add(500, self._update_progress_ui)
        
        thread = threading.Thread(target=self._scan_worker, args=(path, detail), daemon=True)
        thread.start()

    def _update_progress_ui(self):
        if not self.progress_card.get_visible():
            return False
        
        if self.scan_start_time:
            elapsed = int(time.time() - self.scan_start_time)
            self.elapsed_value.set_label(f"{elapsed}s")
        
        progress_msg = getattr(self.scanner, 'progress_message', '')
        if progress_msg:
            self.progress_status.set_label(progress_msg)
            
            if "static analysis" in progress_msg.lower():
                self.progress_bar.set_fraction(0.2)
                self.progress_bar.set_text("20% - Static Analysis")
            elif "ai" in progress_msg.lower() or "analyzing" in progress_msg.lower():
                self.progress_bar.set_fraction(0.6)
                self.progress_bar.set_text("60% - AI Analysis")
            elif "aggregating" in progress_msg.lower():
                self.progress_bar.set_fraction(0.9)
                self.progress_bar.set_text("90% - Finalizing")
        
        return True
    
    def _scan_worker(self, path, detail='standard'):
        try:
            report = self.scanner.scan_file_for_malware(path, detail=detail)
            
            findings = report.get("findings", [])
            try:
                save_scan_history(path, len(findings))
            except Exception:
                pass
            
            GLib.idle_add(self.findings_value.set_label, str(len(findings)))
                
            GLib.idle_add(self._on_scan_finished, report, path)
        except Exception as e:
            GLib.idle_add(self._on_scan_error, str(e))

    def _on_scan_finished(self, report, path):
        self.progress_icon.stop()
        self.progress_bar.set_fraction(1.0)
        self.progress_bar.set_text("Complete!")
        self.progress_status.set_label("Scan completed successfully")
        
        self._update_recent_files()
        
        def navigate():
            self.progress_card.set_visible(False)
            self.drop_zone.set_visible(True)
            
            if self.window.results_view:
                self.window.results_view.display_report(report, path)
            self.window.navigate_to("results")
            
            if self.window.dashboard_view:
                self.window.dashboard_view.last_security_score = report.get("security_score")
                self.window.dashboard_view.last_risk_categories = report.get("risk_categories")
                self.window.dashboard_view.refresh()
            
            return False
        
        GLib.timeout_add(1000, navigate)

    def _on_scan_error(self, error_msg):
        self.progress_icon.stop()
        self.progress_card.set_visible(False)
        self.drop_zone.set_visible(True)
        self._show_error(error_msg)
    
    def _show_error(self, message):
        dialog = Gtk.AlertDialog()
        dialog.set_message("Scan Error")
        dialog.set_detail(message)
        dialog.set_buttons(["OK"])
        dialog.choose(self.window, None, lambda d, r: None)
