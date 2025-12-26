import gi
import os
import tempfile
from datetime import datetime, timedelta
import random

gi.require_version('Gtk', '4.0')
gi.require_version('GdkPixbuf', '2.0')
from gi.repository import Gtk, Gdk, GdkPixbuf, Pango, GLib

import matplotlib
matplotlib.use('Agg') # Backend for saving to file
import matplotlib.pyplot as plt
import matplotlib.dates as mdates

from utils.file_handler import load_scan_history

class DashboardView(Gtk.Box):
    def __init__(self, main_window=None):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.main_window = main_window # Reference to navigate
        
        self.scan_history = load_scan_history()
        self.last_risk_categories = []
        self.last_security_score = 0
        
        self._setup_ui()
        self.refresh()

    def _setup_ui(self):
        # Main Layout
        self.set_margin_top(0)
        self.set_margin_bottom(0)
        self.set_margin_start(0)
        self.set_margin_end(0)
        
        # 1. Header Area
        header_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        header_box.add_css_class("view-header")
        
        title = Gtk.Label(label="Overview")
        title.add_css_class("view-title")
        title.set_halign(Gtk.Align.START)
        header_box.append(title)
        
        # Spacer
        spacer = Gtk.Box()
        spacer.set_hexpand(True)
        header_box.append(spacer)
        
        # Engine status + Run Scan as a compact pill
        controls_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        controls_box.add_css_class("header-controls")
        
        status_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        status_box.set_valign(Gtk.Align.CENTER)
        dot = Gtk.Box()
        dot.add_css_class("status-dot")
        status_lbl = Gtk.Label(label="Engine: Active")
        status_lbl.add_css_class("text-muted")
        status_lbl.set_halign(Gtk.Align.START)
        status_box.append(dot)
        status_box.append(status_lbl)
        controls_box.append(status_box)
        
        scan_btn = Gtk.Button(label="Run Scan")
        scan_btn.add_css_class("primary-button")
        scan_btn.set_valign(Gtk.Align.CENTER)
        # Avoid showing the default blue focus outline around this pill button
        scan_btn.set_can_focus(False)
        scan_btn.connect("clicked", self._on_run_scan_clicked)
        controls_box.append(scan_btn)

        header_box.append(controls_box)
        
        self.append(header_box)
        
        # 2. Scrollable Content Area
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_vexpand(True)
        scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self.append(scrolled)
        
        content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24)
        content_box.set_margin_start(40)
        content_box.set_margin_end(40)
        content_box.set_margin_top(24)
        content_box.set_margin_bottom(40)
        scrolled.set_child(content_box)
        
        # 3. Threat Activity Chart
        self.chart_card = self._create_card("Threat Activity")
        self.chart_picture = Gtk.Picture()
        self.chart_picture.set_size_request(-1, 400)  # Set minimum height for chart
        self.chart_picture.set_can_shrink(False)
        self.chart_card.get_child().append(self.chart_picture) # Add to card content box
        content_box.append(self.chart_card)
        
        # 4. Middle Row: Security Posture & Attack Surface
        mid_grid = Gtk.Grid()
        mid_grid.set_column_spacing(24)
        mid_grid.set_column_homogeneous(True)
        content_box.append(mid_grid)
        
        # Security Posture
        self.posture_card = self._create_card("Security Posture")
        self._build_posture_content(self.posture_card.get_child())
        mid_grid.attach(self.posture_card, 0, 0, 1, 1)
        
        # Attack Surface
        self.surface_card = self._create_card("Attack Surface")
        self._build_surface_content(self.surface_card.get_child())
        mid_grid.attach(self.surface_card, 1, 0, 1, 1)
        
        # 5. Bottom Row: Last Scan Summary & Threats Found
        bottom_grid = Gtk.Grid()
        bottom_grid.set_column_spacing(24)
        bottom_grid.set_column_homogeneous(True)
        bottom_grid.set_row_homogeneous(True)
        content_box.append(bottom_grid)
        
        self.summary_card = self._create_card("Last Scan Summary")
        self.summary_card.set_size_request(-1, 180)  # Minimum height
        self._build_summary_content(self.summary_card.get_child())
        bottom_grid.attach(self.summary_card, 0, 0, 1, 1)
        
        self.threats_card = self._create_card("") # No title for this one in design
        self.threats_card.set_size_request(-1, 180)  # Minimum height
        self._build_threats_content(self.threats_card.get_child())
        bottom_grid.attach(self.threats_card, 1, 0, 1, 1)

    def _create_card(self, title_text):
        frame = Gtk.Frame()
        frame.add_css_class("card")
        frame.set_hexpand(True)
        
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        box.set_hexpand(True)
        frame.set_child(box)
        
        if title_text:
            title = Gtk.Label(label=title_text)
            title.add_css_class("card-title")
            title.set_halign(Gtk.Align.START)
            box.append(title)
            
        return frame

    def _build_posture_content(self, box):
        # WEAK Label
        self.posture_status_lbl = Gtk.Label(label="UNKNOWN")
        self.posture_status_lbl.add_css_class("text-huge")
        self.posture_status_lbl.set_halign(Gtk.Align.START)
        box.append(self.posture_status_lbl)
        
        # Progress Bar
        self.posture_bar = Gtk.ProgressBar()
        self.posture_bar.set_fraction(0.5)
        box.append(self.posture_bar)
        
        # Score Text
        self.posture_score_lbl = Gtk.Label(label="Score: 0 / 100")
        self.posture_score_lbl.add_css_class("text-muted")
        self.posture_score_lbl.set_halign(Gtk.Align.START)
        box.append(self.posture_score_lbl)

    def _build_surface_content(self, box):
        # Add minimum height and better centering
        box.set_vexpand(True)
        
        self.surface_list = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.surface_list.set_valign(Gtk.Align.CENTER)
        self.surface_list.set_vexpand(True)
        box.append(self.surface_list)
        
    def _build_summary_content(self, box):
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
        
        # Icon
        icon_box = Gtk.Box()
        icon_box.add_css_class("icon-button")
        icon = Gtk.Image.new_from_icon_name("document-open-symbolic")
        icon.set_pixel_size(32)
        icon_box.append(icon)
        row.append(icon_box)
        
        # Text
        text_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self.summary_date_lbl = Gtk.Label(label="No scans run yet")
        self.summary_date_lbl.add_css_class("heading")
        self.summary_date_lbl.set_halign(Gtk.Align.START)
        
        self.summary_dur_lbl = Gtk.Label(label="--")
        self.summary_dur_lbl.add_css_class("text-muted")
        self.summary_dur_lbl.set_halign(Gtk.Align.START)
        
        text_box.append(self.summary_date_lbl)
        text_box.append(self.summary_dur_lbl)
        row.append(text_box)
        
        box.append(row)
        
        # Footer
        footer = Gtk.Label(label="Threats Found: 0")
        footer.add_css_class("text-muted")
        footer.set_halign(Gtk.Align.START)
        footer.set_margin_top(8)
        self.summary_count_lbl = footer # Store ref
        box.append(footer)

    def _build_threats_content(self, box):
        # Center content vertically and horizontally
        box.set_vexpand(True)
        
        # Main container centered
        center_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        center_box.set_valign(Gtk.Align.CENTER)
        center_box.set_halign(Gtk.Align.CENTER)
        
        # Icon at top
        icon = Gtk.Image.new_from_icon_name("dialog-warning-symbolic")
        icon.set_pixel_size(64)
        icon.set_opacity(0.8)
        icon.add_css_class("threat-icon")
        center_box.append(icon)
        
        # Text content
        text_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        text_box.set_halign(Gtk.Align.CENTER)
        
        self.total_threats_lbl = Gtk.Label(label="0 Threats Found")
        self.total_threats_lbl.add_css_class("text-huge")
        self.total_threats_lbl.set_halign(Gtk.Align.CENTER)
        
        sub = Gtk.Label(label="Across all historical scans")
        sub.add_css_class("text-muted")
        sub.set_halign(Gtk.Align.CENTER)
        
        text_box.append(self.total_threats_lbl)
        text_box.append(sub)
        center_box.append(text_box)
        
        box.append(center_box)

    def refresh(self, widget=None):
        self.scan_history = load_scan_history()
        
        # Update sidebar stats in main window
        if self.main_window:
            self.main_window.update_sidebar_stats()
        
        # 1. Update Chart
        self._update_chart()
        
        # 2. Update Posture
        # Logic: Calculate average score or use last score
        score = 0
        if self.scan_history:
             # Basic logic: take average of last 5 scans or just last one
             # For design match, let's use last scan
             last = self.scan_history[-1]
             # Score isn't explicitly saved in history in file_handler yet (only threats), 
             # so we might need to mock or derive it.
             # Let's derive a mock score from threats count: 100 - (threats * 5)
             threats = int(last.get('threats', 0))
             score = max(0, 100 - (threats * 5))
             self.last_security_score = score
        else:
            score = 100
        
        self.posture_score_lbl.set_label(f"Score: {score} / 100")
        self.posture_bar.set_fraction(score / 100.0)
        
        if score > 80:
            self.posture_status_lbl.set_label("STRONG")
            self.posture_status_lbl.remove_css_class("text-weak")
            self.posture_status_lbl.remove_css_class("text-medium")
            self.posture_status_lbl.add_css_class("text-strong")
            self.posture_bar.remove_css_class("progress-weak")
            self.posture_bar.remove_css_class("progress-medium")
            self.posture_bar.add_css_class("progress-strong")
        elif score > 50:
            self.posture_status_lbl.set_label("MODERATE")
            self.posture_status_lbl.remove_css_class("text-weak")
            self.posture_status_lbl.add_css_class("text-medium")
            self.posture_status_lbl.remove_css_class("text-strong")
            self.posture_bar.remove_css_class("progress-weak")
            self.posture_bar.add_css_class("progress-medium")
            self.posture_bar.remove_css_class("progress-strong")
        else:
            self.posture_status_lbl.set_label("WEAK")
            self.posture_status_lbl.add_css_class("text-weak")
            self.posture_status_lbl.remove_css_class("text-medium")
            self.posture_status_lbl.remove_css_class("text-strong")
            self.posture_bar.add_css_class("progress-weak")
            self.posture_bar.remove_css_class("progress-medium")
            self.posture_bar.remove_css_class("progress-strong")

        # 3. Update Attack Surface (use real risk categories if available)
        # Clear list
        child = self.surface_list.get_first_child()
        while child:
            next = child.get_next_sibling()
            self.surface_list.remove(child)
            child = next
            
        if not self.scan_history:
             self.surface_list.append(Gtk.Label(label="No data available", css_classes=["text-muted"]))
        else:
            # Use real risk categories from last_risk_categories if available
            if self.last_risk_categories and len(self.last_risk_categories) > 0:
                # Display real categories from scanner
                for category in self.last_risk_categories[:5]:  # Limit to top 5
                    name = category.get('category', 'Unknown')
                    count = category.get('count', 0)
                    # Determine risk level based on count
                    if count >= 3:
                        risk = "High"
                    elif count >= 2:
                        risk = "Medium"
                    else:
                        risk = "Low"
                    self.surface_list.append(self._create_surface_row(name, risk, count))
            else:
                # Fallback: show that scan was done but no specific categories
                last = self.scan_history[-1]
                threats = int(last.get('threats', 0))
                if threats > 0:
                    self.surface_list.append(Gtk.Label(label=f"{threats} threats detected", css_classes=["text-muted"]))
                    self.surface_list.append(Gtk.Label(label="Run new scan for details", css_classes=["text-muted"]))
                else:
                    self.surface_list.append(Gtk.Label(label="No threats detected", css_classes=["text-muted"]))

        # 4. Summary Cards
        if self.scan_history:
            last = self.scan_history[-1]
            date_str = last.get('date', 'Unknown')
            threats = last.get('threats', 0)
            
            # Show file name if available
            file_name = last.get('file', 'Unknown file')
            self.summary_date_lbl.set_label(f"{file_name}")
            self.summary_dur_lbl.set_label(f"Scanned on {date_str}")
            self.summary_count_lbl.set_label(f"Threats Found: {threats}")
            
            total_threats = sum(int(x.get('threats', 0)) for x in self.scan_history)
            self.total_threats_lbl.set_label(f"{total_threats} Threats Found")
        else:
            self.summary_date_lbl.set_label("No scans yet")
            self.summary_count_lbl.set_label("Threats Found: 0")
            self.total_threats_lbl.set_label("0 Threats Found")

    def _create_surface_row(self, name, risk, count):
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        name_lbl = Gtk.Label(label=name)
        name_lbl.set_hexpand(True)
        name_lbl.set_halign(Gtk.Align.START)
        row.append(name_lbl)
        
        badge = Gtk.Label(label=risk)
        if risk == "High":
            badge.add_css_class("badge-high")
        elif risk == "Medium":
            badge.add_css_class("badge-medium")
        else:
            badge.add_css_class("badge-low")
        row.append(badge)
        
        count_lbl = Gtk.Label(label=str(count))
        count_lbl.add_css_class("text-muted")
        row.append(count_lbl)
        return row

    def _update_chart(self):
        try:
            # Generate data - show empty chart if no data, real data if available
            # Group scan history by date and sum threats per day
            from collections import defaultdict
            
            threats_by_date = defaultdict(int)
            for entry in self.scan_history:
                date_str = entry.get('date', '')
                try:
                    # Parse date and sum threats for that day
                    threats = int(entry.get('threats', 0))
                    threats_by_date[date_str] += threats
                except:
                    pass
            
            # Always create 7 days of date labels (last 7 days)
            dates = []
            counts = []
            base = datetime.now()
            for i in range(7):
                d = base - timedelta(days=6-i)
                date_str = d.strftime('%Y-%m-%d')
                dates.append(d)
                # Use real data if available for this date, otherwise 0
                counts.append(threats_by_date.get(date_str, 0))
            
            print(f"[DEBUG] Generating chart with {len(dates)} data points")
            print(f"[DEBUG] Counts: {counts}")
            print(f"[DEBUG] Scan history length: {len(self.scan_history)}")
                    
            # Plotting with larger size
            plt.style.use('dark_background')
            fig, ax = plt.subplots(figsize=(10, 4), dpi=100)
            
            # Colors matching theme
            # bg_color = #161b22
            fig.patch.set_facecolor('#161b22')
            ax.set_facecolor('#161b22')
            
            # Only plot line if there's actual data (not all zeros)
            if any(count > 0 for count in counts):
                # Line color accent blue #58a6ff
                ax.plot(dates, counts, color='#58a6ff', marker='o', linewidth=2, markersize=5)
                # Fill under
                ax.fill_between(dates, counts, color='#58a6ff', alpha=0.1)
            else:
                # Empty chart - just plot the baseline at 0
                ax.plot(dates, counts, color='#58a6ff', linewidth=1, alpha=0.3)
            
            # Grid
            ax.grid(True, color='#30363d', linestyle='-', linewidth=0.5, alpha=0.5)
            
            # Spines
            for spine in ax.spines.values():
                spine.set_visible(False)
                
            # Ticks
            ax.tick_params(axis='x', colors='#8b949e')
            ax.tick_params(axis='y', colors='#8b949e')
            
            # Date format
            ax.xaxis.set_major_formatter(mdates.DateFormatter('%m-%d'))
            plt.xticks(rotation=0)
            
            plt.tight_layout()
            
            # Save to temp file
            with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as tmp:
                tmp_path = tmp.name
            
            plt.savefig(tmp_path, format='png', facecolor='#161b22', bbox_inches='tight')
            plt.close(fig)
            
            print(f"[DEBUG] Chart saved to: {tmp_path}")
            print(f"[DEBUG] File exists: {os.path.exists(tmp_path)}")
            
            # Update Picture Widget
            from gi.repository import Gio
            file = Gio.File.new_for_path(tmp_path)
            self.chart_picture.set_file(file)
            print(f"[DEBUG] Chart picture set from file")
            
        except Exception as e:
            print(f"[ERROR] Failed to generate chart: {e}")
            import traceback
            traceback.print_exc()
        
    def _on_run_scan_clicked(self, btn):
        if self.main_window:
            self.main_window.navigate_to("scan")
