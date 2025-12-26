import gi
gi.require_version('Gtk', '4.0')
from gi.repository import Gtk

from gui.views.dashboard import DashboardView
from gui.views.scan import ScanView
from gui.views.results import ResultsView
from gui.views.settings import SettingsView

class MainWindow(Gtk.ApplicationWindow):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        self.set_title("ShieldEye NeuralScan")
        # Slightly larger default size so most of the dashboard is visible,
        # but the window is not forced to fullscreen.
        self.set_default_size(750, 1050)
        
        # Main Layout
        self.box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        self.set_child(self.box)
        
        # Sidebar
        self.sidebar = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.sidebar.set_size_request(250, -1)
        self.sidebar.add_css_class("sidebar")
        self.box.append(self.sidebar)
        
        # Sidebar Content
        self._build_sidebar()
        
        # View Stack
        self.stack = Gtk.Stack()
        self.stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        self.stack.set_hexpand(True)
        self.stack.set_vexpand(True)
        self.box.append(self.stack)
        
        # Initialize Views
        self.views = {}
        self._init_views()
        
        # Show initial view
        self._on_nav_clicked(None, "dashboard")

    def _build_sidebar(self):
        # Logo/Title Area
        logo_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        logo_box.set_margin_top(24)
        logo_box.set_margin_bottom(32)
        logo_box.set_margin_start(20)
        logo_box.set_margin_end(20)
        
        # Icon and main brand name
        brand_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        logo_icon = Gtk.Image.new_from_icon_name("security-high-symbolic")
        logo_icon.set_pixel_size(24)
        brand_row.append(logo_icon)
        
        title_label = Gtk.Label(label="ShieldEye")
        title_label.add_css_class("logo-label")
        brand_row.append(title_label)
        logo_box.append(brand_row)
        
        # Subtitle
        subtitle_label = Gtk.Label(label="NeuralScan")
        subtitle_label.add_css_class("logo-subtitle")
        subtitle_label.set_halign(Gtk.Align.START)
        subtitle_label.set_margin_start(36)  # Align with text after icon
        logo_box.append(subtitle_label)
        
        self.sidebar.append(logo_box)
        
        # Navigation Buttons
        self.nav_buttons = {}
        nav_items = [
            ("dashboard", "Overview", "view-grid-symbolic"),
            ("scan", "Scan Target", "system-search-symbolic"),
            ("results", "Reports", "document-properties-symbolic"),
            ("settings", "Settings", "preferences-system-symbolic"),
        ]
        
        for id, label, icon_name in nav_items:
            btn = self._create_nav_button(id, label, icon_name)
            self.sidebar.append(btn)
        
        # Separator
        separator1 = Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL)
        separator1.set_margin_top(20)
        separator1.set_margin_bottom(20)
        separator1.set_margin_start(20)
        separator1.set_margin_end(20)
        self.sidebar.append(separator1)
        
        # Quick Stats Section
        stats_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        stats_box.set_margin_start(20)
        stats_box.set_margin_end(20)
        
        stats_title = Gtk.Label(label="Quick Stats")
        stats_title.add_css_class("sidebar-section-title")
        stats_title.set_halign(Gtk.Align.START)
        stats_box.append(stats_title)
        
        # Total Scans
        self.total_scans_label = self._create_stat_row("folder-symbolic", "Total Scans", "0")
        stats_box.append(self.total_scans_label)
        
        # Threats Found
        self.threats_found_label = self._create_stat_row("dialog-warning-symbolic", "Threats Found", "0")
        stats_box.append(self.threats_found_label)
        
        # Last Scan
        self.last_scan_label = self._create_stat_row("document-open-recent-symbolic", "Last Scan", "Never")
        stats_box.append(self.last_scan_label)
        
        self.sidebar.append(stats_box)
        
        # Separator
        separator2 = Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL)
        separator2.set_margin_top(20)
        separator2.set_margin_bottom(20)
        separator2.set_margin_start(20)
        separator2.set_margin_end(20)
        self.sidebar.append(separator2)
        
        # System Status Section
        status_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        status_box.set_margin_start(20)
        status_box.set_margin_end(20)
        
        status_title = Gtk.Label(label="System Status")
        status_title.add_css_class("sidebar-section-title")
        status_title.set_halign(Gtk.Align.START)
        status_box.append(status_title)
        
        # Docker Status
        docker_status = self._create_status_row("Docker Engine", "Active")
        status_box.append(docker_status)
        
        # Trivy Status
        trivy_status = self._create_status_row("Trivy Scanner", "Ready")
        status_box.append(trivy_status)
        
        self.sidebar.append(status_box)
        
        # Spacer to push bottom content down
        spacer = Gtk.Box()
        spacer.set_vexpand(True)
        self.sidebar.append(spacer)
        
        # Version info at bottom
        version_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        version_box.set_margin_start(20)
        version_box.set_margin_end(20)
        version_box.set_margin_bottom(20)
        
        version_label = Gtk.Label(label="NeuralScan v1.0")
        version_label.add_css_class("sidebar-version")
        version_label.set_halign(Gtk.Align.START)
        
        copyright_label = Gtk.Label(label="© 2025 ShieldEye")
        copyright_label.add_css_class("sidebar-copyright")
        copyright_label.set_halign(Gtk.Align.START)
        
        version_box.append(version_label)
        version_box.append(copyright_label)
        self.sidebar.append(version_box)

    def _create_nav_button(self, id, label, icon_name):
        btn = Gtk.Button()
        btn.add_css_class("nav-button") 
        btn.add_css_class("flat")  # Remove default button background/shadow
        
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        
        icon = Gtk.Image.new_from_icon_name(icon_name)
        lbl = Gtk.Label(label=label)
        
        box.append(icon)
        box.append(lbl)
        btn.set_child(box)
        
        btn.connect("clicked", self._on_nav_clicked, id)
        self.nav_buttons[id] = btn
        return btn
    
    def _create_stat_row(self, icon_name, label, value):
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        
        icon = Gtk.Image.new_from_icon_name(icon_name)
        icon.set_pixel_size(16)
        icon.add_css_class("sidebar-stat-icon")
        row.append(icon)
        
        text_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        text_box.set_hexpand(True)
        
        label_widget = Gtk.Label(label=label)
        label_widget.add_css_class("sidebar-stat-label")
        label_widget.set_halign(Gtk.Align.START)
        
        value_widget = Gtk.Label(label=value)
        value_widget.add_css_class("sidebar-stat-value")
        value_widget.set_halign(Gtk.Align.START)
        
        text_box.append(label_widget)
        text_box.append(value_widget)
        row.append(text_box)
        
        return row
    
    def _create_status_row(self, label, status):
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        
        label_widget = Gtk.Label(label=label)
        label_widget.add_css_class("sidebar-status-label")
        label_widget.set_halign(Gtk.Align.START)
        label_widget.set_hexpand(True)
        row.append(label_widget)
        
        status_dot = Gtk.Box()
        status_dot.add_css_class("status-dot")
        status_dot.add_css_class("status-active")
        row.append(status_dot)
        
        status_widget = Gtk.Label(label=status)
        status_widget.add_css_class("sidebar-status-value")
        row.append(status_widget)
        
        return row

    def _init_views(self):
        self.dashboard_view = DashboardView(self)
        self.stack.add_named(self.dashboard_view, "dashboard")
        
        self.scan_view = ScanView(self)
        self.stack.add_named(self.scan_view, "scan")
        
        self.results_view = ResultsView()
        self.stack.add_named(self.results_view, "results")
        
        self.settings_view = SettingsView()
        self.stack.add_named(self.settings_view, "settings")

    def _on_nav_clicked(self, widget, view_name):
        self.stack.set_visible_child_name(view_name)
        
        # Update button states
        for id, btn in self.nav_buttons.items():
            if id == view_name:
                btn.add_css_class("active")
            else:
                btn.remove_css_class("active")

    def navigate_to(self, view_name):
        self._on_nav_clicked(None, view_name)
    
    def update_sidebar_stats(self):
        """Update sidebar Quick Stats with real data from scan history"""
        from utils.file_handler import load_scan_history
        scan_history = load_scan_history()
        
        # Update Total Scans
        total_scans = len(scan_history)
        self._update_stat_value(self.total_scans_label, str(total_scans))
        
        # Update Threats Found (total across all scans)
        total_threats = sum(int(x.get('threats', 0)) for x in scan_history)
        self._update_stat_value(self.threats_found_label, str(total_threats))
        
        # Update Last Scan date
        if scan_history:
            last_date = scan_history[-1].get('date', 'Unknown')
            self._update_stat_value(self.last_scan_label, last_date)
        else:
            self._update_stat_value(self.last_scan_label, "Never")
    
    def _update_stat_value(self, stat_row, new_value):
        """Update the value label in a stat row"""
        # stat_row is a Box containing icon and text_box
        # text_box contains label and value widgets
        child = stat_row.get_first_child()
        while child:
            if isinstance(child, Gtk.Box):  # This is the text_box
                # Find the value label (second child)
                value_child = child.get_first_child()
                if value_child:
                    value_child = value_child.get_next_sibling()
                    if value_child and isinstance(value_child, Gtk.Label):
                        value_child.set_label(new_value)
                        return
            child = child.get_next_sibling()
