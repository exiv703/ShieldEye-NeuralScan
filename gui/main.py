import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image
import os
import threading
import queue
import json
from datetime import datetime
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib as mpl
import matplotlib.pyplot as plt
import logging
import time

from utils.file_handler import save_scan_history, load_scan_history
from scanner import SecurityScanner
from gui.theme import colors, apply_theme

try:
    mpl.set_loglevel("WARNING")
    logging.getLogger("matplotlib").setLevel(logging.WARNING)
    logging.getLogger("matplotlib.category").setLevel(logging.ERROR)
except Exception:
    pass

                                            
try:
    apply_theme()
except Exception:
    pass

class App(ctk.CTk):
    def __init__(self):
        super().__init__(fg_color=colors["bg"])
        self.title("NeuralScan")
        self.geometry("1100x700")
        self.configure(fg_color=colors["bg"]) 

        self.scanner = SecurityScanner()
        try:
            self.scanner.prepare_ai_analyzer()
        except Exception:
            pass
        self.scan_queue = queue.Queue()
        self.after(100, self.process_queue)

        self.current_view_name = "dashboard"
        self.sidebar_buttons = {}
        self.views = {}
        self.view_names = []
        self.min_scan_duration_ms = 2500
        self.scan_started_at = None
        self.last_scanned_file = None
                                                                   
        self.full_ai_var = tk.BooleanVar(value=True)
                                                                          
        self.disable_badge_ui = True
                                                                                 
        self._full_ai_slots = []
                                                              
        self._full_ai_chips = []
                                                                 
        self._disable_animation_until_ready = True

        self.icon_mapping = {
            "logo": "brand-tabler",
            "dashboard": "shield-code",
            "scan": "device-imac-search",
            "results": "report-analytics",  
            "settings": "settings-search",
        }

        self.load_icons()

        self.create_widgets()
                                                    
        self._render_background_gradient()
        self.main_frame.bind("<Configure>", self._on_main_resize)

        self.after_idle(self._init_first_view)
        self.view_container.bind("<Configure>", self._on_container_configure)

    def load_icons(self):
        self.icons = {}
        base_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "assets")
        icon_default_color = colors.get("icon-default", colors.get("text-muted", "#8A8F98"))
        icon_hover_color = colors.get("icon-hover", colors.get("text-primary", "#DDE1E6"))
        icon_active_color = colors.get("icon-active", colors.get("accent-primary", "#47D7FF"))
        for internal_name, filename in self.icon_mapping.items():
            if filename:
                png_path = os.path.join(base_path, f"{filename}.png")
                svg_path = os.path.join(base_path, f"{filename}.svg")
                asset_path = png_path if os.path.exists(png_path) else svg_path
                try:
                    default_img = self._make_tinted_ctkimage(asset_path, icon_default_color, size=(24,24))
                    hover_img = self._make_tinted_ctkimage(asset_path, icon_hover_color, size=(24,24))
                    active_img = self._make_tinted_ctkimage(asset_path, icon_active_color, size=(24,24))
                except FileNotFoundError as e:
                    print(f"Warning: Missing icon for '{internal_name}': {e}")
                    continue
                except Exception as e:
                    print(f"Warning: Could not load icon '{internal_name}' from {asset_path}: {e}")
                    continue
                self.icons[internal_name] = {
                    'default': default_img,
                    'hover': hover_img,
                    'active': active_img
                }

    def _hex_to_rgb(self, hex_color):
        h = hex_color.strip().lstrip('#')
        if len(h) == 3:
            h = ''.join([c*2 for c in h])
        r = int(h[0:2], 16)
        g = int(h[2:4], 16)
        b = int(h[4:6], 16)
        return (r, g, b)

    def _make_tinted_ctkimage(self, path, hex_color, size=(24,24)):
        if not os.path.exists(path):
            raise FileNotFoundError(path)
        ext = os.path.splitext(path)[1].lower()
        if ext == ".svg":
            try:
                import io
                import importlib
                cairosvg = importlib.import_module('cairosvg')
                png_bytes = cairosvg.svg2png(url=path, output_width=size[0] if size else None, output_height=size[1] if size else None)
                img = Image.open(io.BytesIO(png_bytes)).convert("RGBA")
            except Exception as e:
                raise e
        else:
            img = Image.open(path).convert("RGBA")
        r, g, b = self._hex_to_rgb(hex_color)
        _, _, _, a = img.split()
        color_img = Image.new("RGBA", img.size, (r, g, b, 255))
        color_img.putalpha(a)
        if size is not None:
            color_img = color_img.resize(size, Image.LANCZOS)
        return ctk.CTkImage(color_img, size=size)

    def create_widgets(self):
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0, fg_color=colors["sidebar-bg"],
                                          border_width=0) 
        self.sidebar_frame.pack(side="left", fill="y")
        self.sidebar_frame.grid_columnconfigure(0, minsize=4)
        self.sidebar_frame.grid_columnconfigure(1, weight=1)
        self.sidebar_frame.grid_rowconfigure(5, weight=1)

                                                  
        try:
            self.sidebar_divider = ctk.CTkFrame(self, width=1, corner_radius=0, fg_color=colors.get("sidebar-divider", colors.get("border", "#1b2431")))
            self.sidebar_divider.pack(side="left", fill="y")
        except Exception:
            pass

                                                                                   
        try:
            self._initial_poll_retries = 30
        except Exception:
            pass
        self.after(60, self._poll_container_ready)

        logo_icon = self.icons.get("logo", {}).get('default')
        self.logo_button = ctk.CTkButton(self.sidebar_frame,
                                         text="NeuralScan",
                                         image=logo_icon,
                                         font=ctk.CTkFont(size=20, weight="bold"),
                                         fg_color="transparent",
                                         text_color=colors["text-primary"],
                                         anchor="w",
                                         hover=False)
        self.logo_button.grid(row=0, column=1, padx=16, pady=16, sticky="w")

        main_buttons_data = [
            ("dashboard", "Dashboard"),
            ("scan", "Scan File"),
            ("results", "Results")
        ]
        for i, (name, text) in enumerate(main_buttons_data):
            self.create_sidebar_button(name, text, i + 1)
            self.view_names.append(name)

        sep = ctk.CTkFrame(self.sidebar_frame, height=1, fg_color=colors["border"], corner_radius=0)
        sep.grid(row=5, column=0, columnspan=2, sticky="we", padx=10, pady=(6, 6))

        bottom_row_start = 6
        self.create_sidebar_button("settings", "Settings", bottom_row_start)
        self.view_names.append("settings")

        self.main_frame = ctk.CTkFrame(self, fg_color=colors["bg"])
        self.main_frame.pack(side="right", fill="both", expand=True)

                                                   
        self._bg_image = None
        self._bg_label = ctk.CTkLabel(self.main_frame, text="", fg_color="transparent")
        self._bg_label.place(relx=0, rely=0, relwidth=1, relheight=1)

        

                                               
        self._traffic_canvas = tk.Canvas(self.main_frame, bg=colors["bg"], highlightthickness=0, bd=0)
        self._traffic_canvas.place(relx=0.97, rely=0.02, anchor="ne", width=60, height=18)
        self._draw_traffic_lights()

                                                    
        self.view_container = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.view_container.pack(fill="both", expand=True, padx=16, pady=16)

        self.create_views()

    def create_sidebar_button(self, name, text, row):
        icon = self.icons.get(name, {}).get('default') if self.icon_mapping.get(name) else None
        button = ctk.CTkButton(self.sidebar_frame,
                                image=icon,
                                text=text,
                                fg_color="transparent",
                                text_color=colors["text-muted"],
                                anchor="w",
                                font=ctk.CTkFont(size=14, weight="bold"),
                                command=lambda n=name: self.show_view(n),
                                width=160,
                                height=34,
                                corner_radius=8,
                                hover_color=colors["accent-primary-hover-inactive"]) 
        indicator = ctk.CTkFrame(self.sidebar_frame, width=3, height=30, fg_color="transparent", corner_radius=2)
        indicator.grid(row=row, column=0, padx=(0, 0), pady=4, sticky="nsw")

        button.grid(row=row, column=1, padx=12, pady=4, sticky="we")
        button.bind("<Enter>", lambda e, n=name: self.on_button_enter(n))
        button.bind("<Leave>", lambda e, n=name: self.on_button_leave(n))
        self.sidebar_buttons[name] = {"button": button, "indicator": indicator}

    def create_views(self):
        for name in self.view_names:
            view = ctk.CTkFrame(self.view_container, fg_color="transparent")
            self.views[name] = view

                                                                   
                                         
                                                                                         
        header = ctk.CTkFrame(self.views["dashboard"], fg_color="transparent")
        header.pack(fill="x", padx=16, pady=(6, 12))
        ctk.CTkLabel(header, text="Dashboard", font=ctk.CTkFont(size=20, weight="bold"),
                     text_color=colors["text-primary"]).pack(side="left")

        dash = ctk.CTkFrame(self.views["dashboard"], fg_color="transparent")
        dash.pack(fill="both", expand=True, padx=16, pady=10)
        dash.grid_columnconfigure((0,1), weight=1, uniform="dash")
                                     
        dash.grid_rowconfigure(0, weight=2)
        dash.grid_rowconfigure(1, weight=1)

        self.threats_shadow = ctk.CTkFrame(dash, fg_color=colors.get("surface-2", colors["surface-1"]), corner_radius=18)
        self.threats_shadow.grid(row=0, column=0, columnspan=2, sticky="nsew", padx=6, pady=6)
        self.threats_panel = ctk.CTkFrame(self.threats_shadow, fg_color=colors["panel-bg"], corner_radius=16, border_width=1, border_color=colors["border"]) 
        self.threats_panel.pack(fill="both", expand=True, padx=3, pady=3)
        threats_header = ctk.CTkFrame(self.threats_panel, fg_color="transparent")
        threats_header.pack(fill="x", padx=16, pady=(12, 6))
        ctk.CTkLabel(threats_header, text="Threats over time", text_color=colors["text-secondary"], font=ctk.CTkFont(size=16, weight="bold")).pack(side="left")
        th_actions = ctk.CTkFrame(threats_header, fg_color="transparent")
        th_actions.pack(side="right")
        ctk.CTkButton(th_actions, text="⟳", width=28, height=26, corner_radius=6,
                      fg_color="transparent", hover_color=colors.get("surface-3", colors.get("surface-2", colors["panel-bg"])),
                      text_color=colors.get("icon-default", colors["text-secondary"]), border_width=0,
                      command=self.refresh_dashboard).pack(side="left", padx=4)
        ctk.CTkButton(th_actions, text="⚙", width=28, height=26, corner_radius=6,
                      fg_color="transparent", hover_color=colors.get("surface-3", colors.get("surface-2", colors["panel-bg"])),
                      text_color=colors.get("icon-default", colors["text-secondary"]), border_width=0,
                      command=lambda: self.show_view("settings")).pack(side="left", padx=4)
        self.threats_content_frame = ctk.CTkFrame(self.threats_panel, fg_color=colors["panel-bg"], corner_radius=14)
        self.threats_content_frame.pack(fill="both", expand=True, padx=10, pady=(0,10))

        self.score_shadow = ctk.CTkFrame(dash, fg_color=colors.get("surface-2", colors["surface-1"]), corner_radius=18)
        self.score_shadow.grid(row=1, column=0, sticky="nsew", padx=6, pady=6)
        self.score_panel = ctk.CTkFrame(self.score_shadow, fg_color=colors["panel-bg"], corner_radius=16, border_width=1, border_color=colors["border"]) 
        self.score_panel.pack(fill="both", expand=True, padx=3, pady=3)
        score_header = ctk.CTkFrame(self.score_panel, fg_color="transparent")
        score_header.pack(fill="x", padx=16, pady=(12, 6))
        ctk.CTkLabel(score_header, text="Security Score", text_color=colors["text-secondary"], font=ctk.CTkFont(size=16, weight="bold")).pack(side="left")
        sc_actions = ctk.CTkFrame(score_header, fg_color="transparent")
        sc_actions.pack(side="right")
        ctk.CTkButton(sc_actions, text="⟳", width=28, height=26, corner_radius=6,
                      fg_color="transparent", hover_color=colors.get("surface-3", colors.get("surface-2", colors["panel-bg"])),
                      text_color=colors.get("icon-default", colors["text-secondary"]), border_width=0,
                      command=self.refresh_dashboard).pack(side="left", padx=4)
        ctk.CTkButton(sc_actions, text="⚙", width=28, height=26, corner_radius=6,
                      fg_color="transparent", hover_color=colors.get("surface-3", colors.get("surface-2", colors["panel-bg"])),
                      text_color=colors.get("icon-default", colors["text-secondary"]), border_width=0,
                      command=lambda: self.show_view("settings")).pack(side="left", padx=4)
        score_wrap = ctk.CTkFrame(self.score_panel, fg_color="transparent")
        score_wrap.pack(fill="x", padx=12, pady=(2, 12))
        self.score_value_label = ctk.CTkLabel(score_wrap, text="—", text_color=colors["text-primary"], font=ctk.CTkFont(size=28, weight="bold"))
        self.score_value_label.pack(side="left", padx=(0, 8))
                                                                   
        self.score_progress = ctk.CTkProgressBar(score_wrap, height=12, corner_radius=6, fg_color=colors.get("surface-2", colors["panel-bg"]))
        self.score_progress.configure(progress_color=colors.get("success", "#2ECE7E"))
        self.score_progress.pack(side="left", fill="x", expand=True, padx=12)
        try:
            self.score_progress.set(0)
        except Exception:
            pass

        self.risk_shadow = ctk.CTkFrame(dash, fg_color=colors.get("surface-2", colors["surface-1"]), corner_radius=18)
        self.risk_shadow.grid(row=1, column=1, sticky="nsew", padx=6, pady=6)
                                                                                                 
        self.risk_panel = ctk.CTkFrame(self.risk_shadow, fg_color=colors["panel-bg"], corner_radius=16, border_width=1, border_color=colors["border"]) 
        self.risk_panel.pack(fill="both", expand=True, padx=3, pady=3)
        header_row = ctk.CTkFrame(self.risk_panel, fg_color="transparent")
        header_row.pack(fill="x", padx=16, pady=(12, 6))
        ctk.CTkLabel(header_row, text="Top Risk Categories", text_color=colors["text-secondary"], font=ctk.CTkFont(size=18, weight="bold")).pack(side="left")
        rk_actions = ctk.CTkFrame(header_row, fg_color="transparent")
        rk_actions.pack(side="right")
        ctk.CTkButton(rk_actions, text="⟳", width=28, height=26, corner_radius=6,
                      fg_color="transparent", hover_color=colors.get("surface-3", colors.get("surface-2", colors["panel-bg"])),
                      text_color=colors.get("icon-default", colors["text-secondary"]), border_width=0,
                      command=self.refresh_dashboard).pack(side="left", padx=4)
        ctk.CTkButton(rk_actions, text="⚙", width=28, height=26, corner_radius=6,
                      fg_color="transparent", hover_color=colors.get("surface-3", colors.get("surface-2", colors["panel-bg"])),
                      text_color=colors.get("icon-default", colors["text-secondary"]), border_width=0,
                      command=lambda: self.show_view("settings")).pack(side="left", padx=4)
                                                                       
        self.risk_list_frame = ctk.CTkFrame(self.risk_panel, fg_color="transparent")
        self.risk_list_frame.pack(fill="both", expand=True, padx=12, pady=(0,12))

                                                                              

                                                                                        
        self.refresh_dashboard()
                                                                           
        try:
            self._update_global_ai_badge()
        except Exception:
            pass
                                                                   
        try:
            self.after(500, self._auto_enable_ai_badge)
        except Exception:
            pass

        self._add_view_header(self.views["scan"], "Select a file to scan", pad_y=(12, 4))
        self.drop_zone_outline = ctk.CTkFrame(
            self.views["scan"], fg_color=colors["bg"], corner_radius=16,
            border_width=1, border_color=colors["border-2"]
        )
        self.drop_zone_outline.pack(padx=16, pady=10, fill="x")
        self.drop_zone_shadow = ctk.CTkFrame(self.drop_zone_outline, fg_color=colors["surface-1"], corner_radius=16, border_width=0)
        self.drop_zone_shadow.pack(padx=0, pady=0, fill="x")
        self.drop_zone_frame = ctk.CTkFrame(self.drop_zone_shadow, fg_color=colors["panel-bg"], corner_radius=14, border_width=0)
        self.drop_zone_frame.pack(padx=4, pady=4, fill="x")
        inner = ctk.CTkFrame(self.drop_zone_frame, fg_color="transparent")
        inner.pack(pady=18)
        scan_icon_img = self.icons.get("scan", {}).get('active') or self.icons.get("scan", {}).get('default')
        if scan_icon_img:
            self.scan_icon_label = ctk.CTkLabel(inner, image=scan_icon_img, text="")
            self.scan_icon_label.pack(pady=(2, 6))
        ctk.CTkLabel(inner, text="Drop file here or use the button", text_color=colors["text-muted"], font=ctk.CTkFont(size=14)).pack()
        self._make_outlined_button(
            inner,
            text="Select File",
            width=160,
            command=self.select_file
        ).pack(pady=(10, 6))
        ctk.CTkLabel(inner, text="Supported: .py, .js, .sh, Dockerfile", text_color=colors["text-muted"], font=ctk.CTkFont(size=12)).pack()
        self.drop_zone_frame.bind("<Enter>", self._on_dropzone_enter)
        self.drop_zone_frame.bind("<Leave>", self._on_dropzone_leave)
        self.drop_zone_shadow.bind("<Enter>", self._on_dropzone_enter)
        self.drop_zone_shadow.bind("<Leave>", self._on_dropzone_leave)
        self.drop_zone_outline.bind("<Enter>", self._on_dropzone_enter)
        self.drop_zone_outline.bind("<Leave>", self._on_dropzone_leave)
        inner.bind("<Enter>", self._on_dropzone_enter)
        inner.bind("<Leave>", self._on_dropzone_leave)
        self._scan_pulse_phase = 0
        self._scan_pulse_running = True
        self._start_scan_pulse()
        self.file_path_label = ctk.CTkLabel(self.views["scan"], text="", text_color=colors["text-secondary"] if "text-secondary" in colors else colors["text-muted"]) 
        self.file_path_label.pack(pady=6, padx=16, anchor="w")

        self._add_view_header(self.views["results"], "Scan Results", pad_y=(12, 2))
        self.results_message_label = ctk.CTkLabel(self.views["results"], text="", text_color=colors["text-muted"]) 
        self.results_message_label.pack(pady=(10, 4), padx=16, anchor="w")

        self.results_progress = ctk.CTkProgressBar(self.views["results"], mode="indeterminate", height=10)
        self.results_progress.configure(fg_color=colors["panel-bg"], progress_color=colors["accent-primary"])

        self.results_shadow = ctk.CTkFrame(self.views["results"], fg_color=colors.get("surface-2", colors["surface-1"]), corner_radius=14)
        self.results_shadow.pack(padx=16, pady=(0, 10), fill="both", expand=True)
        self.results_scroll_frame = ctk.CTkScrollableFrame(self.results_shadow, fg_color=colors["panel-bg"], corner_radius=12, border_width=1, border_color=colors["border"]) 
        self.results_scroll_frame.pack(padx=3, pady=3, fill="both", expand=True)
        self.views["results"].bind("<Configure>", self._on_results_configure)
        self._results_relayout_scheduled = False
        self._last_results_size = (0, 0)
        self._enable_results_scrollwheel(self.results_scroll_frame)
        self._install_global_wheel_binding(self.results_scroll_frame)
        self.after(10, self._on_results_configure)

        self.scan_again_button = self._make_outlined_button(
            self.views["results"],
            text="Scan Again",
            width=140,
            command=lambda: self.show_view("scan")
        )
        self.scan_again_button.pack(pady=10, padx=16, anchor="e")
                                                                             
        try:
            self._update_full_ai_chips()
        except Exception:
            pass
                                                                         
        try:
            self.show_view(getattr(self, 'current_view_name', 'dashboard'), animate=False)
        except Exception:
            pass

        self._add_view_header(self.views["settings"], "Settings", pad_y=(12, 2))

        set_shadow = ctk.CTkFrame(self.views["settings"], fg_color=colors["surface-1"], corner_radius=14)
        set_shadow.pack(padx=16, pady=10, fill="x")
        set_panel = ctk.CTkFrame(set_shadow, fg_color=colors["panel-bg"], corner_radius=12, border_width=1, border_color=colors["border"]) 
        set_panel.pack(fill="x", padx=2, pady=2)

        row1 = ctk.CTkFrame(set_panel, fg_color="transparent")
        row1.pack(fill="x", padx=12, pady=(10, 8))
        ctk.CTkLabel(row1, text="AI Model", text_color=colors["text-primary"], font=ctk.CTkFont(size=14, weight="bold")).pack(side="left")
        model_values = [
            "bigcode/starcoder2-3b",
            "bigcode/starcoder2-7b",
            "mistralai/Mixtral-8x7B-Instruct-v0.1"
        ]
        self.model_combo = ctk.CTkComboBox(
            row1, values=model_values, width=280,
            fg_color=colors.get("surface-2", colors["panel-bg"]),
            border_color=colors.get("border-2", colors["border"]), border_width=1,
            button_color=colors.get("surface-3", colors["panel-bg"]), button_hover_color=colors.get("surface-3", colors["panel-bg"]),
            dropdown_fg_color=colors.get("surface-1", colors["panel-bg"]),
            dropdown_hover_color=colors.get("surface-2", colors["panel-bg"]),
            dropdown_text_color=colors.get("text-primary", "#DDE1E6")
        )
        self.model_combo.set(getattr(self.scanner, 'desired_model_name', model_values[0]))
        self.model_combo.pack(side="right")
        self._attach_tooltip(self.model_combo, "Select the AI model used for code analysis.")
        help1 = ctk.CTkLabel(set_panel, text="Changing the model will reinitialize the AI analyzer in background.", text_color=colors["text-muted"], font=ctk.CTkFont(size=12))
        help1.pack(padx=12, pady=(0, 6))

                                                              
        row2 = ctk.CTkFrame(set_panel, fg_color="transparent")
        row2.pack(fill="x", padx=12, pady=(6, 8))
        ctk.CTkLabel(row2, text="Full AI mode", text_color=colors["text-primary"], font=ctk.CTkFont(size=14, weight="bold")).pack(side="left")
        self.full_ai_switch = ctk.CTkSwitch(row2, text="", variable=self.full_ai_var,
                                            fg_color=colors.get("surface-2", colors["panel-bg"]),
                                            progress_color=colors.get("accent-primary", "#47D7FF"),
                                            button_color=colors.get("surface-3", colors["panel-bg"]),
                                            command=self._on_full_ai_toggle)
        self.full_ai_switch.pack(side="right")
        help2 = ctk.CTkLabel(set_panel, text="When enabled, a subtle 'FULL AI' badge appears in headers."
                                           " Nie ingeruje w skan (tylko informacja UI).",
                             text_color=colors["text-muted"], font=ctk.CTkFont(size=12))
        help2.pack(fill="x", padx=12, pady=(0, 6))

        row3 = ctk.CTkFrame(set_panel, fg_color="transparent")
        row3.pack(fill="x", padx=12, pady=8)
        ctk.CTkLabel(row3, text="Use Trivy (dependencies/secrets)", text_color=colors["text-primary"], font=ctk.CTkFont(size=14, weight="bold")).pack(side="left")
        trivy_wrap = ctk.CTkFrame(row3, fg_color=colors.get("surface-1", colors["panel-bg"]), corner_radius=12)
        trivy_wrap.pack(side="right", padx=0, pady=2)
        self.trivy_switch = ctk.CTkSwitch(
            trivy_wrap, text="",
            fg_color=colors.get("surface-2", colors["border-2"]),
            progress_color=colors["accent-primary"],
            button_color=colors.get("surface-3", colors["panel-bg"]),
            button_hover_color=colors.get("surface-3", colors["panel-bg"]) 
        )
        self.trivy_switch.pack(padx=8, pady=6)
        self.trivy_switch.select() if self.scanner.settings.get('use_trivy', False) else self.trivy_switch.deselect()
        self._attach_tooltip(self.trivy_switch, "When ON, include Trivy findings alongside AI results.")

        help2 = ctk.CTkLabel(set_panel, text="When ON, results from Trivy may be added as additional entries.", text_color=colors["text-muted"], font=ctk.CTkFont(size=12))
        help2.pack(padx=12, pady=(0, 8), anchor="w")
        self._attach_tooltip(help2, "Trivy scans dependencies/secrets; AI findings remain primary in the UI.")

        row3 = ctk.CTkFrame(set_panel, fg_color="transparent")
        row3.pack(fill="x", padx=12, pady=8)
        ctk.CTkLabel(row3, text="Minimum scan time (ms)", text_color=colors["text-primary"], font=ctk.CTkFont(size=14, weight="bold")).pack(side="left")
        self.min_time_value = ctk.StringVar(value=str(self.min_scan_duration_ms))
        self.min_time_label = ctk.CTkLabel(row3, textvariable=self.min_time_value, text_color=colors["text-muted"])
        self.min_time_label.pack(side="right", padx=(8,0))
        def _on_time_change(value):
            try:
                self.min_time_value.set(str(int(float(value))))
            except Exception:
                self.min_time_value.set(str(self.min_scan_duration_ms))
        slider_wrap = ctk.CTkFrame(row3, fg_color=colors.get("surface-1", colors["panel-bg"]), corner_radius=10)
        slider_wrap.pack(side="right", fill="x", expand=True, padx=(12,0))
        self.min_time_slider = ctk.CTkSlider(
            slider_wrap,
            from_=0, to=5000, number_of_steps=50, command=_on_time_change,
            progress_color=colors["accent-primary"],
            fg_color=colors.get("surface-2", colors["border-2"]),
            button_color=colors.get("surface-3", colors["panel-bg"]),
            button_hover_color=colors.get("surface-3", colors["panel-bg"])
        )
        self.min_time_slider.pack(fill="x", expand=True, padx=8, pady=6)
        self.min_time_slider.set(self.min_scan_duration_ms)
        self._attach_tooltip(self.min_time_slider, "Ensures scans feel realistic by enforcing a minimum duration.")

        row4 = ctk.CTkFrame(set_panel, fg_color="transparent")
        row4.pack(fill="x", padx=12, pady=8)
        ctk.CTkLabel(row4, text="AI explanation detail", text_color=colors["text-primary"], font=ctk.CTkFont(size=14, weight="bold")).pack(side="left")
        self.ai_detail_combo = ctk.CTkComboBox(
            row4, values=["short", "standard", "deep"], width=160,
            fg_color=colors.get("surface-2", colors["panel-bg"]),
            border_color=colors.get("border-2", colors["border"]), border_width=1,
            button_color=colors.get("surface-3", colors["panel-bg"]), button_hover_color=colors.get("surface-3", colors["panel-bg"]),
            dropdown_fg_color=colors.get("surface-1", colors["panel-bg"]),
            dropdown_hover_color=colors.get("surface-2", colors["panel-bg"]),
            dropdown_text_color=colors.get("text-primary", "#DDE1E6")
        )
        self.ai_detail_combo.set(self.scanner.settings.get('ai_detail', 'standard'))
        self.ai_detail_combo.pack(side="right")
        self._attach_tooltip(self.ai_detail_combo, "Controls how verbose AI explanations are in the results.")

        help4 = ctk.CTkLabel(set_panel, text="Controls how verbose AI explanations are.", text_color=colors["text-muted"], font=ctk.CTkFont(size=12))
        help4.pack(padx=12, pady=(0, 8), anchor="w")
        self._attach_tooltip(help4, "Short = concise flags; Deep = thorough rationale and remediation suggestions.")

        row5 = ctk.CTkFrame(set_panel, fg_color="transparent")
        row5.pack(fill="x", padx=12, pady=8)
        ctk.CTkLabel(row5, text="Save scan history", text_color=colors["text-primary"], font=ctk.CTkFont(size=14, weight="bold")).pack(side="left")
        history_wrap = ctk.CTkFrame(row5, fg_color=colors.get("surface-1", colors["panel-bg"]), corner_radius=12)
        history_wrap.pack(side="right", padx=0, pady=2)
        self.history_switch = ctk.CTkSwitch(
            history_wrap, text="",
            fg_color=colors.get("surface-2", colors["border-2"]),
            progress_color=colors["accent-primary"],
            button_color=colors.get("surface-3", colors["panel-bg"]),
            button_hover_color=colors.get("surface-3", colors["panel-bg"]) 
        )
        self.history_switch.pack(padx=8, pady=6)
        self.history_switch.select() if self.scanner.settings.get('save_history', True) else self.history_switch.deselect()
        self._attach_tooltip(self.history_switch, "When ON, scan results will be saved to history for the dashboard.")

        actions = ctk.CTkFrame(set_panel, fg_color="transparent")
        actions.pack(fill="x", padx=12, pady=(8, 12))
        self.apply_btn_outer = self._make_outlined_button(actions, text="Apply Settings", width=160, command=self.apply_settings)
        self.apply_btn_outer.pack(side="right")
        self._attach_tooltip(self.apply_btn_outer, "Apply changes without closing the window.")
        self.settings_saved_chip = ctk.CTkFrame(actions, fg_color=colors.get("accent-primary-transparent", colors["surface-1"]), corner_radius=12)
        chip_label = ctk.CTkLabel(self.settings_saved_chip, text="Saved", text_color=colors["accent-primary"], font=ctk.CTkFont(size=12, weight="bold"))
        chip_label.pack(padx=10, pady=4)
        self.settings_saved_chip.pack(side="left")
        self.settings_saved_chip.pack_forget()

                                                                                 
    def _add_view_header(self, parent, title: str, pad_y=(12, 2)):
                                                                                           
        header = ctk.CTkFrame(parent, fg_color="transparent")
        header.pack(fill="x", padx=16, pady=pad_y)
        ctk.CTkLabel(header, text=title, font=ctk.CTkFont(size=20, weight="bold"), text_color=colors["text-primary"]).pack(side="left")
        if not getattr(self, 'disable_badge_ui', False):
            right = ctk.CTkFrame(header, fg_color="transparent")
            right.pack(side="right")
            self._full_ai_slots.append(right)
            self._add_section_divider(parent).pack(fill="x", padx=16, pady=(0, 8))

    def _create_full_ai_chip(self, parent):
        chip_shadow = ctk.CTkFrame(parent, fg_color=colors.get("surface-2", colors.get("surface-1", colors["panel-bg"])), corner_radius=10)
        chip_inner = ctk.CTkFrame(chip_shadow, fg_color=colors["panel-bg"], corner_radius=8, border_width=1, border_color=colors.get("border", "#1b2431"))
        chip_inner.pack(padx=2, pady=2)
        chip_label = ctk.CTkLabel(chip_inner, text="FULL AI", text_color=colors.get("accent-primary", "#47D7FF"), font=ctk.CTkFont(size=12, weight="bold"))
        chip_label.pack(padx=8, pady=2)
                                     
        self._full_ai_chips.append((chip_shadow, parent))
        return chip_shadow

    def _on_full_ai_toggle(self):
        self._update_full_ai_chips()
                                                            
        try:
            self._update_global_ai_badge()
        except Exception:
            pass

    def _update_full_ai_chips(self):
        if getattr(self, 'disable_badge_ui', False):
            return               
        enabled = bool(self.full_ai_var.get())
                                             
        if not enabled:
            for frame, _parent in list(self._full_ai_chips):
                try:
                    frame.pack_forget()
                    frame.destroy()
                except Exception:
                    pass
            self._full_ai_chips.clear()
        else:
                                                                  
            existing_parents = {p for (_f, p) in self._full_ai_chips}
            for slot in self._full_ai_slots:
                if slot not in existing_parents:
                    try:
                        chip = self._create_full_ai_chip(slot)
                        chip.pack(side="right", padx=6)
                    except Exception:
                        pass
                                                                                           
        try:
            self.view_container.update_idletasks()
            self.show_view(getattr(self, 'current_view_name', 'dashboard'), animate=False)
        except Exception:
            pass

                                                                                
    def _ensure_global_ai_badge(self):
        if getattr(self, '_ai_badge', None) is not None:
            return self._ai_badge
        try:
            cont = self.view_container if hasattr(self, 'view_container') else self
                                             
            outer = ctk.CTkFrame(cont, fg_color=colors.get("surface-2", colors.get("surface-1", colors["panel-bg"])), corner_radius=10)
            inner = ctk.CTkFrame(outer, fg_color=colors["panel-bg"], corner_radius=8, border_width=1, border_color=colors.get("border", "#1b2431"))
            inner.pack(padx=2, pady=2)
            lbl = ctk.CTkLabel(inner, text="FULL AI", text_color=colors.get("accent-primary", "#47D7FF"), font=ctk.CTkFont(size=12, weight="bold"))
            lbl.pack(padx=8, pady=2)
            self._ai_badge = outer
            return outer
        except Exception:
            self._ai_badge = None
            return None

    def _position_global_ai_badge(self):
        try:
            badge = getattr(self, '_ai_badge', None)
            if not badge:
                return
                                                                       
            badge.place(relx=1.0, rely=0.0, x=-24, y=10, anchor="ne")
            badge.lift()
        except Exception:
            pass

    def _update_global_ai_badge(self):
        try:
            enabled = bool(self.full_ai_var.get())
            if enabled:
                badge = self._ensure_global_ai_badge()
                if badge is not None:
                    self._position_global_ai_badge()
            else:
                bdg = getattr(self, '_ai_badge', None)
                if bdg is not None:
                    try:
                        bdg.place_forget()
                        bdg.destroy()
                    except Exception:
                        pass
                    self._ai_badge = None
        except Exception:
            pass

    def _auto_enable_ai_badge(self, attempts: int = 0):
                                                                   
        try:
            ready = False
            try:
                ready = bool(getattr(self.scanner, 'ai_ready', None) and self.scanner.ai_ready.is_set())
            except Exception:
                ready = False
            if not ready:
                try:
                    analyzer = getattr(self.scanner, 'ai_analyzer', None)
                    ready = bool(analyzer and getattr(analyzer, 'model', None))
                except Exception:
                    pass
            if ready and not self.full_ai_var.get():
                try:
                    self.full_ai_var.set(True)
                except Exception:
                    pass
            self._update_global_ai_badge()
            if not ready and attempts < 20:
                self.after(300, lambda: self._auto_enable_ai_badge(attempts + 1))
        except Exception:
            pass

    def apply_settings(self):
        try:
            self._press_flash(self.apply_btn_outer)
        except Exception:
            pass
        model_name = None
        try:
            model_name = self.model_combo.get()
        except Exception:
            pass
        if model_name and model_name != getattr(self.scanner, 'desired_model_name', None):
            try:
                try:
                    self.scanner.ai_ready.clear()
                except Exception:
                    pass
                self.scanner.prepare_ai_analyzer(model_name=model_name)
                self.show_results_message("Reinitializing AI model in background...")
            except Exception as e:
                messagebox.showerror("Settings", f"Failed to reinitialize AI model: {e}")

        try:
            self.scanner.settings['use_trivy'] = bool(self.trivy_switch.get())
        except Exception:
            pass

        try:
            self.min_scan_duration_ms = int(self.min_time_slider.get())
        except Exception:
            pass

        try:
            self.scanner.settings['ai_detail'] = self.ai_detail_combo.get()
        except Exception:
            pass

        try:
            self.scanner.settings['save_history'] = bool(self.history_switch.get())
        except Exception:
            pass

        self._show_saved_chip()
        try:
            self.refresh_dashboard()
        except Exception:
            pass

    def _show_saved_chip(self):
        try:
            if hasattr(self, 'settings_saved_chip'):
                self.settings_saved_chip.pack(side="left")
                self.after(1600, lambda: self.settings_saved_chip.pack_forget())
        except Exception:
            pass

    def _press_flash(self, outer_widget):
        try:
            base = colors.get("accent-primary", "#47D7FF")
            glow = colors.get("accent-primary-hover", base)
            outer_widget.configure(fg_color=glow)
            self.after(150, lambda: outer_widget.configure(fg_color=base))
        except Exception:
            pass

    def _attach_tooltip(self, widget, text: str):
        try:
            tip = {"win": None}
            def show_tip(event=None):
                if tip["win"] is not None:
                    return
                x = widget.winfo_rootx() + 10
                y = widget.winfo_rooty() + widget.winfo_height() + 6
                tip_win = tk.Toplevel(widget)
                tip_win.wm_overrideredirect(True)
                tip_win.configure(bg=colors.get("panel-bg", "#111"))
                              
                border = tk.Frame(tip_win, bg=colors.get("border", "#333"))
                border.pack()
                inner = tk.Frame(border, bg=colors.get("panel-bg", "#111"))
                inner.pack(padx=1, pady=1)
                lbl = tk.Label(inner, text=text, bg=colors.get("panel-bg", "#111"), fg=colors.get("text-muted", "#AAA"), justify="left", wraplength=280, font=("Segoe UI", 10))
                lbl.pack(padx=8, pady=6)
                tip_win.wm_geometry(f"+{x}+{y}")
                tip["win"] = tip_win
            def hide_tip(event=None):
                if tip["win"] is not None:
                    try:
                        tip["win"].destroy()
                    except Exception:
                        pass
                    tip["win"] = None
            widget.bind("<Enter>", show_tip)
            widget.bind("<Leave>", hide_tip)
        except Exception:
            pass

    def _init_first_view(self):
        try:
            self.show_view("dashboard", animate=False)
        except Exception:
            self.after(30, lambda: self.show_view("dashboard", animate=False))
                                                                          
        try:
            self._did_initial_layout = False
        except Exception:
            pass
        self.after_idle(self._stabilize_first_layout)
                                                                                   
        self.after(120, self._nudge_layout_once)
        self.after(350, self._nudge_layout_once)
                                                                                      
        try:
            if not hasattr(self, '_bound_map_once'):
                self._bound_map_once = True
                self.bind('<Map>', lambda e: self.after(20, self._stabilize_first_layout))
        except Exception:
            pass

    def _stabilize_first_layout(self):
                                                                                                        
        if getattr(self, "_did_initial_layout", False):
            return
        self._did_initial_layout = True
        try:
                                         
            self.update_idletasks()
            self.view_container.update_idletasks()
            self._ensure_z_order()
                                                                    
            current = getattr(self, 'current_view_name', 'dashboard')
            self.show_view(current, animate=False)
                                                                        
            try:
                self._render_background_gradient()
                self._bg_label.lower()
            except Exception:
                pass
                                                           
            if current == 'results' and hasattr(self, '_refresh_results_layout'):
                self.after(10, self._refresh_results_layout)
                                                                             
            try:
                self.refresh_dashboard()
            except Exception:
                pass
        except Exception:
            pass
                                                  
        self._disable_animation_until_ready = False
                                                                     
        self._force_relayout()

    def _nudge_layout_once(self):
        try:
            self.update_idletasks()
            self.view_container.update_idletasks()
            self._ensure_z_order()
            current = getattr(self, 'current_view_name', 'dashboard')
            self.show_view(current, animate=False)
        except Exception:
            pass

    def _poll_container_ready(self):
        try:
            w = int(self.view_container.winfo_width())
            h = int(self.view_container.winfo_height())
        except Exception:
            w, h = 0, 0
        if w < 200 or h < 150:
                                       
            try:
                self._initial_poll_retries -= 1
            except Exception:
                self._initial_poll_retries = 0
            if getattr(self, '_initial_poll_retries', 0) > 0:
                self.after(70, self._poll_container_ready)
            return
                                                       
        try:
            self.update_idletasks()
            self._ensure_z_order()
            current = getattr(self, 'current_view_name', 'dashboard')
            self.show_view(current, animate=False)
            try:
                self.refresh_dashboard()
            except Exception:
                pass
        except Exception:
            pass
                                                                
        self._disable_animation_until_ready = False
                                            
        self._force_relayout()

    def _force_relayout(self):
        try:
            geo = self.winfo_geometry()                       
            size, _, pos = geo.partition('+')
            wh = size.split('x')
            if len(wh) != 2:
                return
            w = int(wh[0])
            h = int(wh[1])
                                                         
            self.geometry(f"{w}x{h+1}")
            self.after(40, lambda: self.geometry(f"{w}x{h}"))
        except Exception:
            pass

    def _ensure_z_order(self):
        try:
                                           
            if hasattr(self, '_bg_label'):
                self._bg_label.lower()
                                           
            if hasattr(self, 'view_container'):
                self.view_container.lift()
                                                                  
            if hasattr(self, 'sidebar'):
                self.sidebar.lift()
        except Exception:
            pass

    def _on_container_configure(self, event):
        for name, frame in self.views.items():
            if name == self.current_view_name:
                frame.configure(width=event.width, height=event.height)

    def _on_main_resize(self, event):
                                                           
        try:
            self._render_background_gradient()
                                   
            self._bg_label.lower()
                                                                       
            self._ensure_z_order()
            try:
                current = getattr(self, 'current_view_name', None)
                if current:
                    self.views[current].place_configure(relx=0.0, rely=0.0, relwidth=1.0, relheight=1.0)
            except Exception:
                pass
                                                                  
            try:
                self._position_global_ai_badge()
            except Exception:
                pass
        except Exception:
            pass

    def _on_dashboard_configure(self, event):
        try:
            if getattr(self, '_dashboard_layout_done', False):
                return
            if event.width > 300 and event.height > 200:
                self._dashboard_layout_done = True
                                                       
                self.refresh_dashboard()
        except Exception:
            pass

    def _on_dash_container_configure(self, dash):
        try:
            if getattr(self, '_dash_rows_sized', False):
                return
            h = int(dash.winfo_height())
            if h < 400:
                return                                
                                                                                          
            top_min = max(280, int(h * 0.62))
            bottom_min = max(220, h - top_min - 16)
            dash.grid_rowconfigure(0, minsize=top_min)
            dash.grid_rowconfigure(1, minsize=bottom_min)
            self._dash_rows_sized = True
                                                                          
            try:
                if self.current_view_name == 'dashboard':
                    self.refresh_dashboard()
            except Exception:
                pass
        except Exception:
            pass

    def _create_vertical_gradient(self, width, height, start_hex, end_hex):
        try:
            from PIL import Image
        except Exception:
            return None
        if width < 2 or height < 2:
            width, height = max(width, 2), max(height, 2)
        img = Image.new("RGB", (1, height), start_hex)
                   
        sh = tuple(int(start_hex.lstrip('#')[i:i+2], 16) for i in (0,2,4))
        eh = tuple(int(end_hex.lstrip('#')[i:i+2], 16) for i in (0,2,4))
        for y in range(height):
            t = y / max(1, height-1)
            r = int(sh[0]*(1-t) + eh[0]*t)
            g = int(sh[1]*(1-t) + eh[1]*t)
            b = int(sh[2]*(1-t) + eh[2]*t)
            img.putpixel((0, y), (r, g, b))
        img = img.resize((width, height))
        return img

    def _render_background_gradient(self):
        try:
            w = max(2, self.main_frame.winfo_width())
            h = max(2, self.main_frame.winfo_height())
            start = colors.get("bg-gradient-start", colors["bg"])
            end = colors.get("bg-gradient-end", colors["bg"])
            img = self._create_vertical_gradient(w, h, start, end)
            if img is None:
                return
            self._bg_image = ctk.CTkImage(light_image=img, dark_image=img, size=(w, h))
            self._bg_label.configure(image=self._bg_image)
        except Exception:
            pass

    def _draw_traffic_lights(self):
        try:
            c = self._traffic_canvas
            c.delete("all")
            c.configure(bg=colors["bg"])
            r = 6
            spacing = 6
            x = 6
            y = 9
            c.create_oval(x-r, y-r, x+r, y+r, fill="#ff5f56", outline="")
            x += 2*r + spacing
            c.create_oval(x-r, y-r, x+r, y+r, fill="#ffbd2e", outline="")
            x += 2*r + spacing
            c.create_oval(x-r, y-r, x+r, y+r, fill="#27c93f", outline="")
        except Exception:
            pass

    def _copy_to_clipboard(self, text: str):
        try:
            self.clipboard_clear()
            self.clipboard_append(text)
        except Exception as e:
            print(f"Clipboard error: {e}")

    def show_view(self, name, animate=True):
        if name in self.views:
            new_view = self.views[name]
            old_name = getattr(self, 'current_view_name', None)
            old_view = self.views.get(old_name) if old_name else None
                                                       
            if getattr(self, '_disable_animation_until_ready', False):
                animate = False

            self.view_container.update_idletasks()
            if (old_view is None) or (not animate):
                for vn, vv in self.views.items():
                    if vn != name:
                        vv.place_forget()
                new_view.place(relx=0.0, rely=0.0, relwidth=1.0, relheight=1.0)
            else:
                new_view.place(relx=1.0, rely=0.0, relwidth=1.0, relheight=1.0)
                if str(old_view.winfo_manager()) != 'place':
                    old_view.pack_forget()
                    old_view.place(relx=0.0, rely=0.0, relwidth=1.0, relheight=1.0)
                steps = 12
                duration_ms = 160
                def step(i=0):
                    if i <= steps:
                        t = i / steps
                        relx_new = 1.0 - t
                        relx_old = 0.0 - t
                        new_view.place_configure(relx=relx_new)
                        old_view.place_configure(relx=relx_old)
                        self.after(int(duration_ms/steps), lambda: step(i+1))
                    else:
                        old_view.place_forget()
                        new_view.place_configure(relx=0.0)
                step()

            self.current_view_name = name
            self.update_sidebar_buttons(name)
            try:
                                                                                 
                self._ensure_z_order()
                w = self.view_container.winfo_width()
                h = self.view_container.winfo_height()
                if w > 1 and h > 1:
                    new_view.configure(width=w, height=h)
                self.view_container.update_idletasks()
                if name == 'results' and hasattr(self, '_refresh_results_layout'):
                    self.after(10, self._refresh_results_layout)
                                                                 
                try:
                    self._position_global_ai_badge()
                except Exception:
                    pass
            except Exception:
                pass

    def update_sidebar_buttons(self, active_name):
        for name, data in self.sidebar_buttons.items():
            button = data['button']
            is_active = (name == active_name)
            pill_bg = colors.get("sidebar-pill", colors["accent-primary-transparent"])
            button.configure(
                fg_color=pill_bg if is_active else "transparent",
                text_color=colors["text-primary"] if is_active else colors["text-muted"],
                border_width=0,
                corner_radius=12
            )
            indicator = data.get('indicator')
            if indicator:
                indicator.configure(fg_color=colors["accent-primary"] if is_active else "transparent")
            if self.icon_mapping.get(name):
                icons = self.icons.get(name)
                if icons:
                    button.configure(image=icons['active'] if is_active else icons['default'])

    def on_button_enter(self, name):
        if self.current_view_name != name:
            button = self.sidebar_buttons[name]['button']
            hover_bg = colors.get("sidebar-pill-hover", colors["accent-primary-transparent"]) 
            button.configure(text_color=colors["text-primary"], fg_color=hover_bg) 
            if self.icon_mapping.get(name):
                icons = self.icons.get(name)
                if icons:
                    button.configure(image=icons.get('hover') or icons.get('default'))
            indicator = self.sidebar_buttons[name].get('indicator')
            if indicator:
                indicator.configure(fg_color=colors["accent-primary-hover"] if "accent-primary-hover" in colors else colors["accent-primary"]) 

    def on_button_leave(self, name):
        if self.current_view_name != name:
            button = self.sidebar_buttons[name]['button']
            button.configure(text_color=colors["text-muted"], fg_color="transparent")
            if self.icon_mapping.get(name):
                icons = self.icons.get(name)
                if icons:
                    button.configure(image=icons.get('default'))
            indicator = self.sidebar_buttons[name].get('indicator')
            if indicator:
                indicator.configure(fg_color="transparent")

    def _on_dropzone_enter(self, event=None):
        try:
            self.drop_zone_outline.configure(
                border_color=colors.get("accent-primary-hover", colors["accent-primary"]),
                border_width=2
            )
        except Exception:
            pass

    def _on_dropzone_leave(self, event=None):
        try:
            self.drop_zone_outline.configure(border_color=colors["border-2"], border_width=1)
        except Exception:
            pass

    def _start_scan_pulse(self):
        if not getattr(self, "_scan_pulse_running", False):
            return
        try:
            phase = getattr(self, "_scan_pulse_phase", 0)
            phase = (phase + 1) % 40 
            self._scan_pulse_phase = phase
            t = abs(20 - phase) / 20.0
            def _hex_to_rgb(h):
                h = h.lstrip('#')
                return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))
            def _rgb_to_hex(rgb):
                return '#%02x%02x%02x' % rgb
            c1 = _hex_to_rgb(colors.get("border-2", colors["border"]))
            c2 = _hex_to_rgb(colors.get("accent-primary", "#47D7FF"))
            blend = tuple(int(c1[i] + (c2[i]-c1[i]) * (0.25*t)) for i in range(3))
            self.drop_zone_outline.configure(border_color=_rgb_to_hex(blend), border_width=1 + int(1*t))
        except Exception:
            pass
        self.after(80, self._start_scan_pulse)

    def _make_outlined_button(self, parent, text, width, command):
        outer = ctk.CTkFrame(parent,
                             fg_color=colors.get("accent-primary", "#47D7FF"),
                             corner_radius=10,
                             border_width=0)
        btn = ctk.CTkButton(outer,
                            text=text,
                            width=width,
                            corner_radius=9,
                            fg_color=colors.get("surface-2", colors.get("panel-bg", "#1D2230")),
                            hover_color=colors.get("surface-3", colors.get("surface-2", "#242A3A")),
                            text_color=colors.get("text-primary", "#E6E9EF"),
                            border_width=0,
                            command=command)
        btn.pack(padx=1, pady=1)

        def _enter(_e=None):
            try:
                outer.configure(fg_color=colors.get("accent-primary-hover", colors.get("accent-primary", "#47D7FF")))
            except Exception:
                pass
        def _leave(_e=None):
            try:
                outer.configure(fg_color=colors.get("accent-primary", "#47D7FF"))
            except Exception:
                pass
        btn.bind("<Enter>", _enter)
        btn.bind("<Leave>", _leave)
        return outer

    def select_file(self):
        filepath = filedialog.askopenfilename()
        if filepath:
            self.last_scanned_file = filepath
            self.file_path_label.configure(text=os.path.basename(filepath))
            self.show_view('results')
            self.start_scanning_ui()
            self.scan_started_at = time.time()

            def _poll_ai_and_scan():
                ready = False
                try:
                    ready = bool(self.scanner.ai_ready.is_set())
                except Exception:
                    ready = False

                if ready:
                    scan_thread = threading.Thread(target=self.run_scan, args=(filepath,), daemon=True)
                    scan_thread.start()
                    self.show_results_message("Scanning... Please wait.")
                else:
                    self.show_results_message("Initializing AI analyzer... This may take a moment.")
                    try:
                        self.scanner.prepare_ai_analyzer()
                    except Exception:
                        pass
                    self.after(300, _poll_ai_and_scan)

            _poll_ai_and_scan()

    def run_scan(self, filepath):
        try:
            report = self.scanner.scan_file_for_malware(filepath)
            self.scan_queue.put(report)
        except Exception as e:
            self.scan_queue.put({"error": str(e)})

    def process_queue(self):
        try:
            try:
                prog = getattr(self.scanner, 'progress_message', '')
                if getattr(self, 'is_scanning', False) and prog:
                    self.show_results_message(prog)
            except Exception:
                pass
            report = self.scan_queue.get_nowait()
            if "error" in report:
                self.show_view('results')
                self.stop_scanning_ui()
                self.show_results_message(f"ERROR: {report['error']}")
                messagebox.showerror("Scan Error", report['error'])
            else:
                started = self.scan_started_at or time.time()
                elapsed_ms = int((time.time() - started) * 1000)
                remaining = max(0, self.min_scan_duration_ms - elapsed_ms)
                self.after(remaining, lambda r=report: self.finalize_scan(r))
        except queue.Empty:
            pass
        self.after(100, self.process_queue)

    def start_scanning_ui(self):
        self.show_results_message("Scanning... Please wait.")
        try:
            self.results_progress.pack(padx=20, pady=(0, 10), fill="x")
            self.results_progress.start()
            self.is_scanning = True
            self._show_skeleton_loaders()
        except Exception:
            pass

    def stop_scanning_ui(self):
        try:
            self.results_progress.stop()
            self.results_progress.pack_forget()
            self.is_scanning = False
            self._hide_skeleton_loaders()
        except Exception:
            pass

    def finalize_scan(self, report):
        self.stop_scanning_ui()
        try:
            self.last_security_score = report.get("security_score")
            self.last_risk_categories = report.get("risk_categories", [])
        except Exception:
            self.last_security_score = None
            self.last_risk_categories = []
        self.show_view('results', animate=False)
        self.display_scan_results(report)
        try:
            self.update_idletasks()
            self._refresh_results_layout()
            self.after(16, self._refresh_results_layout)
            self.after(24, self._on_results_configure)
        except Exception:
            pass
        try:
            findings = report.get("findings", [])
            save_scan_history(self.last_scanned_file or "", len(findings))
        except Exception:
            pass
        self.refresh_dashboard()

    def _extract_findings(self, report):
           
        try:
            if not isinstance(report, dict):
                return []
            findings = report.get("findings")
            if isinstance(findings, list):
                                           
                norm = []
                for f in findings:
                    if not isinstance(f, dict):
                        continue
                    norm.append({
                        "line": f.get("line", "N/A"),
                        "code_snippet": f.get("code_snippet", ""),
                        "description": f.get("description", "Potential issue"),
                        "explanation": f.get("explanation", ""),
                        "severity": f.get("severity", "Medium"),
                        "source": f.get("source", "AI Analyzer"),
                    })
                return norm
                                          
            trivy_text = report.get("trivy") or report.get("result") or report.get("message")
            if isinstance(trivy_text, str) and trivy_text.strip():
                return [{
                    "line": "N/A",
                    "code_snippet": "See explanation",
                    "description": "Scan Summary",
                    "explanation": trivy_text.strip(),
                    "severity": "Medium",
                    "source": "Scanner",
                }]
        except Exception:
            pass
        return []

    def display_scan_results(self, report):
        self.results_message_label.configure(text="")
        for child in self.results_scroll_frame.winfo_children():
            child.destroy()

        self._result_cards = []

        findings = self._extract_findings(report)
        score = report.get("security_score", "N/A")

        header_shadow = ctk.CTkFrame(self.results_scroll_frame, fg_color=colors.get("surface-2", colors["surface-1"]), corner_radius=14)
        header_shadow.pack(fill="x", padx=16, pady=(12, 8))
        header = ctk.CTkFrame(header_shadow, fg_color=colors["panel-bg"], corner_radius=12, border_width=1, border_color=colors["border"]) 
        header.pack(fill="x", padx=3, pady=3)

        left = ctk.CTkFrame(header, fg_color="transparent")
        left.pack(side="left", padx=12, pady=10)
        ctk.CTkLabel(left, text="Scan Results", font=ctk.CTkFont(size=18, weight="bold"), text_color=colors["text-primary"]).pack(anchor="w")
        try:
            fname = os.path.basename(self.last_scanned_file) if getattr(self, "last_scanned_file", None) else ""
        except Exception:
            fname = ""
        if fname:
            ctk.CTkLabel(left, text=fname, text_color=colors.get("text-muted", "#9AA4B2")).pack(anchor="w")

        right = ctk.CTkFrame(header, fg_color="transparent")
        right.pack(side="right", padx=8, pady=8)

        count_chip = ctk.CTkFrame(right, fg_color=colors.get("surface-2", colors["surface-1"]), corner_radius=100, border_width=1, border_color=colors["border"]) 
        count_chip.pack(side="right", padx=6)
        ctk.CTkLabel(count_chip, text=f"{len(findings)} findings", text_color=colors["text-muted"]).pack(padx=10, pady=4)

        try:
            elapsed_s = max(0.0, time.time() - (self.scan_started_at or time.time()))
        except Exception:
            elapsed_s = 0.0
        dur_chip = ctk.CTkFrame(right, fg_color=colors.get("surface-2", colors["surface-1"]), corner_radius=100, border_width=1, border_color=colors["border"]) 
        dur_chip.pack(side="right", padx=6)
        ctk.CTkLabel(dur_chip, text=f"{elapsed_s:.1f}s", text_color=colors["text-muted"]).pack(padx=10, pady=4)

        try:
            score_val = float(score) if isinstance(score, (int, float, str)) and str(score).replace('.', '', 1).isdigit() else None
        except Exception:
            score_val = None
        if score_val is not None:
            if score_val >= 80:
                s_bg = colors.get("success", "#36C28A")
            elif score_val >= 50:
                s_bg = colors.get("warning", "#E0B446")
            else:
                s_bg = colors.get("danger", "#E55858")
            score_chip = ctk.CTkFrame(right, fg_color=s_bg, corner_radius=100)
            score_chip.pack(side="right", padx=6)
            ctk.CTkLabel(score_chip, text=f"Score {int(score_val)}", text_color=colors.get("bg", "#0B0F17")).pack(padx=10, pady=4)

        ai_ok = False
        try:
            ai_ok = bool(self.scanner.ai_ready.is_set())
        except Exception:
            ai_ok = False
        ai_color = colors.get("status-ok", "#2DBE78") if ai_ok else colors.get("status-warn", "#E0B446")
        ai_chip = ctk.CTkFrame(right, fg_color=colors["panel-bg"], corner_radius=100, border_width=1, border_color=ai_color)
        ai_chip.pack(side="right", padx=6)
        ctk.CTkLabel(ai_chip, text=("AI Ready" if ai_ok else "AI Initializing"), text_color=ai_color).pack(padx=10, pady=4)

        actions = ctk.CTkFrame(right, fg_color="transparent")
        actions.pack(side="right", padx=6)
        ctk.CTkButton(actions, text="Copy all", width=96, height=28, corner_radius=8,
                      fg_color=colors.get("surface-2", colors["panel-bg"]),
                      hover_color=colors.get("surface-3", colors.get("surface-2", colors["panel-bg"])),
                      text_color=colors["text-primary"], border_width=0,
                      command=self._copy_all_results).pack(side="right", padx=4)
        ctk.CTkButton(actions, text="Collapse all", width=96, height=28, corner_radius=8,
                      fg_color=colors.get("surface-2", colors["panel-bg"]),
                      hover_color=colors.get("surface-3", colors.get("surface-2", colors["panel-bg"])),
                      text_color=colors["text-primary"], border_width=0,
                      command=self._collapse_all_results).pack(side="right", padx=4)
        ctk.CTkButton(actions, text="Expand all", width=96, height=28, corner_radius=8,
                      fg_color=colors.get("surface-2", colors["panel-bg"]),
                      hover_color=colors.get("surface-3", colors.get("surface-2", colors["panel-bg"])),
                      text_color=colors["text-primary"], border_width=0,
                      command=self._expand_all_results).pack(side="right", padx=4)

        if not findings:
            empty = ctk.CTkLabel(self.results_scroll_frame, text="No Threats Detected. This file appears to be safe.", text_color=colors["success"]) 
            empty.pack(padx=10, pady=10, anchor="w")
            return

        for i, finding in enumerate(findings, start=1):
            card = self.build_finding_card(self.results_scroll_frame, i, finding)
            if isinstance(card, dict):
                self._result_cards.append(card)

        self._refresh_results_layout()

    def show_results_message(self, text):
        for child in getattr(self, 'results_scroll_frame', []).winfo_children() if hasattr(self, 'results_scroll_frame') else []:
            child.destroy()
        self._result_cards = []
        self.results_message_label.configure(text=text)

    def build_finding_card(self, parent, idx, finding):
        wrapper = ctk.CTkFrame(parent, fg_color="transparent")
        wrapper.pack(fill="x", padx=10, pady=6)

        stripe = ctk.CTkFrame(wrapper, width=4, fg_color=colors["accent-primary"], corner_radius=3)
        stripe.pack(side="left", fill="y")

        shadow = ctk.CTkFrame(wrapper, fg_color=colors.get("surface-2", colors["surface-1"]), corner_radius=16)
        shadow.pack(side="left", fill="x", expand=True)
        frame = ctk.CTkFrame(shadow, fg_color=colors["panel-bg"], corner_radius=14, border_width=1, border_color=colors["border"]) 
        frame.pack(fill="x", expand=True, padx=3, pady=3)

        title = finding.get('description', 'Issue')
        severity = finding.get('severity', 'N/A')
        header_row = ctk.CTkFrame(frame, fg_color="transparent")
        header_row.pack(fill="x", padx=12, pady=(10, 6))
        ctk.CTkLabel(header_row, text=f"[{idx}] {title}", text_color=colors["accent-primary"], font=ctk.CTkFont(size=16, weight="bold")).pack(side="left")
        code_snippet = finding.get('code_snippet', '')
        if code_snippet:
            copy_btn = ctk.CTkButton(header_row, text="Copy code", width=100, height=28, corner_radius=8,
                                     fg_color=colors.get("surface-2", colors["panel-bg"]),
                                     hover_color=colors.get("surface-3", colors.get("surface-2", colors["panel-bg"])),
                                     text_color=colors["text-primary"],
                                     border_width=0,
                                     command=lambda s=code_snippet: self._copy_to_clipboard(s))
            copy_btn.pack(side="right", padx=(8, 0))
        sev_bg, sev_fg = self.severity_tag_color(severity)
        sev = ctk.CTkLabel(header_row, text=severity.upper(), fg_color=sev_bg, text_color=sev_fg, corner_radius=100, padx=10, pady=4)
        sev.pack(side="right")


        meta = ctk.CTkLabel(frame, text=f"Source: {finding.get('source','Unknown')} | Line: {finding.get('line','N/A')}", text_color=colors["text-muted"]) 
        meta.pack(padx=12, pady=(0, 6), anchor="w")

        if code_snippet:
            mono = ctk.CTkFont(family="Consolas", size=13)
            line_count = code_snippet.count('\n') + 1
            line_px = 20  
            collapsed_lines = min(6, line_count)  
            expanded_lines = min(20, max(line_count, 10))  
            collapsed_h = collapsed_lines * line_px + 16
            expanded_h = expanded_lines * line_px + 16
            code_box = ctk.CTkTextbox(frame, height=collapsed_h, fg_color=colors["surface-1"], text_color=colors["text-primary"], font=mono)
            code_box.pack(fill="x", padx=12, pady=(0, 4))
            code_box.insert("1.0", code_snippet)
            code_box.configure(state="disabled")
            toggle_row = ctk.CTkFrame(frame, fg_color="transparent")
            toggle_row.pack(fill="x", padx=12, pady=(4, 6))
            expanded = {"v": False}
            explanation_text = finding.get('explanation') or "No AI explanation available."
            explanation_frame = None
            if explanation_text:
                explanation_frame = ctk.CTkFrame(frame, fg_color="transparent")
                sep = ctk.CTkFrame(explanation_frame, height=1, fg_color=colors.get("border", "#2A2A2A"))
                sep.pack(fill="x", padx=12, pady=(2, 8))
                header = ctk.CTkLabel(
                    explanation_frame,
                    text="Explanation",
                    text_color=colors.get("text-muted", colors.get("text-secondary", "#AAA")),
                    font=ctk.CTkFont(size=12, weight="bold")
                )
                header.pack(padx=12, pady=(0, 4), anchor="w")
                wrap_len = self._calc_wraplength(frame, fallback=880)
                explanation_label = ctk.CTkLabel(
                    explanation_frame,
                    text=explanation_text,
                    text_color=colors.get("text-secondary", colors.get("text-primary", "#DDD")),
                    wraplength=wrap_len, 
                    justify="left"
                )
                explanation_label.pack(padx=12, pady=(0, 10), anchor="w")
            def _toggle():
                expanded["v"] = not expanded["v"]
                code_box.configure(height=expanded_h if expanded["v"] else collapsed_h)
                toggle_btn.configure(text="Show less" if expanded["v"] else "Show more")
                if explanation_frame is not None:
                    if expanded["v"]:
                        if str(explanation_frame.winfo_manager()) == "":
                            try:
                                explanation_frame.pack(fill="x", padx=0, pady=(2, 8), after=toggle_row)
                            except Exception:
                                explanation_frame.pack(fill="x", padx=0, pady=(2, 8))
                    else:
                        explanation_frame.pack_forget()
                self._refresh_results_layout()
            toggle_btn = ctk.CTkButton(toggle_row, text="Show more", width=110, height=28, corner_radius=100,
                                        fg_color=colors.get("surface-2", colors["panel-bg"]),
                                        hover_color=colors.get("surface-3", colors.get("surface-2", colors["panel-bg"])),
                                        text_color=colors["text-primary"], border_width=0,
                                        command=_toggle)
            toggle_btn.pack(side="right")

            def _expand():
                if not expanded["v"]:
                    _toggle()
            def _collapse():
                if expanded["v"]:
                    _toggle()

        if not code_snippet:
            explanation = finding.get('explanation') or "No AI explanation available."
            if explanation:
                wrap_len2 = self._calc_wraplength(frame, fallback=880)
                ctk.CTkLabel(frame, text=explanation, text_color=colors.get("text-secondary", colors.get("text-primary", "#DDD")), wraplength=wrap_len2, justify="left").pack(padx=12, pady=(6, 12), anchor="w")

        try:
            return {
                "expand": (locals().get("_expand") if code_snippet else (lambda: None)),
                "collapse": (locals().get("_collapse") if code_snippet else (lambda: None)),
                "text": f"[{idx}] {title} | {finding.get('severity','').upper()}\n" + (code_snippet or "") + "\n" + (finding.get('explanation') or ""),
            }
        except Exception:
            return {}

    def severity_tag_color(self, severity):
        sev = (severity or '').lower()
        if 'high' in sev or 'critical' in sev:
            return (colors["danger"], colors["bg"]) 
        if 'medium' in sev:
            return (colors["warning"], colors["bg"]) 
        if 'low' in sev or 'info' in sev:
            return (colors["success"], colors["bg"]) 
        return (colors["tag-bg"], colors["tag-text"]) 

    def _add_section_divider(self, parent):
                                                              
        return ctk.CTkFrame(parent, height=1, fg_color=colors.get("border-soft", colors.get("border", "#1a2430")))

    def _calc_wraplength(self, widget, fallback=880, margin=56):
           
        try:
                                                                                      
            w = widget.winfo_width()
            if w <= 1 and hasattr(widget, 'master') and widget.master is not None:
                w = widget.master.winfo_width()
            if w <= 1 and hasattr(self, 'results_scroll_frame'):
                inner = getattr(self.results_scroll_frame, "_scrollable_frame", None)
                if inner is not None:
                    w = inner.winfo_width()
            if w and w > (margin + 200):
                return max(300, int(w - margin))
        except Exception:
            pass
        return fallback

    def _expand_all_results(self):
        try:
            for card in getattr(self, "_result_cards", []):
                fn = card.get("expand")
                if callable(fn):
                    fn()
        except Exception:
            pass

    def _collapse_all_results(self):
        try:
            for card in getattr(self, "_result_cards", []):
                fn = card.get("collapse")
                if callable(fn):
                    fn()
        except Exception:
            pass

    def _copy_all_results(self):
        try:
            parts = []
            for card in getattr(self, "_result_cards", []):
                t = card.get("text")
                if t:
                    parts.append(t)
            if parts:
                self._copy_to_clipboard("\n\n".join(parts))
        except Exception:
            pass

    def _refresh_results_layout(self):
           
        try:
            self.results_scroll_frame.update_idletasks()

            canvas = (
                getattr(self.results_scroll_frame, "_parent_canvas", None)
                or getattr(self.results_scroll_frame, "_scrollable_canvas", None)
                or getattr(self.results_scroll_frame, "_canvas", None)
            )
            if canvas is not None:
                canvas.configure(scrollregion=canvas.bbox("all"))
        except Exception:
            pass

    def _enable_results_scrollwheel(self, scrollable: "ctk.CTkScrollableFrame"):
           
        try:
            canvas = (
                getattr(scrollable, "_parent_canvas", None)
                or getattr(scrollable, "_scrollable_canvas", None)
                or getattr(scrollable, "_canvas", None)
            )
            inner = getattr(scrollable, "_scrollable_frame", None)
            if canvas is None:
                return

            def _on_mousewheel(event):
                if hasattr(event, "delta") and event.delta != 0:
                    delta = int(event.delta)
                    step = -int(delta/120) if delta % 120 == 0 else (-1 if delta > 0 else 1)
                else:
                    if getattr(event, "num", 0) == 4:
                        step = -1
                    elif getattr(event, "num", 0) == 5:
                        step = 1
                    else:
                        step = 0
                if step:
                    try:
                        canvas.yview_scroll(step, "units")
                        return "break"
                    finally:
                        pass

            for widget in filter(None, [canvas, inner, scrollable]):
                widget.bind("<MouseWheel>", _on_mousewheel)
                widget.bind("<Button-4>", _on_mousewheel)  
                widget.bind("<Button-5>", _on_mousewheel)  
            canvas.bind("<Enter>", lambda e: canvas.focus_set())
        except Exception:
            pass

    def _install_global_wheel_binding(self, scrollable: "ctk.CTkScrollableFrame"):
           
        try:
            canvas = (
                getattr(scrollable, "_parent_canvas", None)
                or getattr(scrollable, "_scrollable_canvas", None)
                or getattr(scrollable, "_canvas", None)
            )
            if canvas is None:
                return

            def _route_wheel(event):
                try:
                    x_root, y_root = event.x_root, event.y_root
                    under = self.winfo_containing(x_root, y_root)
                    cur = under
                    ok = False
                    while cur is not None:
                        if cur is scrollable or cur is getattr(scrollable, "_scrollable_frame", None) or cur is canvas:
                            ok = True
                            break
                        cur = cur.master if hasattr(cur, "master") else None
                    if not ok:
                        return
                    step = 0
                    if hasattr(event, "delta") and event.delta != 0:
                        delta = int(event.delta)
                        step = -int(delta/120) if delta % 120 == 0 else (-1 if delta > 0 else 1)
                    else:
                        if getattr(event, "num", 0) == 4:
                            step = -1
                        elif getattr(event, "num", 0) == 5:
                            step = 1
                    if step:
                        canvas.yview_scroll(step, "units")
                        return "break"
                except Exception:
                    pass

            for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
                self.bind_all(seq, _route_wheel, add=True)
        except Exception:
            pass

    def _on_results_configure(self, event=None):
                                                                                
        if getattr(self, "_results_relayout_scheduled", False):
            return
        self._results_relayout_scheduled = True
        self.after_idle(self._do_results_relayout)

    def _do_results_relayout(self):
        try:
            w = self.views["results"].winfo_width()
            h = self.views["results"].winfo_height()
            if (w, h) != getattr(self, "_last_results_size", (None, None)) and w > 1 and h > 1:
                self._last_results_size = (w, h)
                self.results_shadow.configure(width=w, height=h)
                self.results_scroll_frame.configure(width=w)
                canvas = (
                    getattr(self.results_scroll_frame, "_parent_canvas", None)
                    or getattr(self.results_scroll_frame, "_scrollable_canvas", None)
                    or getattr(self.results_scroll_frame, "_canvas", None)
                )
                inner = getattr(self.results_scroll_frame, "_scrollable_frame", None)
                if canvas is not None and inner is not None:
                    try:
                        inner.configure(width=max(0, canvas.winfo_width()))
                    except Exception:
                        pass
            self._refresh_results_layout()
        except Exception:
            pass
        finally:
            self._results_relayout_scheduled = False

    def create_threats_chart(self, parent, history):
        fig, ax = plt.subplots(figsize=(9, 3.6), dpi=120)
        panel_bg = colors.get("panel-bg", "#111823")
        fig.patch.set_facecolor(panel_bg)
        ax.set_facecolor(panel_bg)

        dates = [datetime.strptime(item['date'], '%Y-%m-%d').strftime('%m-%d') for item in history[-7:]]
        threats = [item['threats'] for item in history[-7:]]

                                                    
        line_color = colors.get("plot-line", colors.get("accent-primary", "#5AE1FF"))
        point_color = colors.get("plot-point", line_color)
        fill_color = colors.get("plot-fill", line_color)
        line, = ax.plot(
            dates,
            threats,
            color=line_color,
            marker='o', linestyle='-', markersize=5,
            markerfacecolor=point_color,
            markeredgecolor=panel_bg, markeredgewidth=1,
            solid_capstyle='round', solid_joinstyle='round', linewidth=2.2
        )

        try:
            from matplotlib.patheffects import withStroke
                                          
            line.set_path_effects([withStroke(linewidth=3.6, foreground=line_color, alpha=0.12)])
        except Exception:
            pass

        grid_color = colors.get("border", "#2A3242")
        ax.grid(True, which='major', axis='both', color=grid_color, linestyle='-', linewidth=0.6, alpha=0.14)
        ax.set_axisbelow(True)

        ax.tick_params(axis='x', colors=colors["text-muted"], rotation=0, labelsize=11)
        ax.tick_params(axis='y', colors=colors["text-muted"], labelsize=11)

        for spine in ax.spines.values():
            spine.set_visible(False)

        ax.set_xlabel("")
        ax.set_ylabel("")
        ax.set_ylim(bottom=0)
        fig.tight_layout(pad=0.6)

        annot = ax.annotate("", xy=(0,0), xytext=(12,12), textcoords="offset points",
                            bbox=dict(boxstyle="round", fc=colors.get("surface-1", colors["panel-bg"]), ec=colors.get("border", "#2A3242"), lw=1),
                            color=colors.get("text-primary", "#E6E9EF"))
        annot.set_visible(False)

        def _update_annot(ind):
            x, y = line.get_data()
            idx = ind["ind"][0]
            annot.xy = (x[idx], y[idx])
            text = f"{x[idx]}\n{y[idx]} threats"
            annot.set_text(text)

        def _hover(event):
            vis = annot.get_visible()
            if event.inaxes == ax:
                cont, ind = line.contains(event)
                if cont:
                    _update_annot(ind)
                    annot.set_visible(True)
                    fig.canvas.draw_idle()
                elif vis:
                    annot.set_visible(False)
                    fig.canvas.draw_idle()

        fig.canvas.mpl_connect("motion_notify_event", _hover)

        canvas = FigureCanvasTkAgg(fig, master=parent)
        try:
            tkc = canvas.get_tk_widget()
            tkc.configure(bg=colors.get("panel-bg", "#1D2230"), highlightthickness=0, bd=0, highlightbackground=colors.get("panel-bg", "#1D2230"))
            wpx, hpx = canvas.get_width_height()
            tkc.configure(width=wpx, height=hpx)
        except Exception:
            pass


        return canvas

    def refresh_dashboard(self):
        for child in getattr(self, 'threats_content_frame', []).winfo_children() if hasattr(self, 'threats_content_frame') else []:
            child.destroy()

        history = load_scan_history()
        # Aggregate entries by date to plot daily totals (maintains previous behavior)
        try:
            daily = {}
            for entry in history:
                d = entry.get('date')
                t = int(entry.get('threats', 0))
                if d:
                    daily[d] = daily.get(d, 0) + t
            history = [{"date": d, "threats": daily[d]} for d in sorted(daily.keys())]
        except Exception:
            pass
        if not history:
            ctk.CTkLabel(self.threats_content_frame, text="No data to display.", text_color=colors["text-muted"]).pack(expand=True)
        else:
            canvas = self.create_threats_chart(self.threats_content_frame, history)
            self._threats_canvas = canvas
            try:
                self._threats_fig = canvas.figure
            except Exception:
                self._threats_fig = None
            canvas.draw()
            try:
                tkc = canvas.get_tk_widget()
                wpx, hpx = canvas.get_width_height()
                tkc.configure(width=wpx, height=hpx)
                tkc.pack(side="top", anchor="nw")
            except Exception:
                canvas.get_tk_widget().pack(side="top", anchor="nw")

        last_score = getattr(self, 'last_security_score', None)
        if last_score is None:
            self.score_value_label.configure(text="—", text_color=colors["text-muted"]) 
            try:
                self.score_progress.set(0)
                self.score_progress.configure(progress_color=colors.get("surface-3", colors["accent-primary"]))
            except Exception:
                pass
        else:
            try:
                s = max(0, min(100, int(last_score)))
            except Exception:
                s = 0
            self.score_value_label.configure(text=f"{s}", text_color=colors["text-primary"]) 
            try:
                self.score_progress.set(s/100.0)
                if s >= 80:
                    bar_color = colors.get("success", "#2ECE7E")
                elif s >= 50:
                    bar_color = colors.get("warning", "#E0B446")
                else:
                    bar_color = colors.get("danger", "#E55858")
                self.score_progress.configure(progress_color=bar_color)
            except Exception:
                pass

        for child in getattr(self, 'risk_list_frame', []).winfo_children() if hasattr(self, 'risk_list_frame') else []:
            child.destroy()
        cats = getattr(self, 'last_risk_categories', []) or []
        if not cats:
            ctk.CTkLabel(self.risk_list_frame, text="No data to display.", text_color=colors["text-muted"]).pack(padx=12, pady=(4,12), anchor="w")
        else:
            # top separator to improve clarity
            ctk.CTkFrame(self.risk_list_frame, height=1, fg_color=colors.get("border", "#2A3242")).pack(fill="x", padx=8, pady=(0, 4))
            for idx, item in enumerate(cats):
                
                if idx > 0:
                    ctk.CTkFrame(self.risk_list_frame, height=1, fg_color=colors.get("border", "#2A3242")).pack(fill="x", padx=8, pady=(4, 4))
                row = ctk.CTkFrame(self.risk_list_frame, fg_color="transparent")
                row.pack(fill="x", padx=8, pady=(2, 0))
                row.grid_columnconfigure(0, weight=1)
                name = str(item.get("category", "Unknown"))
                count = int(item.get("count", 0))
                sev = str(item.get("max_severity", "Medium"))
                ctk.CTkLabel(row, text=name, text_color=colors["text-primary"]).grid(row=0, column=0, sticky="w", padx=4, pady=6)
                sev_bg, sev_fg = self.severity_tag_color(sev)
                s = ctk.CTkLabel(row, text=sev.upper(), fg_color=sev_bg, text_color=sev_fg, corner_radius=100, padx=8, pady=4)
                s.grid(row=0, column=1, sticky="e", padx=6)
                chip = ctk.CTkFrame(row, fg_color=colors.get("surface-2", colors["panel-bg"]), corner_radius=100, border_width=1, border_color=colors["border"]) 
                ctk.CTkLabel(chip, text=str(count), text_color=colors["text-muted"]).pack(padx=8, pady=2)
                chip.grid(row=0, column=2, sticky="e", padx=6)

    def _show_skeleton_loaders(self):
        try:
            self._hide_skeleton_loaders()
            self.skeleton_frames = []
            for _ in range(3):
                wrap = ctk.CTkFrame(self.results_scroll_frame, fg_color="transparent")
                wrap.pack(fill="x", padx=10, pady=6)
                shadow = ctk.CTkFrame(wrap, fg_color=colors.get("surface-2", colors.get("surface-1", colors["panel-bg"])), corner_radius=16)
                shadow.pack(fill="x", expand=True)
                card = ctk.CTkFrame(shadow, fg_color=colors.get("panel-bg", "#1D2230"), corner_radius=14, border_width=1, border_color=colors.get("border", "#2A3242"))
                card.pack(fill="x", expand=True, padx=3, pady=3)
                for h in (14, 14, 14, 14):
                    bar = ctk.CTkFrame(card, fg_color=colors.get("surface-2", colors.get("surface-1", "#232A3A")), height=h, corner_radius=8)
                    bar.pack(fill="x", padx=12, pady=8)
                self.skeleton_frames.append((card, 0))
            self._animate_skeleton()
        except Exception:
            pass

    def _animate_skeleton(self):
        try:
            next_colors = [colors.get("surface-3", colors.get("surface-2", "#2A3242")), colors.get("surface-2", "#242A3A")]
            updated = []
            for (card, phase) in getattr(self, 'skeleton_frames', []):
                for child in card.winfo_children():
                    if isinstance(child, ctk.CTkFrame):
                        child.configure(fg_color=next_colors[phase % 2])
                updated.append((card, (phase + 1) % 2))
            self.skeleton_frames = updated
        except Exception:
            pass
        if getattr(self, 'is_scanning', False):
            self.after(220, self._animate_skeleton)

    def _hide_skeleton_loaders(self):
        try:
            for item in getattr(self, 'skeleton_frames', []):
                card = item[0]
                parent = card.master.master  
                parent.destroy()
            self.skeleton_frames = []
        except Exception:
            pass

    


if __name__ == "__main__":

    app = App()
    app.mainloop()
