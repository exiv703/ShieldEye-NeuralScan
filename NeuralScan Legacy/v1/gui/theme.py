import customtkinter as ctk

def blend_colors(fg_hex, bg_hex, alpha):
                                                                                             
    fg_rgb = tuple(int(fg_hex.lstrip('#')[i:i+2], 16) for i in (0, 2, 4))
    bg_rgb = tuple(int(bg_hex.lstrip('#')[i:i+2], 16) for i in (0, 2, 4))
    blended_rgb = [int(fg_rgb[i] * alpha + bg_rgb[i] * (1 - alpha)) for i in range(3)]
    return f"#{blended_rgb[0]:02x}{blended_rgb[1]:02x}{blended_rgb[2]:02x}"

_bg = "#0B0F14"
_sidebar_bg = "#0E141B"
_panel_bg = "#111823"

_accent_primary = "#5AE1FF"
_accent_hover = "#8B7CFF"
_accent_secondary = "#FF8B6B"

_active_glow = "#1F2B3A"
_border_1 = "#1C2633"
_border_2 = "#2A3A4A"

_alpha_for_accent = 0.16
_alpha_for_inactive_hover = 0.08

colors = {
    "bg": _bg,
    "sidebar-bg": _sidebar_bg,
    "panel-bg": _panel_bg,
    "nav-bg": _bg,

    "surface-1": _panel_bg,
    "surface-2": _active_glow,
    "surface-3": "#1a2230",

    "border": _border_1,
    "border-2": _border_2,

    "text-primary": "#EAF2FF",
    "text-secondary": "#D6E2F3",
    "text-muted": "#8FA0B5",
    "text-inactive": "#6E7F93",

    "accent-primary": _accent_primary,
    "accent-primary-hover": _accent_hover,
    "accent-primary-transparent": blend_colors(_accent_primary, _sidebar_bg, _alpha_for_accent),
    "accent-primary-hover-inactive": blend_colors(_accent_primary, _sidebar_bg, _alpha_for_inactive_hover),
    "accent-secondary": _accent_secondary,

    "danger": "#FF5C78",
    "warning": "#FFCB6B",
    "success": "#72F1B8",
    "info": _accent_primary,

                                                 
    "status-ok": "#2DBE78",
    "status-warn": "#E0B446",

    "chart-gradient-start": _accent_primary,
    "chart-gradient-end": _accent_secondary,
    "chart-1": _accent_primary,
    "chart-2": _accent_secondary,
    "chart-3": "#FFCB6B",
    "chart-4": "#72F1B8",
    "chart-5": _accent_hover,

    "tag-bg": "#1C2633",
    "tag-text": "#8FA0B5",
    "tag-active-bg": _active_glow,
    "tag-active-text": _accent_primary,
    
                                                  
    "sidebar-pill": blend_colors(_accent_primary, _sidebar_bg, 0.22),
    "sidebar-pill-hover": blend_colors(_accent_primary, _sidebar_bg, 0.32),

                 
    "plot-line": _accent_primary,
    "plot-point": _accent_primary,
    "plot-fill": blend_colors(_accent_primary, _panel_bg, 0.12),

                                  
    "bg-gradient-start": "#0B0F14",
    "bg-gradient-end": "#151B26",

                                                    
    "bg-glow-tr": "#3b2ca8",                           
    "bg-glow-bl": "#0d5a82",                           

                                  
    "sidebar-gradient-start": "#0A0E13",
    "sidebar-gradient-end": "#0F1620",
    "sidebar-divider": "#1b2431",

                                         
    "border-soft": "#1a2430",
    "panel-inner": "#0e141c",
    "sidebar-glow": "#2c3f72",

                                                
    "icon-default": "#8FA0B5",          
    "icon-hover": "#D6E2F3",                              
    "icon-active": _accent_primary,
}

def apply_theme():
                                                                     
    ctk.set_appearance_mode("Dark")
    try:
                                            
        ctk.set_widget_scaling(1.0)
        ctk.set_window_scaling(1.0)
    except Exception:
        pass

