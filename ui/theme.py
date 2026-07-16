"""Tema escuro moderno compartilhado pela interface desktop do DevSec.

A paleta segue a interface web: fundo carvão, painéis elevados, bordas discretas
 e vermelho como cor principal. O módulo também centraliza o estilo do ttk,
 usado nas tabelas de alto volume.
"""

from tkinter import ttk
import customtkinter as ctk

COLORS = {
    "bg": "#09090B",
    "panel": "#141416",
    "panel_alt": "#1B1B1F",
    "sidebar": "#0C0C0E",
    "terminal": "#101012",
    "terminal_2": "#17171A",
    "text": "#F5F5F7",
    "muted": "#9CA3AF",
    "cream_text": "#F5F5F7",
    "red": "#DA251C",
    "red_hover": "#FF453A",
    "red_light": "#FF8F88",
    "green": "#22C55E",
    "green_soft": "#86EFAC",
    "yellow": "#F59E0B",
    "yellow_soft": "#FCD34D",
    "blue": "#38BDF8",
    "blue_soft": "#7DD3FC",
    "border": "#2A2A30",
    "border_hover": "#46464F",
    "white": "#FFFFFF",
}

FONT = "Segoe UI"
MONO_FONT = "Cascadia Code"
_PATCHED = False


def apply_theme(root=None):
    """Aplica os padrões de cor do CustomTkinter e do ttk."""
    global _PATCHED

    ctk.set_appearance_mode("dark")
    try:
        ctk.set_default_color_theme("dark-blue")
    except Exception:
        pass

    if root is not None:
        try:
            root.configure(fg_color=COLORS["bg"])
        except Exception:
            pass
        configure_ttk(root)

    if _PATCHED:
        return
    _PATCHED = True

    original_frame_init = ctk.CTkFrame.__init__

    def themed_frame_init(self, *args, **kwargs):
        kwargs.setdefault("fg_color", COLORS["panel"])
        kwargs.setdefault("border_color", COLORS["border"])
        original_frame_init(self, *args, **kwargs)

    ctk.CTkFrame.__init__ = themed_frame_init

    original_button_init = ctk.CTkButton.__init__

    def themed_button_init(self, *args, **kwargs):
        kwargs.setdefault("fg_color", COLORS["red"])
        kwargs.setdefault("hover_color", COLORS["red_hover"])
        kwargs.setdefault("text_color", COLORS["text"])
        kwargs.setdefault("corner_radius", 9)
        kwargs.setdefault("height", 38)
        kwargs.setdefault("font", (FONT, 12, "bold"))
        original_button_init(self, *args, **kwargs)

    ctk.CTkButton.__init__ = themed_button_init

    original_label_init = ctk.CTkLabel.__init__

    def themed_label_init(self, *args, **kwargs):
        kwargs.setdefault("text_color", COLORS["text"])
        kwargs.setdefault("font", (FONT, 12))
        original_label_init(self, *args, **kwargs)

    ctk.CTkLabel.__init__ = themed_label_init

    original_entry_init = ctk.CTkEntry.__init__

    def themed_entry_init(self, *args, **kwargs):
        kwargs.setdefault("fg_color", COLORS["panel_alt"])
        kwargs.setdefault("border_color", COLORS["border"])
        kwargs.setdefault("text_color", COLORS["text"])
        kwargs.setdefault("placeholder_text_color", COLORS["muted"])
        kwargs.setdefault("corner_radius", 9)
        kwargs.setdefault("height", 38)
        original_entry_init(self, *args, **kwargs)

    ctk.CTkEntry.__init__ = themed_entry_init

    original_textbox_init = ctk.CTkTextbox.__init__

    def themed_textbox_init(self, *args, **kwargs):
        kwargs.setdefault("fg_color", COLORS["terminal"])
        kwargs.setdefault("border_color", COLORS["border"])
        kwargs.setdefault("border_width", 1)
        kwargs.setdefault("text_color", COLORS["text"])
        kwargs.setdefault("corner_radius", 10)
        kwargs.setdefault("font", (MONO_FONT, 11))
        original_textbox_init(self, *args, **kwargs)

    ctk.CTkTextbox.__init__ = themed_textbox_init

    original_optionmenu_init = ctk.CTkOptionMenu.__init__

    def themed_optionmenu_init(self, *args, **kwargs):
        kwargs.setdefault("fg_color", COLORS["panel_alt"])
        kwargs.setdefault("button_color", COLORS["red"])
        kwargs.setdefault("button_hover_color", COLORS["red_hover"])
        kwargs.setdefault("text_color", COLORS["text"])
        kwargs.setdefault("dropdown_fg_color", COLORS["panel_alt"])
        kwargs.setdefault("dropdown_text_color", COLORS["text"])
        kwargs.setdefault("dropdown_hover_color", COLORS["border"])
        kwargs.setdefault("corner_radius", 9)
        kwargs.setdefault("height", 38)
        original_optionmenu_init(self, *args, **kwargs)

    ctk.CTkOptionMenu.__init__ = themed_optionmenu_init


def configure_ttk(root):
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except Exception:
        pass

    style.configure(
        "DevSec.Treeview",
        background=COLORS["panel"],
        fieldbackground=COLORS["panel"],
        foreground=COLORS["text"],
        bordercolor=COLORS["border"],
        lightcolor=COLORS["border"],
        darkcolor=COLORS["border"],
        rowheight=31,
        font=(FONT, 10),
        relief="flat",
    )
    style.configure(
        "DevSec.Treeview.Heading",
        background=COLORS["panel_alt"],
        foreground="#D1D5DB",
        bordercolor=COLORS["border"],
        relief="flat",
        font=(FONT, 9, "bold"),
        padding=(8, 8),
    )
    style.map(
        "DevSec.Treeview",
        background=[("selected", "#4A1718")],
        foreground=[("selected", COLORS["white"])],
    )
    style.map(
        "DevSec.Treeview.Heading",
        background=[("active", COLORS["border"])],
        foreground=[("active", COLORS["white"])],
    )
    style.configure(
        "DevSec.Vertical.TScrollbar",
        troughcolor=COLORS["panel"],
        background=COLORS["border"],
        bordercolor=COLORS["panel"],
        arrowcolor=COLORS["muted"],
    )
    style.configure(
        "DevSec.Horizontal.TScrollbar",
        troughcolor=COLORS["panel"],
        background=COLORS["border"],
        bordercolor=COLORS["panel"],
        arrowcolor=COLORS["muted"],
    )


def primary_button():
    return {"fg_color": COLORS["red"], "hover_color": COLORS["red_hover"], "text_color": COLORS["text"]}


def danger_button():
    return {
        "fg_color": "transparent",
        "hover_color": "#351214",
        "text_color": COLORS["red_light"],
        "border_width": 1,
        "border_color": "#6C2528",
    }


def dark_button():
    return {
        "fg_color": COLORS["panel_alt"],
        "hover_color": COLORS["border"],
        "text_color": COLORS["text"],
        "border_width": 1,
        "border_color": COLORS["border"],
    }


def secondary_button():
    return dark_button()


def success_button():
    return {
        "fg_color": "#153922",
        "hover_color": "#1D4C2C",
        "text_color": COLORS["green_soft"],
        "border_width": 1,
        "border_color": "#285D37",
    }
