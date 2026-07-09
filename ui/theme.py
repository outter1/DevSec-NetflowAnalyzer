"""
Tema visual do DevSec inspirado no site do vídeo enviado.

Paleta observada:
- fundo creme/bege claro
- preto/carvão para sidebar e áreas de contraste
- vermelho forte para ações, destaques e alertas
"""

from tkinter import ttk
import customtkinter as ctk

COLORS = {
    "bg": "#EFE7D5",          # creme do site
    "panel": "#F6EEDC",       # cards/áreas internas
    "panel_alt": "#E7DCC8",   # filtros/caixas secundárias
    "sidebar": "#0B0D0B",     # preto quase absoluto
    "terminal": "#10110F",    # preto de terminal
    "terminal_2": "#171915",
    "text": "#171717",
    "muted": "#6B6254",
    "cream_text": "#F6EEDC",
    "red": "#B30E1A",         # vermelho principal
    "red_hover": "#8F0B14",
    "red_light": "#D32633",
    "border": "#CBBFA8",
    "white": "#FFFFFF",
}

_PATCHED = False


def apply_theme(root=None):
    """Aplica defaults visuais no CustomTkinter e no ttk."""
    global _PATCHED

    ctk.set_appearance_mode("light")

    # Mantém um tema base estável; os componentes abaixo recebem overrides.
    try:
        ctk.set_default_color_theme("red")
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

    # ------------------------------------------------------------------ #
    # CTkFrame: por padrão usa painel creme, respeitando fg_color explícito.
    # ------------------------------------------------------------------ #
    original_frame_init = ctk.CTkFrame.__init__

    def themed_frame_init(self, *args, **kwargs):
        kwargs.setdefault("fg_color", COLORS["panel"])
        kwargs.setdefault("border_color", COLORS["border"])
        original_frame_init(self, *args, **kwargs)

    ctk.CTkFrame.__init__ = themed_frame_init

    # ------------------------------------------------------------------ #
    # CTkButton: vermelho principal, parecido com CTA do site.
    # ------------------------------------------------------------------ #
    original_button_init = ctk.CTkButton.__init__

    def themed_button_init(self, *args, **kwargs):
        kwargs.setdefault("fg_color", COLORS["red"])
        kwargs.setdefault("hover_color", COLORS["red_hover"])
        kwargs.setdefault("text_color", COLORS["cream_text"])
        kwargs.setdefault("corner_radius", 4)
        kwargs.setdefault("border_width", 0)
        original_button_init(self, *args, **kwargs)

    ctk.CTkButton.__init__ = themed_button_init

    # ------------------------------------------------------------------ #
    # CTkLabel: texto escuro para fundos claros.
    # ------------------------------------------------------------------ #
    original_label_init = ctk.CTkLabel.__init__

    def themed_label_init(self, *args, **kwargs):
        kwargs.setdefault("text_color", COLORS["text"])
        original_label_init(self, *args, **kwargs)

    ctk.CTkLabel.__init__ = themed_label_init

    # ------------------------------------------------------------------ #
    # CTkEntry / CTkTextbox / CTkOptionMenu: creme + borda suave.
    # ------------------------------------------------------------------ #
    original_entry_init = ctk.CTkEntry.__init__

    def themed_entry_init(self, *args, **kwargs):
        kwargs.setdefault("fg_color", COLORS["white"])
        kwargs.setdefault("border_color", COLORS["border"])
        kwargs.setdefault("text_color", COLORS["text"])
        kwargs.setdefault("placeholder_text_color", COLORS["muted"])
        kwargs.setdefault("corner_radius", 4)
        original_entry_init(self, *args, **kwargs)

    ctk.CTkEntry.__init__ = themed_entry_init

    original_textbox_init = ctk.CTkTextbox.__init__

    def themed_textbox_init(self, *args, **kwargs):
        kwargs.setdefault("fg_color", COLORS["terminal"])
        kwargs.setdefault("border_color", COLORS["border"])
        kwargs.setdefault("text_color", COLORS["cream_text"])
        kwargs.setdefault("corner_radius", 4)
        original_textbox_init(self, *args, **kwargs)

    ctk.CTkTextbox.__init__ = themed_textbox_init

    original_optionmenu_init = ctk.CTkOptionMenu.__init__

    def themed_optionmenu_init(self, *args, **kwargs):
        kwargs.setdefault("fg_color", COLORS["terminal"])
        kwargs.setdefault("button_color", COLORS["red"])
        kwargs.setdefault("button_hover_color", COLORS["red_hover"])
        kwargs.setdefault("text_color", COLORS["cream_text"])
        kwargs.setdefault("dropdown_fg_color", COLORS["panel"])
        kwargs.setdefault("dropdown_text_color", COLORS["text"])
        kwargs.setdefault("dropdown_hover_color", COLORS["panel_alt"])
        kwargs.setdefault("corner_radius", 4)
        original_optionmenu_init(self, *args, **kwargs)

    ctk.CTkOptionMenu.__init__ = themed_optionmenu_init


def configure_ttk(root):
    """Estiliza Treeview/Scrollbar do ttk na paleta do site."""
    style = ttk.Style(root)

    try:
        style.theme_use("clam")
    except Exception:
        pass

    style.configure(
        "Treeview",
        background=COLORS["white"],
        fieldbackground=COLORS["white"],
        foreground=COLORS["text"],
        bordercolor=COLORS["border"],
        lightcolor=COLORS["border"],
        darkcolor=COLORS["border"],
        rowheight=24,
        font=("Arial", 10),
    )
    style.configure(
        "Treeview.Heading",
        background=COLORS["terminal"],
        foreground=COLORS["cream_text"],
        bordercolor=COLORS["red"],
        relief="flat",
        font=("Arial", 10, "bold"),
    )
    style.map(
        "Treeview",
        background=[("selected", COLORS["red"])],
        foreground=[("selected", COLORS["cream_text"])],
    )
    style.map(
        "Treeview.Heading",
        background=[("active", COLORS["red"])],
        foreground=[("active", COLORS["cream_text"])],
    )
    style.configure(
        "Vertical.TScrollbar",
        troughcolor=COLORS["panel_alt"],
        background=COLORS["red"],
        bordercolor=COLORS["border"],
        arrowcolor=COLORS["cream_text"],
    )


def danger_button():
    return {"fg_color": COLORS["red"], "hover_color": COLORS["red_hover"], "text_color": COLORS["cream_text"]}


def dark_button():
    return {"fg_color": COLORS["terminal"], "hover_color": COLORS["red_hover"], "text_color": COLORS["cream_text"]}


def secondary_button():
    return {"fg_color": COLORS["panel_alt"], "hover_color": COLORS["border"], "text_color": COLORS["text"]}
