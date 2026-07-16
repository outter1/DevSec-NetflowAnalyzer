"""Componentes visuais reutilizáveis da interface desktop."""

from __future__ import annotations

from tkinter import ttk
import customtkinter as ctk

from ui.theme import COLORS, FONT


class PageHeader(ctk.CTkFrame):
    def __init__(self, master, title: str, subtitle: str = "", actions=None):
        super().__init__(master, fg_color="transparent")
        self.pack(fill="x", padx=2, pady=(0, 18))
        self.grid_columnconfigure(0, weight=1)

        text_box = ctk.CTkFrame(self, fg_color="transparent")
        text_box.grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(text_box, text=title, font=(FONT, 25, "bold")).pack(anchor="w")
        if subtitle:
            ctk.CTkLabel(
                text_box,
                text=subtitle,
                text_color=COLORS["muted"],
                font=(FONT, 12),
                justify="left",
            ).pack(anchor="w", pady=(4, 0))

        if actions:
            action_box = ctk.CTkFrame(self, fg_color="transparent")
            action_box.grid(row=0, column=1, sticky="e")
            for widget in actions:
                widget.pack(in_=action_box, side="left", padx=(8, 0))


class Panel(ctk.CTkFrame):
    def __init__(self, master, title: str | None = None, subtitle: str | None = None, **kwargs):
        kwargs.setdefault("corner_radius", 14)
        kwargs.setdefault("border_width", 1)
        kwargs.setdefault("border_color", COLORS["border"])
        super().__init__(master, **kwargs)
        self.body = self

        if title:
            head = ctk.CTkFrame(self, fg_color="transparent")
            head.pack(fill="x", padx=18, pady=(15, 10))
            ctk.CTkLabel(head, text=title.upper(), font=(FONT, 11, "bold")).pack(anchor="w")
            if subtitle:
                ctk.CTkLabel(
                    head,
                    text=subtitle,
                    text_color=COLORS["muted"],
                    font=(FONT, 10),
                    justify="left",
                ).pack(anchor="w", pady=(3, 0))
            divider = ctk.CTkFrame(self, height=1, corner_radius=0, fg_color=COLORS["border"])
            divider.pack(fill="x")


class MetricCard(ctk.CTkFrame):
    def __init__(self, master, label: str, value: str = "—", accent=None):
        super().__init__(
            master,
            corner_radius=13,
            border_width=1,
            border_color=COLORS["border"],
            fg_color=COLORS["panel"],
        )
        self.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            self,
            text=label.upper(),
            text_color=COLORS["muted"],
            font=(FONT, 9, "bold"),
        ).grid(row=0, column=0, sticky="w", padx=15, pady=(14, 2))
        self.value_label = ctk.CTkLabel(
            self,
            text=value,
            text_color=accent or COLORS["text"],
            font=(FONT, 23, "bold"),
        )
        self.value_label.grid(row=1, column=0, sticky="w", padx=15, pady=(3, 14))

    def set(self, value, color=None):
        self.value_label.configure(text=str(value))
        if color:
            self.value_label.configure(text_color=color)


def create_table(master, columns, headings, widths=None, height=15, minwidth=60):
    """Cria uma Treeview escura com rolagem horizontal e vertical."""
    container = ctk.CTkFrame(master, fg_color="transparent")
    container.grid_rowconfigure(0, weight=1)
    container.grid_columnconfigure(0, weight=1)

    tree = ttk.Treeview(
        container,
        columns=columns,
        show="headings",
        height=height,
        style="DevSec.Treeview",
        selectmode="browse",
    )
    widths = widths or {}
    for column in columns:
        tree.heading(column, text=headings.get(column, column), anchor="w")
        tree.column(column, width=widths.get(column, 130), minwidth=minwidth, anchor="w", stretch=True)

    scroll_y = ttk.Scrollbar(
        container, orient="vertical", command=tree.yview, style="DevSec.Vertical.TScrollbar"
    )
    scroll_x = ttk.Scrollbar(
        container, orient="horizontal", command=tree.xview, style="DevSec.Horizontal.TScrollbar"
    )
    tree.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)

    tree.grid(row=0, column=0, sticky="nsew")
    scroll_y.grid(row=0, column=1, sticky="ns")
    scroll_x.grid(row=1, column=0, sticky="ew")

    tree.tag_configure("critical", foreground=COLORS["red_light"])
    tree.tag_configure("high", foreground=COLORS["yellow_soft"])
    tree.tag_configure("safe", foreground=COLORS["green_soft"])
    tree.tag_configure("info", foreground=COLORS["blue_soft"])
    tree.tag_configure("muted", foreground=COLORS["muted"])
    return container, tree


def clear_table(tree):
    for item in tree.get_children():
        tree.delete(item)


def selected_values(tree):
    selection = tree.selection()
    if not selection:
        return None
    values = tree.item(selection[0], "values")
    return values or None


def severity_tag(value):
    text = str(value or "").upper()
    if "CRÍT" in text or "BLOQUE" in text:
        return "critical"
    if "ALTO" in text or "BLACKLIST" in text:
        return "high"
    if "BAIXO" in text or "NORMAL" in text or "WHITELIST" in text:
        return "safe"
    return "info"
