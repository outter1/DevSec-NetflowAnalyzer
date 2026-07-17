# SPDX-License-Identifier: MIT
# Copyright (c) 2026 DEVSEC
# Copyright (c) 2026 Gabriel Silva Bastos
# Copyright (c) 2026 Matheus Dominato
# Copyright (c) 2026 Isabelle Guimarães de Andrade
# Copyright (c) 2026 Nicolas Urtiaga
# Copyright (c) 2026 Pedro Lages da Silva

"""Exportação das evidências coletadas."""

import os
from tkinter import filedialog
import customtkinter as ctk

from ui.components import PageHeader, Panel
from ui.theme import COLORS, FONT, dark_button, primary_button


class ReportsFrame(ctk.CTkFrame):
    def __init__(self, master, app):
        super().__init__(master, fg_color="transparent")
        self.app = app
        self._criar_layout()

    def _criar_layout(self):
        PageHeader(
            self,
            "Relatórios",
            "Exporte os dados reais para investigação, documentação e análise externa.",
        )

        grid = ctk.CTkFrame(self, fg_color="transparent")
        grid.pack(fill="x", pady=(0, 14))
        for col in range(3):
            grid.grid_columnconfigure(col, weight=1, uniform="report")

        self._report_card(
            grid, 0, "Fluxos CSV", "Exporta todo o histórico de fluxos persistido no SQLite.",
            "Exportar fluxos", self._export_flows,
        )
        self._report_card(
            grid, 1, "Alertas CSV", "Exporta classificações, severidade, motivo e contagem de eventos.",
            "Exportar alertas", self._export_alerts,
        )
        self._report_card(
            grid, 2, "Relatório PDF", "Gera uma visão geral pronta para anexar a uma análise.",
            "Gerar PDF", self._export_pdf,
        )

        panel = Panel(self, "Console de exportação")
        panel.pack(fill="both", expand=True)
        self.status = ctk.CTkTextbox(panel, height=260)
        self.status.pack(fill="both", expand=True, padx=12, pady=12)
        self.status.insert(
            "end",
            "Os relatórios usam somente os dados registrados pelo programa.\n"
            "Para um PDF específico de um IP, selecione o IP na tela Alertas.\n",
        )

    def _report_card(self, master, column, title, description, button_text, command):
        card = Panel(master)
        card.grid(row=0, column=column, sticky="nsew", padx=6)
        ctk.CTkLabel(card, text=title, font=(FONT, 17, "bold")).pack(anchor="w", padx=16, pady=(18, 7))
        ctk.CTkLabel(
            card,
            text=description,
            width=225,
            text_color=COLORS["muted"],
            justify="left",
            anchor="w",
            wraplength=225,
        ).pack(fill="x", anchor="w", padx=16, pady=(0, 18))
        ctk.CTkButton(card, text=button_text, command=command, **primary_button()).pack(
            anchor="w", padx=16, pady=(0, 18)
        )

    def _log(self, message):
        self.status.insert("end", message + "\n")
        self.status.see("end")

    def _export_flows(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv", initialfile="fluxos.csv", filetypes=[("CSV", "*.csv")])
        if not path: return
        try:
            self.app.exportar_fluxos_csv(path)
            self._log(f"[OK] Fluxos exportados para {os.path.basename(path)}.")
        except Exception as error:
            self._log(f"[ERRO] {error}")

    def _export_alerts(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv", initialfile="alertas.csv", filetypes=[("CSV", "*.csv")])
        if not path: return
        try:
            self.app.exportar_alertas_csv(path)
            self._log(f"[OK] Alertas exportados para {os.path.basename(path)}.")
        except Exception as error:
            self._log(f"[ERRO] {error}")

    def _export_pdf(self):
        path = filedialog.asksaveasfilename(defaultextension=".pdf", initialfile="relatorio_geral.pdf", filetypes=[("PDF", "*.pdf")])
        if not path: return
        try:
            self.app.exportar_relatorio_geral_pdf(path)
            self._log(f"[OK] Relatório gerado em {os.path.basename(path)}.")
        except Exception as error:
            self._log(f"[ERRO] {error}")
