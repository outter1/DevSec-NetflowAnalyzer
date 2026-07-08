"""
Tela de Relatórios: exporta as evidências coletadas (fluxos e alertas)
em CSV ou PDF, para uso em investigação forense ou documentação de
incidentes.
"""

import os
from tkinter import filedialog

import customtkinter as ctk


class ReportsFrame(ctk.CTkFrame):
    def __init__(self, master, app):
        super().__init__(master, fg_color="transparent")
        self.app = app
        self._criar_layout()

    def _criar_layout(self):
        ctk.CTkLabel(
            self,
            text="Exporte os dados capturados para análise externa ou como evidência forense.",
            font=("Arial", 15),
        ).pack(anchor="w", padx=20, pady=(20, 10))

        frame_botoes = ctk.CTkFrame(self, fg_color="transparent")
        frame_botoes.pack(fill="x", padx=20, pady=10)

        botoes = [
            ("Exportar Fluxos (CSV)", self._exportar_fluxos_csv),
            ("Exportar Alertas (CSV)", self._exportar_alertas_csv),
            ("Exportar Relatório Geral (PDF)", self._exportar_geral_pdf),
        ]

        for texto, comando in botoes:
            ctk.CTkButton(frame_botoes, text=texto, height=40, command=comando).pack(
                anchor="w", pady=8
            )

        self.caixa_status = ctk.CTkTextbox(self, height=140)
        self.caixa_status.pack(fill="both", expand=True, padx=20, pady=20)
        self.caixa_status.insert(
            "end",
            "Dica: para exportar o relatório de investigação de um IP específico "
            "(com linha do tempo de eventos), use o botão correspondente na tela de Alertas.\n",
        )

    def _log(self, mensagem):
        self.caixa_status.insert("end", mensagem + "\n")
        self.caixa_status.see("end")

    def _exportar_fluxos_csv(self):
        caminho = filedialog.asksaveasfilename(
            defaultextension=".csv",
            initialfile="fluxos.csv",
            filetypes=[("Arquivo CSV", "*.csv")],
        )
        if not caminho:
            return
        try:
            self.app.exportar_fluxos_csv(caminho)
            self._log(f"Fluxos exportados para {os.path.basename(caminho)}.")
        except Exception as erro:
            self._log(f"[ERRO] {erro}")

    def _exportar_alertas_csv(self):
        caminho = filedialog.asksaveasfilename(
            defaultextension=".csv",
            initialfile="alertas.csv",
            filetypes=[("Arquivo CSV", "*.csv")],
        )
        if not caminho:
            return
        try:
            self.app.exportar_alertas_csv(caminho)
            self._log(f"Alertas exportados para {os.path.basename(caminho)}.")
        except Exception as erro:
            self._log(f"[ERRO] {erro}")

    def _exportar_geral_pdf(self):
        caminho = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            initialfile="relatorio_geral.pdf",
            filetypes=[("Arquivo PDF", "*.pdf")],
        )
        if not caminho:
            return
        try:
            self.app.exportar_relatorio_geral_pdf(caminho)
            self._log(f"Relatório geral exportado para {os.path.basename(caminho)}.")
        except Exception as erro:
            self._log(f"[ERRO] {erro}")
