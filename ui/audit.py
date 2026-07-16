"""Histórico de ações realizadas pelo analista no desktop e na web."""

import customtkinter as ctk

from ui.components import PageHeader, Panel, clear_table, create_table
from ui.theme import dark_button


class AuditFrame(ctk.CTkFrame):
    def __init__(self, master, app):
        super().__init__(master, fg_color="transparent")
        self.app = app
        self._signature = None
        self._criar_layout()
        self.recarregar(force=True)

    def _criar_layout(self):
        PageHeader(self, "Auditoria", "Registro das ações manuais executadas nas interfaces do DevSec.")
        panel = Panel(self, "Ações do analista")
        panel.pack(fill="both", expand=True)
        top = ctk.CTkFrame(panel, fg_color="transparent")
        top.pack(fill="x", padx=12, pady=(12, 4))
        self.limit = ctk.CTkOptionMenu(top, values=["100", "250", "500", "1000"], width=100)
        self.limit.set("250")
        self.limit.pack(side="left")
        ctk.CTkButton(top, text="Atualizar", width=95, command=lambda: self.recarregar(True), **dark_button()).pack(side="left", padx=8)

        columns = ("time", "analyst", "action", "details", "source")
        headings = {
            "time": "DATA/HORA", "analyst": "ANALISTA", "action": "AÇÃO",
            "details": "DETALHES", "source": "ORIGEM",
        }
        widths = {"time": 150, "analyst": 120, "action": 220, "details": 500, "source": 140}
        host, self.table = create_table(panel, columns, headings, widths, height=18)
        host.pack(fill="both", expand=True, padx=12, pady=(4, 12))

    def recarregar(self, force=False):
        records = self.app.db.listar_auditoria(int(self.limit.get()))
        signature = tuple((r["id"], r["timestamp_acao"]) for r in records)
        if not force and signature == self._signature:
            return
        clear_table(self.table)
        for record in records:
            self.table.insert(
                "", "end",
                values=(record["timestamp_acao"], record["usuario_analista"], record["acao_realizada"], record.get("detalhes") or "—", record.get("ip_origem_analista") or "local"),
                tags=("info",),
            )
        self._signature = signature

    def atualizar_automatico(self):
        self.recarregar()
