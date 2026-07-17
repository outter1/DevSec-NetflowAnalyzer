# SPDX-License-Identifier: MIT
# Copyright (c) 2026 KillChain
# Copyright (c) 2026 Gabriel Silva Bastos
# Copyright (c) 2026 Matheus Dominato
# Copyright (c) 2026 Isabelle Guimarães de Andrade
# Copyright (c) 2026 Nicolas Urtiaga
# Copyright (c) 2026 Pedro Lages da Silva

"""Blacklist de IPs e regras efetivas do firewall."""

import customtkinter as ctk

from ui.components import PageHeader, Panel, clear_table, create_table, selected_values
from ui.theme import dark_button, danger_button, primary_button


class IPPolicyFrame(ctk.CTkFrame):
    def __init__(self, master, app):
        super().__init__(master, fg_color="transparent")
        self.app = app
        self._signature = None
        self._criar_layout()
        self.recarregar(force=True)

    def _criar_layout(self):
        PageHeader(
            self, "Blacklist de IPs",
            "Classifique IPs e aplique ou remova regras reais no firewall local.",
        )

        form = Panel(self, "Adicionar IP à blacklist")
        form.pack(fill="x", pady=(0, 14))
        row = ctk.CTkFrame(form, fg_color="transparent")
        row.pack(fill="x", padx=14, pady=14)
        self.ip_entry = ctk.CTkEntry(row, placeholder_text="192.168.1.50", width=190)
        self.ip_entry.pack(side="left", padx=(0, 8))
        self.reason_entry = ctk.CTkEntry(row, placeholder_text="Motivo da classificação", width=430)
        self.reason_entry.pack(side="left", fill="x", expand=True, padx=8)
        ctk.CTkButton(row, text="Adicionar e alertar", command=self._add, **primary_button()).pack(side="right", padx=(8, 0))
        self.ip_entry.bind("<Return>", lambda _e: self._add())

        split = ctk.CTkFrame(self, fg_color="transparent")
        split.pack(fill="both", expand=True)
        split.grid_columnconfigure(0, weight=1, uniform="policy")
        split.grid_columnconfigure(1, weight=1, uniform="policy")
        split.grid_rowconfigure(0, weight=1)

        black_panel = Panel(split, "IPs classificados")
        black_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 7))
        host, self.black_table = create_table(
            black_panel, ("ip", "reason", "added"),
            {"ip": "IP", "reason": "MOTIVO", "added": "ADICIONADO EM"},
            {"ip": 140, "reason": 280, "added": 145}, height=16,
        )
        host.pack(fill="both", expand=True, padx=12, pady=(12, 6))
        actions = ctk.CTkFrame(black_panel, fg_color="transparent")
        actions.pack(fill="x", padx=12, pady=(4, 12))
        ctk.CTkButton(actions, text="Bloquear selecionado", command=self._block, **danger_button()).pack(side="left")
        ctk.CTkButton(actions, text="Remover da blacklist", command=self._remove, **dark_button()).pack(side="right")

        blocked_panel = Panel(split, "Bloqueados no firewall")
        blocked_panel.grid(row=0, column=1, sticky="nsew", padx=(7, 0))
        host, self.blocked_table = create_table(
            blocked_panel, ("ip", "date"), {"ip": "IP", "date": "BLOQUEADO EM"},
            {"ip": 180, "date": 180}, height=16,
        )
        host.pack(fill="both", expand=True, padx=12, pady=(12, 6))
        actions2 = ctk.CTkFrame(blocked_panel, fg_color="transparent")
        actions2.pack(fill="x", padx=12, pady=(4, 12))
        ctk.CTkButton(actions2, text="Remover bloqueio", command=self._unblock, **dark_button()).pack(side="left")
        ctk.CTkButton(actions2, text="Atualizar", width=90, command=lambda: self.recarregar(True), **primary_button()).pack(side="right")

    def recarregar(self, force=False):
        black = self.app.db.listar_ip_blacklist()
        blocked = self.app.db.listar_ips_bloqueados_detalhes()
        signature = (
            tuple((x["ip"], x.get("motivo"), x["adicionado_em"]) for x in black),
            tuple((x["ip"], x["bloqueado_em"]) for x in blocked),
        )
        if not force and signature == self._signature:
            return
        clear_table(self.black_table)
        for item in black:
            self.black_table.insert("", "end", values=(item["ip"], item.get("motivo") or "—", item["adicionado_em"]), tags=("high",))
        clear_table(self.blocked_table)
        for item in blocked:
            self.blocked_table.insert("", "end", values=(item["ip"], item["bloqueado_em"]), tags=("critical",))
        self._signature = signature

    def _add(self):
        ip = self.ip_entry.get().strip()
        reason = self.reason_entry.get().strip() or "Adicionado manualmente à blacklist"
        if self.app.adicionar_ip_blacklist(ip, reason):
            self.ip_entry.delete(0, "end")
            self.reason_entry.delete(0, "end")
            self.recarregar(True)

    def _selected_black(self):
        values = selected_values(self.black_table)
        if not values:
            self.app.registrar_alerta_ui("[ERRO] Selecione um IP da blacklist.")
            return None
        return values[0]

    def _selected_blocked(self):
        values = selected_values(self.blocked_table)
        if not values:
            self.app.registrar_alerta_ui("[ERRO] Selecione um IP bloqueado.")
            return None
        return values[0]

    def _block(self):
        ip = self._selected_black()
        if ip: self.app.bloquear_ip_selecionado(ip); self.recarregar(True)

    def _remove(self):
        ip = self._selected_black()
        if ip: self.app.remover_ip_blacklist(ip); self.recarregar(True)

    def _unblock(self):
        ip = self._selected_blocked()
        if ip: self.app.desbloquear_ip_selecionado(ip); self.recarregar(True)

    def atualizar_automatico(self):
        self.recarregar()
