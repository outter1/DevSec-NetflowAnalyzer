# SPDX-License-Identifier: MIT
# Copyright (c) 2026 DEVSEC
# Copyright (c) 2026 Gabriel Silva Bastos
# Copyright (c) 2026 Matheus Dominato
# Copyright (c) 2026 Isabelle Guimarães de Andrade
# Copyright (c) 2026 Nicolas Urtiaga
# Copyright (c) 2026 Pedro Lages da Silva

"""Investigação e resposta aos alertas de IP."""

import os
from tkinter import filedialog
import customtkinter as ctk

from ui.components import PageHeader, Panel, clear_table, create_table, selected_values, severity_tag
from ui.theme import COLORS, dark_button, danger_button, primary_button, success_button


class AlertsFrame(ctk.CTkFrame):
    def __init__(self, master, app):
        super().__init__(master, fg_color="transparent")
        self.app = app
        self._signature = None
        self._criar_layout()
        self.recarregar(force=True)

    def _criar_layout(self):
        PageHeader(self, "Alertas", "Classifique, investigue e responda aos IPs detectados pelo motor.")

        actions = Panel(self, "Ações do analista")
        actions.pack(fill="x", pady=(0, 12))
        grid = ctk.CTkFrame(actions, fg_color="transparent")
        grid.pack(fill="x", padx=12, pady=12)
        for col in range(4):
            grid.grid_columnconfigure(col, weight=1, uniform="alert_action")
        buttons = [
            ("Normal", self._normal, success_button()),
            ("Crítico", self._critical, danger_button()),
            ("Whitelist", self._whitelist, dark_button()),
            ("Blacklist", self._blacklist, dark_button()),
            ("Bloquear IP", self._block, danger_button()),
            ("Desbloquear", self._unblock, dark_button()),
            ("Exportar PDF", self._export_pdf, dark_button()),
            ("Atualizar", lambda: self.recarregar(True), primary_button()),
        ]
        for index, (text, command, style) in enumerate(buttons):
            ctk.CTkButton(grid, text=text, command=command, **style).grid(
                row=index // 4, column=index % 4, sticky="ew", padx=5, pady=5
            )

        self.tabs = ctk.CTkTabview(
            self,
            fg_color=COLORS["panel"],
            border_width=1,
            border_color=COLORS["border"],
            corner_radius=14,
            segmented_button_fg_color=COLORS["panel_alt"],
            segmented_button_selected_color=COLORS["red"],
            segmented_button_selected_hover_color=COLORS["red_hover"],
            segmented_button_unselected_color=COLORS["panel_alt"],
            segmented_button_unselected_hover_color=COLORS["border"],
            text_color=COLORS["text"],
        )
        self.tabs.pack(fill="both", expand=True)
        alerts_tab = self.tabs.add("Alertas e classificação")
        context_tab = self.tabs.add("Contexto selecionado")
        alerts_tab.configure(fg_color=COLORS["panel"])
        context_tab.configure(fg_color=COLORS["panel"])

        columns = ("ip", "severity", "reason", "status", "events", "last")
        headings = {
            "ip": "IP", "severity": "SEVERIDADE", "reason": "MOTIVO",
            "status": "STATUS", "events": "EVENTOS", "last": "ÚLTIMO EVENTO",
        }
        widths = {"ip": 145, "severity": 105, "reason": 420, "status": 120, "events": 75, "last": 150}
        host, self.table = create_table(alerts_tab, columns, headings, widths, height=13)
        host.pack(fill="both", expand=True, padx=10, pady=10)
        self.table.bind("<<TreeviewSelect>>", self._show_details)
        self.table.bind("<Double-1>", lambda _event: self.tabs.set("Contexto selecionado"))

        self.info = ctk.CTkTextbox(context_tab)
        self.info.pack(fill="both", expand=True, padx=10, pady=10)
        self.info.insert("end", "Selecione um IP na tabela para ver a linha do tempo recente.\n")

    def recarregar(self, force=False):
        alerts = self.app.db.listar_alertas()
        signature = tuple((a["ip"], a["status"], a["eventos"], a["ultimo_evento"]) for a in alerts)
        if not force and signature == self._signature:
            return
        selected_ip = None
        values = selected_values(self.table)
        if values:
            selected_ip = values[0]
        clear_table(self.table)
        selected_item = None
        for alert in alerts:
            tag = severity_tag(alert["severidade"] + " " + alert["status"])
            item = self.table.insert(
                "", "end",
                values=(alert["ip"], alert["severidade"], alert["motivo"], alert["status"], alert["eventos"], alert["ultimo_evento"]),
                tags=(tag,),
            )
            if alert["ip"] == selected_ip:
                selected_item = item
        if selected_item:
            self.table.selection_set(selected_item)
        self._signature = signature

    def _selected_ip(self, warn=True):
        values = selected_values(self.table)
        if not values:
            if warn:
                self.app.registrar_alerta_ui("[ERRO] Selecione um IP na tabela de alertas.")
            return None
        return values[0]

    def _show_details(self, _event=None):
        ip = self._selected_ip(warn=False)
        if not ip:
            return
        alert = self.app.db.obter_alerta(ip) or {}
        logs = self.app.db.listar_log(limite=40, ip=ip)
        self.info.delete("1.0", "end")
        self.info.insert("end", f"IP: {ip}\n")
        self.info.insert("end", f"Status: {alert.get('status', '-')}\n")
        self.info.insert("end", f"Severidade: {alert.get('severidade', '-')}\n")
        self.info.insert("end", f"Primeiro evento: {alert.get('primeiro_evento', '-')}\n")
        self.info.insert("end", f"Último evento: {alert.get('ultimo_evento', '-')}\n")
        self.info.insert("end", f"Total de eventos: {alert.get('eventos', '-')}\n")
        self.info.insert("end", f"Motivo atual: {alert.get('motivo', '-')}\n\nLINHA DO TEMPO\n")
        if not logs:
            self.info.insert("end", "Nenhum log detalhado registrado para este IP.\n")
        for log in reversed(logs):
            self.info.insert("end", f"• {log['data_hora']} — {log['mensagem']}\n")

    def _normal(self):
        ip = self._selected_ip()
        if ip:
            self.app.classificar_ip_normal(ip)
            self.recarregar(True)

    def _critical(self):
        ip = self._selected_ip()
        if ip:
            self.app.classificar_ip_critico(ip)
            self.recarregar(True)

    def _whitelist(self):
        ip = self._selected_ip()
        if ip:
            self.app.adicionar_ip_whitelist(ip)
            self.recarregar(True)

    def _blacklist(self):
        ip = self._selected_ip()
        if ip:
            self.app.adicionar_ip_blacklist(ip, "Adicionado a partir da tela de alertas")
            self.recarregar(True)

    def _block(self):
        ip = self._selected_ip()
        if ip:
            self.app.bloquear_ip_selecionado(ip)
            self.recarregar(True)

    def _unblock(self):
        ip = self._selected_ip()
        if ip:
            self.app.desbloquear_ip_selecionado(ip)
            self.recarregar(True)

    def _export_pdf(self):
        ip = self._selected_ip()
        if not ip:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".pdf", initialfile=f"relatorio_{ip.replace('.', '_')}.pdf",
            filetypes=[("Arquivo PDF", "*.pdf")],
        )
        if not path:
            return
        try:
            self.app.exportar_relatorio_ip_pdf(ip, path)
            self.app.registrar_alerta_ui(f"Relatório de {ip} exportado para {os.path.basename(path)}.")
        except Exception as error:
            self.app.registrar_alerta_ui(f"[ERRO] Falha ao exportar relatório: {error}")

    def atualizar_automatico(self):
        self.recarregar()
