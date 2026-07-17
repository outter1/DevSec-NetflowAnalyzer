# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Gabriel Silva Bastos

"""Domínios observados e políticas de blacklist de domínio."""

import threading
import customtkinter as ctk

from ui.components import PageHeader, Panel, clear_table, create_table, selected_values
from ui.theme import COLORS, dark_button, danger_button, primary_button


class DomainsFrame(ctk.CTkFrame):
    def __init__(self, master, app):
        super().__init__(master, fg_color="transparent")
        self.app = app
        self._signature = None
        self._busy = False
        self._criar_layout()
        self.recarregar(force=True)

    def _criar_layout(self):
        PageHeader(
            self,
            "Domínios acessados",
            "Observação passiva por DNS, HTTP Host e TLS SNI quando esses dados estiverem visíveis.",
        )

        form = Panel(self, "Adicionar política de domínio")
        form.pack(fill="x", pady=(0, 12))
        row = ctk.CTkFrame(form, fg_color="transparent")
        row.pack(fill="x", padx=14, pady=(12, 6))
        self.domain_entry = ctk.CTkEntry(row, placeholder_text="exemplo.com", width=250)
        self.domain_entry.pack(side="left", padx=(0, 8))
        self.client_entry = ctk.CTkEntry(row, placeholder_text="IP cliente ou *", width=180)
        self.client_entry.insert(0, "*")
        self.client_entry.pack(side="left", padx=8)
        self.mode = ctk.CTkOptionMenu(row, values=["Monitorar e alertar", "Bloquear neste computador"], width=230)
        self.mode.set("Monitorar e alertar")
        self.mode.pack(side="left", padx=8)
        self.add_button = ctk.CTkButton(row, text="Adicionar política", command=self._add, **primary_button())
        self.add_button.pack(side="right", padx=(8, 0))
        ctk.CTkLabel(
            form,
            text=(
                "O bloqueio cria regras de saída no firewall local. Para controlar outro host da LAN, "
                "o DevSec precisa atuar como gateway, firewall ou DNS desse dispositivo."
            ),
            text_color=COLORS["muted"],
            justify="left",
            anchor="w",
            wraplength=820,
        ).pack(fill="x", anchor="w", padx=16, pady=(0, 12))

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
        recent_tab = self.tabs.add("Acessos recentes")
        policies_tab = self.tabs.add("Políticas")
        recent_tab.configure(fg_color=COLORS["panel"])
        policies_tab.configure(fg_color=COLORS["panel"])

        filters = ctk.CTkFrame(recent_tab, fg_color="transparent")
        filters.pack(fill="x", padx=10, pady=(12, 7))
        self.filter_ip = ctk.CTkEntry(filters, placeholder_text="IP cliente", width=170)
        self.filter_ip.pack(side="left", padx=(0, 6))
        self.filter_domain = ctk.CTkEntry(filters, placeholder_text="Filtrar domínio", width=230)
        self.filter_domain.pack(side="left", padx=6)
        self.seconds = ctk.CTkOptionMenu(filters, values=["Últimos 10s", "Últimos 30s", "Último minuto", "Últimos 5 min"], width=155)
        self.seconds.set("Últimos 30s")
        self.seconds.pack(side="left", padx=6)
        ctk.CTkButton(filters, text="Atualizar", width=95, command=lambda: self.recarregar(True), **dark_button()).pack(side="left", padx=6)
        ctk.CTkButton(filters, text="Limpar filtros", width=110, command=self._clear_filters, **dark_button()).pack(side="left", padx=6)

        columns = ("time", "client", "domain", "destination", "source", "policy")
        headings = {
            "time": "OBSERVADO EM", "client": "IP CLIENTE", "domain": "DOMÍNIO",
            "destination": "DESTINO", "source": "FONTE", "policy": "POLÍTICA",
        }
        widths = {"time": 145, "client": 135, "domain": 300, "destination": 170, "source": 105, "policy": 135}
        host, self.recent_table = create_table(recent_tab, columns, headings, widths, height=12)
        host.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        columns = ("domain", "client", "mode", "ips", "state", "updated")
        headings = {
            "domain": "DOMÍNIO", "client": "CLIENTE", "mode": "MODO",
            "ips": "IPS RESOLVIDOS", "state": "ESTADO", "updated": "ATUALIZADO EM",
        }
        widths = {"domain": 260, "client": 130, "mode": 150, "ips": 320, "state": 180, "updated": 145}
        host, self.policy_table = create_table(policies_tab, columns, headings, widths, height=12)
        host.pack(fill="both", expand=True, padx=10, pady=(12, 5))
        actions = ctk.CTkFrame(policies_tab, fg_color="transparent")
        actions.pack(fill="x", padx=10, pady=(4, 10))
        ctk.CTkButton(actions, text="Reaplicar selecionada", command=self._reapply, **dark_button()).pack(side="left")
        ctk.CTkButton(actions, text="Remover política", command=self._remove, **danger_button()).pack(side="right")

    def _seconds_value(self):
        return {
            "Últimos 10s": 10,
            "Últimos 30s": 30,
            "Último minuto": 60,
            "Últimos 5 min": 300,
        }.get(self.seconds.get(), 30)

    def recarregar(self, force=False):
        observations = self.app.db.listar_dominios_recentes(
            segundos=self._seconds_value(), limite=500,
            ip_cliente=self.filter_ip.get().strip() or None,
            dominio=self.filter_domain.get().strip() or None,
        )
        policies = self.app.db.listar_domain_blacklist()
        signature = (
            tuple((o["id"], o["observado_em"], o["bloqueado_pela_politica"]) for o in observations),
            tuple((p["dominio"], p["ip_cliente"], p["modo"], p.get("atualizado_em"), p.get("ultimo_erro")) for p in policies),
        )
        if not force and signature == self._signature:
            return

        clear_table(self.recent_table)
        for item in observations:
            policy = self.app.encontrar_regra_dominio(item["dominio"], item["ip_cliente"])
            policy_text = "Sem regra"
            tag = "info"
            if policy:
                policy_text = "Bloqueio local" if policy.get("modo") == "bloquear_local" else "Monitorado"
                tag = "critical" if policy.get("modo") == "bloquear_local" else "high"
            destination = item.get("ip_destino") or "—"
            if item.get("porta_destino"):
                destination = f"{destination}:{item['porta_destino']}"
            self.recent_table.insert(
                "", "end",
                values=(item["observado_em"], item["ip_cliente"], item["dominio"], destination, item["fonte"], policy_text),
                tags=(tag,),
            )

        clear_table(self.policy_table)
        for item in policies:
            ips = ", ".join(item.get("ips_resolvidos") or []) or "—"
            state = item.get("ultimo_erro") or "Ativa"
            tag = "critical" if item.get("ultimo_erro") else ("high" if item["modo"] == "bloquear_local" else "safe")
            mode = "Bloquear local" if item["modo"] == "bloquear_local" else "Monitorar"
            self.policy_table.insert(
                "", "end",
                values=(item["dominio"], item["ip_cliente"], mode, ips, state, item["atualizado_em"]),
                tags=(tag,),
            )
        self._signature = signature

    def _set_busy(self, busy):
        self._busy = busy
        self.add_button.configure(state="disabled" if busy else "normal", text="Aplicando..." if busy else "Adicionar política")

    def _add(self):
        if self._busy:
            return
        domain = self.domain_entry.get().strip()
        client = self.client_entry.get().strip() or "*"
        mode = "bloquear_local" if self.mode.get() == "Bloquear neste computador" else "monitorar"
        self._set_busy(True)

        def worker():
            ok = self.app.adicionar_politica_dominio(domain, client, mode)
            self.after(0, lambda: self._finish_add(ok))

        threading.Thread(target=worker, daemon=True).start()

    def _finish_add(self, ok):
        self._set_busy(False)
        if ok:
            self.domain_entry.delete(0, "end")
            self.recarregar(True)

    def _selected_policy(self):
        values = selected_values(self.policy_table)
        if not values:
            self.app.registrar_alerta_ui("[ERRO] Selecione uma política de domínio.")
            return None
        return values[0], values[1]

    def _remove(self):
        selected = self._selected_policy()
        if not selected or self._busy:
            return
        domain, client = selected
        self._set_busy(True)

        def worker():
            self.app.remover_politica_dominio(domain, client)
            self.after(0, self._finish_remove)

        threading.Thread(target=worker, daemon=True).start()

    def _finish_remove(self):
        self._set_busy(False)
        self.recarregar(True)

    def _reapply(self):
        selected = self._selected_policy()
        if not selected or self._busy:
            return
        domain, client = selected
        self._set_busy(True)

        def worker():
            self.app.reconciliar_regra_dominio(domain, client)
            self.after(0, self._finish_remove)

        threading.Thread(target=worker, daemon=True).start()

    def _clear_filters(self):
        self.filter_ip.delete(0, "end")
        self.filter_domain.delete(0, "end")
        self.seconds.set("Últimos 30s")
        self.recarregar(True)

    def atualizar_automatico(self):
        self.recarregar()
