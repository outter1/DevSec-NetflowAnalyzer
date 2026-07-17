# SPDX-License-Identifier: MIT
# Copyright (c) 2026 KillChain
# Copyright (c) 2026 Gabriel Silva Bastos
# Copyright (c) 2026 Matheus Dominato
# Copyright (c) 2026 Isabelle Guimarães de Andrade
# Copyright (c) 2026 Nicolas Urtiaga
# Copyright (c) 2026 Pedro Lages da Silva

"""Visão geral operacional do DevSec."""

import customtkinter as ctk

from ui.components import MetricCard, PageHeader, Panel, clear_table, create_table, severity_tag
from ui.theme import COLORS, FONT, dark_button, danger_button, primary_button


class DashboardFrame(ctk.CTkFrame):
    def __init__(self, master, app):
        super().__init__(master, fg_color="transparent")
        self.app = app
        self.cards = {}
        self._ultima_assinatura = None
        self._criar_layout()
        self.atualizar()

    def _criar_layout(self):
        PageHeader(
            self,
            "Central operacional",
            "Dados reais da captura e do SQLite, atualizados enquanto o programa estiver aberto.",
        )

        cards = ctk.CTkFrame(self, fg_color="transparent")
        cards.pack(fill="x", pady=(0, 16))
        for coluna in range(3):
            cards.grid_columnconfigure(coluna, weight=1, uniform="metric")

        definicoes = [
            ("total_fluxos", "Fluxos", COLORS["blue_soft"]),
            ("total_alertas", "Alertas", COLORS["red_light"]),
            ("total_bloqueados", "IPs bloqueados", COLORS["red_light"]),
            ("total_blacklist", "Blacklist IP", COLORS["yellow_soft"]),
            ("dominios_recentes", "Domínios / 30s", COLORS["green_soft"]),
            ("total_dispositivos", "Dispositivos", COLORS["blue_soft"]),
        ]
        for indice, (chave, titulo, cor) in enumerate(definicoes):
            card = MetricCard(cards, titulo, accent=cor)
            card.grid(row=indice // 3, column=indice % 3, sticky="nsew", padx=6, pady=6)
            self.cards[chave] = card

        status_panel = Panel(self, "Estado da captura")
        status_panel.pack(fill="x", pady=(0, 16))
        status_body = ctk.CTkFrame(status_panel, fg_color="transparent")
        status_body.pack(fill="x", padx=18, pady=15)
        self.status_dot = ctk.CTkLabel(status_body, text="●", font=(FONT, 18), width=24)
        self.status_dot.pack(side="left")
        self.status_text = ctk.CTkLabel(status_body, text="Captura parada", font=(FONT, 13, "bold"))
        self.status_text.pack(side="left", padx=(4, 12))
        self.status_detail = ctk.CTkLabel(
            status_body, text="", text_color=COLORS["muted"], font=(FONT, 11)
        )
        self.status_detail.pack(side="left")
        ctk.CTkButton(
            status_body, text="Parar", width=90, command=self.app.parar_captura, **danger_button()
        ).pack(side="right", padx=(8, 0))
        ctk.CTkButton(
            status_body, text="Iniciar", width=90, command=self.app.iniciar_captura, **primary_button()
        ).pack(side="right")

        recent_panel = Panel(self, "Fluxos recentes", "A tabela mostra somente tráfego realmente persistido.")
        recent_panel.pack(fill="both", expand=True)
        columns = ("ultimo", "origem", "po", "destino", "pd", "protocolo", "pacotes", "bytes")
        headings = {
            "ultimo": "ÚLTIMO EVENTO",
            "origem": "ORIGEM",
            "po": "PORTA",
            "destino": "DESTINO",
            "pd": "PORTA",
            "protocolo": "PROTOCOLO",
            "pacotes": "PACOTES",
            "bytes": "BYTES",
        }
        widths = {"ultimo": 145, "origem": 135, "po": 70, "destino": 135, "pd": 70, "protocolo": 90}
        host, self.table = create_table(recent_panel, columns, headings, widths, height=12)
        host.pack(fill="both", expand=True, padx=12, pady=12)

    def atualizar(self):
        resumo = self.app.db.obter_resumo(segundos_dominios=30)
        assinatura = tuple(resumo.get(k, 0) for k in sorted(resumo)) + (self.app.captura.ativo,)
        for chave, card in self.cards.items():
            card.set(resumo.get(chave, 0))

        ativa = self.app.captura.ativo
        self.status_dot.configure(text_color=COLORS["green"] if ativa else COLORS["red"])
        self.status_text.configure(text="Captura ativa" if ativa else "Captura parada")
        interface = self.app.captura.interface or "interface automática"
        self.status_detail.configure(text=f"Interface: {interface}")

        if assinatura != self._ultima_assinatura:
            clear_table(self.table)
            for fluxo in self.app.db.listar_fluxos(limite=80):
                self.table.insert(
                    "",
                    "end",
                    values=(
                        fluxo["ultimo_evento"], fluxo["ip_origem"], fluxo["porta_origem"],
                        fluxo["ip_destino"], fluxo["porta_destino"], fluxo["protocolo"],
                        fluxo["pacotes"], fluxo["bytes"],
                    ),
                    tags=("info",),
                )
            self._ultima_assinatura = assinatura

    def atualizar_automatico(self):
        self.atualizar()
