# SPDX-License-Identifier: MIT
# Copyright (c) 2026 KillChain
# Copyright (c) 2026 Gabriel Silva Bastos
# Copyright (c) 2026 Matheus Dominato
# Copyright (c) 2026 Isabelle Guimarães de Andrade
# Copyright (c) 2026 Nicolas Urtiaga
# Copyright (c) 2026 Pedro Lages da Silva

"""Configurações do capturador e do motor de detecção."""

import customtkinter as ctk

from capture.packet_capture import PacketCapture
from ui.components import PageHeader, Panel, create_table
from ui.theme import COLORS, dark_button, danger_button, primary_button


class SettingsFrame(ctk.CTkFrame):
    def __init__(self, master, app):
        super().__init__(master, fg_color="transparent")
        self.app = app
        self._criar_layout()
        self._load()

    def _criar_layout(self):
        PageHeader(self, "Configurações", "Ajustes persistidos e aplicados ao capturador sem usar dados simulados.")

        general = Panel(self, "Captura e detecção de port scan")
        general.pack(fill="x", pady=(0, 14))
        row = ctk.CTkFrame(general, fg_color="transparent")
        row.pack(fill="x", padx=14, pady=14)

        interfaces = ["Padrão do sistema"] + PacketCapture.listar_interfaces()
        self.interface = ctk.CTkOptionMenu(row, values=interfaces or ["Padrão do sistema"], width=330)
        self.interface.pack(side="left", padx=(0, 14))

        ctk.CTkLabel(row, text="Portas para alertar:", text_color=COLORS["muted"]).pack(side="left")
        self.scan_limit = ctk.CTkEntry(row, width=72)
        self.scan_limit.pack(side="left", padx=(7, 14))
        ctk.CTkLabel(row, text="Janela (s):", text_color=COLORS["muted"]).pack(side="left")
        self.scan_window = ctk.CTkEntry(row, width=72)
        self.scan_window.pack(side="left", padx=7)
        ctk.CTkButton(row, text="Salvar configurações", command=self._save, **primary_button()).pack(side="right")

        ports = Panel(self, "Portas sensíveis monitoradas")
        ports.pack(fill="both", expand=True)
        form = ctk.CTkFrame(ports, fg_color="transparent")
        form.pack(fill="x", padx=12, pady=(12, 4))
        self.port_entry = ctk.CTkEntry(form, placeholder_text="Porta", width=100)
        self.port_entry.pack(side="left", padx=(0, 6))
        self.name_entry = ctk.CTkEntry(form, placeholder_text="Serviço", width=190)
        self.name_entry.pack(side="left", padx=6)
        self.severity = ctk.CTkOptionMenu(form, values=["BAIXO", "MÉDIO", "ALTO", "CRÍTICO"], width=125)
        self.severity.set("MÉDIO")
        self.severity.pack(side="left", padx=6)
        ctk.CTkButton(form, text="Adicionar", width=100, command=self._add_port, **dark_button()).pack(side="left", padx=6)
        ctk.CTkButton(form, text="Remover", width=100, command=self._remove_port, **danger_button()).pack(side="left", padx=6)

        host, self.port_table = create_table(
            ports, ("port", "service", "severity"),
            {"port": "PORTA", "service": "SERVIÇO", "severity": "SEVERIDADE"},
            {"port": 100, "service": 300, "severity": 130}, height=11,
        )
        host.pack(fill="both", expand=True, padx=12, pady=(4, 12))

    def _load(self):
        db = self.app.db
        saved = db.obter_configuracao("interface_rede", "")
        self.interface.set(saved if saved else "Padrão do sistema")
        for port in db.obter_portas_sensiveis():
            self.port_table.insert("", "end", values=(port["porta"], port["nome"], port["severidade"]), tags=("info",))
        self.scan_limit.insert(0, db.obter_configuracao("limite_portas_scan", "15"))
        self.scan_window.insert(0, db.obter_configuracao("janela_scan_segundos", "10"))

    def _add_port(self):
        port = self.port_entry.get().strip()
        service = self.name_entry.get().strip()
        if not port.isdigit() or not 1 <= int(port) <= 65535 or not service:
            self.app.registrar_alerta_ui("[ERRO] Informe uma porta entre 1 e 65535 e o nome do serviço.")
            return
        self.port_table.insert("", "end", values=(int(port), service, self.severity.get()), tags=("info",))
        self.port_entry.delete(0, "end")
        self.name_entry.delete(0, "end")

    def _remove_port(self):
        selected = self.port_table.selection()
        if selected:
            self.port_table.delete(selected[0])

    def _save(self):
        interface = self.interface.get()
        interface_final = "" if interface == "Padrão do sistema" else interface
        ports = []
        for item in self.port_table.get_children():
            port, name, severity = self.port_table.item(item, "values")
            ports.append({"porta": int(port), "nome": name, "severidade": severity})
        try:
            limit = int(self.scan_limit.get().strip() or 15)
            window = int(self.scan_window.get().strip() or 10)
            if limit < 2 or window < 1:
                raise ValueError
        except ValueError:
            self.app.registrar_alerta_ui("[ERRO] Limite e janela precisam ser números positivos válidos.")
            return

        db = self.app.db
        db.definir_configuracao("interface_rede", interface_final)
        db.definir_portas_sensiveis(ports)
        db.definir_configuracao("limite_portas_scan", str(limit))
        db.definir_configuracao("janela_scan_segundos", str(window))
        self.app.aplicar_configuracoes(interface_final or None, ports, limit, window)
        self.app.auditar("CONFIGURACOES_ATUALIZADAS", f"interface={interface_final or 'automática'}; limite={limit}; janela={window}")
        self.app.registrar_alerta_ui("Configurações salvas e aplicadas.")
