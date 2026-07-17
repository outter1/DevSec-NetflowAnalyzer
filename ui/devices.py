# SPDX-License-Identifier: MIT
# Copyright (c) 2026 DEVSEC
# Copyright (c) 2026 Gabriel Silva Bastos
# Copyright (c) 2026 Matheus Dominato
# Copyright (c) 2026 Isabelle Guimarães de Andrade
# Copyright (c) 2026 Nicolas Urtiaga
# Copyright (c) 2026 Pedro Lages da Silva

"""Dispositivos vistos passivamente e descoberta ativa autorizada via ARP."""

import socket
import threading
import customtkinter as ctk

from ui.components import PageHeader, Panel, clear_table, create_table
from ui.theme import dark_button, primary_button


class DevicesFrame(ctk.CTkFrame):
    def __init__(self, master, app):
        super().__init__(master, fg_color="transparent")
        self.app = app
        self._signature = None
        self._criar_layout()
        self.recarregar(force=True)

    def _criar_layout(self):
        PageHeader(self, "Dispositivos", "Hosts observados na captura e descoberta ARP da rede local autorizada.")
        actions = Panel(self, "Descoberta e enriquecimento")
        actions.pack(fill="x", pady=(0, 14))
        row = ctk.CTkFrame(actions, fg_color="transparent")
        row.pack(fill="x", padx=14, pady=14)
        ctk.CTkButton(row, text="Descobrir via ARP", command=self._discover_arp, **primary_button()).pack(side="left")
        ctk.CTkButton(row, text="Resolver hostnames", command=self._resolve_hostnames, **dark_button()).pack(side="left", padx=8)
        ctk.CTkButton(row, text="Atualizar", width=95, command=lambda: self.recarregar(True), **dark_button()).pack(side="right")

        panel = Panel(self, "Dispositivos observados")
        panel.pack(fill="both", expand=True)
        columns = ("ip", "hostname", "mac", "status", "connections", "first", "last")
        headings = {
            "ip": "IP", "hostname": "HOSTNAME", "mac": "MAC", "status": "STATUS",
            "connections": "CONEXÕES", "first": "PRIMEIRO VISTO", "last": "ÚLTIMO VISTO",
        }
        widths = {"ip": 140, "hostname": 230, "mac": 160, "status": 95, "connections": 90, "first": 150, "last": 150}
        host, self.table = create_table(panel, columns, headings, widths, height=18)
        host.pack(fill="both", expand=True, padx=12, pady=12)

    def recarregar(self, force=False):
        devices = self.app.db.listar_dispositivos()
        signature = tuple((d["ip"], d.get("hostname"), d.get("mac"), d["conexoes"], d["ultimo_visto"]) for d in devices)
        if not force and signature == self._signature:
            return
        clear_table(self.table)
        for device in devices:
            self.table.insert(
                "", "end",
                values=(device["ip"], device.get("hostname") or "—", device.get("mac") or "—", device["status"], device["conexoes"], device["primeiro_visto"], device["ultimo_visto"]),
                tags=("safe" if device["status"] == "Ativo" else "muted",),
            )
        self._signature = signature

    def _resolve_hostnames(self):
        self.app.registrar_alerta_ui("Resolvendo hostnames dos dispositivos conhecidos...")
        threading.Thread(target=self._resolve_worker, daemon=True).start()

    def _resolve_worker(self):
        for device in self.app.db.listar_dispositivos():
            if device.get("hostname"):
                continue
            try:
                hostname = socket.gethostbyaddr(device["ip"])[0]
                self.app.db.registrar_dispositivo(device["ip"], hostname=hostname)
            except Exception:
                continue
        self.app.registrar_alerta_ui("Resolução de hostnames concluída.")
        self.after(0, lambda: self.recarregar(True))

    def _discover_arp(self):
        self.app.registrar_alerta_ui("Iniciando descoberta ARP autorizada na rede local...")
        threading.Thread(target=self._arp_worker, daemon=True).start()

    def _arp_worker(self):
        try:
            from scapy.all import ARP, Ether, srp
        except Exception as error:
            self.app.registrar_alerta_ui(f"[ERRO] Scapy indisponível para ARP scan: {error}")
            return
        network = self.app.obter_faixa_rede_local()
        if not network:
            self.app.registrar_alerta_ui("[ERRO] Não foi possível determinar a faixa da rede local.")
            return
        try:
            request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
            answers = srp(request, timeout=3, verbose=False)[0]
            for _, received in answers:
                self.app.db.registrar_dispositivo(received.psrc, mac=received.hwsrc)
            self.app.registrar_alerta_ui(f"Descoberta ARP concluída: {len(answers)} dispositivo(s).")
        except Exception as error:
            self.app.registrar_alerta_ui(f"[ERRO] Falha no ARP scan; verifique privilégios: {error}")
        self.after(0, lambda: self.recarregar(True))

    def atualizar_automatico(self):
        self.recarregar()
