"""
Tela de Dispositivos: lista os hosts vistos na rede (populados
passivamente a partir dos fluxos capturados) e permite uma descoberta
ativa via ARP scan para tentar obter hostname/MAC de cada IP da LAN.
"""

import socket
import threading
from tkinter import ttk

import customtkinter as ctk
from ui.theme import COLORS, dark_button, danger_button, secondary_button


class DevicesFrame(ctk.CTkFrame):
    def __init__(self, master, app):
        super().__init__(master, fg_color="transparent")
        self.app = app
        self.tabela = None

        self._criar_layout()
        self.recarregar()

    def _criar_layout(self):
        frame_acoes = ctk.CTkFrame(self, fg_color="transparent")
        frame_acoes.pack(fill="x", padx=20, pady=10)

        ctk.CTkButton(frame_acoes, text="Atualizar Lista", command=self.recarregar).pack(
            side="left", padx=6, pady=8
        )
        ctk.CTkButton(
            frame_acoes,
            text="Descobrir Dispositivos na Rede (ARP)",
            command=self._descobrir_via_arp,
        ).pack(side="left", padx=6, pady=8)
        ctk.CTkButton(
            frame_acoes,
            text="Resolver Hostnames",
            command=self._resolver_hostnames,
        ).pack(side="left", padx=6, pady=8)

        frame_tabela = ctk.CTkFrame(self, fg_color="transparent")
        frame_tabela.pack(fill="both", expand=True, padx=20, pady=10)

        colunas = ("ip", "hostname", "mac", "status", "conexoes", "ultimo_visto")
        self.tabela = ttk.Treeview(frame_tabela, columns=colunas, show="headings", height=18)

        titulos = {
            "ip": "IP",
            "hostname": "Hostname",
            "mac": "MAC",
            "status": "Status",
            "conexoes": "Conexões",
            "ultimo_visto": "Último Visto",
        }
        larguras = {
            "ip": 140,
            "hostname": 220,
            "mac": 160,
            "status": 100,
            "conexoes": 100,
            "ultimo_visto": 160,
        }

        for coluna in colunas:
            self.tabela.heading(coluna, text=titulos[coluna], anchor="w")
            self.tabela.column(coluna, width=larguras[coluna], anchor="w")

        scrollbar = ttk.Scrollbar(frame_tabela, orient="vertical", command=self.tabela.yview)
        self.tabela.configure(yscrollcommand=scrollbar.set)

        self.tabela.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=10)
        scrollbar.pack(side="right", fill="y", padx=(0, 10), pady=10)

    def recarregar(self):
        for item in self.tabela.get_children():
            self.tabela.delete(item)

        for dispositivo in self.app.db.listar_dispositivos():
            self.tabela.insert(
                "",
                "end",
                values=(
                    dispositivo["ip"],
                    dispositivo.get("hostname") or "-",
                    dispositivo.get("mac") or "-",
                    dispositivo["status"],
                    dispositivo["conexoes"],
                    dispositivo["ultimo_visto"],
                ),
            )

    def _resolver_hostnames(self):
        self.app.registrar_alerta_ui("Resolvendo hostnames dos dispositivos conhecidos...")
        thread = threading.Thread(target=self._resolver_hostnames_thread, daemon=True)
        thread.start()

    def _resolver_hostnames_thread(self):
        for dispositivo in self.app.db.listar_dispositivos():
            ip = dispositivo["ip"]
            if dispositivo.get("hostname"):
                continue
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                self.app.db.registrar_dispositivo(ip, hostname=hostname)
            except Exception:
                continue

        self.app.registrar_alerta_ui("Resolução de hostnames concluída.")
        self.after(0, self.recarregar)

    def _descobrir_via_arp(self):
        self.app.registrar_alerta_ui(
            "Iniciando descoberta ARP na rede local (pode levar alguns segundos)..."
        )
        thread = threading.Thread(target=self._descobrir_via_arp_thread, daemon=True)
        thread.start()

    def _descobrir_via_arp_thread(self):
        try:
            from scapy.all import ARP, Ether, srp
        except Exception as erro:
            self.app.registrar_alerta_ui(f"[ERRO] Scapy indisponível para ARP scan: {erro}")
            return

        rede = self.app.obter_faixa_rede_local()
        if not rede:
            self.app.registrar_alerta_ui(
                "[ERRO] Não foi possível determinar a faixa de rede local. "
                "Configure a interface em Configurações."
            )
            return

        try:
            requisicao = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=rede)
            respostas = srp(requisicao, timeout=3, verbose=False)[0]

            for _, recebido in respostas:
                self.app.db.registrar_dispositivo(recebido.psrc, mac=recebido.hwsrc)

            self.app.registrar_alerta_ui(f"Descoberta ARP concluída: {len(respostas)} dispositivo(s) encontrado(s).")
        except Exception as erro:
            self.app.registrar_alerta_ui(
                f"[ERRO] Falha no ARP scan (normalmente requer privilégios de administrador): {erro}"
            )

        self.after(0, self.recarregar)
