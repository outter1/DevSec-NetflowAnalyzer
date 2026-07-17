# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Gabriel Silva Bastos

"""
Transforma pacotes capturados (objetos Scapy) em fluxos de rede agregados
(origem, destino, portas, protocolo, contagem de pacotes/bytes) e mantém
esse estado em memória para exibição em tempo real na tabela da UI.

Este módulo não sabe nada sobre Tkinter/CustomTkinter nem sobre SQLite -
ele só entende de "pacote -> fluxo". Isso deixa a lógica testável de forma
isolada e reutilizável (ex.: em testes automatizados ou em um modo CLI).
"""

from datetime import datetime

try:
    from scapy.config import conf
    conf.ipv6_enabled = False
    from scapy.layers.inet import IP, TCP, UDP
except Exception:  # pragma: no cover - Scapy ausente ou indisponível no SO
    IP = TCP = UDP = None


class FlowAnalyzer:
    def __init__(self):
        # chave = (ip_origem, ip_destino, porta_origem, porta_destino, protocolo)
        self.fluxos = {}

    # ------------------------------------------------------------------ #
    # Conversão pacote -> fluxo
    # ------------------------------------------------------------------ #
    def pacote_para_fluxo(self, pacote):
        """Recebe um pacote Scapy e devolve um dicionário de fluxo, ou None
        se o pacote não tiver camada IP (ex.: ARP puro)."""
        if IP is None or IP not in pacote:
            return None

        ip_origem = pacote[IP].src
        ip_destino = pacote[IP].dst

        porta_origem = 0
        porta_destino = 0
        protocolo = "IP"

        if TCP in pacote:
            porta_origem = int(pacote[TCP].sport)
            porta_destino = int(pacote[TCP].dport)
            protocolo = "TCP"
        elif UDP in pacote:
            porta_origem = int(pacote[UDP].sport)
            porta_destino = int(pacote[UDP].dport)
            protocolo = "UDP"
        else:
            protocolo = str(pacote[IP].proto)

        return {
            "ip_origem": ip_origem,
            "ip_destino": ip_destino,
            "porta_origem": porta_origem,
            "porta_destino": porta_destino,
            "protocolo": protocolo,
            "bytes": len(pacote),
            "horario": datetime.now().strftime("%H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # Agregação em memória
    # ------------------------------------------------------------------ #
    def chave_fluxo(self, fluxo):
        return (
            fluxo["ip_origem"],
            fluxo["ip_destino"],
            fluxo["porta_origem"],
            fluxo["porta_destino"],
            fluxo["protocolo"],
        )

    def atualizar_fluxo(self, fluxo):
        """Soma o fluxo recebido ao estado agregado. Devolve uma tupla
        (chave, registro_atualizado, é_novo)."""
        chave = self.chave_fluxo(fluxo)
        e_novo = chave not in self.fluxos

        if e_novo:
            self.fluxos[chave] = {
                "ip_origem": fluxo["ip_origem"],
                "ip_destino": fluxo["ip_destino"],
                "porta_origem": fluxo["porta_origem"],
                "porta_destino": fluxo["porta_destino"],
                "protocolo": fluxo["protocolo"],
                "pacotes": 0,
                "bytes": 0,
                "ultimo": fluxo["horario"],
            }

        registro = self.fluxos[chave]
        registro["pacotes"] += 1
        registro["bytes"] += fluxo["bytes"]
        registro["ultimo"] = fluxo["horario"]

        return chave, registro, e_novo

    def obter_fluxos(self):
        return self.fluxos

    def limpar(self):
        self.fluxos = {}

    @staticmethod
    def fluxo_passou_filtro(fluxo, filtro_ip=None, filtro_porta=None, filtro_protocolo=None):
        if filtro_ip:
            if filtro_ip not in fluxo["ip_origem"] and filtro_ip not in fluxo["ip_destino"]:
                return False

        if filtro_porta:
            if (
                str(filtro_porta) != str(fluxo["porta_origem"])
                and str(filtro_porta) != str(fluxo["porta_destino"])
            ):
                return False

        if filtro_protocolo and filtro_protocolo != "Todos":
            if fluxo["protocolo"] != filtro_protocolo:
                return False

        return True
