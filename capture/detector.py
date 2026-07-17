# SPDX-License-Identifier: MIT
# Copyright (c) 2026 DEVSEC
# Copyright (c) 2026 Gabriel Silva Bastos
# Copyright (c) 2026 Matheus Dominato
# Copyright (c) 2026 Isabelle Guimarães de Andrade
# Copyright (c) 2026 Nicolas Urtiaga
# Copyright (c) 2026 Pedro Lages da Silva

"""
Motor de detecção do DevSec - NetFlow Analyzer.

Duas estratégias de detecção, propositalmente simples e explicáveis
(nada de "caixa preta"), pensadas para um projeto educacional de Blue Team:

1. Portas sensíveis: qualquer fluxo cuja porta de destino esteja na lista
   configurável (SSH, Telnet, SMB, RDP, etc.) gera um alerta imediato.

2. Varredura de portas (port scan): se um mesmo IP de origem falar com
   muitas portas de destino diferentes em uma janela curta de tempo,
   isso é um forte indício de scan (ex.: nmap -p 1-1000). Esse é o tipo
   de comportamento que dá pra gerar de propósito com Nmap para validar
   a ferramenta (o lado "Red Team" do projeto).
"""

from collections import defaultdict, deque
from datetime import datetime, timedelta

NIVEIS_SEVERIDADE = {"BAIXO": 1, "MÉDIO": 2, "ALTO": 3, "CRÍTICO": 4}


def severidade_maior(nova, atual):
    return NIVEIS_SEVERIDADE.get(nova, 0) > NIVEIS_SEVERIDADE.get(atual, 0)


class Detector:
    def __init__(self, portas_sensiveis=None, limite_portas_scan=15, janela_scan_segundos=10):
        # Lista de dicts: {"porta": int, "nome": str, "severidade": str}
        self.portas_sensiveis = portas_sensiveis or [
            {"porta": 22, "nome": "SSH", "severidade": "MÉDIO"},
            {"porta": 23, "nome": "Telnet", "severidade": "ALTO"},
            {"porta": 445, "nome": "SMB", "severidade": "ALTO"},
            {"porta": 3389, "nome": "RDP", "severidade": "ALTO"},
        ]

        self.limite_portas_scan = limite_portas_scan
        self.janela_scan = timedelta(seconds=janela_scan_segundos)

        # ip_origem -> deque[(timestamp, porta_destino)] para detectar scan
        self._historico_portas = defaultdict(deque)
        # evita repetir o alerta de scan a cada pacote novo do mesmo IP
        self._ips_scan_ja_alertados = set()

    def atualizar_portas_sensiveis(self, portas_sensiveis):
        self.portas_sensiveis = portas_sensiveis

    def _mapa_portas_sensiveis(self):
        return {item["porta"]: item for item in self.portas_sensiveis}

    def verificar_fluxo(self, fluxo, whitelist=None):
        """Recebe um fluxo (dict) e devolve uma lista de alertas gerados
        (pode ser vazia). Cada alerta é um dict:
        {"ip": ..., "severidade": ..., "motivo": ..., "mensagem": ...}
        """
        whitelist = whitelist or set()
        ip_origem = fluxo["ip_origem"]
        ip_destino = fluxo["ip_destino"]
        porta_destino = fluxo["porta_destino"]

        if ip_origem in whitelist:
            return []

        alertas = []

        mapa = self._mapa_portas_sensiveis()
        if porta_destino in mapa:
            info = mapa[porta_destino]
            mensagem = (
                f"[{info['severidade']}] Conexão {info['nome']} detectada: "
                f"{ip_origem} -> {ip_destino}:{porta_destino}"
            )
            alertas.append(
                {
                    "ip": ip_origem,
                    "severidade": info["severidade"],
                    "motivo": f"Conexão {info['nome']} detectada",
                    "mensagem": mensagem,
                }
            )

        alerta_scan = self._verificar_varredura_portas(ip_origem, ip_destino, porta_destino)
        if alerta_scan:
            alertas.append(alerta_scan)

        return alertas

    def _verificar_varredura_portas(self, ip_origem, ip_destino, porta_destino):
        agora = datetime.now()
        historico = self._historico_portas[ip_origem]

        historico.append((agora, porta_destino))

        while historico and (agora - historico[0][0]) > self.janela_scan:
            historico.popleft()

        portas_distintas = {porta for _, porta in historico}

        if len(portas_distintas) >= self.limite_portas_scan:
            if ip_origem in self._ips_scan_ja_alertados:
                return None

            self._ips_scan_ja_alertados.add(ip_origem)

            mensagem = (
                f"[CRÍTICO] Possível varredura de portas (port scan): {ip_origem} "
                f"acessou {len(portas_distintas)} portas diferentes em "
                f"{self.janela_scan.seconds}s (destino mais recente: {ip_destino}:{porta_destino})"
            )

            return {
                "ip": ip_origem,
                "severidade": "CRÍTICO",
                "motivo": f"Varredura de portas: {len(portas_distintas)} portas em {self.janela_scan.seconds}s",
                "mensagem": mensagem,
            }

        if len(portas_distintas) < max(1, self.limite_portas_scan // 2):
            self._ips_scan_ja_alertados.discard(ip_origem)

        return None
