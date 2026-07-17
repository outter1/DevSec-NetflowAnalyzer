# SPDX-License-Identifier: MIT
# Copyright (c) 2026 KillChain
# Copyright (c) 2026 Gabriel Silva Bastos
# Copyright (c) 2026 Matheus Dominato
# Copyright (c) 2026 Isabelle Guimarães de Andrade
# Copyright (c) 2026 Nicolas Urtiaga
# Copyright (c) 2026 Pedro Lages da Silva

"""
Geração de evidências / relatórios do DevSec - NetFlow Analyzer:

- CSV de fluxos capturados
- CSV de alertas / IPs suspeitos
- PDF com relatório geral (resumo + fluxos + alertas)
- PDF de investigação de um único IP suspeito (relatório forense pontual)

Usa apenas `csv` (biblioteca padrão) e `reportlab` (já usado por muitos
projetos Python para gerar PDF sem depender de LaTeX/wkhtmltopdf).
"""

import csv
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

COLUNAS_FLUXOS = [
    "ip_origem",
    "ip_destino",
    "porta_origem",
    "porta_destino",
    "protocolo",
    "pacotes",
    "bytes",
    "ultimo_evento",
]

CABECALHO_FLUXOS = [
    "IP Origem",
    "IP Destino",
    "Porta Origem",
    "Porta Destino",
    "Protocolo",
    "Pacotes",
    "Bytes",
    "Último Evento",
]

COLUNAS_ALERTAS = [
    "ip",
    "severidade",
    "motivo",
    "status",
    "eventos",
    "ultimo_evento",
]

CABECALHO_ALERTAS = [
    "IP",
    "Severidade",
    "Motivo",
    "Status",
    "Eventos",
    "Último Evento",
]


# ---------------------------------------------------------------------- #
# CSV
# ---------------------------------------------------------------------- #
def exportar_fluxos_csv(fluxos, caminho):
    """fluxos: lista de dicts (ex.: Database.listar_fluxos())"""
    with open(caminho, "w", newline="", encoding="utf-8-sig") as arquivo:
        escritor = csv.writer(arquivo)
        escritor.writerow(CABECALHO_FLUXOS)

        for fluxo in fluxos:
            escritor.writerow([fluxo.get(coluna, "") for coluna in COLUNAS_FLUXOS])

    return caminho


def exportar_alertas_csv(alertas, caminho):
    """alertas: lista de dicts (ex.: Database.listar_alertas())"""
    with open(caminho, "w", newline="", encoding="utf-8-sig") as arquivo:
        escritor = csv.writer(arquivo)
        escritor.writerow(CABECALHO_ALERTAS)

        for alerta in alertas:
            escritor.writerow([alerta.get(coluna, "") for coluna in COLUNAS_ALERTAS])

    return caminho


# ---------------------------------------------------------------------- #
# PDF
# ---------------------------------------------------------------------- #
def _cabecalho_relatorio(titulo, estilos):
    elementos = [
        Paragraph("DevSec - NetFlow Analyzer", estilos["Title"]),
        Paragraph(titulo, estilos["Heading2"]),
        Paragraph(
            f"Gerado em: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}",
            estilos["Normal"],
        ),
        Spacer(1, 0.6 * cm),
    ]
    return elementos


def _tabela_estilizada(dados):
    tabela = Table(dados, repeatRows=1)
    tabela.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3f4f6")]),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    return tabela


def exportar_relatorio_pdf(caminho, resumo, fluxos, alertas):
    """
    resumo: dict com contadores gerais, ex.:
        {"total_fluxos": .., "total_suspeitos": .., "total_bloqueados": .., "status_captura": ..}
    fluxos: lista de dicts
    alertas: lista de dicts
    """
    estilos = getSampleStyleSheet()
    documento = SimpleDocTemplate(caminho, pagesize=A4, title="Relatório DevSec NetFlow Analyzer")
    elementos = _cabecalho_relatorio("Relatório Geral de Tráfego e Alertas", estilos)

    elementos.append(Paragraph("Resumo", estilos["Heading3"]))
    linhas_resumo = [
        ["Fluxos monitorados", str(resumo.get("total_fluxos", 0))],
        ["IPs suspeitos", str(resumo.get("total_suspeitos", 0))],
        ["IPs bloqueados", str(resumo.get("total_bloqueados", 0))],
        ["Status da captura", str(resumo.get("status_captura", "Parada"))],
    ]
    elementos.append(_tabela_estilizada(linhas_resumo))
    elementos.append(Spacer(1, 0.8 * cm))

    elementos.append(Paragraph("Fluxos de rede (mais recentes primeiro)", estilos["Heading3"]))
    dados_fluxos = [CABECALHO_FLUXOS] + [
        [str(fluxo.get(coluna, "")) for coluna in COLUNAS_FLUXOS] for fluxo in fluxos[:200]
    ]
    elementos.append(_tabela_estilizada(dados_fluxos))
    elementos.append(Spacer(1, 0.8 * cm))

    elementos.append(Paragraph("IPs suspeitos / alertas", estilos["Heading3"]))
    dados_alertas = [CABECALHO_ALERTAS] + [
        [str(alerta.get(coluna, "")) for coluna in COLUNAS_ALERTAS] for alerta in alertas
    ]
    elementos.append(_tabela_estilizada(dados_alertas))

    documento.build(elementos)
    return caminho


def exportar_relatorio_ip_pdf(caminho, alerta, eventos_log):
    """
    Relatório forense de investigação de um único IP.

    alerta: dict vindo de Database.obter_alerta(ip)
    eventos_log: lista de dicts vindos de Database.listar_log(ip=ip)
    """
    estilos = getSampleStyleSheet()
    documento = SimpleDocTemplate(caminho, pagesize=A4, title=f"Relatório do IP {alerta.get('ip')}")
    elementos = _cabecalho_relatorio(
        f"Relatório de Investigação - IP {alerta.get('ip', '?')}", estilos
    )

    elementos.append(Paragraph("Classificação atual", estilos["Heading3"]))
    linhas = [
        ["IP", alerta.get("ip", "")],
        ["Severidade", alerta.get("severidade", "")],
        ["Motivo", alerta.get("motivo", "")],
        ["Status", alerta.get("status", "")],
        ["Eventos", str(alerta.get("eventos", 0))],
        ["Primeiro evento", alerta.get("primeiro_evento", "")],
        ["Último evento", alerta.get("ultimo_evento", "")],
    ]
    elementos.append(_tabela_estilizada(linhas))
    elementos.append(Spacer(1, 0.8 * cm))

    elementos.append(Paragraph("Linha do tempo de eventos (log bruto)", estilos["Heading3"]))
    dados_log = [["Data/Hora", "Mensagem"]] + [
        [evento.get("data_hora", ""), evento.get("mensagem", "")] for evento in eventos_log
    ]
    elementos.append(_tabela_estilizada(dados_log))

    documento.build(elementos)
    return caminho
