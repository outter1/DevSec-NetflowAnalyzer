# SPDX-License-Identifier: MIT
# Copyright (c) 2026 KillChain
# Copyright (c) 2026 Gabriel Silva Bastos
# Copyright (c) 2026 Matheus Dominato
# Copyright (c) 2026 Isabelle Guimarães de Andrade
# Copyright (c) 2026 Nicolas Urtiaga
# Copyright (c) 2026 Pedro Lages da Silva

"""
Definições do schema SQLite do DevSec - NetFlow Analyzer.

As instruções usam ``IF NOT EXISTS`` para permitir que instalações antigas
sejam atualizadas sem apagar fluxos, alertas ou evidências já coletadas.
"""

SQL_CRIAR_FLUXOS = """
CREATE TABLE IF NOT EXISTS fluxos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_origem TEXT NOT NULL,
    ip_destino TEXT NOT NULL,
    porta_origem INTEGER NOT NULL,
    porta_destino INTEGER NOT NULL,
    protocolo TEXT NOT NULL,
    pacotes INTEGER NOT NULL DEFAULT 0,
    bytes INTEGER NOT NULL DEFAULT 0,
    primeiro_evento TEXT NOT NULL,
    ultimo_evento TEXT NOT NULL,
    UNIQUE(ip_origem, ip_destino, porta_origem, porta_destino, protocolo)
);
"""

SQL_CRIAR_ALERTAS = """
CREATE TABLE IF NOT EXISTS alertas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL UNIQUE,
    severidade TEXT NOT NULL,
    motivo TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Suspeito',
    eventos INTEGER NOT NULL DEFAULT 1,
    primeiro_evento TEXT NOT NULL,
    ultimo_evento TEXT NOT NULL
);
"""

SQL_CRIAR_LOG_EVENTOS = """
CREATE TABLE IF NOT EXISTS log_eventos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    data_hora TEXT NOT NULL,
    ip TEXT,
    mensagem TEXT NOT NULL
);
"""

SQL_CRIAR_IPS_BLOQUEADOS = """
CREATE TABLE IF NOT EXISTS ips_bloqueados (
    ip TEXT PRIMARY KEY,
    bloqueado_em TEXT NOT NULL
);
"""

SQL_CRIAR_IP_BLACKLIST = """
CREATE TABLE IF NOT EXISTS ip_blacklist (
    ip TEXT PRIMARY KEY,
    motivo TEXT,
    adicionado_em TEXT NOT NULL
);
"""

SQL_CRIAR_WHITELIST = """
CREATE TABLE IF NOT EXISTS whitelist (
    ip TEXT PRIMARY KEY,
    adicionado_em TEXT NOT NULL
);
"""

SQL_CRIAR_DISPOSITIVOS = """
CREATE TABLE IF NOT EXISTS dispositivos (
    ip TEXT PRIMARY KEY,
    hostname TEXT,
    mac TEXT,
    status TEXT NOT NULL DEFAULT 'Ativo',
    conexoes INTEGER NOT NULL DEFAULT 0,
    primeiro_visto TEXT NOT NULL,
    ultimo_visto TEXT NOT NULL
);
"""

SQL_CRIAR_DOMINIOS_ACESSADOS = """
CREATE TABLE IF NOT EXISTS dominios_acessados (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_cliente TEXT NOT NULL,
    dominio TEXT NOT NULL,
    ip_destino TEXT,
    porta_destino INTEGER,
    fonte TEXT NOT NULL,
    bloqueado_pela_politica INTEGER NOT NULL DEFAULT 0,
    observado_em TEXT NOT NULL
);
"""

SQL_CRIAR_DOMAIN_BLACKLIST = """
CREATE TABLE IF NOT EXISTS domain_blacklist (
    dominio TEXT NOT NULL,
    ip_cliente TEXT NOT NULL DEFAULT '*',
    modo TEXT NOT NULL DEFAULT 'monitorar',
    ativo INTEGER NOT NULL DEFAULT 1,
    ips_resolvidos TEXT NOT NULL DEFAULT '[]',
    ultimo_erro TEXT,
    adicionado_em TEXT NOT NULL,
    atualizado_em TEXT NOT NULL,
    PRIMARY KEY (dominio, ip_cliente)
);
"""


SQL_CRIAR_LOGS_AUDITORIA = """
CREATE TABLE IF NOT EXISTS logs_auditoria (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_acao TEXT NOT NULL,
    usuario_analista TEXT NOT NULL,
    acao_realizada TEXT NOT NULL,
    detalhes TEXT,
    ip_origem_analista TEXT
);
"""

SQL_CRIAR_CONFIGURACOES = """
CREATE TABLE IF NOT EXISTS configuracoes (
    chave TEXT PRIMARY KEY,
    valor TEXT
);
"""

SQL_INDICE_FLUXOS_ULTIMO = """
CREATE INDEX IF NOT EXISTS idx_fluxos_ultimo_evento
ON fluxos(ultimo_evento DESC);
"""

SQL_INDICE_ALERTAS_ULTIMO = """
CREATE INDEX IF NOT EXISTS idx_alertas_ultimo_evento
ON alertas(ultimo_evento DESC);
"""

SQL_INDICE_DOMINIOS_TEMPO = """
CREATE INDEX IF NOT EXISTS idx_dominios_observado_em
ON dominios_acessados(observado_em DESC);
"""

SQL_INDICE_DOMINIOS_CLIENTE = """
CREATE INDEX IF NOT EXISTS idx_dominios_cliente_tempo
ON dominios_acessados(ip_cliente, observado_em DESC);
"""

SQL_INDICE_DOMINIOS_NOME = """
CREATE INDEX IF NOT EXISTS idx_dominios_nome_tempo
ON dominios_acessados(dominio, observado_em DESC);
"""

TABELAS = (
    SQL_CRIAR_FLUXOS,
    SQL_CRIAR_ALERTAS,
    SQL_CRIAR_LOG_EVENTOS,
    SQL_CRIAR_IPS_BLOQUEADOS,
    SQL_CRIAR_IP_BLACKLIST,
    SQL_CRIAR_WHITELIST,
    SQL_CRIAR_DISPOSITIVOS,
    SQL_CRIAR_DOMINIOS_ACESSADOS,
    SQL_CRIAR_DOMAIN_BLACKLIST,
    SQL_CRIAR_LOGS_AUDITORIA,
    SQL_CRIAR_CONFIGURACOES,
    SQL_INDICE_FLUXOS_ULTIMO,
    SQL_INDICE_ALERTAS_ULTIMO,
    SQL_INDICE_DOMINIOS_TEMPO,
    SQL_INDICE_DOMINIOS_CLIENTE,
    SQL_INDICE_DOMINIOS_NOME,
)

CONFIGURACOES_PADRAO = {
    "interface_rede": "",
    "portas_sensiveis": (
        '[{"porta": 22, "nome": "SSH", "severidade": "MÉDIO"},'
        '{"porta": 23, "nome": "Telnet", "severidade": "ALTO"},'
        '{"porta": 445, "nome": "SMB", "severidade": "ALTO"},'
        '{"porta": 3389, "nome": "RDP", "severidade": "ALTO"}]'
    ),
    "limite_portas_scan": "15",
    "janela_scan_segundos": "10",
    "retencao_dominios_horas": "168",
}
