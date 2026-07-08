"""
Definições de esquema (schema) do banco de dados SQLite do DevSec - NetFlow Analyzer.

Cada string SQL_CRIAR_* cria uma tabela apenas se ela ainda não existir,
para que o schema possa ser aplicado com segurança toda vez que o app iniciar.
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

SQL_CRIAR_CONFIGURACOES = """
CREATE TABLE IF NOT EXISTS configuracoes (
    chave TEXT PRIMARY KEY,
    valor TEXT
);
"""

TABELAS = (
    SQL_CRIAR_FLUXOS,
    SQL_CRIAR_ALERTAS,
    SQL_CRIAR_LOG_EVENTOS,
    SQL_CRIAR_IPS_BLOQUEADOS,
    SQL_CRIAR_WHITELIST,
    SQL_CRIAR_DISPOSITIVOS,
    SQL_CRIAR_CONFIGURACOES,
)

# Configurações padrão gravadas na primeira execução (chave -> valor em texto/JSON)
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
}
