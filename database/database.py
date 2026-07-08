"""
Camada de persistência do DevSec - NetFlow Analyzer.

Usa SQLite (biblioteca padrão do Python) para guardar fluxos, alertas,
IPs bloqueados, whitelist, dispositivos e configurações. Isso transforma
o software de "só monitoramento em tempo real" em uma ferramenta que também
guarda histórico para investigação forense.

A classe é pensada para ser usada a partir de múltiplas threads (a thread
de captura de pacotes e a thread principal da interface gráfica), por isso
usa check_same_thread=False e um Lock para serializar o acesso.
"""

import json
import os
import sqlite3
import threading
from datetime import datetime

from database.models import TABELAS, CONFIGURACOES_PADRAO

CAMINHO_BANCO_PADRAO = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "devsec_netflow.db",
)


class Database:
    def __init__(self, caminho_banco=CAMINHO_BANCO_PADRAO):
        self.caminho_banco = caminho_banco
        self._lock = threading.Lock()
        self._conexao = sqlite3.connect(self.caminho_banco, check_same_thread=False)
        self._conexao.row_factory = sqlite3.Row
        self._configurar_sqlite()
        self._criar_schema()
        self._aplicar_configuracoes_padrao()

    # ------------------------------------------------------------------ #
    # Infraestrutura
    # ------------------------------------------------------------------ #
    def _configurar_sqlite(self):
        """Configura o SQLite para aguentar gravações constantes sem travar a UI.

        WAL permite leitura e escrita com menos bloqueio. synchronous=NORMAL reduz
        custo de fsync sem abrir mão da segurança suficiente para este projeto.
        busy_timeout evita erro imediato quando uma transação curta estiver ativa.
        """
        with self._lock:
            self._conexao.execute("PRAGMA journal_mode=WAL;")
            self._conexao.execute("PRAGMA synchronous=NORMAL;")
            self._conexao.execute("PRAGMA temp_store=MEMORY;")
            self._conexao.execute("PRAGMA cache_size=-20000;")
            self._conexao.execute("PRAGMA busy_timeout=5000;")
            self._conexao.execute("PRAGMA foreign_keys = ON;")

    def _criar_schema(self):
        with self._lock:
            cursor = self._conexao.cursor()
            for sql in TABELAS:
                cursor.execute(sql)
            self._conexao.commit()

    def _aplicar_configuracoes_padrao(self):
        for chave, valor in CONFIGURACOES_PADRAO.items():
            if self.obter_configuracao(chave) is None:
                self.definir_configuracao(chave, valor)

    def fechar(self):
        with self._lock:
            self._conexao.close()

    @staticmethod
    def _agora():
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ------------------------------------------------------------------ #
    # Fluxos
    # ------------------------------------------------------------------ #
    def salvar_fluxo(self, fluxo):
        """Insere o fluxo ou soma pacotes/bytes se ele já existir (upsert)."""
        agora = self._agora()

        with self._lock:
            cursor = self._conexao.cursor()
            cursor.execute(
                """
                INSERT INTO fluxos (
                    ip_origem, ip_destino, porta_origem, porta_destino,
                    protocolo, pacotes, bytes, primeiro_evento, ultimo_evento
                )
                VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)
                ON CONFLICT(ip_origem, ip_destino, porta_origem, porta_destino, protocolo)
                DO UPDATE SET
                    pacotes = pacotes + 1,
                    bytes = bytes + excluded.bytes,
                    ultimo_evento = excluded.ultimo_evento
                """,
                (
                    fluxo["ip_origem"],
                    fluxo["ip_destino"],
                    fluxo["porta_origem"],
                    fluxo["porta_destino"],
                    fluxo["protocolo"],
                    fluxo["bytes"],
                    agora,
                    agora,
                ),
            )
            self._conexao.commit()

    def salvar_fluxos_lote(self, fluxos):
        """Salva vários fluxos em uma única transação.

        Em captura real chegam muitos pacotes por segundo. Gravar um commit por
        pacote deixa a interface travada. Aqui agregamos por chave de fluxo e
        fazemos um único commit para o lote inteiro.
        """
        if not fluxos:
            return

        agora = self._agora()
        agregados = {}

        for fluxo in fluxos:
            chave = (
                fluxo["ip_origem"],
                fluxo["ip_destino"],
                fluxo["porta_origem"],
                fluxo["porta_destino"],
                fluxo["protocolo"],
            )

            if chave not in agregados:
                agregados[chave] = {"pacotes": 0, "bytes": 0}

            agregados[chave]["pacotes"] += 1
            agregados[chave]["bytes"] += int(fluxo.get("bytes", 0))

        linhas = [
            (
                chave[0],
                chave[1],
                chave[2],
                chave[3],
                chave[4],
                dados["pacotes"],
                dados["bytes"],
                agora,
                agora,
            )
            for chave, dados in agregados.items()
        ]

        with self._lock:
            cursor = self._conexao.cursor()
            cursor.executemany(
                """
                INSERT INTO fluxos (
                    ip_origem, ip_destino, porta_origem, porta_destino,
                    protocolo, pacotes, bytes, primeiro_evento, ultimo_evento
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip_origem, ip_destino, porta_origem, porta_destino, protocolo)
                DO UPDATE SET
                    pacotes = pacotes + excluded.pacotes,
                    bytes = bytes + excluded.bytes,
                    ultimo_evento = excluded.ultimo_evento
                """,
                linhas,
            )
            self._conexao.commit()


    def listar_fluxos(self, limite=500):
        with self._lock:
            cursor = self._conexao.cursor()
            cursor.execute(
                "SELECT * FROM fluxos ORDER BY ultimo_evento DESC LIMIT ?",
                (limite,),
            )
            return [dict(linha) for linha in cursor.fetchall()]

    def limpar_fluxos(self):
        with self._lock:
            cursor = self._conexao.cursor()
            cursor.execute("DELETE FROM fluxos")
            self._conexao.commit()

    # ------------------------------------------------------------------ #
    # Alertas / IPs suspeitos
    # ------------------------------------------------------------------ #
    def registrar_alerta(self, ip, severidade, motivo):
        agora = self._agora()

        with self._lock:
            cursor = self._conexao.cursor()
            cursor.execute("SELECT * FROM alertas WHERE ip = ?", (ip,))
            existente = cursor.fetchone()

            if existente is None:
                cursor.execute(
                    """
                    INSERT INTO alertas (
                        ip, severidade, motivo, status, eventos,
                        primeiro_evento, ultimo_evento
                    )
                    VALUES (?, ?, ?, 'Suspeito', 1, ?, ?)
                    """,
                    (ip, severidade, motivo, agora, agora),
                )
            else:
                severidade_final = severidade
                niveis = {"BAIXO": 1, "MÉDIO": 2, "ALTO": 3, "CRÍTICO": 4}
                if niveis.get(existente["severidade"], 0) > niveis.get(severidade, 0):
                    severidade_final = existente["severidade"]

                cursor.execute(
                    """
                    UPDATE alertas
                    SET severidade = ?, motivo = ?, eventos = eventos + 1,
                        ultimo_evento = ?
                    WHERE ip = ?
                    """,
                    (severidade_final, motivo, agora, ip),
                )

            self._conexao.commit()

    def registrar_alertas_lote(self, alertas):
        """Registra vários alertas em uma única transação."""
        if not alertas:
            return

        agora = self._agora()
        niveis = {"BAIXO": 1, "MÉDIO": 2, "ALTO": 3, "CRÍTICO": 4}

        with self._lock:
            cursor = self._conexao.cursor()

            for alerta in alertas:
                ip = alerta["ip"]
                severidade = alerta["severidade"]
                motivo = alerta["motivo"]

                cursor.execute("SELECT severidade FROM alertas WHERE ip = ?", (ip,))
                existente = cursor.fetchone()

                if existente is not None and niveis.get(existente["severidade"], 0) > niveis.get(severidade, 0):
                    severidade = existente["severidade"]

                cursor.execute(
                    """
                    INSERT INTO alertas (
                        ip, severidade, motivo, status, eventos,
                        primeiro_evento, ultimo_evento
                    )
                    VALUES (?, ?, ?, 'Suspeito', 1, ?, ?)
                    ON CONFLICT(ip)
                    DO UPDATE SET
                        severidade = excluded.severidade,
                        motivo = excluded.motivo,
                        eventos = eventos + 1,
                        ultimo_evento = excluded.ultimo_evento
                    """,
                    (ip, severidade, motivo, agora, agora),
                )

            self._conexao.commit()

    def atualizar_status_ip(self, ip, status, severidade=None, motivo=None):
        agora = self._agora()

        with self._lock:
            cursor = self._conexao.cursor()

            if severidade is not None and motivo is not None:
                cursor.execute(
                    """
                    UPDATE alertas
                    SET status = ?, severidade = ?, motivo = ?, ultimo_evento = ?
                    WHERE ip = ?
                    """,
                    (status, severidade, motivo, agora, ip),
                )
            else:
                cursor.execute(
                    "UPDATE alertas SET status = ?, ultimo_evento = ? WHERE ip = ?",
                    (status, agora, ip),
                )

            self._conexao.commit()

    def listar_alertas(self):
        with self._lock:
            cursor = self._conexao.cursor()
            cursor.execute("SELECT * FROM alertas ORDER BY ultimo_evento DESC")
            return [dict(linha) for linha in cursor.fetchall()]

    def obter_alerta(self, ip):
        with self._lock:
            cursor = self._conexao.cursor()
            cursor.execute("SELECT * FROM alertas WHERE ip = ?", (ip,))
            linha = cursor.fetchone()
            return dict(linha) if linha else None

    # ------------------------------------------------------------------ #
    # Log de eventos (histórico bruto, útil para forense)
    # ------------------------------------------------------------------ #
    def registrar_log(self, mensagem, ip=None):
        agora = self._agora()

        with self._lock:
            cursor = self._conexao.cursor()
            cursor.execute(
                "INSERT INTO log_eventos (data_hora, ip, mensagem) VALUES (?, ?, ?)",
                (agora, ip, mensagem),
            )
            self._conexao.commit()

    def registrar_logs_lote(self, logs):
        """Registra vários logs em uma única transação."""
        if not logs:
            return

        agora = self._agora()
        linhas = [(agora, log.get("ip"), log["mensagem"]) for log in logs]

        with self._lock:
            cursor = self._conexao.cursor()
            cursor.executemany(
                "INSERT INTO log_eventos (data_hora, ip, mensagem) VALUES (?, ?, ?)",
                linhas,
            )
            self._conexao.commit()

    def listar_log(self, limite=1000, ip=None):
        with self._lock:
            cursor = self._conexao.cursor()
            if ip:
                cursor.execute(
                    "SELECT * FROM log_eventos WHERE ip = ? ORDER BY id DESC LIMIT ?",
                    (ip, limite),
                )
            else:
                cursor.execute(
                    "SELECT * FROM log_eventos ORDER BY id DESC LIMIT ?", (limite,)
                )
            return [dict(linha) for linha in cursor.fetchall()]

    # ------------------------------------------------------------------ #
    # IPs bloqueados / whitelist
    # ------------------------------------------------------------------ #
    def bloquear_ip(self, ip):
        with self._lock:
            cursor = self._conexao.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO ips_bloqueados (ip, bloqueado_em) VALUES (?, ?)",
                (ip, self._agora()),
            )
            self._conexao.commit()

    def desbloquear_ip(self, ip):
        with self._lock:
            cursor = self._conexao.cursor()
            cursor.execute("DELETE FROM ips_bloqueados WHERE ip = ?", (ip,))
            self._conexao.commit()

    def listar_ips_bloqueados(self):
        with self._lock:
            cursor = self._conexao.cursor()
            cursor.execute("SELECT ip FROM ips_bloqueados")
            return [linha["ip"] for linha in cursor.fetchall()]

    def adicionar_whitelist(self, ip):
        with self._lock:
            cursor = self._conexao.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO whitelist (ip, adicionado_em) VALUES (?, ?)",
                (ip, self._agora()),
            )
            self._conexao.commit()

    def remover_whitelist(self, ip):
        with self._lock:
            cursor = self._conexao.cursor()
            cursor.execute("DELETE FROM whitelist WHERE ip = ?", (ip,))
            self._conexao.commit()

    def listar_whitelist(self):
        with self._lock:
            cursor = self._conexao.cursor()
            cursor.execute("SELECT ip FROM whitelist")
            return [linha["ip"] for linha in cursor.fetchall()]

    # ------------------------------------------------------------------ #
    # Dispositivos
    # ------------------------------------------------------------------ #
    def registrar_dispositivo(self, ip, hostname=None, mac=None):
        agora = self._agora()

        with self._lock:
            cursor = self._conexao.cursor()
            cursor.execute("SELECT * FROM dispositivos WHERE ip = ?", (ip,))
            existente = cursor.fetchone()

            if existente is None:
                cursor.execute(
                    """
                    INSERT INTO dispositivos (
                        ip, hostname, mac, status, conexoes,
                        primeiro_visto, ultimo_visto
                    )
                    VALUES (?, ?, ?, 'Ativo', 1, ?, ?)
                    """,
                    (ip, hostname, mac, agora, agora),
                )
            else:
                cursor.execute(
                    """
                    UPDATE dispositivos
                    SET hostname = COALESCE(?, hostname),
                        mac = COALESCE(?, mac),
                        conexoes = conexoes + 1,
                        ultimo_visto = ?,
                        status = 'Ativo'
                    WHERE ip = ?
                    """,
                    (hostname, mac, agora, ip),
                )

            self._conexao.commit()

    def registrar_dispositivos_lote(self, ips):
        """Atualiza vários dispositivos em uma única transação."""
        if not ips:
            return

        agora = self._agora()
        contagem = {}
        for ip in ips:
            if not ip:
                continue
            contagem[ip] = contagem.get(ip, 0) + 1

        if not contagem:
            return

        linhas = [(ip, quantidade, agora, agora) for ip, quantidade in contagem.items()]

        with self._lock:
            cursor = self._conexao.cursor()
            cursor.executemany(
                """
                INSERT INTO dispositivos (
                    ip, status, conexoes, primeiro_visto, ultimo_visto
                )
                VALUES (?, 'Ativo', ?, ?, ?)
                ON CONFLICT(ip)
                DO UPDATE SET
                    conexoes = conexoes + excluded.conexoes,
                    ultimo_visto = excluded.ultimo_visto,
                    status = 'Ativo'
                """,
                linhas,
            )
            self._conexao.commit()

    def listar_dispositivos(self):
        with self._lock:
            cursor = self._conexao.cursor()
            cursor.execute("SELECT * FROM dispositivos ORDER BY ultimo_visto DESC")
            return [dict(linha) for linha in cursor.fetchall()]

    # ------------------------------------------------------------------ #
    # Configurações
    # ------------------------------------------------------------------ #
    def definir_configuracao(self, chave, valor):
        with self._lock:
            cursor = self._conexao.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO configuracoes (chave, valor) VALUES (?, ?)",
                (chave, valor),
            )
            self._conexao.commit()

    def obter_configuracao(self, chave, padrao=None):
        with self._lock:
            cursor = self._conexao.cursor()
            cursor.execute("SELECT valor FROM configuracoes WHERE chave = ?", (chave,))
            linha = cursor.fetchone()
            return linha["valor"] if linha else padrao

    def obter_portas_sensiveis(self):
        bruto = self.obter_configuracao(
            "portas_sensiveis", CONFIGURACOES_PADRAO["portas_sensiveis"]
        )
        return json.loads(bruto)

    def definir_portas_sensiveis(self, lista_portas):
        self.definir_configuracao("portas_sensiveis", json.dumps(lista_portas))
