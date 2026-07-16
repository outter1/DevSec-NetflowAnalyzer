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
from datetime import datetime, timedelta

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
        """Atualiza o alerta do IP e cria o registro quando ele ainda não existe.

        A versão anterior executava apenas ``UPDATE``. Assim, adicionar um IP
        diretamente à blacklist ou bloqueá-lo não aparecia na tela de alertas
        quando aquele IP ainda não tinha sido detectado pelo motor.
        """
        agora = self._agora()

        with self._lock:
            cursor = self._conexao.cursor()
            cursor.execute("SELECT severidade, motivo, eventos, primeiro_evento FROM alertas WHERE ip = ?", (ip,))
            existente = cursor.fetchone()

            severidade_final = severidade or (existente["severidade"] if existente else "MÉDIO")
            motivo_final = motivo or (existente["motivo"] if existente else f"Status alterado para {status}")

            if existente is None:
                cursor.execute(
                    """
                    INSERT INTO alertas (
                        ip, severidade, motivo, status, eventos,
                        primeiro_evento, ultimo_evento
                    ) VALUES (?, ?, ?, ?, 1, ?, ?)
                    """,
                    (ip, severidade_final, motivo_final, status, agora, agora),
                )
            else:
                cursor.execute(
                    """
                    UPDATE alertas
                    SET status = ?, severidade = ?, motivo = ?,
                        eventos = eventos + 1, ultimo_evento = ?
                    WHERE ip = ?
                    """,
                    (status, severidade_final, motivo_final, agora, ip),
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
    # Auditoria da interface web
    # ------------------------------------------------------------------ #
    def registrar_auditoria(self, usuario, acao, detalhes=None, ip_origem=None):
        with self._lock:
            cursor = self._conexao.cursor()
            cursor.execute(
                """
                INSERT INTO logs_auditoria (
                    timestamp_acao, usuario_analista, acao_realizada,
                    detalhes, ip_origem_analista
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (self._agora(), usuario, acao, detalhes, ip_origem),
            )
            self._conexao.commit()

    def listar_auditoria(self, limite=100):
        limite = max(1, min(int(limite), 2000))
        with self._lock:
            cursor = self._conexao.cursor()
            cursor.execute(
                "SELECT * FROM logs_auditoria ORDER BY id DESC LIMIT ?",
                (limite,),
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
            cursor.execute("SELECT ip FROM ips_bloqueados ORDER BY bloqueado_em DESC")
            return [linha["ip"] for linha in cursor.fetchall()]

    def listar_ips_bloqueados_detalhes(self):
        with self._lock:
            cursor = self._conexao.cursor()
            cursor.execute("SELECT * FROM ips_bloqueados ORDER BY bloqueado_em DESC")
            return [dict(linha) for linha in cursor.fetchall()]

    def adicionar_ip_blacklist(self, ip, motivo=None):
        with self._lock:
            cursor = self._conexao.cursor()
            cursor.execute(
                """
                INSERT INTO ip_blacklist (ip, motivo, adicionado_em)
                VALUES (?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    motivo = excluded.motivo,
                    adicionado_em = excluded.adicionado_em
                """,
                (ip, motivo, self._agora()),
            )
            self._conexao.commit()

    def remover_ip_blacklist(self, ip):
        with self._lock:
            cursor = self._conexao.cursor()
            cursor.execute("DELETE FROM ip_blacklist WHERE ip = ?", (ip,))
            self._conexao.commit()

    def listar_ip_blacklist(self):
        with self._lock:
            cursor = self._conexao.cursor()
            cursor.execute("SELECT * FROM ip_blacklist ORDER BY adicionado_em DESC")
            return [dict(linha) for linha in cursor.fetchall()]

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
    # Domínios observados / blacklist de domínios
    # ------------------------------------------------------------------ #
    def registrar_dominios_lote(self, observacoes):
        if not observacoes:
            return

        agora = self._agora()
        linhas = []
        for item in observacoes:
            dominio = (item.get("dominio") or "").strip().lower().rstrip(".")
            ip_cliente = (item.get("ip_cliente") or "").strip()
            if not dominio or not ip_cliente:
                continue
            linhas.append(
                (
                    ip_cliente,
                    dominio,
                    item.get("ip_destino"),
                    item.get("porta_destino"),
                    item.get("fonte") or "DESCONHECIDA",
                    1 if item.get("bloqueado_pela_politica") else 0,
                    item.get("observado_em") or agora,
                )
            )

        if not linhas:
            return

        with self._lock:
            cursor = self._conexao.cursor()
            cursor.executemany(
                """
                INSERT INTO dominios_acessados (
                    ip_cliente, dominio, ip_destino, porta_destino,
                    fonte, bloqueado_pela_politica, observado_em
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                linhas,
            )
            self._conexao.commit()

    def listar_dominios_recentes(self, segundos=30, limite=500, ip_cliente=None, dominio=None):
        segundos = max(1, min(int(segundos), 86400))
        limite = max(1, min(int(limite), 5000))
        desde = (datetime.now() - timedelta(seconds=segundos)).strftime("%Y-%m-%d %H:%M:%S")

        filtros = ["observado_em >= ?"]
        parametros = [desde]
        if ip_cliente:
            filtros.append("ip_cliente = ?")
            parametros.append(ip_cliente)
        if dominio:
            filtros.append("dominio LIKE ?")
            parametros.append(f"%{dominio.lower()}%")

        parametros.append(limite)
        sql = f"""
            SELECT * FROM dominios_acessados
            WHERE {' AND '.join(filtros)}
            ORDER BY observado_em DESC, id DESC
            LIMIT ?
        """
        with self._lock:
            cursor = self._conexao.cursor()
            cursor.execute(sql, tuple(parametros))
            return [dict(linha) for linha in cursor.fetchall()]

    def limpar_dominios_antigos(self, horas=168):
        horas = max(1, int(horas))
        limite = (datetime.now() - timedelta(hours=horas)).strftime("%Y-%m-%d %H:%M:%S")
        with self._lock:
            cursor = self._conexao.cursor()
            cursor.execute("DELETE FROM dominios_acessados WHERE observado_em < ?", (limite,))
            removidos = cursor.rowcount
            self._conexao.commit()
            return removidos

    def adicionar_domain_blacklist(self, dominio, ip_cliente="*", modo="monitorar"):
        agora = self._agora()
        with self._lock:
            cursor = self._conexao.cursor()
            cursor.execute(
                """
                INSERT INTO domain_blacklist (
                    dominio, ip_cliente, modo, ativo, ips_resolvidos,
                    ultimo_erro, adicionado_em, atualizado_em
                ) VALUES (?, ?, ?, 1, '[]', NULL, ?, ?)
                ON CONFLICT(dominio, ip_cliente) DO UPDATE SET
                    modo = excluded.modo,
                    ativo = 1,
                    atualizado_em = excluded.atualizado_em,
                    ultimo_erro = NULL
                """,
                (dominio, ip_cliente, modo, agora, agora),
            )
            self._conexao.commit()

    def remover_domain_blacklist(self, dominio, ip_cliente="*"):
        with self._lock:
            cursor = self._conexao.cursor()
            cursor.execute(
                "DELETE FROM domain_blacklist WHERE dominio = ? AND ip_cliente = ?",
                (dominio, ip_cliente),
            )
            self._conexao.commit()

    def listar_domain_blacklist(self, somente_ativos=False):
        with self._lock:
            cursor = self._conexao.cursor()
            if somente_ativos:
                cursor.execute(
                    "SELECT * FROM domain_blacklist WHERE ativo = 1 ORDER BY atualizado_em DESC"
                )
            else:
                cursor.execute("SELECT * FROM domain_blacklist ORDER BY atualizado_em DESC")
            resultado = []
            for linha in cursor.fetchall():
                item = dict(linha)
                try:
                    item["ips_resolvidos"] = json.loads(item.get("ips_resolvidos") or "[]")
                except json.JSONDecodeError:
                    item["ips_resolvidos"] = []
                resultado.append(item)
            return resultado

    def obter_domain_blacklist(self, dominio, ip_cliente="*"):
        with self._lock:
            cursor = self._conexao.cursor()
            cursor.execute(
                "SELECT * FROM domain_blacklist WHERE dominio = ? AND ip_cliente = ?",
                (dominio, ip_cliente),
            )
            linha = cursor.fetchone()
            if not linha:
                return None
            item = dict(linha)
            try:
                item["ips_resolvidos"] = json.loads(item.get("ips_resolvidos") or "[]")
            except json.JSONDecodeError:
                item["ips_resolvidos"] = []
            return item

    def atualizar_resolucao_domain_blacklist(self, dominio, ip_cliente, ips, erro=None):
        with self._lock:
            cursor = self._conexao.cursor()
            cursor.execute(
                """
                UPDATE domain_blacklist
                SET ips_resolvidos = ?, ultimo_erro = ?, atualizado_em = ?
                WHERE dominio = ? AND ip_cliente = ?
                """,
                (json.dumps(sorted(set(ips))), erro, self._agora(), dominio, ip_cliente),
            )
            self._conexao.commit()

    def dominio_esta_bloqueado(self, dominio, ip_cliente):
        dominio = dominio.lower().rstrip(".")
        with self._lock:
            cursor = self._conexao.cursor()
            cursor.execute(
                """
                SELECT * FROM domain_blacklist
                WHERE ativo = 1
                  AND (ip_cliente = '*' OR ip_cliente = ?)
                  AND (? = dominio OR ? LIKE '%.' || dominio)
                ORDER BY CASE WHEN ip_cliente = ? THEN 0 ELSE 1 END
                LIMIT 1
                """,
                (ip_cliente, dominio, dominio, ip_cliente),
            )
            linha = cursor.fetchone()
            return dict(linha) if linha else None

    def obter_resumo(self, segundos_dominios=30):
        desde = (datetime.now() - timedelta(seconds=max(1, int(segundos_dominios)))).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        with self._lock:
            cursor = self._conexao.cursor()
            tabelas = {
                "total_fluxos": "fluxos",
                "total_alertas": "alertas",
                "total_bloqueados": "ips_bloqueados",
                "total_blacklist": "ip_blacklist",
                "total_dispositivos": "dispositivos",
                "total_domain_blacklist": "domain_blacklist",
            }
            resumo = {}
            for chave, tabela in tabelas.items():
                cursor.execute(f"SELECT COUNT(*) AS total FROM {tabela}")
                resumo[chave] = int(cursor.fetchone()["total"])
            cursor.execute(
                "SELECT COUNT(*) AS total FROM dominios_acessados WHERE observado_em >= ?",
                (desde,),
            )
            resumo["dominios_recentes"] = int(cursor.fetchone()["total"])
            return resumo

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
