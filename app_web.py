"""Interface web integrada do DevSec - NetFlow Analyzer.

Diferente da versão anterior, este módulo usa os mesmos componentes reais do
programa desktop: captura Scapy, conversão de pacotes em fluxos, detector de
alertas e banco SQLite. A página consulta APIs JSON periodicamente, portanto
fluxos, alertas, blacklists e domínios aparecem sem recarregar o navegador.
"""

from __future__ import annotations

import atexit
import functools
import ipaddress
import os
import queue
import secrets
import threading
import time
from collections import deque
from datetime import datetime

from flask import Flask, jsonify, redirect, render_template, request, session, url_for

from capture.detector import Detector
from capture.domain_analyzer import DomainAnalyzer, normalizar_dominio
from capture.flow_analyzer import FlowAnalyzer
from capture.packet_capture import PacketCapture
from database.database import CAMINHO_BANCO_PADRAO, Database
from network_control import FirewallController


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, "ui", "templates")

app = Flask(__name__, template_folder=TEMPLATE_DIR)
app.secret_key = os.environ.get("DEVSEC_WEB_SECRET") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    JSON_AS_ASCII=False,
)


class AnalyzerRuntime:
    """Mantém captura e persistência fora das threads do servidor Flask."""

    def __init__(self):
        self.db = Database(os.environ.get("DEVSEC_DB_PATH", CAMINHO_BANCO_PADRAO))
        self.flow_analyzer = FlowAnalyzer()
        self.domain_analyzer = DomainAnalyzer()
        self.firewall = FirewallController()

        self.detector = Detector(
            portas_sensiveis=self.db.obter_portas_sensiveis(),
            limite_portas_scan=int(self.db.obter_configuracao("limite_portas_scan", "15")),
            janela_scan_segundos=int(self.db.obter_configuracao("janela_scan_segundos", "10")),
        )

        self.interface = self.db.obter_configuracao("interface_rede", "") or None
        self.capture = PacketCapture(
            callback_pacote=self._callback_pacote,
            interface=self.interface,
            filtro_bpf=None,
            callback_log=self._registrar_status_captura,
        )

        self.event_queue: queue.Queue = queue.Queue(maxsize=20000)
        self._running = True
        self._policy_lock = threading.RLock()
        self._cooldown_lock = threading.Lock()
        self._alert_cooldowns = {}

        self.packet_count = 0
        self.dropped_events = 0
        self.last_capture_message = "Captura parada."
        self.last_capture_message_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.recent_runtime_messages = deque(maxlen=100)

        self.whitelist = set()
        self.ip_blacklist = set()
        self.blocked_ips = set()
        self.domain_rules = []
        self.reload_policies()

        self.worker = threading.Thread(target=self._event_loop, daemon=True, name="devsec-web-worker")
        self.worker.start()

        self.domain_worker = threading.Thread(
            target=self._domain_maintenance_loop,
            daemon=True,
            name="devsec-domain-maintenance",
        )
        self.domain_worker.start()

    # -------------------------- estado e políticas ------------------------- #
    def reload_policies(self):
        with self._policy_lock:
            self.whitelist = set(self.db.listar_whitelist())
            self.ip_blacklist = {item["ip"] for item in self.db.listar_ip_blacklist()}
            self.blocked_ips = set(self.db.listar_ips_bloqueados())
            self.domain_rules = self.db.listar_domain_blacklist(somente_ativos=True)

    def status(self):
        resumo = self.db.obter_resumo(segundos_dominios=30)
        resumo.update(
            {
                "captura_ativa": self.capture.ativo,
                "interface": self.capture.interface or "Automática",
                "pacotes_processados_sessao": self.packet_count,
                "eventos_descartados": self.dropped_events,
                "fila_pendente": self.event_queue.qsize(),
                "mensagem_captura": self.last_capture_message,
                "mensagem_captura_em": self.last_capture_message_at,
            }
        )
        return resumo

    def iniciar_captura(self):
        if self.capture.ativo:
            return True, "A captura já está ativa."
        iniciou = self.capture.iniciar()
        if not iniciou:
            return False, self.last_capture_message
        # Dá tempo para erros imediatos (Npcap ausente ou falta de privilégio)
        # serem reportados pela thread antes de responder à interface.
        time.sleep(0.08)
        if not self.capture.ativo:
            return False, self.last_capture_message
        return True, "Captura iniciada."

    def parar_captura(self):
        self.capture.parar()
        return True, "Solicitação de parada enviada."

    def definir_interface(self, interface):
        if self.capture.ativo:
            return False, "Pare a captura antes de trocar a interface."
        interface = (interface or "").strip()
        self.capture.interface = interface or None
        self.db.definir_configuracao("interface_rede", interface)
        return True, "Interface atualizada."

    # ------------------------------ captura -------------------------------- #
    def _registrar_status_captura(self, mensagem):
        self.last_capture_message = mensagem
        self.last_capture_message_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.recent_runtime_messages.appendleft(
            {"data_hora": self.last_capture_message_at, "mensagem": mensagem}
        )
        print(f"[CAPTURA WEB] {mensagem}")

    def _callback_pacote(self, pacote):
        fluxo = self.flow_analyzer.pacote_para_fluxo(pacote)
        observacoes = self.domain_analyzer.extrair_observacoes(pacote)
        if fluxo is None and not observacoes:
            return

        evento = {"fluxo": fluxo, "dominios": observacoes}
        try:
            self.event_queue.put_nowait(evento)
            self.packet_count += 1
        except queue.Full:
            self.dropped_events += 1
            self._registrar_status_captura(
                "Fila de processamento cheia; um evento de captura foi descartado."
            )

    def _event_loop(self):
        pendentes = []
        ultimo_flush = time.monotonic()

        while self._running or not self.event_queue.empty():
            try:
                pendentes.append(self.event_queue.get(timeout=0.2))
            except queue.Empty:
                pass

            tempo = time.monotonic() - ultimo_flush >= 0.7
            cheio = len(pendentes) >= 300
            if pendentes and (tempo or cheio):
                self._persistir_eventos(pendentes)
                pendentes.clear()
                ultimo_flush = time.monotonic()

        if pendentes:
            self._persistir_eventos(pendentes)

    def _persistir_eventos(self, eventos):
        fluxos = []
        dispositivos = []
        observacoes = []
        alertas = []
        logs = []

        with self._policy_lock:
            whitelist = set(self.whitelist)
            blacklist = set(self.ip_blacklist)
            bloqueados = set(self.blocked_ips)
            regras_dominio = list(self.domain_rules)

        for evento in eventos:
            fluxo = evento.get("fluxo")
            if fluxo:
                fluxos.append(fluxo)
                dispositivos.extend((fluxo["ip_origem"], fluxo["ip_destino"]))

                for alerta in self.detector.verificar_fluxo(fluxo, whitelist=whitelist):
                    self._acumular_alerta(alerta, alertas, logs)

                envolvidos = {fluxo["ip_origem"], fluxo["ip_destino"]}
                for ip in envolvidos & blacklist:
                    self._acumular_alerta(
                        {
                            "ip": ip,
                            "severidade": "ALTO",
                            "motivo": "Tráfego envolvendo IP presente na blacklist",
                            "mensagem": (
                                f"[ALTO] Tráfego do IP em blacklist: "
                                f"{fluxo['ip_origem']} -> {fluxo['ip_destino']}:{fluxo['porta_destino']}"
                            ),
                        },
                        alertas,
                        logs,
                    )

                for ip in envolvidos & bloqueados:
                    self._acumular_alerta(
                        {
                            "ip": ip,
                            "severidade": "CRÍTICO",
                            "motivo": "Tráfego observado envolvendo IP bloqueado",
                            "mensagem": (
                                f"[CRÍTICO] Ainda há tráfego visível envolvendo o IP bloqueado {ip}: "
                                f"{fluxo['ip_origem']} -> {fluxo['ip_destino']}"
                            ),
                        },
                        alertas,
                        logs,
                    )

            for observacao in evento.get("dominios") or []:
                regra = self._regra_para_dominio(
                    observacao["dominio"], observacao["ip_cliente"], regras_dominio
                )
                observacao["bloqueado_pela_politica"] = bool(regra)
                observacoes.append(observacao)

                if regra:
                    modo = regra.get("modo", "monitorar")
                    self._acumular_alerta(
                        {
                            "ip": observacao["ip_cliente"],
                            "severidade": "CRÍTICO" if modo == "bloquear_local" else "ALTO",
                            "motivo": f"Acesso a domínio em blacklist: {observacao['dominio']}",
                            "mensagem": (
                                f"[POLÍTICA] {observacao['ip_cliente']} consultou/acessou "
                                f"{observacao['dominio']} ({observacao['fonte']})."
                            ),
                        },
                        alertas,
                        logs,
                    )

        try:
            self.db.salvar_fluxos_lote(fluxos)
            self.db.registrar_dispositivos_lote(dispositivos)
            self.db.registrar_dominios_lote(observacoes)
            self.db.registrar_alertas_lote(alertas)
            self.db.registrar_logs_lote(logs)
        except Exception as erro:
            self._registrar_status_captura(f"Erro ao persistir eventos: {erro}")

    def _acumular_alerta(self, alerta, alertas, logs):
        chave = (alerta.get("ip"), alerta.get("motivo"))
        agora = time.monotonic()
        with self._cooldown_lock:
            ultimo = self._alert_cooldowns.get(chave, 0.0)
            if agora - ultimo < 4.0:
                return
            self._alert_cooldowns[chave] = agora

        alertas.append(
            {
                "ip": alerta["ip"],
                "severidade": alerta["severidade"],
                "motivo": alerta["motivo"],
            }
        )
        logs.append({"ip": alerta["ip"], "mensagem": alerta["mensagem"]})

    @staticmethod
    def _regra_para_dominio(dominio, ip_cliente, regras):
        candidatas = []
        for regra in regras:
            dominio_regra = regra["dominio"].lower().rstrip(".")
            cliente_regra = regra.get("ip_cliente") or "*"
            if cliente_regra not in ("*", ip_cliente):
                continue
            if dominio == dominio_regra or dominio.endswith("." + dominio_regra):
                candidatas.append(regra)
        if not candidatas:
            return None
        candidatas.sort(
            key=lambda item: (
                0 if item.get("ip_cliente") == ip_cliente else 1,
                -len(item.get("dominio", "")),
            )
        )
        return candidatas[0]

    # -------------------------- domínio / firewall ------------------------- #
    def reconciliar_regra_dominio(self, dominio, ip_cliente="*"):
        regra = self.db.obter_domain_blacklist(dominio, ip_cliente)
        if not regra:
            return False, "Regra de domínio não encontrada.", []
        if regra.get("modo") != "bloquear_local":
            return True, "Regra configurada apenas para monitoramento.", []
        if ip_cliente != "*":
            mensagem = (
                "O firewall deste computador não consegue impor bloqueio a outro IP da LAN. "
                "A regra foi mantida como política de detecção."
            )
            self.db.atualizar_resolucao_domain_blacklist(dominio, ip_cliente, [], mensagem)
            return False, mensagem, []

        try:
            resolvidos = self.firewall.resolver_dominio(dominio)
        except OSError as erro:
            mensagem = f"Falha ao resolver o domínio: {erro}"
            self.db.atualizar_resolucao_domain_blacklist(dominio, ip_cliente, [], mensagem)
            return False, mensagem, []

        if not resolvidos:
            mensagem = "O domínio não retornou endereços IP no momento."
            self.db.atualizar_resolucao_domain_blacklist(dominio, ip_cliente, [], mensagem)
            return False, mensagem, []

        anteriores = set(regra.get("ips_resolvidos") or [])
        aplicados = set(anteriores)
        erros = []
        for ip in resolvidos:
            if ip in anteriores:
                continue
            identificador = f"DOMAIN_{dominio}_{ip}"
            sucesso, mensagem = self.firewall.bloquear_ip(
                ip, identificador=identificador, somente_saida=True
            )
            if sucesso:
                aplicados.add(ip)
            else:
                erros.append(f"{ip}: {mensagem}")

        erro_final = " | ".join(erros) if erros else None
        self.db.atualizar_resolucao_domain_blacklist(
            dominio, ip_cliente, sorted(aplicados), erro_final
        )
        self.reload_policies()

        if erros:
            return False, "A política foi salva, mas parte do bloqueio local falhou.", sorted(aplicados)
        return True, "Domínio resolvido e bloqueado localmente no firewall.", sorted(aplicados)

    def remover_regra_dominio(self, dominio, ip_cliente="*"):
        regra = self.db.obter_domain_blacklist(dominio, ip_cliente)
        if not regra:
            return False, "Regra não encontrada."

        erros = []
        if regra.get("modo") == "bloquear_local":
            for ip in regra.get("ips_resolvidos") or []:
                identificador = f"DOMAIN_{dominio}_{ip}"
                sucesso, mensagem = self.firewall.desbloquear_ip(
                    ip, identificador=identificador, somente_saida=True
                )
                if not sucesso:
                    erros.append(f"{ip}: {mensagem}")

        self.db.remover_domain_blacklist(dominio, ip_cliente)
        self.reload_policies()
        if erros:
            return True, "Regra removida do banco; algumas regras de firewall não foram encontradas."
        return True, "Regra de domínio removida."

    def _domain_maintenance_loop(self):
        # Atualiza IPs de domínios dinâmicos sem bloquear a inicialização.
        while self._running:
            for _ in range(300):
                if not self._running:
                    return
                time.sleep(1)
            for regra in self.db.listar_domain_blacklist(somente_ativos=True):
                if regra.get("modo") == "bloquear_local" and regra.get("ip_cliente") == "*":
                    self.reconciliar_regra_dominio(regra["dominio"], regra["ip_cliente"])
            try:
                horas = int(self.db.obter_configuracao("retencao_dominios_horas", "168"))
                self.db.limpar_dominios_antigos(horas)
            except Exception as erro:
                self._registrar_status_captura(f"Falha na manutenção de domínios: {erro}")

    def shutdown(self):
        if not self._running:
            return
        self.capture.parar()
        self._running = False
        if self.worker.is_alive():
            self.worker.join(timeout=2)
        try:
            self.db.fechar()
        except Exception:
            pass


runtime = AnalyzerRuntime()
atexit.register(runtime.shutdown)


# --------------------------------------------------------------------------- #
# Autenticação e validação
# --------------------------------------------------------------------------- #
def login_required(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get("usuario"):
            if request.path.startswith("/api/"):
                return jsonify({"ok": False, "erro": "Sessão expirada."}), 401
            return redirect(url_for("welcome"))
        return func(*args, **kwargs)

    return wrapper


def csrf_required(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        token = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
        if not token or not secrets.compare_digest(token, session.get("csrf_token", "")):
            return jsonify({"ok": False, "erro": "Token CSRF inválido."}), 403
        return func(*args, **kwargs)

    return wrapper


def usuario_atual():
    return session.get("usuario")


def auditar(acao, detalhes):
    runtime.db.registrar_auditoria(
        usuario=usuario_atual() or "sessao-nao-autenticada",
        acao=acao,
        detalhes=detalhes,
        ip_origem=request.remote_addr,
    )


def validar_ip(valor):
    try:
        return str(ipaddress.ip_address((valor or "").strip()))
    except ValueError as erro:
        raise ValueError("Informe um endereço IPv4 ou IPv6 válido.") from erro


def payload_json():
    return request.get_json(silent=True) or {}


# --------------------------------------------------------------------------- #
# Páginas
# --------------------------------------------------------------------------- #
@app.route("/")
def welcome():
    if session.get("usuario"):
        return redirect(url_for("dashboard"))
    return render_template("welcome.html")


@app.route("/login", methods=["POST"])
def login():
    usuario = (request.form.get("usuario") or "").strip()
    if not usuario:
        return render_template("welcome.html", erro="Informe a identidade do analista."), 400

    session.clear()
    session["usuario"] = usuario[:80]
    session["csrf_token"] = secrets.token_urlsafe(32)
    runtime.db.registrar_auditoria(
        usuario=session["usuario"],
        acao="AUTENTICACAO",
        detalhes="Sessão iniciada na Central Web DevSec.",
        ip_origem=request.remote_addr,
    )
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    if session.get("usuario"):
        auditar("ENCERRAMENTO_SESSAO", "Sessão encerrada pelo analista.")
    session.clear()
    return redirect(url_for("welcome"))


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template(
        "index.html",
        usuario=usuario_atual(),
        csrf_token=session["csrf_token"],
    )


@app.route("/atualizar")
@login_required
def atualizar():
    # Compatibilidade com o botão/URL da versão antiga.
    auditar("CONSULTA", "Painel sincronizado manualmente.")
    return redirect(url_for("dashboard"))


# --------------------------------------------------------------------------- #
# APIs somente leitura
# --------------------------------------------------------------------------- #
@app.route("/api/status")
@login_required
def api_status():
    return jsonify({"ok": True, "dados": runtime.status()})


@app.route("/api/flows")
@login_required
def api_flows():
    limite = request.args.get("limit", 100, type=int) or 100
    return jsonify({"ok": True, "dados": runtime.db.listar_fluxos(limite=min(limite, 1000))})


@app.route("/api/alerts")
@login_required
def api_alerts():
    return jsonify({"ok": True, "dados": runtime.db.listar_alertas()})


@app.route("/api/devices")
@login_required
def api_devices():
    return jsonify({"ok": True, "dados": runtime.db.listar_dispositivos()})


@app.route("/api/audit")
@login_required
def api_audit():
    limite = request.args.get("limit", 100, type=int) or 100
    return jsonify({"ok": True, "dados": runtime.db.listar_auditoria(limite)})


@app.route("/api/logs")
@login_required
def api_logs():
    limite = request.args.get("limit", 200, type=int) or 200
    ip = request.args.get("ip") or None
    return jsonify({"ok": True, "dados": runtime.db.listar_log(limite, ip=ip)})


@app.route("/api/domains/recent")
@login_required
def api_domains_recent():
    segundos = request.args.get("seconds", 30, type=int) or 30
    limite = request.args.get("limit", 500, type=int) or 500
    ip_cliente = request.args.get("client_ip") or None
    dominio = request.args.get("domain") or None
    if ip_cliente:
        try:
            ip_cliente = validar_ip(ip_cliente)
        except ValueError as erro:
            return jsonify({"ok": False, "erro": str(erro)}), 400
    dados = runtime.db.listar_dominios_recentes(
        segundos=segundos,
        limite=limite,
        ip_cliente=ip_cliente,
        dominio=dominio,
    )
    return jsonify({"ok": True, "dados": dados})


@app.route("/api/ip-blacklist")
@login_required
def api_list_ip_blacklist():
    return jsonify({"ok": True, "dados": runtime.db.listar_ip_blacklist()})


@app.route("/api/blocked-ips")
@login_required
def api_list_blocked_ips():
    return jsonify({"ok": True, "dados": runtime.db.listar_ips_bloqueados_detalhes()})


@app.route("/api/domain-blacklist")
@login_required
def api_list_domain_blacklist():
    return jsonify({"ok": True, "dados": runtime.db.listar_domain_blacklist()})


@app.route("/api/capture/interfaces")
@login_required
def api_capture_interfaces():
    return jsonify({"ok": True, "dados": PacketCapture.listar_interfaces()})


# --------------------------------------------------------------------------- #
# APIs de captura e políticas
# --------------------------------------------------------------------------- #
@app.route("/api/capture/start", methods=["POST"])
@login_required
@csrf_required
def api_capture_start():
    sucesso, mensagem = runtime.iniciar_captura()
    auditar("CAPTURA_INICIADA", mensagem)
    return jsonify({"ok": sucesso, "mensagem": mensagem}), 200 if sucesso else 400


@app.route("/api/capture/stop", methods=["POST"])
@login_required
@csrf_required
def api_capture_stop():
    sucesso, mensagem = runtime.parar_captura()
    auditar("CAPTURA_PARADA", mensagem)
    return jsonify({"ok": sucesso, "mensagem": mensagem})


@app.route("/api/capture/interface", methods=["POST"])
@login_required
@csrf_required
def api_capture_interface():
    interface = payload_json().get("interface", "")
    sucesso, mensagem = runtime.definir_interface(interface)
    if sucesso:
        auditar("INTERFACE_REDE", f"Interface de captura definida como: {interface or 'automática'}")
    return jsonify({"ok": sucesso, "mensagem": mensagem}), 200 if sucesso else 409


@app.route("/api/ip-blacklist", methods=["POST"])
@login_required
@csrf_required
def api_add_ip_blacklist():
    dados = payload_json()
    try:
        ip = validar_ip(dados.get("ip"))
    except ValueError as erro:
        return jsonify({"ok": False, "erro": str(erro)}), 400

    motivo = (dados.get("motivo") or "Adicionado manualmente à blacklist").strip()[:300]
    runtime.db.adicionar_ip_blacklist(ip, motivo)
    runtime.db.atualizar_status_ip(ip, "Blacklist", "ALTO", motivo)
    runtime.db.registrar_log(f"[BLACKLIST] {ip}: {motivo}", ip=ip)
    runtime.reload_policies()
    auditar("IP_BLACKLIST_ADICIONADO", f"{ip} — {motivo}")
    return jsonify({"ok": True, "mensagem": f"IP {ip} adicionado à blacklist e aos alertas."})


@app.route("/api/ip-blacklist/<path:ip>", methods=["DELETE"])
@login_required
@csrf_required
def api_remove_ip_blacklist(ip):
    try:
        ip = validar_ip(ip)
    except ValueError as erro:
        return jsonify({"ok": False, "erro": str(erro)}), 400

    runtime.db.remover_ip_blacklist(ip)
    novo_status = "Bloqueado" if ip in set(runtime.db.listar_ips_bloqueados()) else "Suspeito"
    runtime.db.atualizar_status_ip(
        ip,
        novo_status,
        "CRÍTICO" if novo_status == "Bloqueado" else "MÉDIO",
        "IP removido da blacklist manual",
    )
    runtime.reload_policies()
    auditar("IP_BLACKLIST_REMOVIDO", ip)
    return jsonify({"ok": True, "mensagem": f"IP {ip} removido da blacklist."})


@app.route("/api/ip-block/<path:ip>", methods=["POST"])
@login_required
@csrf_required
def api_block_ip(ip):
    try:
        ip = validar_ip(ip)
    except ValueError as erro:
        return jsonify({"ok": False, "erro": str(erro)}), 400

    sucesso, mensagem = runtime.firewall.bloquear_ip(ip)
    if sucesso:
        runtime.db.bloquear_ip(ip)
        runtime.db.atualizar_status_ip(
            ip, "Bloqueado", "CRÍTICO", "Bloqueado manualmente no firewall local"
        )
        runtime.db.registrar_log(f"[BLOQUEADO] {ip} no firewall local.", ip=ip)
        runtime.reload_policies()
        auditar("IP_BLOQUEADO", ip)
        return jsonify({"ok": True, "mensagem": f"IP {ip} bloqueado no firewall local."})

    runtime.db.atualizar_status_ip(
        ip, "Falha no bloqueio", "ALTO", f"Falha ao aplicar firewall: {mensagem}"
    )
    runtime.db.registrar_log(f"[ERRO BLOQUEIO] {ip}: {mensagem}", ip=ip)
    auditar("FALHA_BLOQUEIO_IP", f"{ip} — {mensagem}")
    return jsonify({"ok": False, "erro": mensagem}), 409


@app.route("/api/ip-block/<path:ip>", methods=["DELETE"])
@login_required
@csrf_required
def api_unblock_ip(ip):
    try:
        ip = validar_ip(ip)
    except ValueError as erro:
        return jsonify({"ok": False, "erro": str(erro)}), 400

    sucesso, mensagem = runtime.firewall.desbloquear_ip(ip)
    if not sucesso:
        return jsonify({"ok": False, "erro": mensagem}), 409

    runtime.db.desbloquear_ip(ip)
    em_blacklist = ip in {item["ip"] for item in runtime.db.listar_ip_blacklist()}
    runtime.db.atualizar_status_ip(
        ip,
        "Blacklist" if em_blacklist else "Suspeito",
        "ALTO" if em_blacklist else "MÉDIO",
        "Bloqueio de firewall removido manualmente",
    )
    runtime.reload_policies()
    auditar("IP_DESBLOQUEADO", ip)
    return jsonify({"ok": True, "mensagem": f"Bloqueio do IP {ip} removido."})


@app.route("/api/domain-blacklist", methods=["POST"])
@login_required
@csrf_required
def api_add_domain_blacklist():
    dados = payload_json()
    dominio = normalizar_dominio(dados.get("domain"))
    if not dominio:
        return jsonify({"ok": False, "erro": "Informe um domínio válido, como exemplo.com."}), 400

    ip_cliente = (dados.get("client_ip") or "*").strip()
    if ip_cliente != "*":
        try:
            ip_cliente = validar_ip(ip_cliente)
        except ValueError as erro:
            return jsonify({"ok": False, "erro": str(erro)}), 400

    modo = dados.get("mode") or "monitorar"
    if modo not in {"monitorar", "bloquear_local"}:
        return jsonify({"ok": False, "erro": "Modo de domínio inválido."}), 400

    runtime.db.adicionar_domain_blacklist(dominio, ip_cliente, modo)
    runtime.reload_policies()
    auditar(
        "DOMINIO_BLACKLIST_ADICIONADO",
        f"{dominio} | cliente={ip_cliente} | modo={modo}",
    )

    sucesso, mensagem, ips = runtime.reconciliar_regra_dominio(dominio, ip_cliente)
    # A política continua válida para detecção mesmo quando o firewall local falha.
    return jsonify(
        {
            "ok": True,
            "enforced": sucesso,
            "mensagem": mensagem,
            "ips_resolvidos": ips,
        }
    )


@app.route("/api/domain-blacklist", methods=["DELETE"])
@login_required
@csrf_required
def api_remove_domain_blacklist():
    dados = payload_json()
    dominio = normalizar_dominio(dados.get("domain"))
    ip_cliente = (dados.get("client_ip") or "*").strip()
    if not dominio:
        return jsonify({"ok": False, "erro": "Domínio inválido."}), 400
    if ip_cliente != "*":
        try:
            ip_cliente = validar_ip(ip_cliente)
        except ValueError as erro:
            return jsonify({"ok": False, "erro": str(erro)}), 400

    sucesso, mensagem = runtime.remover_regra_dominio(dominio, ip_cliente)
    if sucesso:
        auditar("DOMINIO_BLACKLIST_REMOVIDO", f"{dominio} | cliente={ip_cliente}")
    return jsonify({"ok": sucesso, "mensagem": mensagem}), 200 if sucesso else 404


if __name__ == "__main__":
    auto_capture = os.environ.get("DEVSEC_AUTO_CAPTURE", "1").strip().lower() not in {
        "0",
        "false",
        "nao",
        "não",
    }
    if auto_capture:
        runtime.iniciar_captura()

    host = os.environ.get("DEVSEC_WEB_HOST", "127.0.0.1")
    port = int(os.environ.get("DEVSEC_WEB_PORT", "5000"))
    debug = os.environ.get("DEVSEC_WEB_DEBUG", "0") == "1"
    app.run(host=host, port=port, debug=debug, use_reloader=False, threaded=True)
