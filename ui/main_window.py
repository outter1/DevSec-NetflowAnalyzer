# SPDX-License-Identifier: MIT
# Copyright (c) 2026 DEVSEC
# Copyright (c) 2026 Gabriel Silva Bastos
# Copyright (c) 2026 Matheus Dominato
# Copyright (c) 2026 Isabelle Guimarães de Andrade
# Copyright (c) 2026 Nicolas Urtiaga
# Copyright (c) 2026 Pedro Lages da Silva

"""Janela principal moderna do DevSec - NetFlow Analyzer.

A interface desktop usa os mesmos dados e controles reais da interface web:
fluxos, alertas, blacklist de IP, políticas de domínio, dispositivos, relatórios
e auditoria. Captura e persistência continuam em threads separadas para manter o
CustomTkinter responsivo mesmo sob tráfego intenso.
"""

from __future__ import annotations

import ipaddress
import queue
import socket
import threading
import time
from datetime import datetime, timedelta

import customtkinter as ctk

from capture.detector import Detector
from capture.domain_analyzer import DomainAnalyzer, normalizar_dominio
from capture.flow_analyzer import FlowAnalyzer
from capture.packet_capture import PacketCapture
from database.database import Database
from network_control import FirewallController
from reports import export as relatorios
from ui.alerts import AlertsFrame
from ui.audit import AuditFrame
from ui.dashboard import DashboardFrame
from ui.devices import DevicesFrame
from ui.domains import DomainsFrame
from ui.flows import FlowsFrame
from ui.ip_policy import IPPolicyFrame
from ui.reports import ReportsFrame
from ui.settings import SettingsFrame
from ui.theme import COLORS, FONT, apply_theme, dark_button, danger_button, primary_button


class MainWindow(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("DevSec — NetFlow Analyzer")
        self.geometry("1460x880")
        self.minsize(1180, 720)
        apply_theme(self)

        self.db = Database()
        interface_saved = self.db.obter_configuracao("interface_rede", "") or None
        sensitive_ports = self.db.obter_portas_sensiveis()
        scan_limit = int(self.db.obter_configuracao("limite_portas_scan", "15"))
        scan_window = int(self.db.obter_configuracao("janela_scan_segundos", "10"))

        self.analisador_fluxos = FlowAnalyzer()
        self.analisador_dominios = DomainAnalyzer()
        self.detector = Detector(
            portas_sensiveis=sensitive_ports,
            limite_portas_scan=scan_limit,
            janela_scan_segundos=scan_window,
        )
        self.firewall = FirewallController()
        self.captura = PacketCapture(
            callback_pacote=self._callback_pacote,
            interface=interface_saved,
            callback_log=self.registrar_alerta_ui,
        )

        self.whitelist = set(self.db.listar_whitelist())
        self.ips_bloqueados = set(self.db.listar_ips_bloqueados())
        self.ip_blacklist = {item["ip"] for item in self.db.listar_ip_blacklist()}
        self.domain_rules = self.db.listar_domain_blacklist(somente_ativos=True)

        self.fila_fluxos = queue.Queue()
        self.fila_dominios = queue.Queue()
        self.fila_alertas = queue.Queue()
        self.fila_persistencia = queue.Queue()

        self.max_fluxos_por_ciclo_ui = 140
        self.max_dominios_por_ciclo_ui = 100
        self.max_alertas_por_ciclo_ui = 60
        self.intervalo_processamento_ui_ms = 80
        self.persistencia_ativa = True
        self.tamanho_lote_banco = 350
        self.intervalo_lote_banco = 1.0
        self._cooldown_alerta_por_chave = {}
        self.cooldown_alerta_segundos = 4.0
        self._last_page_refresh = 0.0
        self._last_status_refresh = 0.0
        self._stop_event = threading.Event()

        self.tela_atual_nome = None
        self.frame_atual = None
        self.nav_buttons = {}

        self.protocol("WM_DELETE_WINDOW", self._ao_fechar)
        self._criar_layout()

        self.thread_persistencia = threading.Thread(target=self._loop_persistencia, daemon=True)
        self.thread_persistencia.start()
        self.thread_manutencao = threading.Thread(target=self._loop_manutencao_dominios, daemon=True)
        self.thread_manutencao.start()

        self.mostrar_pagina("Visão geral")
        self._processar_filas()

    # ================================================================== #
    # Layout
    # ================================================================== #
    def _criar_layout(self):
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        self.sidebar = ctk.CTkFrame(
            self, width=238, corner_radius=0, fg_color=COLORS["sidebar"],
            border_width=0,
        )
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)
        self.sidebar.grid_rowconfigure(2, weight=1)

        brand = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        brand.grid(row=0, column=0, sticky="ew", padx=18, pady=(22, 16))
        mark = ctk.CTkLabel(
            brand, text="◆", width=38, height=38, corner_radius=9,
            fg_color="#281313", text_color=COLORS["red_hover"], font=(FONT, 20, "bold"),
        )
        mark.pack(side="left")
        brand_text = ctk.CTkFrame(brand, fg_color="transparent")
        brand_text.pack(side="left", padx=10)
        ctk.CTkLabel(brand_text, text="DevSec", font=(FONT, 20, "bold")).pack(anchor="w")
        ctk.CTkLabel(
            brand_text, text="NETFLOW ANALYZER", text_color=COLORS["muted"], font=(FONT, 8, "bold")
        ).pack(anchor="w")

        separator = ctk.CTkFrame(self.sidebar, height=1, fg_color=COLORS["border"], corner_radius=0)
        separator.grid(row=1, column=0, sticky="ew")

        nav = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        nav.grid(row=2, column=0, sticky="nsew", padx=12, pady=16)
        items = [
            ("Visão geral", "◫"),
            ("Fluxos", "⇄"),
            ("Alertas", "⚠"),
            ("Blacklist IP", "⛨"),
            ("Domínios", "◎"),
            ("Dispositivos", "▦"),
            ("Relatórios", "▤"),
            ("Configurações", "⚙"),
            ("Auditoria", "⌁"),
        ]
        for name, icon in items:
            button = ctk.CTkButton(
                nav,
                text=f"  {icon}   {name}",
                anchor="w",
                fg_color="transparent",
                hover_color=COLORS["panel_alt"],
                text_color=COLORS["muted"],
                border_width=1,
                border_color=COLORS["sidebar"],
                height=43,
                command=lambda n=name: self.mostrar_pagina(n),
            )
            button.pack(fill="x", pady=3)
            self.nav_buttons[name] = button

        note = ctk.CTkFrame(
            self.sidebar, fg_color=COLORS["panel"], corner_radius=10,
            border_width=1, border_color=COLORS["border"],
        )
        note.grid(row=3, column=0, sticky="ew", padx=14, pady=14)
        ctk.CTkLabel(
            note,
            text="Use apenas em redes e dispositivos sob sua autorização.",
            text_color=COLORS["muted"],
            justify="left",
            wraplength=180,
            font=(FONT, 10),
        ).pack(anchor="w", padx=12, pady=12)

        self.main_shell = ctk.CTkFrame(self, fg_color=COLORS["bg"], corner_radius=0, border_width=0)
        self.main_shell.grid(row=0, column=1, sticky="nsew")
        self.main_shell.grid_rowconfigure(1, weight=1)
        self.main_shell.grid_columnconfigure(0, weight=1)

        self._criar_topbar()

        self.content = ctk.CTkFrame(self.main_shell, fg_color="transparent")
        self.content.grid(row=1, column=0, sticky="nsew", padx=24, pady=22)

        self.statusbar = ctk.CTkFrame(
            self.main_shell, height=34, corner_radius=0, fg_color=COLORS["sidebar"],
            border_width=0,
        )
        self.statusbar.grid(row=2, column=0, sticky="ew")
        self.statusbar.grid_columnconfigure(0, weight=1)
        self.last_event_label = ctk.CTkLabel(
            self.statusbar, text="Sistema iniciado.", text_color=COLORS["muted"], font=(FONT, 10)
        )
        self.last_event_label.grid(row=0, column=0, sticky="w", padx=15, pady=7)
        self.queue_label = ctk.CTkLabel(
            self.statusbar, text="Filas: 0", text_color=COLORS["muted"], font=(FONT, 10)
        )
        self.queue_label.grid(row=0, column=1, sticky="e", padx=15)

    def _criar_topbar(self):
        topbar = ctk.CTkFrame(
            self.main_shell, height=70, corner_radius=0, fg_color=COLORS["sidebar"],
            border_width=0,
        )
        topbar.grid(row=0, column=0, sticky="ew")
        topbar.grid_columnconfigure(1, weight=1)

        self.page_title = ctk.CTkLabel(topbar, text="Visão geral", font=(FONT, 16, "bold"))
        self.page_title.grid(row=0, column=0, sticky="w", padx=24)

        controls = ctk.CTkFrame(topbar, fg_color="transparent")
        controls.grid(row=0, column=2, sticky="e", padx=20, pady=14)

        interfaces = ["Automática"] + PacketCapture.listar_interfaces()
        self.interface_select = ctk.CTkOptionMenu(controls, values=interfaces or ["Automática"], width=210)
        self.interface_select.set(self.captura.interface or "Automática")
        self.interface_select.pack(side="left", padx=5)
        ctk.CTkButton(
            controls, text="Usar interface", width=115, command=self._salvar_interface_topbar, **dark_button()
        ).pack(side="left", padx=5)
        ctk.CTkButton(
            controls, text="Iniciar", width=88, command=self.iniciar_captura, **primary_button()
        ).pack(side="left", padx=5)
        ctk.CTkButton(
            controls, text="Parar", width=82, command=self.parar_captura, **danger_button()
        ).pack(side="left", padx=5)

        status = ctk.CTkFrame(
            controls, fg_color=COLORS["panel"], corner_radius=10,
            border_width=1, border_color=COLORS["border"],
        )
        status.pack(side="left", padx=(10, 0))
        self.capture_dot = ctk.CTkLabel(status, text="●", width=20, text_color=COLORS["red"])
        self.capture_dot.pack(side="left", padx=(9, 0), pady=7)
        self.capture_state = ctk.CTkLabel(status, text="Parada", width=72, font=(FONT, 10, "bold"))
        self.capture_state.pack(side="left", padx=(0, 8), pady=7)

    def mostrar_pagina(self, nome):
        for widget in self.content.winfo_children():
            widget.destroy()

        mapping = {
            "Visão geral": DashboardFrame,
            "Fluxos": FlowsFrame,
            "Alertas": AlertsFrame,
            "Blacklist IP": IPPolicyFrame,
            "Domínios": DomainsFrame,
            "Dispositivos": DevicesFrame,
            "Relatórios": ReportsFrame,
            "Configurações": SettingsFrame,
            "Auditoria": AuditFrame,
        }
        frame_class = mapping.get(nome, DashboardFrame)
        self.tela_atual_nome = nome
        self.page_title.configure(text=nome)

        for key, button in self.nav_buttons.items():
            active = key == nome
            button.configure(
                fg_color="#2A1516" if active else "transparent",
                hover_color="#321819" if active else COLORS["panel_alt"],
                text_color=COLORS["text"] if active else COLORS["muted"],
                border_color="#663033" if active else COLORS["sidebar"],
            )

        self.frame_atual = frame_class(self.content, self)
        self.frame_atual.pack(fill="both", expand=True)
        self._last_page_refresh = time.monotonic()

    # ================================================================== #
    # Captura e processamento
    # ================================================================== #
    def iniciar_captura(self):
        started = self.captura.iniciar()
        if started:
            self.auditar("CAPTURA_INICIADA", f"interface={self.captura.interface or 'automática'}")
        return started

    def parar_captura(self):
        was_active = self.captura.parar()
        if was_active:
            self.auditar("CAPTURA_PARADA", f"interface={self.captura.interface or 'automática'}")
        return was_active

    def _salvar_interface_topbar(self):
        selected = self.interface_select.get()
        interface = None if selected == "Automática" else selected
        self.captura.interface = interface
        self.db.definir_configuracao("interface_rede", interface or "")
        self.auditar("INTERFACE_CAPTURA_ALTERADA", interface or "automática")
        self.registrar_alerta_ui(f"Interface de captura definida como {interface or 'automática'}.")

    def _callback_pacote(self, pacote):
        flow = self.analisador_fluxos.pacote_para_fluxo(pacote)
        if flow is not None:
            self.fila_fluxos.put(flow)
        try:
            for observation in self.analisador_dominios.extrair_observacoes(pacote):
                self.fila_dominios.put(observation)
        except Exception as error:
            self.registrar_alerta_ui(f"[ERRO] Falha ao analisar domínio no pacote: {error}")

    def _processar_filas(self):
        processed = 0
        while processed < self.max_fluxos_por_ciclo_ui:
            try:
                flow = self.fila_fluxos.get_nowait()
            except queue.Empty:
                break
            self._processar_fluxo(flow)
            processed += 1

        processed_domains = 0
        while processed_domains < self.max_dominios_por_ciclo_ui:
            try:
                observation = self.fila_dominios.get_nowait()
            except queue.Empty:
                break
            self._processar_dominio(observation)
            processed_domains += 1

        processed_alerts = 0
        while processed_alerts < self.max_alertas_por_ciclo_ui:
            try:
                message = self.fila_alertas.get_nowait()
            except queue.Empty:
                break
            self._exibir_alerta(message)
            processed_alerts += 1

        now = time.monotonic()
        if now - self._last_page_refresh >= 1.0:
            frame = self.frame_atual
            if frame is not None and hasattr(frame, "atualizar_automatico"):
                try:
                    frame.atualizar_automatico()
                except Exception as error:
                    print(f"Falha ao atualizar tela {self.tela_atual_nome}: {error}")
            self._last_page_refresh = now

        if now - self._last_status_refresh >= 0.4:
            self._atualizar_status_global()
            self._last_status_refresh = now

        self._after_process_id = self.after(
            self.intervalo_processamento_ui_ms, self._processar_filas
        )

    def _processar_fluxo(self, flow):
        key, record, _is_new = self.analisador_fluxos.atualizar_fluxo(flow)
        self.fila_persistencia.put({"tipo": "fluxo", "dados": flow})
        self.fila_persistencia.put({"tipo": "dispositivo", "ip": flow["ip_origem"]})
        self.fila_persistencia.put({"tipo": "dispositivo", "ip": flow["ip_destino"]})

        if isinstance(self.frame_atual, FlowsFrame):
            self.frame_atual.atualizar_fluxo(key, record)

        alerts = self.detector.verificar_fluxo(flow, whitelist=self.whitelist)
        for ip in {flow["ip_origem"], flow["ip_destino"]}:
            if ip in self.ip_blacklist and ip not in self.whitelist:
                alerts.append(
                    {
                        "ip": ip,
                        "severidade": "ALTO",
                        "motivo": "IP presente na blacklist",
                        "mensagem": f"[BLACKLIST] Tráfego observado envolvendo o IP {ip}.",
                    }
                )

        for alert in alerts:
            self._registrar_alerta_detectado(alert)

    def _processar_dominio(self, observation):
        rule = self.encontrar_regra_dominio(observation["dominio"], observation["ip_cliente"])
        if rule:
            blocked = rule.get("modo") == "bloquear_local"
            observation["bloqueado_pela_politica"] = blocked
            mode_text = "bloqueio local" if blocked else "monitoramento"
            alert = {
                "ip": observation["ip_cliente"],
                "severidade": "CRÍTICO" if blocked else "ALTO",
                "motivo": f"Acesso a domínio em blacklist: {observation['dominio']}",
                "mensagem": (
                    f"[DOMÍNIO] {observation['ip_cliente']} acessou {observation['dominio']} "
                    f"via {observation['fonte']} — política: {mode_text}."
                ),
            }
            self._registrar_alerta_detectado(alert)
        self.fila_persistencia.put({"tipo": "dominio", "dados": observation})

    def _registrar_alerta_detectado(self, alert):
        if not self._alerta_passou_cooldown(alert):
            return
        self.registrar_alerta_ui(alert["mensagem"])
        self.fila_persistencia.put({"tipo": "alerta", "dados": alert})
        self.fila_persistencia.put({"tipo": "log", "ip": alert["ip"], "mensagem": alert["mensagem"]})

    def _alerta_passou_cooldown(self, alert):
        key = (alert.get("ip"), alert.get("motivo"))
        now = time.monotonic()
        last = self._cooldown_alerta_por_chave.get(key, 0.0)
        if now - last < self.cooldown_alerta_segundos:
            return False
        self._cooldown_alerta_por_chave[key] = now
        return True

    def _atualizar_status_global(self):
        active = self.captura.ativo
        self.capture_dot.configure(text_color=COLORS["green"] if active else COLORS["red"])
        self.capture_state.configure(text="Ativa" if active else "Parada")
        total_queue = self.fila_fluxos.qsize() + self.fila_dominios.qsize() + self.fila_persistencia.qsize()
        self.queue_label.configure(text=f"Filas: {total_queue}  •  Banco: SQLite")

    # ================================================================== #
    # Persistência em lote
    # ================================================================== #
    def _loop_persistencia(self):
        flows, devices, alerts, logs, domains = [], [], [], [], []
        last_flush = time.monotonic()

        while self.persistencia_ativa or not self.fila_persistencia.empty():
            try:
                event = self.fila_persistencia.get(timeout=0.2)
                event_type = event.get("tipo")
                if event_type == "fluxo":
                    flows.append(event["dados"])
                elif event_type == "dispositivo":
                    devices.append(event.get("ip"))
                elif event_type == "alerta":
                    alerts.append(event["dados"])
                elif event_type == "log":
                    logs.append({"ip": event.get("ip"), "mensagem": event["mensagem"]})
                elif event_type == "dominio":
                    domains.append(event["dados"])
            except queue.Empty:
                pass

            total = len(flows) + len(devices) + len(alerts) + len(logs) + len(domains)
            timed_out = time.monotonic() - last_flush >= self.intervalo_lote_banco
            if total and (timed_out or total >= self.tamanho_lote_banco):
                self._salvar_lote_persistencia(flows, devices, alerts, logs, domains)
                flows.clear(); devices.clear(); alerts.clear(); logs.clear(); domains.clear()
                last_flush = time.monotonic()

        if flows or devices or alerts or logs or domains:
            self._salvar_lote_persistencia(flows, devices, alerts, logs, domains)

    def _salvar_lote_persistencia(self, flows, devices, alerts, logs, domains):
        try:
            self.db.salvar_fluxos_lote(flows)
            self.db.registrar_dispositivos_lote(devices)
            self.db.registrar_alertas_lote(alerts)
            self.db.registrar_logs_lote(logs)
            self.db.registrar_dominios_lote(domains)
        except Exception as error:
            self.fila_alertas.put(
                f"[{datetime.now().strftime('%H:%M:%S')}] [ERRO] Persistência em lote falhou: {error}\n"
            )

    # ================================================================== #
    # IPs / alertas / firewall
    # ================================================================== #
    def classificar_ip_normal(self, ip):
        self.db.atualizar_status_ip(ip, "Normal", "BAIXO", "Classificado manualmente como normal")
        self.auditar("IP_CLASSIFICADO_NORMAL", ip)
        self.registrar_alerta_ui(f"IP {ip} classificado como normal.")

    def classificar_ip_critico(self, ip):
        self.db.atualizar_status_ip(ip, "Crítico", "CRÍTICO", "Classificado manualmente como crítico")
        self.auditar("IP_CLASSIFICADO_CRITICO", ip)
        self.registrar_alerta_ui(f"IP {ip} marcado como crítico.")

    def adicionar_ip_whitelist(self, ip):
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            self.registrar_alerta_ui(f"[ERRO] IP inválido: {ip}")
            return False
        self.whitelist.add(ip)
        self.db.adicionar_whitelist(ip)
        self.db.atualizar_status_ip(ip, "Whitelist", "BAIXO", "IP adicionado à whitelist")
        self.auditar("IP_ADICIONADO_WHITELIST", ip)
        self.registrar_alerta_ui(f"IP {ip} adicionado à whitelist.")
        return True

    def adicionar_ip_blacklist(self, ip, motivo=None):
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            self.registrar_alerta_ui(f"[ERRO] Endereço IP inválido: {ip or 'vazio'}")
            return False
        reason = motivo or "Adicionado manualmente à blacklist"
        self.ip_blacklist.add(ip)
        self.db.adicionar_ip_blacklist(ip, reason)
        self.db.atualizar_status_ip(ip, "Blacklist", "ALTO", reason)
        self.db.registrar_log(f"IP adicionado à blacklist: {reason}", ip=ip)
        self.auditar("IP_ADICIONADO_BLACKLIST", f"{ip} | {reason}")
        self.registrar_alerta_ui(f"[BLACKLIST] IP {ip} adicionado e refletido nos alertas.")
        return True

    def remover_ip_blacklist(self, ip):
        self.ip_blacklist.discard(ip)
        self.db.remover_ip_blacklist(ip)
        status = "Bloqueado" if ip in self.ips_bloqueados else "Suspeito"
        self.db.atualizar_status_ip(ip, status, motivo="IP removido manualmente da blacklist")
        self.auditar("IP_REMOVIDO_BLACKLIST", ip)
        self.registrar_alerta_ui(f"IP {ip} removido da blacklist.")
        return True

    def bloquear_ip_selecionado(self, ip):
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            self.registrar_alerta_ui(f"[ERRO] IP inválido: {ip}")
            return False
        success, message = self.firewall.bloquear_ip(ip, identificador=ip, somente_saida=False)
        if success:
            self.ips_bloqueados.add(ip)
            self.db.bloquear_ip(ip)
            self.db.atualizar_status_ip(ip, "Bloqueado", "CRÍTICO", "Bloqueado manualmente no firewall")
            self.db.registrar_log("IP bloqueado manualmente no firewall", ip=ip)
            self.auditar("IP_BLOQUEADO_FIREWALL", ip)
            self.registrar_alerta_ui(f"[BLOQUEADO] IP {ip}: {message}")
            return True
        self.registrar_alerta_ui(f"[ERRO] Não foi possível bloquear {ip}: {message}")
        return False

    def desbloquear_ip_selecionado(self, ip):
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            self.registrar_alerta_ui(f"[ERRO] IP inválido: {ip}")
            return False
        success, message = self.firewall.desbloquear_ip(ip, identificador=ip, somente_saida=False)
        if success:
            self.ips_bloqueados.discard(ip)
            self.db.desbloquear_ip(ip)
            status = "Blacklist" if ip in self.ip_blacklist else "Suspeito"
            severity = "ALTO" if ip in self.ip_blacklist else "MÉDIO"
            self.db.atualizar_status_ip(ip, status, severity, "Bloqueio removido manualmente")
            self.db.registrar_log("Bloqueio removido manualmente", ip=ip)
            self.auditar("IP_DESBLOQUEADO_FIREWALL", ip)
            self.registrar_alerta_ui(f"[DESBLOQUEADO] IP {ip}: {message}")
            return True
        self.registrar_alerta_ui(f"[ERRO] Não foi possível remover o bloqueio de {ip}: {message}")
        return False

    # ================================================================== #
    # Políticas de domínio
    # ================================================================== #
    def atualizar_regras_dominio(self):
        self.domain_rules = self.db.listar_domain_blacklist(somente_ativos=True)

    def encontrar_regra_dominio(self, dominio, ip_cliente):
        domain = str(dominio or "").lower().rstrip(".")
        matches = []
        for rule in list(self.domain_rules):
            rule_domain = rule["dominio"].lower().rstrip(".")
            if rule.get("ip_cliente") not in ("*", ip_cliente):
                continue
            if domain == rule_domain or domain.endswith("." + rule_domain):
                matches.append(rule)
        if not matches:
            return None
        matches.sort(key=lambda item: (0 if item.get("ip_cliente") == ip_cliente else 1, -len(item["dominio"])))
        return matches[0]

    def adicionar_politica_dominio(self, dominio, ip_cliente="*", modo="monitorar"):
        domain = normalizar_dominio(dominio)
        if not domain:
            self.registrar_alerta_ui(f"[ERRO] Domínio inválido: {dominio or 'vazio'}")
            return False
        client = (ip_cliente or "*").strip()
        if client != "*":
            try:
                client = str(ipaddress.ip_address(client))
            except ValueError:
                self.registrar_alerta_ui(f"[ERRO] IP do cliente inválido: {client}")
                return False
        if modo not in {"monitorar", "bloquear_local"}:
            self.registrar_alerta_ui(f"[ERRO] Modo de política inválido: {modo}")
            return False

        previous_rule = self.db.obter_domain_blacklist(domain, client)
        if previous_rule and previous_rule.get("modo") == "bloquear_local" and modo != "bloquear_local":
            for old_ip in previous_rule.get("ips_resolvidos") or []:
                identifier = f"DOMAIN_{domain}_{old_ip}"
                self.firewall.desbloquear_ip(old_ip, identificador=identifier, somente_saida=True)

        self.db.adicionar_domain_blacklist(domain, client, modo)
        self.atualizar_regras_dominio()
        self.auditar("DOMINIO_BLACKLIST_ADICIONADO", f"{domain} | cliente={client} | modo={modo}")

        if modo == "bloquear_local":
            success, message, _ips = self.reconciliar_regra_dominio(domain, client)
            self.registrar_alerta_ui(("[DOMÍNIO BLOQUEADO] " if success else "[ERRO] ") + message)
            return success

        self.db.atualizar_resolucao_domain_blacklist(domain, client, [], None)
        self.registrar_alerta_ui(f"[DOMÍNIO] {domain} adicionado para monitoramento do cliente {client}.")
        return True

    def reconciliar_regra_dominio(self, dominio, ip_cliente="*"):
        rule = self.db.obter_domain_blacklist(dominio, ip_cliente)
        if not rule:
            return False, "Política de domínio não encontrada.", []
        if rule.get("modo") != "bloquear_local":
            self.db.atualizar_resolucao_domain_blacklist(dominio, ip_cliente, [], None)
            self.atualizar_regras_dominio()
            return True, f"Política de monitoramento atualizada para {dominio}.", []

        try:
            resolved = self.firewall.resolver_dominio(dominio)
        except Exception as error:
            message = f"Falha ao resolver {dominio}: {error}"
            self.db.atualizar_resolucao_domain_blacklist(dominio, ip_cliente, [], message)
            self.atualizar_regras_dominio()
            return False, message, []

        if not resolved:
            message = f"Nenhum IP foi resolvido para {dominio}."
            self.db.atualizar_resolucao_domain_blacklist(dominio, ip_cliente, [], message)
            self.atualizar_regras_dominio()
            return False, message, []

        previous_ips = set(rule.get("ips_resolvidos") or [])
        resolved_set = set(resolved)
        for stale_ip in previous_ips - resolved_set:
            identifier = f"DOMAIN_{dominio}_{stale_ip}"
            self.firewall.desbloquear_ip(stale_ip, identificador=identifier, somente_saida=True)

        applied = []
        errors = []
        for ip in resolved:
            identifier = f"DOMAIN_{dominio}_{ip}"
            success, message = self.firewall.bloquear_ip(ip, identificador=identifier, somente_saida=True)
            if success:
                applied.append(ip)
            else:
                errors.append(f"{ip}: {message}")

        final_error = "; ".join(errors) if errors else None
        self.db.atualizar_resolucao_domain_blacklist(dominio, ip_cliente, applied, final_error)
        self.atualizar_regras_dominio()
        if applied:
            message = f"{dominio} aplicado no firewall local para {len(applied)} IP(s)."
            if errors:
                message += f" Falhas: {final_error}"
            return True, message, applied
        return False, final_error or f"Não foi possível bloquear {dominio}.", []

    def remover_politica_dominio(self, dominio, ip_cliente="*"):
        rule = self.db.obter_domain_blacklist(dominio, ip_cliente)
        if not rule:
            self.registrar_alerta_ui("[ERRO] Política de domínio não encontrada.")
            return False
        errors = []
        if rule.get("modo") == "bloquear_local":
            for ip in rule.get("ips_resolvidos") or []:
                identifier = f"DOMAIN_{dominio}_{ip}"
                success, message = self.firewall.desbloquear_ip(ip, identificador=identifier, somente_saida=True)
                if not success:
                    errors.append(f"{ip}: {message}")
        self.db.remover_domain_blacklist(dominio, ip_cliente)
        self.atualizar_regras_dominio()
        self.auditar("DOMINIO_BLACKLIST_REMOVIDO", f"{dominio} | cliente={ip_cliente}")
        if errors:
            self.registrar_alerta_ui(f"Política removida, mas algumas regras não puderam ser excluídas: {'; '.join(errors)}")
        else:
            self.registrar_alerta_ui(f"Política de {dominio} removida.")
        return True

    def _loop_manutencao_dominios(self):
        # Atualiza periodicamente os IPs de domínios que podem mudar de endereço.
        while not self._stop_event.wait(300):
            try:
                for rule in self.db.listar_domain_blacklist(somente_ativos=True):
                    if rule.get("modo") == "bloquear_local":
                        self.reconciliar_regra_dominio(rule["dominio"], rule["ip_cliente"])
                retention = int(self.db.obter_configuracao("retencao_dominios_horas", "168"))
                self.db.limpar_dominios_antigos(retention)
            except Exception as error:
                self.registrar_alerta_ui(f"[ERRO] Manutenção das políticas de domínio falhou: {error}")

    # ================================================================== #
    # Configuração, auditoria e relatórios
    # ================================================================== #
    def aplicar_configuracoes(self, interface, portas_sensiveis, limite_scan, janela_scan):
        self.captura.interface = interface
        self.detector.atualizar_portas_sensiveis(portas_sensiveis)
        self.detector.limite_portas_scan = limite_scan
        self.detector.janela_scan = timedelta(seconds=janela_scan)
        self.interface_select.set(interface or "Automática")

    def auditar(self, action, details=None):
        try:
            self.db.registrar_auditoria("desktop", action, details, "local")
        except Exception as error:
            print(f"Falha ao registrar auditoria: {error}")

    def obter_faixa_rede_local(self):
        ip_local = None
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(("8.8.8.8", 80))
            ip_local = sock.getsockname()[0]
        except Exception:
            try:
                ip_local = socket.gethostbyname(socket.gethostname())
            except Exception:
                return None
        finally:
            if sock:
                sock.close()
        try:
            return str(ipaddress.ip_network(f"{ip_local}/24", strict=False))
        except ValueError:
            return None

    def exportar_fluxos_csv(self, caminho):
        result = relatorios.exportar_fluxos_csv(self.db.listar_fluxos(limite=100000), caminho)
        self.auditar("RELATORIO_FLUXOS_CSV", caminho)
        return result

    def exportar_alertas_csv(self, caminho):
        result = relatorios.exportar_alertas_csv(self.db.listar_alertas(), caminho)
        self.auditar("RELATORIO_ALERTAS_CSV", caminho)
        return result

    def exportar_relatorio_geral_pdf(self, caminho):
        summary = self.db.obter_resumo(segundos_dominios=30)
        summary["status_captura"] = "Ativa" if self.captura.ativo else "Parada"
        result = relatorios.exportar_relatorio_pdf(
            caminho, summary, self.db.listar_fluxos(limite=500), self.db.listar_alertas()
        )
        self.auditar("RELATORIO_GERAL_PDF", caminho)
        return result

    def exportar_relatorio_ip_pdf(self, ip, caminho):
        alert = self.db.obter_alerta(ip)
        if alert is None:
            raise ValueError(f"Não há registro de alerta para o IP {ip}.")
        result = relatorios.exportar_relatorio_ip_pdf(caminho, alert, self.db.listar_log(ip=ip))
        self.auditar("RELATORIO_IP_PDF", f"{ip} | {caminho}")
        return result

    # ================================================================== #
    # Mensagens e encerramento
    # ================================================================== #
    def registrar_alerta_ui(self, mensagem):
        text = f"[{datetime.now().strftime('%H:%M:%S')}] {mensagem}\n"
        self.fila_alertas.put(text)
        print(text, end="")

    def _exibir_alerta(self, text):
        compact = text.strip()
        self.last_event_label.configure(text=compact[-180:])
        frame = self.frame_atual
        if frame is not None and hasattr(frame, "adicionar_log"):
            try:
                frame.adicionar_log(text)
            except Exception:
                pass

    def _ao_fechar(self):
        after_id = getattr(self, "_after_process_id", None)
        if after_id is not None:
            try:
                self.after_cancel(after_id)
            except Exception:
                pass
            self._after_process_id = None

        self.captura.parar()
        self.persistencia_ativa = False
        self._stop_event.set()
        if hasattr(self, "thread_persistencia") and self.thread_persistencia.is_alive():
            self.thread_persistencia.join(timeout=2)
        self.db.fechar()
        self.destroy()
