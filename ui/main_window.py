"""
Janela principal do DevSec - NetFlow Analyzer.

Esta classe é o "orquestrador": ela conecta a interface gráfica
(CustomTkinter) com os módulos de domínio:

- database.database.Database        -> persistência (SQLite)
- capture.packet_capture.PacketCapture -> captura real de pacotes (Scapy)
- capture.flow_analyzer.FlowAnalyzer   -> agregação de pacotes em fluxos
- capture.detector.Detector            -> geração de alertas
- reports.export                       -> exportação de evidências (CSV/PDF)

As telas de Dashboard, Alertas, Dispositivos, Relatórios e Configurações
vivem em módulos próprios dentro de ui/. A tela de Captura continua
implementada aqui, porque ela está fortemente acoplada às filas
(queue.Queue) que recebem dados da thread de captura em tempo real.
"""

import ipaddress
import os
import queue
import socket
import subprocess
import threading
import time
from datetime import datetime, timedelta
from tkinter import ttk

import customtkinter as ctk

from capture.detector import Detector
from capture.flow_analyzer import FlowAnalyzer
from capture.packet_capture import PacketCapture
from database.database import Database
from reports import export as relatorios
from ui.dashboard import DashboardFrame
from ui.alerts import AlertsFrame
from ui.devices import DevicesFrame
from ui.reports import ReportsFrame
from ui.settings import SettingsFrame
from ui.theme import COLORS, apply_theme, dark_button, danger_button, secondary_button


class MainWindow(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("DevSec - NetFlow Analyzer")
        self.geometry("1280x740")
        self.minsize(1080, 620)

        apply_theme(self)

        # ---------------------------------------------------------------- #
        # Estado / módulos de domínio
        # ---------------------------------------------------------------- #
        self.db = Database()

        interface_salva = self.db.obter_configuracao("interface_rede", "") or None
        portas_sensiveis = self.db.obter_portas_sensiveis()
        limite_scan = int(self.db.obter_configuracao("limite_portas_scan", "15"))
        janela_scan = int(self.db.obter_configuracao("janela_scan_segundos", "10"))

        self.analisador_fluxos = FlowAnalyzer()
        self.detector = Detector(
            portas_sensiveis=portas_sensiveis,
            limite_portas_scan=limite_scan,
            janela_scan_segundos=janela_scan,
        )
        self.captura = PacketCapture(
            callback_pacote=self._callback_pacote,
            interface=interface_salva,
            callback_log=self.registrar_alerta_ui,
        )

        self.whitelist = set(self.db.listar_whitelist())
        self.ips_bloqueados = set(self.db.listar_ips_bloqueados())

        self.fila_fluxos = queue.Queue()
        self.fila_alertas = queue.Queue()
        self.fila_persistencia = queue.Queue()

        # Limites de processamento para a UI não travar com tráfego real.
        self.max_fluxos_por_ciclo_ui = 120
        self.max_alertas_por_ciclo_ui = 50
        self.intervalo_processamento_ui_ms = 100

        # Gravação em banco fica em lote, em uma thread separada da interface.
        self.persistencia_ativa = True
        self.tamanho_lote_banco = 300
        self.intervalo_lote_banco = 1.0

        # Evita atualizar telas pesadas a cada pacote.
        self._ultima_atualizacao_dashboard = 0.0
        self._ultima_atualizacao_alertas = 0.0
        self._cooldown_alerta_por_chave = {}
        self.cooldown_alerta_segundos = 4.0

        self.linhas_tabela = {}
        self.tabela = None
        self.caixa_alertas = None

        self.filtro_ip = None
        self.filtro_porta = None
        self.filtro_protocolo = None

        self.tela_atual_nome = None
        self.frame_atual = None

        self.protocol("WM_DELETE_WINDOW", self._ao_fechar)

        self.thread_persistencia = threading.Thread(target=self._loop_persistencia, daemon=True)
        self.thread_persistencia.start()

        self._criar_layout()
        self._processar_filas()

    # ====================================================================== #
    # Layout / navegação
    # ====================================================================== #
    def _criar_layout(self):
        self.sidebar = ctk.CTkFrame(self, width=220, corner_radius=0, fg_color=COLORS["sidebar"])
        self.sidebar.pack(side="left", fill="y")

        self.conteudo = ctk.CTkFrame(self, fg_color=COLORS["bg"])
        self.conteudo.pack(side="right", fill="both", expand=True, padx=10, pady=10)

        ctk.CTkLabel(
            self.sidebar,
            text="◆ DEVSEC",
            font=("Arial", 26, "bold"),
            text_color=COLORS["cream_text"],
        ).pack(pady=25)

        botoes = ["Dashboard", "Captura", "Alertas", "Dispositivos", "Relatórios", "Configurações"]

        for nome in botoes:
            ctk.CTkButton(
                self.sidebar,
                text=nome.upper(),
                height=40,
                command=lambda n=nome: self.mostrar_pagina(n),
                fg_color=COLORS["sidebar"],
                hover_color=COLORS["red"],
                text_color=COLORS["cream_text"],
                border_width=1,
                border_color=COLORS["red"],
            ).pack(fill="x", padx=20, pady=8)

        self.mostrar_pagina("Dashboard")

    def mostrar_pagina(self, nome):
        for widget in self.conteudo.winfo_children():
            widget.destroy()

        self.tabela = None
        self.caixa_alertas = None
        self.tela_atual_nome = nome
        self.frame_atual = None

        ctk.CTkLabel(
            self.conteudo,
            text=nome.upper(),
            font=("Arial", 28, "bold"),
            text_color=COLORS["terminal"],
        ).pack(pady=15)

        if nome == "Dashboard":
            self.frame_atual = DashboardFrame(self.conteudo, self)
            self.frame_atual.pack(fill="both", expand=True)

        elif nome == "Captura":
            self._tela_captura()

        elif nome == "Alertas":
            self.frame_atual = AlertsFrame(self.conteudo, self)
            self.frame_atual.pack(fill="both", expand=True)

        elif nome == "Dispositivos":
            self.frame_atual = DevicesFrame(self.conteudo, self)
            self.frame_atual.pack(fill="both", expand=True)

        elif nome == "Relatórios":
            self.frame_atual = ReportsFrame(self.conteudo, self)
            self.frame_atual.pack(fill="both", expand=True)

        elif nome == "Configurações":
            self.frame_atual = SettingsFrame(self.conteudo, self)
            self.frame_atual.pack(fill="both", expand=True)

    # ====================================================================== #
    # Tela de Captura (tabela de fluxos em tempo real)
    # ====================================================================== #
    def _tela_captura(self):
        frame_botoes = ctk.CTkFrame(self.conteudo, fg_color=COLORS["panel_alt"])
        frame_botoes.pack(fill="x", padx=20, pady=10)

        ctk.CTkButton(frame_botoes, text="Iniciar Captura Real", height=38, command=self.iniciar_captura).pack(
            side="left", padx=10, pady=10
        )
        ctk.CTkButton(
            frame_botoes,
            text="Parar Captura",
            height=38,
            fg_color=COLORS["red"],
            hover_color=COLORS["red_hover"],
            command=self.parar_captura,
        ).pack(side="left", padx=10, pady=10)
        ctk.CTkButton(frame_botoes, text="Limpar Tabela", height=38, command=self.limpar_tabela, **dark_button()).pack(
            side="left", padx=10, pady=10
        )

        frame_filtros = ctk.CTkFrame(self.conteudo, fg_color=COLORS["panel_alt"])
        frame_filtros.pack(fill="x", padx=20, pady=5)

        self.filtro_ip = ctk.CTkEntry(frame_filtros, placeholder_text="Filtrar por IP", width=180)
        self.filtro_ip.pack(side="left", padx=10, pady=10)

        self.filtro_porta = ctk.CTkEntry(frame_filtros, placeholder_text="Filtrar por porta", width=150)
        self.filtro_porta.pack(side="left", padx=10, pady=10)

        self.filtro_protocolo = ctk.CTkOptionMenu(frame_filtros, values=["Todos", "TCP", "UDP", "IP"], width=140)
        self.filtro_protocolo.set("Todos")
        self.filtro_protocolo.pack(side="left", padx=10, pady=10)

        ctk.CTkButton(frame_filtros, text="Aplicar Filtros", command=self.aplicar_filtros).pack(
            side="left", padx=10, pady=10
        )
        ctk.CTkButton(frame_filtros, text="Resetar Filtros", command=self.resetar_filtros).pack(
            side="left", padx=10, pady=10
        )

        frame_tabela = ctk.CTkFrame(self.conteudo, fg_color=COLORS["panel"])
        frame_tabela.pack(fill="both", expand=True, padx=20, pady=10)

        colunas = (
            "origem", "destino", "porta_origem", "porta_destino",
            "protocolo", "pacotes", "bytes", "ultimo",
        )

        self.tabela = ttk.Treeview(frame_tabela, columns=colunas, show="headings", height=15)

        titulos = {
            "origem": "IP Origem", "destino": "IP Destino", "porta_origem": "Porta Origem",
            "porta_destino": "Porta Destino", "protocolo": "Protocolo", "pacotes": "Pacotes",
            "bytes": "Bytes", "ultimo": "Último",
        }
        larguras = {
            "origem": 140, "destino": 140, "porta_origem": 110, "porta_destino": 110,
            "protocolo": 100, "pacotes": 100, "bytes": 110, "ultimo": 100,
        }

        for coluna in colunas:
            self.tabela.heading(coluna, text=titulos[coluna], anchor="w")
            self.tabela.column(coluna, width=larguras[coluna], anchor="w")

        scrollbar = ttk.Scrollbar(frame_tabela, orient="vertical", command=self.tabela.yview)
        self.tabela.configure(yscrollcommand=scrollbar.set)

        self.tabela.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=10)
        scrollbar.pack(side="right", fill="y", padx=(0, 10), pady=10)

        self.caixa_alertas = ctk.CTkTextbox(self.conteudo, height=110)
        self.caixa_alertas.pack(fill="x", padx=20, pady=10)
        self.caixa_alertas.insert("end", "Alertas aparecerão aqui...\n")

        self.linhas_tabela = {}
        self._recarregar_tabela()

    # ====================================================================== #
    # Controle de captura
    # ====================================================================== #
    def iniciar_captura(self):
        self.captura.iniciar()

    def parar_captura(self):
        self.captura.parar()

    def _callback_pacote(self, pacote):
        """Executado na thread de captura (Scapy). Só converte o pacote em
        fluxo e devolve para a fila; todo o resto acontece na thread da UI."""
        fluxo = self.analisador_fluxos.pacote_para_fluxo(pacote)
        if fluxo is not None:
            self.fila_fluxos.put(fluxo)

    def _processar_filas(self):
        # Processa uma quantidade limitada por ciclo para manter o mainloop livre
        # para redesenhar a janela. Sem isso, tráfego real pode travar tudo.
        fluxos_processados = 0
        while fluxos_processados < self.max_fluxos_por_ciclo_ui and not self.fila_fluxos.empty():
            fluxo = self.fila_fluxos.get()
            self._processar_fluxo(fluxo)
            fluxos_processados += 1

        alertas_processados = 0
        while alertas_processados < self.max_alertas_por_ciclo_ui and not self.fila_alertas.empty():
            mensagem = self.fila_alertas.get()
            self._exibir_alerta(mensagem)
            alertas_processados += 1

        self.after(self.intervalo_processamento_ui_ms, self._processar_filas)

    def _processar_fluxo(self, fluxo):
        chave, registro, e_novo = self.analisador_fluxos.atualizar_fluxo(fluxo)

        # Nada de SQLite aqui. A interface só atualiza a memória e a tabela.
        # O banco recebe os dados por uma fila separada e grava em lote.
        self.fila_persistencia.put({"tipo": "fluxo", "dados": fluxo})
        self.fila_persistencia.put({"tipo": "dispositivo", "ip": fluxo["ip_origem"]})
        self.fila_persistencia.put({"tipo": "dispositivo", "ip": fluxo["ip_destino"]})

        self._atualizar_linha_tabela(chave, registro)

        alertas = self.detector.verificar_fluxo(fluxo, whitelist=self.whitelist)
        for alerta in alertas:
            if not self._alerta_passou_cooldown(alerta):
                continue

            self.registrar_alerta_ui(alerta["mensagem"])
            self.fila_persistencia.put({"tipo": "alerta", "dados": alerta})
            self.fila_persistencia.put(
                {"tipo": "log", "ip": alerta["ip"], "mensagem": alerta["mensagem"]}
            )

        agora = time.monotonic()

        if alertas and self.tela_atual_nome == "Alertas" and self.frame_atual is not None:
            if agora - self._ultima_atualizacao_alertas >= 1.0:
                self.frame_atual.recarregar()
                self._ultima_atualizacao_alertas = agora

        if self.tela_atual_nome == "Dashboard" and self.frame_atual is not None:
            if agora - self._ultima_atualizacao_dashboard >= 1.0:
                self.frame_atual.atualizar()
                self._ultima_atualizacao_dashboard = agora

    def _alerta_passou_cooldown(self, alerta):
        """Evita spam de alerta visual/log para o mesmo IP+motivo a cada pacote."""
        chave = (alerta.get("ip"), alerta.get("motivo"))
        agora = time.monotonic()
        ultimo = self._cooldown_alerta_por_chave.get(chave, 0.0)

        if agora - ultimo < self.cooldown_alerta_segundos:
            return False

        self._cooldown_alerta_por_chave[chave] = agora
        return True

    def _atualizar_linha_tabela(self, chave, registro):
        if self.tabela is None:
            return

        if not self._fluxo_passou_filtro(registro):
            if chave in self.linhas_tabela:
                self.tabela.delete(self.linhas_tabela[chave])
                del self.linhas_tabela[chave]
            return

        valores = (
            registro["ip_origem"], registro["ip_destino"], registro["porta_origem"],
            registro["porta_destino"], registro["protocolo"], registro["pacotes"],
            registro["bytes"], registro["ultimo"],
        )

        if chave in self.linhas_tabela:
            linha_id = self.linhas_tabela[chave]
            self.tabela.item(linha_id, values=valores)
        else:
            linha_id = self.tabela.insert("", "end", values=valores)
            self.linhas_tabela[chave] = linha_id

        self.tabela.see(linha_id)

    def _fluxo_passou_filtro(self, fluxo):
        filtro_ip = self.filtro_ip.get().strip() if self.filtro_ip is not None else None
        filtro_porta = self.filtro_porta.get().strip() if self.filtro_porta is not None else None
        filtro_protocolo = self.filtro_protocolo.get() if self.filtro_protocolo is not None else None

        return FlowAnalyzer.fluxo_passou_filtro(
            fluxo, filtro_ip=filtro_ip, filtro_porta=filtro_porta, filtro_protocolo=filtro_protocolo
        )

    def aplicar_filtros(self):
        self._recarregar_tabela()
        self.registrar_alerta_ui("Filtros aplicados.")

    def resetar_filtros(self):
        if self.filtro_ip is not None:
            self.filtro_ip.delete(0, "end")
        if self.filtro_porta is not None:
            self.filtro_porta.delete(0, "end")
        if self.filtro_protocolo is not None:
            self.filtro_protocolo.set("Todos")

        self._recarregar_tabela()
        self.registrar_alerta_ui("Filtros resetados.")

    def _recarregar_tabela(self):
        if self.tabela is None:
            return

        for item in self.tabela.get_children():
            self.tabela.delete(item)

        self.linhas_tabela = {}

        for chave, registro in self.analisador_fluxos.obter_fluxos().items():
            if not self._fluxo_passou_filtro(registro):
                continue

            valores = (
                registro["ip_origem"], registro["ip_destino"], registro["porta_origem"],
                registro["porta_destino"], registro["protocolo"], registro["pacotes"],
                registro["bytes"], registro["ultimo"],
            )
            linha_id = self.tabela.insert("", "end", values=valores)
            self.linhas_tabela[chave] = linha_id

    def limpar_tabela(self):
        self.analisador_fluxos.limpar()
        self.linhas_tabela = {}

        if self.tabela is not None:
            for item in self.tabela.get_children():
                self.tabela.delete(item)

        self.registrar_alerta_ui("Tabela de fluxos limpa (o histórico no banco de dados é mantido).")

    # ====================================================================== #
    # Persistência assíncrona em lote
    # ====================================================================== #
    def _loop_persistencia(self):
        fluxos = []
        dispositivos = []
        alertas = []
        logs = []
        ultimo_flush = time.monotonic()

        while self.persistencia_ativa or not self.fila_persistencia.empty():
            try:
                evento = self.fila_persistencia.get(timeout=0.2)

                tipo = evento.get("tipo")
                if tipo == "fluxo":
                    fluxos.append(evento["dados"])
                elif tipo == "dispositivo":
                    dispositivos.append(evento.get("ip"))
                elif tipo == "alerta":
                    alertas.append(evento["dados"])
                elif tipo == "log":
                    logs.append({"ip": evento.get("ip"), "mensagem": evento["mensagem"]})

            except queue.Empty:
                pass

            total_pendente = len(fluxos) + len(dispositivos) + len(alertas) + len(logs)
            tempo_estourou = (time.monotonic() - ultimo_flush) >= self.intervalo_lote_banco
            lote_cheio = total_pendente >= self.tamanho_lote_banco

            if total_pendente and (tempo_estourou or lote_cheio):
                self._salvar_lote_persistencia(fluxos, dispositivos, alertas, logs)
                fluxos.clear()
                dispositivos.clear()
                alertas.clear()
                logs.clear()
                ultimo_flush = time.monotonic()

        if fluxos or dispositivos or alertas or logs:
            self._salvar_lote_persistencia(fluxos, dispositivos, alertas, logs)

    def _salvar_lote_persistencia(self, fluxos, dispositivos, alertas, logs):
        try:
            self.db.salvar_fluxos_lote(fluxos)
            self.db.registrar_dispositivos_lote(dispositivos)
            self.db.registrar_alertas_lote(alertas)
            self.db.registrar_logs_lote(logs)
        except Exception as erro:
            # Não tenta gravar esse erro no banco para evitar loop de falha.
            self.fila_alertas.put(f"[{datetime.now().strftime('%H:%M:%S')}] [ERRO] Persistência em lote falhou: {erro}\n")

    # ====================================================================== #
    # Ações de Alertas (chamadas pela AlertsFrame)
    # ====================================================================== #
    def classificar_ip_normal(self, ip):
        self.db.atualizar_status_ip(ip, "Normal", "BAIXO", "Classificado manualmente como normal")
        self.registrar_alerta_ui(f"IP {ip} classificado como normal.")

    def classificar_ip_critico(self, ip):
        self.db.atualizar_status_ip(ip, "Crítico", "CRÍTICO", "Classificado manualmente como crítico")
        self.registrar_alerta_ui(f"IP {ip} marcado como crítico.")

    def adicionar_ip_whitelist(self, ip):
        self.whitelist.add(ip)
        self.db.adicionar_whitelist(ip)
        self.db.atualizar_status_ip(ip, "Whitelist", "BAIXO", "IP adicionado à whitelist")
        self.registrar_alerta_ui(f"IP {ip} adicionado à whitelist.")

    def bloquear_ip_selecionado(self, ip):
        sucesso, mensagem = self._bloquear_ip_windows(ip)

        if sucesso:
            self.ips_bloqueados.add(ip)
            self.db.bloquear_ip(ip)
            self.db.atualizar_status_ip(ip, "Bloqueado", "CRÍTICO", "Bloqueado manualmente no firewall")
            self.registrar_alerta_ui(f"[BLOQUEADO] IP {ip} bloqueado no Windows Firewall.")
        else:
            self.registrar_alerta_ui(f"[ERRO] Não foi possível bloquear {ip}: {mensagem}")

    def desbloquear_ip_selecionado(self, ip):
        sucesso, mensagem = self._desbloquear_ip_windows(ip)

        if sucesso:
            self.ips_bloqueados.discard(ip)
            self.db.desbloquear_ip(ip)
            self.db.atualizar_status_ip(ip, "Suspeito", motivo="Bloqueio removido manualmente")
            self.registrar_alerta_ui(f"[DESBLOQUEADO] Bloqueio do IP {ip} removido.")
        else:
            self.registrar_alerta_ui(f"[ERRO] Não foi possível remover bloqueio de {ip}: {mensagem}")

    # ====================================================================== #
    # Firewall (Windows) - bloqueio real via netsh
    # ====================================================================== #
    def _bloquear_ip_windows(self, ip):
        if os.name != "nt":
            return False, "Bloqueio automático implementado apenas para Windows neste código."

        try:
            nome_entrada = f"DevSec Block IN {ip}"
            nome_saida = f"DevSec Block OUT {ip}"

            comando_entrada = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={nome_entrada}", "dir=in", "action=block", f"remoteip={ip}",
            ]
            comando_saida = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={nome_saida}", "dir=out", "action=block", f"remoteip={ip}",
            ]

            resultado_entrada = subprocess.run(comando_entrada, capture_output=True, text=True, shell=False)
            resultado_saida = subprocess.run(comando_saida, capture_output=True, text=True, shell=False)

            if resultado_entrada.returncode == 0 and resultado_saida.returncode == 0:
                return True, "IP bloqueado com sucesso."

            erro = resultado_entrada.stderr + resultado_saida.stderr
            saida = resultado_entrada.stdout + resultado_saida.stdout
            return False, erro or saida or "Erro desconhecido."

        except Exception as erro:
            return False, str(erro)

    def _desbloquear_ip_windows(self, ip):
        if os.name != "nt":
            return False, "Remoção de bloqueio implementada apenas para Windows neste código."

        try:
            nome_entrada = f"DevSec Block IN {ip}"
            nome_saida = f"DevSec Block OUT {ip}"

            comando_entrada = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={nome_entrada}"]
            comando_saida = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={nome_saida}"]

            resultado_entrada = subprocess.run(comando_entrada, capture_output=True, text=True, shell=False)
            resultado_saida = subprocess.run(comando_saida, capture_output=True, text=True, shell=False)

            if resultado_entrada.returncode == 0 or resultado_saida.returncode == 0:
                return True, "Bloqueio removido."

            erro = resultado_entrada.stderr + resultado_saida.stderr
            saida = resultado_entrada.stdout + resultado_saida.stdout
            return False, erro or saida or "Regra não encontrada."

        except Exception as erro:
            return False, str(erro)

    # ====================================================================== #
    # Configurações (chamadas pela SettingsFrame)
    # ====================================================================== #
    def aplicar_configuracoes(self, interface, portas_sensiveis, limite_scan, janela_scan):
        self.captura.interface = interface
        self.detector.atualizar_portas_sensiveis(portas_sensiveis)
        self.detector.limite_portas_scan = limite_scan
        self.detector.janela_scan = timedelta(seconds=janela_scan)

    def obter_faixa_rede_local(self):
        """Estima a faixa /24 da rede local a partir do IP da máquina, para
        uso no ARP scan da tela de Dispositivos."""
        try:
            ip_local = socket.gethostbyname(socket.gethostname())
            rede = ipaddress.ip_network(f"{ip_local}/24", strict=False)
            return str(rede)
        except Exception:
            return None

    # ====================================================================== #
    # Relatórios (chamadas pela ReportsFrame / AlertsFrame)
    # ====================================================================== #
    def exportar_fluxos_csv(self, caminho):
        return relatorios.exportar_fluxos_csv(self.db.listar_fluxos(limite=100000), caminho)

    def exportar_alertas_csv(self, caminho):
        return relatorios.exportar_alertas_csv(self.db.listar_alertas(), caminho)

    def exportar_relatorio_geral_pdf(self, caminho):
        resumo = {
            "total_fluxos": len(self.analisador_fluxos.obter_fluxos()),
            "total_suspeitos": len(self.db.listar_alertas()),
            "total_bloqueados": len(self.db.listar_ips_bloqueados()),
            "status_captura": "Ativa" if self.captura.ativo else "Parada",
        }
        return relatorios.exportar_relatorio_pdf(
            caminho, resumo, self.db.listar_fluxos(limite=500), self.db.listar_alertas()
        )

    def exportar_relatorio_ip_pdf(self, ip, caminho):
        alerta = self.db.obter_alerta(ip)
        if alerta is None:
            raise ValueError(f"Não há registro de alerta para o IP {ip}.")

        eventos_log = self.db.listar_log(ip=ip)
        return relatorios.exportar_relatorio_ip_pdf(caminho, alerta, eventos_log)

    # ====================================================================== #
    # Log / alertas de UI
    # ====================================================================== #
    def registrar_alerta_ui(self, mensagem):
        horario = datetime.now().strftime("%H:%M:%S")
        texto = f"[{horario}] {mensagem}\n"
        self.fila_alertas.put(texto)
        print(texto, end="")

    def _exibir_alerta(self, texto):
        if self.caixa_alertas is not None:
            self.caixa_alertas.insert("end", texto)
            self.caixa_alertas.see("end")

    # ====================================================================== #
    # Encerramento
    # ====================================================================== #
    def _ao_fechar(self):
        self.captura.parar()
        self.persistencia_ativa = False

        if hasattr(self, "thread_persistencia") and self.thread_persistencia.is_alive():
            self.thread_persistencia.join(timeout=2)

        self.db.fechar()
        self.destroy()
