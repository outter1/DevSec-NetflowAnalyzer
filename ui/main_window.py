import customtkinter as ctk
from tkinter import ttk
import threading
import queue
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP


class MainWindow(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("DevSec - NetFlow Analyzer")
        self.geometry("1150x680")
        self.minsize(950, 550)

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.captura_ativa = False

        self.fila_fluxos = queue.Queue()
        self.fila_alertas = queue.Queue()

        self.fluxos = {}
        self.linhas_tabela = {}

        self.tabela = None
        self.caixa_alertas = None

        self.criar_layout()
        self.processar_filas()

    def criar_layout(self):
        self.sidebar = ctk.CTkFrame(self, width=220, corner_radius=0)
        self.sidebar.pack(side="left", fill="y")

        self.conteudo = ctk.CTkFrame(self)
        self.conteudo.pack(side="right", fill="both", expand=True, padx=10, pady=10)

        titulo = ctk.CTkLabel(
            self.sidebar,
            text="DevSec",
            font=("Arial", 26, "bold")
        )
        titulo.pack(pady=25)

        botoes = [
            "Dashboard",
            "Captura",
            "Alertas",
            "Dispositivos",
            "Relatórios",
            "Configurações"
        ]

        for nome in botoes:
            botao = ctk.CTkButton(
                self.sidebar,
                text=nome,
                height=40,
                command=lambda n=nome: self.mostrar_pagina(n)
            )
            botao.pack(fill="x", padx=20, pady=8)

        self.mostrar_pagina("Dashboard")

    def mostrar_pagina(self, nome):
        for widget in self.conteudo.winfo_children():
            widget.destroy()

        self.tabela = None
        self.caixa_alertas = None

        titulo = ctk.CTkLabel(
            self.conteudo,
            text=nome,
            font=("Arial", 28, "bold")
        )
        titulo.pack(pady=15)

        if nome == "Captura":
            self.tela_captura()
        elif nome == "Dashboard":
            self.tela_dashboard()
        else:
            texto = ctk.CTkLabel(
                self.conteudo,
                text=f"Tela de {nome}",
                font=("Arial", 16)
            )
            texto.pack(pady=10)

    def tela_dashboard(self):
        frame_cards = ctk.CTkFrame(self.conteudo)
        frame_cards.pack(fill="x", padx=20, pady=20)

        total_fluxos = len(self.fluxos)

        card1 = ctk.CTkLabel(
            frame_cards,
            text=f"Fluxos monitorados\n{total_fluxos}",
            font=("Arial", 20, "bold"),
            width=250,
            height=100
        )
        card1.pack(side="left", padx=15, pady=15)

        status = "Ativa" if self.captura_ativa else "Parada"

        card2 = ctk.CTkLabel(
            frame_cards,
            text=f"Captura\n{status}",
            font=("Arial", 20, "bold"),
            width=250,
            height=100
        )
        card2.pack(side="left", padx=15, pady=15)

        texto = ctk.CTkLabel(
            self.conteudo,
            text="Use a tela Captura para iniciar a análise real de tráfego com Scapy.",
            font=("Arial", 16)
        )
        texto.pack(pady=20)

    def tela_captura(self):
        frame_botoes = ctk.CTkFrame(self.conteudo)
        frame_botoes.pack(fill="x", padx=20, pady=10)

        botao_iniciar = ctk.CTkButton(
            frame_botoes,
            text="Iniciar Captura Real",
            height=38,
            command=self.iniciar_captura
        )
        botao_iniciar.pack(side="left", padx=10, pady=10)

        botao_parar = ctk.CTkButton(
            frame_botoes,
            text="Parar Captura",
            height=38,
            fg_color="#7f1d1d",
            hover_color="#991b1b",
            command=self.parar_captura
        )
        botao_parar.pack(side="left", padx=10, pady=10)

        frame_tabela = ctk.CTkFrame(self.conteudo)
        frame_tabela.pack(fill="both", expand=True, padx=20, pady=10)

        colunas = (
            "origem",
            "destino",
            "porta_origem",
            "porta_destino",
            "protocolo",
            "pacotes",
            "bytes",
            "ultimo"
        )

        self.tabela = ttk.Treeview(
            frame_tabela,
            columns=colunas,
            show="headings",
            height=14
        )

        self.tabela.heading("origem", text="IP Origem", anchor="w")
        self.tabela.heading("destino", text="IP Destino", anchor="w")
        self.tabela.heading("porta_origem", text="Porta Origem", anchor="w")
        self.tabela.heading("porta_destino", text="Porta Destino", anchor="w")
        self.tabela.heading("protocolo", text="Protocolo", anchor="w")
        self.tabela.heading("pacotes", text="Pacotes", anchor="w")
        self.tabela.heading("bytes", text="Bytes", anchor="w")
        self.tabela.heading("ultimo", text="Último", anchor="w")

        self.tabela.column("origem", width=140, anchor="w")
        self.tabela.column("destino", width=140, anchor="w")
        self.tabela.column("porta_origem", width=110, anchor="w")
        self.tabela.column("porta_destino", width=110, anchor="w")
        self.tabela.column("protocolo", width=100, anchor="w")
        self.tabela.column("pacotes", width=100, anchor="w")
        self.tabela.column("bytes", width=110, anchor="w")
        self.tabela.column("ultimo", width=100, anchor="w")

        self.tabela.pack(fill="both", expand=True, padx=10, pady=10)

        self.caixa_alertas = ctk.CTkTextbox(
            self.conteudo,
            height=120
        )
        self.caixa_alertas.pack(fill="x", padx=20, pady=10)

        self.caixa_alertas.insert("end", "Alertas aparecerão aqui...\n")

        self.recarregar_tabela()

    def iniciar_captura(self):
        if self.captura_ativa:
            self.adicionar_alerta("A captura já está em execução.")
            return

        self.captura_ativa = True
        self.adicionar_alerta("Captura real iniciada.")

        thread = threading.Thread(target=self.capturar_fluxos_reais)
        thread.daemon = True
        thread.start()

    def parar_captura(self):
        self.captura_ativa = False
        self.adicionar_alerta("Solicitação para parar captura enviada.")

    def capturar_fluxos_reais(self):
        try:
            sniff(
                prn=self.converter_pacote_em_fluxo,
                store=False,
                stop_filter=lambda pacote: not self.captura_ativa
            )

        except Exception as erro:
            self.captura_ativa = False
            self.adicionar_alerta(f"[ERRO] Falha na captura real: {erro}")

    def converter_pacote_em_fluxo(self, pacote):
        if IP not in pacote:
            return

        ip_origem = pacote[IP].src
        ip_destino = pacote[IP].dst

        porta_origem = 0
        porta_destino = 0
        protocolo = "IP"

        if TCP in pacote:
            porta_origem = pacote[TCP].sport
            porta_destino = pacote[TCP].dport
            protocolo = "TCP"

        elif UDP in pacote:
            porta_origem = pacote[UDP].sport
            porta_destino = pacote[UDP].dport
            protocolo = "UDP"

        else:
            protocolo = str(pacote[IP].proto)

        fluxo = {
            "ip_origem": ip_origem,
            "ip_destino": ip_destino,
            "porta_origem": porta_origem,
            "porta_destino": porta_destino,
            "protocolo": protocolo,
            "bytes": len(pacote),
            "horario": datetime.now().strftime("%H:%M:%S")
        }

        self.fila_fluxos.put(fluxo)

    def processar_filas(self):
        while not self.fila_fluxos.empty():
            fluxo = self.fila_fluxos.get()
            self.atualizar_fluxo(fluxo)
            self.verificar_alertas(fluxo)

        while not self.fila_alertas.empty():
            mensagem = self.fila_alertas.get()
            self.exibir_alerta(mensagem)

        self.after(500, self.processar_filas)

    def atualizar_fluxo(self, fluxo):
        chave = (
            fluxo["ip_origem"],
            fluxo["ip_destino"],
            fluxo["porta_origem"],
            fluxo["porta_destino"],
            fluxo["protocolo"]
        )

        if chave not in self.fluxos:
            self.fluxos[chave] = {
                "ip_origem": fluxo["ip_origem"],
                "ip_destino": fluxo["ip_destino"],
                "porta_origem": fluxo["porta_origem"],
                "porta_destino": fluxo["porta_destino"],
                "protocolo": fluxo["protocolo"],
                "pacotes": 0,
                "bytes": 0,
                "ultimo": fluxo["horario"]
            }

        self.fluxos[chave]["pacotes"] += 1
        self.fluxos[chave]["bytes"] += fluxo["bytes"]
        self.fluxos[chave]["ultimo"] = fluxo["horario"]

        if self.tabela is None:
            return

        valores = (
            self.fluxos[chave]["ip_origem"],
            self.fluxos[chave]["ip_destino"],
            self.fluxos[chave]["porta_origem"],
            self.fluxos[chave]["porta_destino"],
            self.fluxos[chave]["protocolo"],
            self.fluxos[chave]["pacotes"],
            self.fluxos[chave]["bytes"],
            self.fluxos[chave]["ultimo"]
        )

        if chave in self.linhas_tabela:
            self.tabela.item(self.linhas_tabela[chave], values=valores)
        else:
            linha_id = self.tabela.insert("", "end", values=valores)
            self.linhas_tabela[chave] = linha_id

    def recarregar_tabela(self):
        if self.tabela is None:
            return

        for chave, fluxo in self.fluxos.items():
            valores = (
                fluxo["ip_origem"],
                fluxo["ip_destino"],
                fluxo["porta_origem"],
                fluxo["porta_destino"],
                fluxo["protocolo"],
                fluxo["pacotes"],
                fluxo["bytes"],
                fluxo["ultimo"]
            )

            if chave in self.linhas_tabela:
                self.tabela.item(self.linhas_tabela[chave], values=valores)
            else:
                linha_id = self.tabela.insert("", "end", values=valores)
                self.linhas_tabela[chave] = linha_id

    def verificar_alertas(self, fluxo):
        porta = fluxo["porta_destino"]

        if porta == 22:
            self.adicionar_alerta(
                f"[MÉDIO] Conexão SSH detectada: "
                f"{fluxo['ip_origem']} -> {fluxo['ip_destino']}:22"
            )

        elif porta == 445:
            self.adicionar_alerta(
                f"[ALTO] Tráfego SMB detectado: "
                f"{fluxo['ip_origem']} -> {fluxo['ip_destino']}:445"
            )

        elif porta == 3389:
            self.adicionar_alerta(
                f"[ALTO] Conexão RDP detectada: "
                f"{fluxo['ip_origem']} -> {fluxo['ip_destino']}:3389"
            )

        elif porta == 23:
            self.adicionar_alerta(
                f"[ALTO] Telnet detectado: "
                f"{fluxo['ip_origem']} -> {fluxo['ip_destino']}:23"
            )

    def adicionar_alerta(self, mensagem):
        horario = datetime.now().strftime("%H:%M:%S")
        texto = f"[{horario}] {mensagem}\n"

        self.fila_alertas.put(texto)
        print(texto)

    def exibir_alerta(self, texto):
        if self.caixa_alertas is not None:
            self.caixa_alertas.insert("end", texto)
            self.caixa_alertas.see("end")