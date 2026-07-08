"""
Tela de Configurações: interface de rede a capturar, portas sensíveis
monitoradas e limites de detecção de varredura de portas (port scan).

Tudo é persistido na tabela `configuracoes` do banco (database/database.py)
e aplicado em tempo real ao Detector/PacketCapture já em execução.
"""

from tkinter import ttk

import customtkinter as ctk

from capture.packet_capture import PacketCapture


class SettingsFrame(ctk.CTkFrame):
    def __init__(self, master, app):
        super().__init__(master, fg_color="transparent")
        self.app = app
        self.tabela_portas = None

        self._criar_layout()
        self._carregar_configuracoes()

    def _criar_layout(self):
        # -- Interface de rede -------------------------------------------------
        frame_interface = ctk.CTkFrame(self)
        frame_interface.pack(fill="x", padx=20, pady=(20, 10))

        ctk.CTkLabel(frame_interface, text="Interface de rede", font=("Arial", 16, "bold")).pack(
            anchor="w", padx=15, pady=(10, 0)
        )

        interfaces = ["Padrão do sistema"] + PacketCapture.listar_interfaces()

        self.combo_interface = ctk.CTkOptionMenu(frame_interface, values=interfaces, width=320)
        self.combo_interface.pack(anchor="w", padx=15, pady=10)

        # -- Portas sensíveis ----------------------------------------------------
        frame_portas = ctk.CTkFrame(self)
        frame_portas.pack(fill="both", expand=True, padx=20, pady=10)

        ctk.CTkLabel(frame_portas, text="Portas sensíveis monitoradas", font=("Arial", 16, "bold")).pack(
            anchor="w", padx=15, pady=(10, 5)
        )

        frame_form_porta = ctk.CTkFrame(frame_portas, fg_color="transparent")
        frame_form_porta.pack(fill="x", padx=15, pady=5)

        self.entrada_porta = ctk.CTkEntry(frame_form_porta, placeholder_text="Porta", width=100)
        self.entrada_porta.pack(side="left", padx=5)

        self.entrada_nome = ctk.CTkEntry(frame_form_porta, placeholder_text="Nome do serviço", width=160)
        self.entrada_nome.pack(side="left", padx=5)

        self.combo_severidade = ctk.CTkOptionMenu(
            frame_form_porta, values=["BAIXO", "MÉDIO", "ALTO", "CRÍTICO"], width=120
        )
        self.combo_severidade.set("MÉDIO")
        self.combo_severidade.pack(side="left", padx=5)

        ctk.CTkButton(frame_form_porta, text="Adicionar Porta", command=self._adicionar_porta).pack(
            side="left", padx=5
        )
        ctk.CTkButton(
            frame_form_porta, text="Remover Selecionada", command=self._remover_porta
        ).pack(side="left", padx=5)

        self.tabela_portas = ttk.Treeview(
            frame_portas, columns=("porta", "nome", "severidade"), show="headings", height=6
        )
        self.tabela_portas.heading("porta", text="Porta", anchor="w")
        self.tabela_portas.heading("nome", text="Serviço", anchor="w")
        self.tabela_portas.heading("severidade", text="Severidade", anchor="w")
        self.tabela_portas.column("porta", width=100, anchor="w")
        self.tabela_portas.column("nome", width=200, anchor="w")
        self.tabela_portas.column("severidade", width=120, anchor="w")
        self.tabela_portas.pack(fill="both", expand=True, padx=15, pady=10)

        # -- Detecção de varredura de portas -------------------------------------
        frame_scan = ctk.CTkFrame(self)
        frame_scan.pack(fill="x", padx=20, pady=10)

        ctk.CTkLabel(
            frame_scan, text="Detecção de varredura de portas (port scan)", font=("Arial", 16, "bold")
        ).pack(anchor="w", padx=15, pady=(10, 5))

        frame_scan_campos = ctk.CTkFrame(frame_scan, fg_color="transparent")
        frame_scan_campos.pack(fill="x", padx=15, pady=5)

        ctk.CTkLabel(frame_scan_campos, text="Portas distintas para alertar:").pack(side="left", padx=5)
        self.entrada_limite_scan = ctk.CTkEntry(frame_scan_campos, width=80)
        self.entrada_limite_scan.pack(side="left", padx=5)

        ctk.CTkLabel(frame_scan_campos, text="Janela de tempo (segundos):").pack(side="left", padx=15)
        self.entrada_janela_scan = ctk.CTkEntry(frame_scan_campos, width=80)
        self.entrada_janela_scan.pack(side="left", padx=5)

        # -- Salvar -------------------------------------------------------------
        ctk.CTkButton(
            self, text="Salvar Configurações", height=40, command=self._salvar
        ).pack(anchor="w", padx=20, pady=15)

    def _carregar_configuracoes(self):
        db = self.app.db

        interface_salva = db.obter_configuracao("interface_rede", "")
        self.combo_interface.set(interface_salva if interface_salva else "Padrão do sistema")

        for porta in db.obter_portas_sensiveis():
            self.tabela_portas.insert(
                "", "end", values=(porta["porta"], porta["nome"], porta["severidade"])
            )

        self.entrada_limite_scan.insert(0, db.obter_configuracao("limite_portas_scan", "15"))
        self.entrada_janela_scan.insert(0, db.obter_configuracao("janela_scan_segundos", "10"))

    def _adicionar_porta(self):
        porta = self.entrada_porta.get().strip()
        nome = self.entrada_nome.get().strip()
        severidade = self.combo_severidade.get()

        if not porta.isdigit() or not nome:
            self.app.registrar_alerta_ui("[ERRO] Informe uma porta numérica e um nome de serviço válidos.")
            return

        self.tabela_portas.insert("", "end", values=(int(porta), nome, severidade))
        self.entrada_porta.delete(0, "end")
        self.entrada_nome.delete(0, "end")

    def _remover_porta(self):
        selecionado = self.tabela_portas.selection()
        if selecionado:
            self.tabela_portas.delete(selecionado[0])

    def _salvar(self):
        db = self.app.db

        interface = self.combo_interface.get()
        interface_final = "" if interface == "Padrão do sistema" else interface
        db.definir_configuracao("interface_rede", interface_final)

        portas_sensiveis = []
        for item_id in self.tabela_portas.get_children():
            porta, nome, severidade = self.tabela_portas.item(item_id, "values")
            portas_sensiveis.append({"porta": int(porta), "nome": nome, "severidade": severidade})

        db.definir_portas_sensiveis(portas_sensiveis)

        limite_scan = self.entrada_limite_scan.get().strip() or "15"
        janela_scan = self.entrada_janela_scan.get().strip() or "10"
        db.definir_configuracao("limite_portas_scan", limite_scan)
        db.definir_configuracao("janela_scan_segundos", janela_scan)

        self.app.aplicar_configuracoes(
            interface=interface_final or None,
            portas_sensiveis=portas_sensiveis,
            limite_scan=int(limite_scan),
            janela_scan=int(janela_scan),
        )

        self.app.registrar_alerta_ui("Configurações salvas e aplicadas com sucesso.")
