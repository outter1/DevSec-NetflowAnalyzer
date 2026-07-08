"""
Tela de Alertas: lista os IPs suspeitos (persistidos no banco de dados) e
permite classificar, colocar em whitelist, bloquear/desbloquear no firewall
e exportar um relatório PDF de investigação para aquele IP.

Toda a lógica de negócio (bloqueio real, persistência) fica na MainWindow
(`app`); esta classe cuida só da apresentação e repassa as ações do usuário.
"""

import os
from tkinter import filedialog, ttk

import customtkinter as ctk


class AlertsFrame(ctk.CTkFrame):
    def __init__(self, master, app):
        super().__init__(master, fg_color="transparent")
        self.app = app
        self.tabela = None
        self.caixa_info = None

        self._criar_layout()
        self.recarregar()

    def _criar_layout(self):
        frame_acoes = ctk.CTkFrame(self, fg_color="transparent")
        frame_acoes.pack(fill="x", padx=20, pady=10)

        botoes = [
            ("Atualizar Lista", self.recarregar, None),
            ("Classificar como Normal", self._classificar_normal, None),
            ("Marcar como Crítico", self._classificar_critico, "#7f1d1d"),
            ("Adicionar à Whitelist", self._adicionar_whitelist, None),
            ("Bloquear IP", self._bloquear, "#991b1b"),
            ("Remover Bloqueio", self._desbloquear, None),
            ("Exportar Relatório do IP (PDF)", self._exportar_pdf_ip, None),
        ]

        for texto, comando, cor in botoes:
            kwargs = {"height": 36, "command": comando}
            if cor:
                kwargs["fg_color"] = cor
            ctk.CTkButton(frame_acoes, text=texto, **kwargs).pack(side="left", padx=6, pady=8)

        frame_tabela = ctk.CTkFrame(self, fg_color="transparent")
        frame_tabela.pack(fill="both", expand=True, padx=20, pady=10)

        colunas = ("ip", "severidade", "motivo", "status", "eventos", "ultimo")

        self.tabela = ttk.Treeview(frame_tabela, columns=colunas, show="headings", height=17)

        titulos = {
            "ip": "IP",
            "severidade": "Severidade",
            "motivo": "Motivo",
            "status": "Status",
            "eventos": "Eventos",
            "ultimo": "Último Evento",
        }
        larguras = {
            "ip": 150,
            "severidade": 110,
            "motivo": 380,
            "status": 120,
            "eventos": 90,
            "ultimo": 150,
        }

        for coluna in colunas:
            self.tabela.heading(coluna, text=titulos[coluna], anchor="w")
            self.tabela.column(coluna, width=larguras[coluna], anchor="w")

        scrollbar = ttk.Scrollbar(frame_tabela, orient="vertical", command=self.tabela.yview)
        self.tabela.configure(yscrollcommand=scrollbar.set)

        self.tabela.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=10)
        scrollbar.pack(side="right", fill="y", padx=(0, 10), pady=10)

        self.caixa_info = ctk.CTkTextbox(self, height=90)
        self.caixa_info.pack(fill="x", padx=20, pady=10)
        self.caixa_info.insert(
            "end",
            "Selecione um IP na tabela para classificar, colocar em whitelist, bloquear "
            "ou exportar um relatório de investigação.\n"
            "O bloqueio real usa o Windows Firewall (netsh) e precisa ser executado como Administrador.\n",
        )

    # ------------------------------------------------------------------ #
    def recarregar(self):
        for item in self.tabela.get_children():
            self.tabela.delete(item)

        for alerta in self.app.db.listar_alertas():
            self.tabela.insert(
                "",
                "end",
                values=(
                    alerta["ip"],
                    alerta["severidade"],
                    alerta["motivo"],
                    alerta["status"],
                    alerta["eventos"],
                    alerta["ultimo_evento"],
                ),
            )

    def _ip_selecionado(self):
        selecionado = self.tabela.selection()

        if not selecionado:
            self.app.registrar_alerta_ui("[ERRO] Selecione um IP na tabela de alertas.")
            return None

        valores = self.tabela.item(selecionado[0], "values")
        return valores[0] if valores else None

    def _classificar_normal(self):
        ip = self._ip_selecionado()
        if ip:
            self.app.classificar_ip_normal(ip)
            self.recarregar()

    def _classificar_critico(self):
        ip = self._ip_selecionado()
        if ip:
            self.app.classificar_ip_critico(ip)
            self.recarregar()

    def _adicionar_whitelist(self):
        ip = self._ip_selecionado()
        if ip:
            self.app.adicionar_ip_whitelist(ip)
            self.recarregar()

    def _bloquear(self):
        ip = self._ip_selecionado()
        if ip:
            self.app.bloquear_ip_selecionado(ip)
            self.recarregar()

    def _desbloquear(self):
        ip = self._ip_selecionado()
        if ip:
            self.app.desbloquear_ip_selecionado(ip)
            self.recarregar()

    def _exportar_pdf_ip(self):
        ip = self._ip_selecionado()
        if not ip:
            return

        caminho_sugerido = f"relatorio_{ip.replace('.', '_')}.pdf"
        caminho = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            initialfile=caminho_sugerido,
            filetypes=[("Arquivo PDF", "*.pdf")],
        )

        if not caminho:
            return

        try:
            self.app.exportar_relatorio_ip_pdf(ip, caminho)
            self.app.registrar_alerta_ui(f"Relatório do IP {ip} exportado para {os.path.basename(caminho)}.")
        except Exception as erro:
            self.app.registrar_alerta_ui(f"[ERRO] Falha ao exportar relatório: {erro}")
