"""
Tela de Dashboard: resumo geral do estado do sistema.

Recebe a instância da MainWindow (app) para ler o estado compartilhado
(fluxos, alertas, bloqueios, status de captura) sem duplicar dados.
"""

import customtkinter as ctk


class DashboardFrame(ctk.CTkFrame):
    def __init__(self, master, app):
        super().__init__(master, fg_color="transparent")
        self.app = app

        self.rotulos_cards = {}
        self._criar_layout()
        self.atualizar()

    def _criar_layout(self):
        frame_cards = ctk.CTkFrame(self, fg_color="transparent")
        frame_cards.pack(fill="x", padx=20, pady=20)

        definicoes = [
            ("total_fluxos", "Fluxos monitorados"),
            ("total_suspeitos", "IPs suspeitos"),
            ("total_bloqueados", "IPs bloqueados"),
            ("total_dispositivos", "Dispositivos"),
            ("status_captura", "Captura"),
        ]

        for chave, titulo in definicoes:
            card = ctk.CTkFrame(frame_cards, width=210, height=110, corner_radius=12)
            card.pack(side="left", padx=10, pady=10)
            card.pack_propagate(False)

            ctk.CTkLabel(card, text=titulo, font=("Arial", 14)).pack(pady=(16, 4))

            valor = ctk.CTkLabel(card, text="0", font=("Arial", 24, "bold"))
            valor.pack()

            self.rotulos_cards[chave] = valor

        frame_info = ctk.CTkFrame(self, fg_color="transparent")
        frame_info.pack(fill="x", padx=20, pady=10)

        ctk.CTkLabel(
            frame_info,
            text=(
                "Use a tela Captura para iniciar a análise de tráfego em tempo real.\n"
                "Use Alertas para investigar, classificar ou bloquear IPs suspeitos.\n"
                "Use Relatórios para exportar evidências (CSV/PDF) para investigação forense."
            ),
            font=("Arial", 15),
            justify="left",
        ).pack(anchor="w", pady=10)

        botao_atualizar = ctk.CTkButton(self, text="Atualizar Dashboard", command=self.atualizar)
        botao_atualizar.pack(anchor="w", padx=20, pady=10)

    def atualizar(self):
        total_fluxos = len(self.app.analisador_fluxos.obter_fluxos())
        total_suspeitos = len(self.app.db.listar_alertas())
        total_bloqueados = len(self.app.db.listar_ips_bloqueados())
        total_dispositivos = len(self.app.db.listar_dispositivos())
        status = "Ativa" if self.app.captura.ativo else "Parada"

        self.rotulos_cards["total_fluxos"].configure(text=str(total_fluxos))
        self.rotulos_cards["total_suspeitos"].configure(text=str(total_suspeitos))
        self.rotulos_cards["total_bloqueados"].configure(text=str(total_bloqueados))
        self.rotulos_cards["total_dispositivos"].configure(text=str(total_dispositivos))
        self.rotulos_cards["status_captura"].configure(text=status)
