"""Tela de fluxos e captura em tempo real."""

import customtkinter as ctk

from capture.flow_analyzer import FlowAnalyzer
from ui.components import PageHeader, Panel, clear_table, create_table
from ui.theme import COLORS, dark_button, danger_button, primary_button


class FlowsFrame(ctk.CTkFrame):
    def __init__(self, master, app):
        super().__init__(master, fg_color="transparent")
        self.app = app
        self.rows = {}
        self._criar_layout()
        self.recarregar()

    def _criar_layout(self):
        PageHeader(
            self,
            "Fluxos em tempo real",
            "Inicie a captura, aplique filtros e acompanhe somente tráfego realmente observado.",
        )

        controls = Panel(self, "Controles e filtros")
        controls.pack(fill="x", pady=(0, 12))
        grid = ctk.CTkFrame(controls, fg_color="transparent")
        grid.pack(fill="x", padx=12, pady=10)
        for column in range(6):
            grid.grid_columnconfigure(column, weight=1, uniform="flow_controls")

        ctk.CTkButton(
            grid,
            text="Iniciar captura",
            command=self.app.iniciar_captura,
            **primary_button(),
        ).grid(row=0, column=0, columnspan=2, sticky="ew", padx=5, pady=5)
        ctk.CTkButton(
            grid,
            text="Parar captura",
            command=self.app.parar_captura,
            **danger_button(),
        ).grid(row=0, column=2, columnspan=2, sticky="ew", padx=5, pady=5)
        ctk.CTkButton(
            grid,
            text="Limpar memória",
            command=self._clear_memory,
            **dark_button(),
        ).grid(row=0, column=4, columnspan=2, sticky="ew", padx=5, pady=5)

        self.filter_ip = ctk.CTkEntry(grid, placeholder_text="Filtrar IP")
        self.filter_ip.grid(row=1, column=0, columnspan=2, sticky="ew", padx=5, pady=5)
        self.filter_port = ctk.CTkEntry(grid, placeholder_text="Porta")
        self.filter_port.grid(row=1, column=2, sticky="ew", padx=5, pady=5)
        self.filter_protocol = ctk.CTkOptionMenu(grid, values=["Todos", "TCP", "UDP", "IP"])
        self.filter_protocol.set("Todos")
        self.filter_protocol.grid(row=1, column=3, sticky="ew", padx=5, pady=5)
        ctk.CTkButton(
            grid,
            text="Aplicar filtros",
            command=self.recarregar,
            **dark_button(),
        ).grid(row=1, column=4, sticky="ew", padx=5, pady=5)
        ctk.CTkButton(
            grid,
            text="Limpar filtros",
            command=self._reset_filters,
            **dark_button(),
        ).grid(row=1, column=5, sticky="ew", padx=5, pady=5)

        self.tabs = ctk.CTkTabview(
            self,
            fg_color=COLORS["panel"],
            border_width=1,
            border_color=COLORS["border"],
            corner_radius=14,
            segmented_button_fg_color=COLORS["panel_alt"],
            segmented_button_selected_color=COLORS["red"],
            segmented_button_selected_hover_color=COLORS["red_hover"],
            segmented_button_unselected_color=COLORS["panel_alt"],
            segmented_button_unselected_hover_color=COLORS["border"],
            text_color=COLORS["text"],
        )
        self.tabs.pack(fill="both", expand=True)
        traffic_tab = self.tabs.add("Tráfego agregado")
        console_tab = self.tabs.add("Console operacional")
        traffic_tab.configure(fg_color=COLORS["panel"])
        console_tab.configure(fg_color=COLORS["panel"])

        ctk.CTkLabel(
            traffic_tab,
            text="Um registro por combinação de origem, destino, portas e protocolo.",
            text_color=COLORS["muted"],
            anchor="w",
        ).pack(fill="x", padx=12, pady=(11, 5))

        columns = ("origem", "destino", "po", "pd", "protocolo", "pacotes", "bytes", "ultimo")
        headings = {
            "origem": "IP ORIGEM",
            "destino": "IP DESTINO",
            "po": "PORTA ORIGEM",
            "pd": "PORTA DESTINO",
            "protocolo": "PROTOCOLO",
            "pacotes": "PACOTES",
            "bytes": "BYTES",
            "ultimo": "ÚLTIMO",
        }
        widths = {
            "origem": 145,
            "destino": 145,
            "po": 105,
            "pd": 105,
            "protocolo": 90,
            "pacotes": 80,
            "bytes": 95,
            "ultimo": 90,
        }
        host, self.table = create_table(traffic_tab, columns, headings, widths, height=13)
        host.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self.log = ctk.CTkTextbox(console_tab)
        self.log.pack(fill="both", expand=True, padx=10, pady=10)
        self.log.insert("end", "Aguardando eventos reais da captura...\n")

    def _passes(self, flow):
        return FlowAnalyzer.fluxo_passou_filtro(
            flow,
            filtro_ip=self.filter_ip.get().strip(),
            filtro_porta=self.filter_port.get().strip(),
            filtro_protocolo=self.filter_protocol.get(),
        )

    def atualizar_fluxo(self, key, record):
        if not self._passes(record):
            row_id = self.rows.pop(key, None)
            if row_id:
                self.table.delete(row_id)
            return

        values = (
            record["ip_origem"],
            record["ip_destino"],
            record["porta_origem"],
            record["porta_destino"],
            record["protocolo"],
            record["pacotes"],
            record["bytes"],
            record["ultimo"],
        )
        row_id = self.rows.get(key)
        if row_id:
            self.table.item(row_id, values=values)
        else:
            self.rows[key] = self.table.insert("", 0, values=values, tags=("info",))
            if len(self.rows) > 1500:
                oldest = self.table.get_children()[-1]
                self.table.delete(oldest)
                for flow_key, item_id in list(self.rows.items()):
                    if item_id == oldest:
                        self.rows.pop(flow_key, None)
                        break

    def adicionar_log(self, text):
        self.log.insert("end", text)
        self.log.see("end")
        try:
            lines = int(self.log.index("end-1c").split(".")[0])
            if lines > 500:
                self.log.delete("1.0", "80.0")
        except Exception:
            pass

    def recarregar(self):
        clear_table(self.table)
        self.rows = {}
        for key, record in reversed(list(self.app.analisador_fluxos.obter_fluxos().items())):
            if self._passes(record):
                self.atualizar_fluxo(key, record)

    def _reset_filters(self):
        self.filter_ip.delete(0, "end")
        self.filter_port.delete(0, "end")
        self.filter_protocol.set("Todos")
        self.recarregar()

    def _clear_memory(self):
        self.app.analisador_fluxos.limpar()
        clear_table(self.table)
        self.rows = {}
        self.app.registrar_alerta_ui("Tabela em memória limpa; o histórico SQLite foi mantido.")
