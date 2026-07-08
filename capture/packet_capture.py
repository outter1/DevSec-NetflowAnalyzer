"""
Encapsula a captura real de pacotes com Scapy em uma thread separada,
para não travar a interface gráfica (CustomTkinter/Tkinter rodam em
single-thread e não podem ficar bloqueados esperando pacotes chegarem).

Uso típico:

    captura = PacketCapture(interface="Wi-Fi", callback_pacote=minha_funcao)
    captura.iniciar()
    ...
    captura.parar()
"""

import threading

from scapy.all import sniff


class PacketCapture:
    def __init__(self, callback_pacote, interface=None, filtro_bpf=None, callback_log=None):
        """
        callback_pacote: função chamada para cada pacote capturado (pacote) -> None
        interface: nome da interface de rede (None = interface padrão do SO)
        filtro_bpf: filtro estilo tcpdump/BPF (ex.: "tcp or udp"), opcional
        callback_log: função opcional para mandar mensagens de status (str) -> None
        """
        self.callback_pacote = callback_pacote
        self.interface = interface or None
        self.filtro_bpf = filtro_bpf
        self.callback_log = callback_log or (lambda mensagem: None)

        self._ativo = False
        self._thread = None

    @property
    def ativo(self):
        return self._ativo

    def iniciar(self):
        if self._ativo:
            self.callback_log("A captura já está em execução.")
            return

        self._ativo = True
        self._thread = threading.Thread(target=self._loop_captura, daemon=True)
        self._thread.start()
        self.callback_log("Captura real iniciada.")

    def parar(self):
        self._ativo = False
        self.callback_log("Solicitação para parar captura enviada.")

    def _loop_captura(self):
        self.callback_log("Thread de captura iniciada.")

        while self._ativo:
            try:
                sniff(
                    prn=self.callback_pacote,
                    store=False,
                    timeout=5,
                    iface=self.interface,
                    filter=self.filtro_bpf,
                )
            except Exception as erro:
                self._ativo = False
                self.callback_log(f"[ERRO] Falha na captura: {erro}")
                break

        self.callback_log("Thread de captura encerrada.")

    @staticmethod
    def listar_interfaces():
        """Devolve a lista de interfaces de rede disponíveis para o usuário
        escolher na tela de Configurações."""
        try:
            from scapy.all import get_if_list
            return get_if_list()
        except Exception:
            return []
