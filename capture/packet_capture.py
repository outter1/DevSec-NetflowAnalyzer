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

try:
    from scapy.config import conf
    conf.ipv6_enabled = False
    from scapy.sendrecv import sniff
    from scapy.interfaces import get_if_list
    ERRO_IMPORTACAO_SCAPY = None
except Exception as erro:  # Scapy ausente ou falha específica do sistema
    sniff = None
    get_if_list = None
    ERRO_IMPORTACAO_SCAPY = str(erro)


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
            return True

        if sniff is None:
            self.callback_log(
                "[ERRO] Scapy não pôde ser carregado. Instale/atualize as dependências "
                f"e o driver de captura. Detalhes: {ERRO_IMPORTACAO_SCAPY}"
            )
            return False

        self._ativo = True
        self.callback_log("Captura real iniciada.")
        self._thread = threading.Thread(target=self._loop_captura, daemon=True)
        self._thread.start()
        return True

    def parar(self):
        estava_ativa = self._ativo
        self._ativo = False
        self.callback_log("Solicitação para parar captura enviada.")
        return estava_ativa

    def _loop_captura(self):
        self.callback_log("Thread de captura iniciada.")
        falhou = False

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
                falhou = True
                self._ativo = False
                self.callback_log(f"[ERRO] Falha na captura: {erro}")
                break

        if not falhou:
            self.callback_log("Thread de captura encerrada.")

    @staticmethod
    def listar_interfaces():
        """Devolve a lista de interfaces de rede disponíveis para o usuário
        escolher na tela de Configurações."""
        try:
            return get_if_list() if get_if_list is not None else []
        except Exception:
            return []
