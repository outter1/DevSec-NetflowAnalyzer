"""Extração passiva de nomes de domínio a partir de pacotes de rede.

São registradas somente evidências presentes no tráfego capturado:

* consultas DNS tradicionais (UDP/TCP 53);
* cabeçalho HTTP ``Host`` em tráfego não criptografado;
* SNI do TLS ClientHello quando ele estiver visível.

DNS sobre HTTPS/TLS, VPNs e TLS com ECH podem ocultar o domínio. Por isso uma
captura passiva não consegue garantir visibilidade total em todos os ambientes.
"""

from __future__ import annotations

import re
from datetime import datetime

try:
    from scapy.config import conf

    # O restante do projeto trabalha com IPv4. Desativar o carregamento IPv6
    # também evita falhas de inicialização do Scapy em alguns ambientes.
    conf.ipv6_enabled = False
    from scapy.layers.inet import IP, TCP, UDP
except Exception:  # pragma: no cover
    IP = TCP = UDP = None


_DOMINIO_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.IGNORECASE,
)
_HTTP_HOST_RE = re.compile(br"(?:^|\r\n)Host:\s*([^\r\n:]+)(?::\d+)?\r\n", re.IGNORECASE)


def normalizar_dominio(valor) -> str | None:
    if isinstance(valor, bytes):
        try:
            valor = valor.decode("ascii", errors="strict")
        except UnicodeDecodeError:
            valor = valor.decode("utf-8", errors="ignore")

    dominio = str(valor or "").strip().lower().rstrip(".")
    if dominio.startswith("http://") or dominio.startswith("https://"):
        dominio = dominio.split("://", 1)[1].split("/", 1)[0]
    dominio = dominio.split(":", 1)[0]

    try:
        dominio_ascii = dominio.encode("idna").decode("ascii")
    except UnicodeError:
        return None

    if not _DOMINIO_RE.fullmatch(dominio_ascii):
        return None
    return dominio_ascii


def _ler_u16(dados: bytes, offset: int) -> tuple[int, int]:
    if offset + 2 > len(dados):
        raise ValueError("payload incompleto")
    return int.from_bytes(dados[offset : offset + 2], "big"), offset + 2


def _ler_nome_dns(dados: bytes, offset: int, profundidade: int = 0) -> tuple[str | None, int]:
    """Lê um nome DNS, incluindo ponteiros de compressão quando presentes."""
    if profundidade > 8:
        raise ValueError("compressão DNS recursiva demais")

    rotulos = []
    offset_original = offset
    usou_ponteiro = False

    while offset < len(dados):
        tamanho = dados[offset]
        if tamanho == 0:
            offset += 1
            break

        if tamanho & 0xC0 == 0xC0:
            if offset + 1 >= len(dados):
                raise ValueError("ponteiro DNS incompleto")
            ponteiro = ((tamanho & 0x3F) << 8) | dados[offset + 1]
            nome_apontado, _ = _ler_nome_dns(dados, ponteiro, profundidade + 1)
            if nome_apontado:
                rotulos.extend(nome_apontado.split("."))
            offset += 2
            usou_ponteiro = True
            break

        offset += 1
        if tamanho > 63 or offset + tamanho > len(dados):
            raise ValueError("rótulo DNS inválido")
        rotulos.append(dados[offset : offset + tamanho].decode("ascii", errors="ignore"))
        offset += tamanho

    nome = normalizar_dominio(".".join(rotulos))
    return nome, offset if not usou_ponteiro else offset


def extrair_consultas_dns(payload: bytes, tcp: bool = False) -> list[str]:
    """Extrai nomes consultados de uma mensagem DNS sem depender do dissector Scapy."""
    try:
        if tcp:
            if len(payload) < 2:
                return []
            tamanho = int.from_bytes(payload[:2], "big")
            payload = payload[2 : 2 + tamanho]

        if len(payload) < 12:
            return []
        flags = int.from_bytes(payload[2:4], "big")
        if flags & 0x8000:  # resposta, não consulta
            return []
        quantidade = int.from_bytes(payload[4:6], "big")
        offset = 12
        nomes = []
        for _ in range(min(quantidade, 50)):
            nome, offset = _ler_nome_dns(payload, offset)
            if offset + 4 > len(payload):
                break
            offset += 4  # QTYPE + QCLASS
            if nome and nome not in nomes:
                nomes.append(nome)
        return nomes
    except (ValueError, IndexError):
        return []


def extrair_tls_sni(payload: bytes) -> str | None:
    """Extrai o primeiro SNI de um TLS ClientHello sem depender do dissector TLS."""
    try:
        if len(payload) < 9 or payload[0] != 0x16:
            return None

        tamanho_registro = int.from_bytes(payload[3:5], "big")
        fim_registro = min(len(payload), 5 + tamanho_registro)
        if fim_registro < 9 or payload[5] != 0x01:
            return None

        tamanho_handshake = int.from_bytes(payload[6:9], "big")
        fim_handshake = min(fim_registro, 9 + tamanho_handshake)
        offset = 9
        if offset + 34 > fim_handshake:
            return None
        offset += 34  # versão do cliente + random

        tamanho_sessao = payload[offset]
        offset += 1 + tamanho_sessao

        tamanho_cifras, offset = _ler_u16(payload, offset)
        offset += tamanho_cifras
        if offset >= fim_handshake:
            return None

        tamanho_compressao = payload[offset]
        offset += 1 + tamanho_compressao
        if offset + 2 > fim_handshake:
            return None

        tamanho_extensoes, offset = _ler_u16(payload, offset)
        fim_extensoes = min(fim_handshake, offset + tamanho_extensoes)

        while offset + 4 <= fim_extensoes:
            tipo, offset = _ler_u16(payload, offset)
            tamanho, offset = _ler_u16(payload, offset)
            fim_extensao = offset + tamanho
            if fim_extensao > fim_extensoes:
                return None

            if tipo == 0x0000 and tamanho >= 5:
                _, pos = _ler_u16(payload, offset)
                while pos + 3 <= fim_extensao:
                    tipo_nome = payload[pos]
                    pos += 1
                    tamanho_nome, pos = _ler_u16(payload, pos)
                    if pos + tamanho_nome > fim_extensao:
                        break
                    if tipo_nome == 0:
                        return normalizar_dominio(payload[pos : pos + tamanho_nome])
                    pos += tamanho_nome

            offset = fim_extensao
    except (IndexError, ValueError):
        return None
    return None


class DomainAnalyzer:
    def extrair_observacoes(self, pacote):
        if IP is None or IP not in pacote:
            return []

        ip_cliente = pacote[IP].src
        ip_destino = pacote[IP].dst
        porta_destino = 0
        payload = b""
        transporte = None

        if TCP is not None and TCP in pacote:
            transporte = "TCP"
            porta_destino = int(pacote[TCP].dport)
            payload = bytes(pacote[TCP].payload)
        elif UDP is not None and UDP in pacote:
            transporte = "UDP"
            porta_destino = int(pacote[UDP].dport)
            payload = bytes(pacote[UDP].payload)

        observacoes = []
        vistos = set()
        agora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        def adicionar(dominio, fonte):
            dominio_normalizado = normalizar_dominio(dominio)
            if not dominio_normalizado:
                return
            chave = (dominio_normalizado, fonte)
            if chave in vistos:
                return
            vistos.add(chave)
            observacoes.append(
                {
                    "ip_cliente": ip_cliente,
                    "dominio": dominio_normalizado,
                    "ip_destino": ip_destino,
                    "porta_destino": porta_destino,
                    "fonte": fonte,
                    "observado_em": agora,
                }
            )

        if porta_destino == 53 and payload:
            for dominio in extrair_consultas_dns(payload, tcp=transporte == "TCP"):
                adicionar(dominio, "DNS")

        if transporte == "TCP" and payload:
            host = _HTTP_HOST_RE.search(payload[:8192])
            if host:
                adicionar(host.group(1), "HTTP-HOST")

            sni = extrair_tls_sni(payload[:65535])
            if sni:
                adicionar(sni, "TLS-SNI")

        return observacoes
