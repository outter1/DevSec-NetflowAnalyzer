# SPDX-License-Identifier: MIT
# Copyright (c) 2026 DEVSEC
# Copyright (c) 2026 Gabriel Silva Bastos
# Copyright (c) 2026 Matheus Dominato
# Copyright (c) 2026 Isabelle Guimarães de Andrade
# Copyright (c) 2026 Nicolas Urtiaga
# Copyright (c) 2026 Pedro Lages da Silva

"""Controles locais de firewall usados pela interface web.

O bloqueio atua no computador onde o DevSec está sendo executado. Para impor
políticas a outros dispositivos da LAN, o analisador precisa ser o gateway,
firewall ou servidor DNS desses dispositivos.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import socket
import subprocess


class FirewallController:
    def __init__(self):
        self.sistema = os.name

    @staticmethod
    def _validar_ip(ip: str) -> str:
        return str(ipaddress.ip_address(ip))

    @staticmethod
    def _nome_seguro(valor: str) -> str:
        return re.sub(r"[^A-Za-z0-9_.:-]+", "_", valor)[:90]

    @staticmethod
    def resolver_dominio(dominio: str) -> list[str]:
        ips = set()
        for familia, _, _, _, endereco in socket.getaddrinfo(dominio, None):
            if familia in (socket.AF_INET, socket.AF_INET6):
                try:
                    ips.add(str(ipaddress.ip_address(endereco[0])))
                except ValueError:
                    continue
        return sorted(ips)

    def bloquear_ip(self, ip: str, identificador: str | None = None, somente_saida: bool = False):
        ip = self._validar_ip(ip)
        tag = self._nome_seguro(identificador or ip)

        if os.name == "nt":
            return self._bloquear_windows(ip, tag, somente_saida)
        return self._bloquear_linux(ip, tag, somente_saida)

    def desbloquear_ip(self, ip: str, identificador: str | None = None, somente_saida: bool = False):
        ip = self._validar_ip(ip)
        tag = self._nome_seguro(identificador or ip)

        if os.name == "nt":
            return self._desbloquear_windows(tag, somente_saida)
        return self._desbloquear_linux(ip, tag, somente_saida)

    def _executar(self, comando):
        try:
            resultado = subprocess.run(
                comando,
                capture_output=True,
                text=True,
                shell=False,
                timeout=20,
            )
        except (OSError, subprocess.SubprocessError) as erro:
            return False, str(erro)

        texto = "\n".join(parte.strip() for parte in (resultado.stdout, resultado.stderr) if parte.strip())
        return resultado.returncode == 0, texto or "Comando concluído."

    def _bloquear_windows(self, ip, tag, somente_saida):
        regras = [(f"DevSec Block OUT {tag}", "out", f"remoteip={ip}")]
        if not somente_saida:
            regras.insert(0, (f"DevSec Block IN {tag}", "in", f"remoteip={ip}"))

        criadas = []
        for nome, direcao, alvo in regras:
            # Remove uma regra antiga com o mesmo nome para evitar duplicação.
            self._executar(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={nome}"])
            sucesso, mensagem = self._executar(
                [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={nome}", f"dir={direcao}", "action=block", alvo,
                    "enable=yes", "profile=any",
                ]
            )
            if not sucesso:
                for nome_criado, _, _ in criadas:
                    self._executar(
                        ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={nome_criado}"]
                    )
                return False, mensagem
            criadas.append((nome, direcao, alvo))

        return True, "Regra aplicada no Windows Firewall."

    def _desbloquear_windows(self, tag, somente_saida):
        nomes = [f"DevSec Block OUT {tag}"]
        if not somente_saida:
            nomes.insert(0, f"DevSec Block IN {tag}")

        resultados = []
        algum_sucesso = False
        for nome in nomes:
            sucesso, mensagem = self._executar(
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={nome}"]
            )
            algum_sucesso = algum_sucesso or sucesso
            resultados.append(mensagem)

        if algum_sucesso:
            return True, "Regra removida do Windows Firewall."
        return False, " ".join(resultados)

    def _bloquear_linux(self, ip, tag, somente_saida):
        iptables = shutil.which("ip6tables" if ":" in ip else "iptables")
        if not iptables:
            return False, "iptables/ip6tables não encontrado."

        regras = [("OUTPUT", "-d")]
        if not somente_saida:
            regras.insert(0, ("INPUT", "-s"))

        criadas = []
        for cadeia, operador in regras:
            base = [iptables, cadeia, operador, ip, "-m", "comment", "--comment", f"DevSec:{tag}", "-j", "DROP"]
            existe, _ = self._executar([iptables, "-C", *base[1:]])
            if existe:
                continue
            sucesso, mensagem = self._executar([iptables, "-I", *base[1:]])
            if not sucesso:
                return False, mensagem
            criadas.append(base)
        return True, "Regra aplicada no firewall Linux."

    def _desbloquear_linux(self, ip, tag, somente_saida):
        iptables = shutil.which("ip6tables" if ":" in ip else "iptables")
        if not iptables:
            return False, "iptables/ip6tables não encontrado."

        regras = [("OUTPUT", "-d")]
        if not somente_saida:
            regras.insert(0, ("INPUT", "-s"))

        removeu = False
        mensagens = []
        for cadeia, operador in regras:
            comando = [
                iptables, "-D", cadeia, operador, ip,
                "-m", "comment", "--comment", f"DevSec:{tag}", "-j", "DROP",
            ]
            sucesso, mensagem = self._executar(comando)
            removeu = removeu or sucesso
            mensagens.append(mensagem)
        return (True, "Regra removida do firewall Linux.") if removeu else (False, " ".join(mensagens))
