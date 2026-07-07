# FlowWatch - NetFlow Analyzer

![Status](https://img.shields.io/badge/status-em%20desenvolvimento-blue)
![Python](https://img.shields.io/badge/Python-3.12-blue)
![Interface](https://img.shields.io/badge/Interface-CustomTkinter-darkgreen)
![Security](https://img.shields.io/badge/Area-Blue%20Team%20%7C%20Forense%20%7C%20Red%20Team-red)

## Sobre o projeto

O **FlowWatch** é uma plataforma desktop desenvolvida em Python para análise de fluxos de rede, inspirada em soluções de monitoramento baseadas em **NetFlow**, **Blue Team**, **Forense Digital** e **Análise de Tráfego**.

A ideia principal do projeto é centralizar informações sobre conexões de rede, permitindo visualizar dados como:

- IP de origem;
- IP de destino;
- Porta de origem;
- Porta de destino;
- Protocolo utilizado;
- Quantidade de pacotes;
- Quantidade de bytes trafegados;
- Horário da última comunicação.

O projeto tem como objetivo auxiliar na identificação de comportamentos suspeitos dentro de uma rede, como acessos a serviços sensíveis, tráfego anormal e possíveis indícios de ataques.

---

## Objetivo

Desenvolver uma solução de análise de tráfego de rede com interface gráfica, capaz de capturar, processar e exibir fluxos IP de forma centralizada.

A proposta é unir conceitos de:

- **Blue Team**: monitoramento e detecção de eventos suspeitos;
- **Forense Digital**: investigação de conexões e rastreamento de atividades;
- **Red Team**: geração de tráfego controlado para testar alertas;
- **Redes de Computadores**: análise de IPs, portas, protocolos e comunicação entre hosts.

---

## Tecnologias utilizadas

- **Python**
- **CustomTkinter**
- **Tkinter / ttk**
- **Scapy**
- **Threading**
- **Queue**
- **Npcap** para captura real de pacotes no Windows

---

## Funcionalidades atuais

- Interface desktop moderna com menu lateral;
- Tela de Dashboard;
- Tela de Captura;
- Tabela para visualização dos fluxos de rede;
- Captura real de pacotes com Scapy;
- Conversão de pacotes em fluxos;
- Detecção básica de serviços sensíveis;
- Sistema de alertas dentro da interface;
- Execução da captura em thread separada para não travar o software.

---

## Alertas implementados

Atualmente, o sistema gera alertas para conexões em portas sensíveis, como:

| Porta | Serviço | Severidade |
|------|---------|------------|
| 22 | SSH | Médio |
| 23 | Telnet | Alto |
| 445 | SMB | Alto |
| 3389 | RDP | Alto |

Exemplo de alerta:

```text
[15:58:03] [ALTO] Conexão RDP detectada: 192.168.0.10 -> 192.168.0.1:3389
