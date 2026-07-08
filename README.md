# DevSec - NetFlow Analyzer

![Status](https://img.shields.io/badge/status-funcional-brightgreen)
![Python](https://img.shields.io/badge/Python-3.12-blue)
![Interface](https://img.shields.io/badge/Interface-CustomTkinter-darkgreen)
![Security](https://img.shields.io/badge/Area-Blue%20Team%20%7C%20Forense%20%7C%20Red%20Team-red)

## Sobre o projeto

O **DevSec / FlowWatch NetFlow Analyzer** é uma plataforma desktop desenvolvida em Python para
análise de fluxos de rede, inspirada em soluções de monitoramento baseadas em **NetFlow**,
**Blue Team**, **Forense Digital** e **Análise de Tráfego** — um mini SIEM local.

Captura pacotes → transforma em fluxos → exibe origem, destino, portas, protocolo, bytes e
pacotes → detecta comportamento suspeito → gera alertas → classifica IPs → permite bloqueio
manual no firewall → ajuda na investigação forense.

---

## Arquitetura do projeto

```
DevSec-NetflowAnalyzer/
├── main.py                     # ponto de entrada
├── requirements.txt
├── devsec_netflow.db           # criado automaticamente na 1ª execução (SQLite)
│
├── capture/
│   ├── packet_capture.py       # captura real com Scapy, em thread separada
│   ├── flow_analyzer.py        # converte pacotes em fluxos agregados
│   └── detector.py             # detecção de portas sensíveis + varredura de portas
│
├── database/
│   ├── models.py                # schema SQL (CREATE TABLE)
│   └── database.py              # camada de persistência (fluxos, alertas, log, devices...)
│
├── reports/
│   └── export.py                # exportação CSV e PDF (reportlab)
│
└── ui/
    ├── main_window.py            # orquestrador: menu lateral + tela de Captura
    ├── dashboard.py               # tela Dashboard
    ├── alerts.py                  # tela Alertas
    ├── devices.py                 # tela Dispositivos (+ ARP scan)
    ├── reports.py                 # tela Relatórios
    └── settings.py                # tela Configurações
```

---

## Tecnologias utilizadas

- **Python 3.12**
- **CustomTkinter** / Tkinter / ttk
- **Scapy** (captura de pacotes) + **Npcap** no Windows
- **SQLite** (`sqlite3`, biblioteca padrão) para histórico e investigação
- **ReportLab** para geração de relatórios em PDF
- Threading + Queue para não travar a interface durante a captura

---

## Funcionalidades

- Interface desktop com menu lateral e 6 telas: Dashboard, Captura, Alertas, Dispositivos,
  Relatórios e Configurações;
- Captura real de pacotes com Scapy, convertidos em fluxos (IP origem/destino, portas,
  protocolo, pacotes, bytes, horário);
- **Persistência em SQLite**: fluxos, alertas, log bruto de eventos, IPs bloqueados,
  whitelist, dispositivos e configurações sobrevivem a reinícios do programa;
- Filtros por IP, porta e protocolo na tela de Captura;
- Detecção de portas sensíveis (SSH, Telnet, SMB, RDP — configurável na tela de
  Configurações, pode adicionar/remover portas);
- **Detecção de varredura de portas (port scan)**: se um IP acessa muitas portas
  distintas em pouco tempo, gera alerta CRÍTICO automaticamente — dá pra testar de
  propósito com `nmap -p 1-1000 <alvo>` (lado Red Team do projeto);
- Tela de Alertas: classificar IP como normal/crítico, whitelist, bloquear/desbloquear
  no Windows Firewall (via `netsh`), exportar relatório de investigação do IP em PDF;
- Tela de Dispositivos: hosts vistos passivamente nos fluxos, descoberta ativa via
  ARP scan e resolução de hostname;
- Tela de Relatórios: exporta fluxos e alertas em CSV, e um relatório geral em PDF;
- Tela de Configurações: interface de rede, portas sensíveis monitoradas, limite e
  janela de tempo da detecção de varredura de portas — tudo persistido e aplicado
  em tempo real, sem precisar reiniciar o programa.

---

## Como rodar

```bash
pip install -r requirements.txt
python main.py
```

> A captura real de pacotes normalmente exige privilégios de administrador/root
> (e, no Windows, o **Npcap** instalado). Sem privilégios elevados, a captura falha
> e a thread reporta o erro na caixa de alertas — o restante do app (dashboard,
> alertas, dispositivos, relatórios, configurações) funciona normalmente.

O bloqueio/desbloqueio real de IP no firewall (`netsh advfirewall`) só funciona no
Windows e precisa ser executado como Administrador; em outros sistemas operacionais,
o app informa isso na tela de Alertas em vez de falhar silenciosamente.

## Alertas implementados

| Detecção | Severidade padrão |
|---|---|
| SSH (porta 22) | Médio |
| Telnet (porta 23) | Alto |
| SMB (porta 445) | Alto |
| RDP (porta 3389) | Alto |
| Varredura de portas (≥ N portas distintas em X segundos, configurável) | Crítico |

Exemplo:
```text
[15:58:03] [ALTO] Conexão RDP detectada: 192.168.0.10 -> 192.168.0.1:3389
[16:02:11] [CRÍTICO] Possível varredura de portas (port scan): 192.168.0.20 acessou 18 portas diferentes em 10s (destino mais recente: 192.168.0.10:445)
```

## Próximos passos sugeridos

- Empacotar com PyInstaller para gerar um `.exe` standalone no Windows;
- Adicionar autenticação/login para múltiplos analistas;
- Gráficos de tráfego por IP/porta ao longo do tempo no Dashboard (ex.: com `matplotlib`);
- Integração com listas de IPs maliciosos conhecidos (threat intelligence feeds).
