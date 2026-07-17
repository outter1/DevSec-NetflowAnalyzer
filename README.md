# DevSec - NetFlow Analyzer

![Status](https://img.shields.io/badge/status-funcional-brightgreen)
![Python](https://img.shields.io/badge/Python-3.12-blue)
![Interface](https://img.shields.io/badge/Interface-CustomTkinter-2f855a)
![Database](https://img.shields.io/badge/Database-SQLite-orange)
![Security](https://img.shields.io/badge/Área-Blue%20Team%20%7C%20Forense%20%7C%20Red%20Team-red)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

---

## Visão geral

O **DevSec - NetFlow Analyzer** é uma plataforma desktop e web de análise de tráfego de rede desenvolvida em **Python**, com foco em **Blue Team**, **Forense Digital**, **Redes** e **Resposta a Incidentes**.

A proposta do projeto é funcionar como um **mini SIEM local**, capaz de capturar pacotes da rede, transformar esses pacotes em fluxos, identificar comportamentos suspeitos, gerar alertas, classificar IPs e permitir ações manuais de resposta, como whitelist e bloqueio no firewall.

```text
Captura de pacotes
        ↓
Conversão em fluxos
        ↓
Análise de IPs, portas e protocolos
        ↓
Detecção de comportamento suspeito
        ↓
Geração de alertas
        ↓
Classificação de IPs
        ↓
Bloqueio manual / investigação / relatório
```

---

## Objetivo do projeto

O objetivo do **DevSec** é oferecer uma ferramenta local para auxiliar na visibilidade da rede, permitindo que o analista entenda:

- quais IPs estão se comunicando;
- quais portas estão sendo acessadas;
- quais protocolos estão em uso;
- quais hosts podem estar gerando tráfego suspeito;
- quais IPs precisam ser investigados;
- quais eventos devem ser registrados como evidência.

O projeto une conceitos de:

| Área | Aplicação no projeto |
|---|---|
| **Blue Team** | Monitoramento, alertas e resposta a eventos |
| **Forense Digital** | Investigação de conexões, horários, IPs e evidências |
| **Red Team** | Testes controlados com Nmap, scans e tráfego suspeito |
| **Redes** | Análise de IPs, portas, protocolos e fluxos |
| **Desenvolvimento** | Interface desktop, banco de dados, relatórios e automação |

---

## Funcionalidades principais

### Interface desktop moderna

O `main.py` utiliza uma interface escura inspirada na versão web, com menu lateral, barra de captura fixa, cards de métricas, tabelas interativas e atualização automática. A navegação contém:

- visão geral;
- fluxos em tempo real;
- alertas;
- blacklist de IPs;
- domínios acessados e políticas de domínio;
- dispositivos;
- relatórios;
- configurações;
- auditoria.

### Dashboard

Visão geral do ambiente monitorado:

- total de fluxos capturados;
- quantidade de IPs suspeitos;
- quantidade de IPs bloqueados;
- status da captura;
- resumo operacional da ferramenta.

---

### Captura de tráfego

A tela de captura exibe os fluxos de rede em tempo real, com informações como:

- IP de origem;
- IP de destino;
- porta de origem;
- porta de destino;
- protocolo;
- quantidade de pacotes;
- quantidade de bytes;
- horário da última comunicação.

Também possui filtros por:

- IP;
- porta;
- protocolo.

---

### Alertas e classificação

O sistema identifica automaticamente conexões em portas sensíveis e registra IPs suspeitos.

Na tela de alertas, o analista pode:

- classificar IP como normal;
- marcar IP como crítico;
- adicionar IP à whitelist;
- bloquear IP no firewall;
- remover bloqueio;
- exportar relatório de investigação.

---


### Interface web integrada

O arquivo `app_web.py` executa a mesma captura, detecção e persistência reais do programa, usando o mesmo banco SQLite. A interface web oferece:

- atualização automática de fluxos e alertas;
- inclusão de IP em blacklist com atualização imediata da tela de alertas;
- bloqueio e desbloqueio de IP no firewall local;
- blacklist de domínios por todos os clientes ou por IP de origem;
- visualização de domínios observados nos últimos segundos;
- evidências de domínio extraídas de DNS tradicional, HTTP Host e TLS SNI;
- lista de dispositivos e auditoria das ações do analista.

> Em redes com switch, um computador comum não enxerga automaticamente o tráfego unicast dos outros hosts. Para monitorar a LAN, execute o DevSec no gateway ou use uma porta SPAN/espelhada. DNS sobre HTTPS/TLS, VPN e TLS com ECH podem ocultar domínios. Para bloquear domínios em outros dispositivos, o DevSec precisa ser o gateway, firewall ou DNS desses equipamentos.

---

### Detecção de portas sensíveis

| Porta | Serviço | Severidade padrão |
|---|---|---|
| 22 | SSH | Médio |
| 23 | Telnet | Alto |
| 445 | SMB | Alto |
| 3389 | RDP | Alto |

Exemplo de alerta:

```text
[15:58:03] [ALTO] Conexão RDP detectada: 192.168.0.10 -> 192.168.0.1:3389
```

---

### Detecção de Port Scan

O sistema também possui detecção de varredura de portas.

Quando um mesmo IP acessa várias portas diferentes em um curto período de tempo, o sistema gera um alerta crítico.

Exemplo:

```text
[16:02:11] [CRÍTICO] Possível varredura de portas: 192.168.0.20 acessou 18 portas diferentes em 10s
```

Teste controlado com Nmap:

```bash
nmap -p 1-1000 <ip-alvo>
```

---

### Dispositivos

A tela de dispositivos permite visualizar hosts identificados pela ferramenta, incluindo informações como:

- IP;
- hostname;
- status;
- origem da descoberta;
- atividade observada.

Também há suporte para descoberta ativa usando ARP scan.

---

### Relatórios

O projeto possui exportação de dados para fins de documentação e investigação.

Formatos suportados:

- CSV;
- PDF.

Relatórios possíveis:

- fluxos capturados;
- alertas gerados;
- IPs suspeitos;
- relatório geral de investigação.

---

### Configurações

A tela de configurações permite ajustar regras importantes do sistema, como:

- interface de rede;
- portas sensíveis monitoradas;
- limite para detecção de port scan;
- janela de tempo para detecção;
- parâmetros persistidos no banco SQLite.

---

## Arquitetura do projeto

```text
DevSec-NetflowAnalyzer/
│
├── main.py                         # Ponto de entrada da aplicação desktop
├── app_web.py                      # Interface web, APIs e captura integrada
├── network_control.py              # Regras locais de firewall
├── requirements.txt                # Dependências do projeto
├── devsec_netflow.db               # Banco SQLite criado automaticamente
│
├── capture/
│   ├── packet_capture.py           # Captura real com Scapy
│   ├── flow_analyzer.py            # Conversão de pacotes em fluxos
│   ├── domain_analyzer.py          # DNS, HTTP Host e TLS SNI
│   └── detector.py                 # Regras de detecção
│
├── database/
│   ├── models.py                   # Estrutura SQL das tabelas
│   └── database.py                 # Persistência de fluxos, alertas e logs
│
├── reports/
│   └── export.py                   # Exportação de relatórios CSV/PDF
│
└── ui/
    ├── main_window.py              # Orquestração, captura, firewall e navegação
    ├── components.py               # Cards, painéis, cabeçalhos e tabelas
    ├── dashboard.py                # Visão geral e fluxos recentes
    ├── flows.py                    # Fluxos em tempo real e console
    ├── alerts.py                   # Investigação e resposta aos alertas
    ├── ip_policy.py                # Blacklist e bloqueios de IP
    ├── domains.py                  # Domínios recentes e políticas
    ├── devices.py                  # Dispositivos e descoberta ARP
    ├── audit.py                    # Auditoria das ações do analista
    ├── reports.py                  # Exportação CSV/PDF
    ├── settings.py                 # Configurações de captura/detecção
    └── theme.py                    # Tema escuro inspirado na interface web
```

---

## Tecnologias utilizadas

| Tecnologia | Uso no projeto |
|---|---|
| **Python 3.12** | Linguagem principal |
| **CustomTkinter** | Interface gráfica moderna |
| **Tkinter / ttk** | Componentes visuais e tabelas |
| **Scapy** | Captura e análise de pacotes |
| **SQLite** | Persistência local dos dados |
| **ReportLab** | Geração de relatórios PDF |
| **Threading** | Execução paralela sem travar a interface |
| **Queue** | Comunicação segura entre threads |
| **Npcap** | Captura de pacotes no Windows |
| **libpcap** | Captura de pacotes no Linux |

---

## Banco de dados

O projeto utiliza **SQLite** para manter histórico de investigação.

Dados persistidos:

- fluxos de rede;
- alertas;
- dispositivos;
- IPs bloqueados;
- whitelist;
- configurações;
- logs de eventos.

O banco é criado automaticamente na primeira execução:

```text
devsec_netflow.db
```

A persistência foi otimizada para evitar travamentos na interface, usando:

- gravação em lote;
- fila de persistência;
- thread separada;
- modo WAL do SQLite.

---

## Instalação

### 1. Clone o repositório

```bash
git clone https://github.com/seu-usuario/DevSec-NetflowAnalyzer.git
```

### 2. Entre na pasta

```bash
cd DevSec-NetflowAnalyzer
```

### 3. Crie um ambiente virtual

#### Windows

```bash
python -m venv .venv
.venv\Scripts\activate
```

#### Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 4. Instale as dependências

```bash
pip install -r requirements.txt
```

---

## Execução

### Interface desktop

```bash
python main.py
```

No Linux, a captura real geralmente exige permissão elevada:

```bash
sudo .venv/bin/python main.py
```

No Windows, execute o terminal ou VS Code como **Administrador**.

---

### Interface web

No terminal, dentro da pasta do projeto:

```bash
python app_web.py
```

Abra no navegador:

```text
http://127.0.0.1:5000
```

A captura inicia automaticamente. Para desativar o início automático:

#### Windows PowerShell

```powershell
$env:DEVSEC_AUTO_CAPTURE="0"
python app_web.py
```

#### Linux

```bash
DEVSEC_AUTO_CAPTURE=0 python app_web.py
```

Variáveis opcionais:

| Variável | Finalidade | Padrão |
|---|---|---|
| `DEVSEC_WEB_HOST` | Endereço do servidor web | `127.0.0.1` |
| `DEVSEC_WEB_PORT` | Porta HTTP | `5000` |
| `DEVSEC_WEB_SECRET` | Chave persistente da sessão Flask | gerada ao iniciar |
| `DEVSEC_DB_PATH` | Caminho de outro banco SQLite | `devsec_netflow.db` |
| `DEVSEC_AUTO_CAPTURE` | Iniciar captura ao abrir | `1` |


## Requisitos para captura real

### Windows

Para capturar pacotes no Windows, é necessário instalar o **Npcap**.

Durante a instalação, marque a opção:

```text
Install Npcap in WinPcap API-compatible Mode
```

Também é recomendado executar o projeto como Administrador.

---

### Linux

No Linux, instale as dependências de captura:

```bash
sudo apt install libpcap-dev tcpdump python3-tk
```

Depois execute com permissão:

```bash
sudo .venv/bin/python main.py
```

---

## Bloqueio de IP

O bloqueio real de IP usa o **Windows Firewall** (`netsh advfirewall`) no Windows e `iptables`/`ip6tables` quando disponível no Linux.

Exemplo de ação realizada pelo sistema:

```bash
netsh advfirewall firewall add rule name="DevSec Block IN 192.168.0.50" dir=in action=block remoteip=192.168.0.50
```

Esse recurso precisa de permissão de Administrador.

No Linux, as regras exigem `iptables` ou `ip6tables` e privilégios administrativos.

---

## Exemplo de fluxo capturado

| IP Origem | IP Destino | Porta Origem | Porta Destino | Protocolo | Pacotes | Bytes | Último |
|---|---|---:|---:|---|---:|---:|---|
| 192.168.0.10 | 192.168.0.1 | 33592 | 8080 | TCP | 1 | 2142 | 15:58:03 |
| 192.168.0.35 | 8.8.8.8 | 6094 | 53 | UDP | 3 | 3237 | 15:58:04 |
| 10.0.0.8 | 1.1.1.1 | 60046 | 443 | TCP | 5 | 1364 | 15:58:05 |

---

## Exemplo de alerta

```text
[21:13:19] [ALTO] Tráfego SMB detectado: 192.168.0.168 -> 192.168.0.156:445
[21:13:22] [MÉDIO] Conexão SSH detectada: 192.168.0.12 -> 192.168.0.168:22
[21:13:30] [CRÍTICO] Possível port scan detectado: 192.168.0.20 acessou múltiplas portas em curto período
```

---

## Fluxo de uso

```text
1. Abrir o DevSec
2. Iniciar captura pela barra superior ou pela tela Fluxos
3. Observar fluxos em tempo real
4. Aplicar filtros por IP, porta ou protocolo
5. Verificar alertas gerados
6. Classificar IPs suspeitos
7. Adicionar IPs confiáveis à whitelist
8. Bloquear IPs maliciosos quando necessário
9. Exportar relatório para investigação
```

---

## Casos de uso

O DevSec pode ser usado para:

- estudar análise de tráfego;
- demonstrar conceitos de NetFlow;
- investigar conexões suspeitas;
- testar detecção de port scan;
- criar relatórios de segurança;
- compor portfólio em cibersegurança;
- simular uma ferramenta de Blue Team;
- apoiar projetos acadêmicos ou TCC.

---

## Próximas melhorias

- Empacotar o projeto com PyInstaller;
- Gerar instalador para Windows;
- Adicionar autenticação de analistas;
- Criar gráficos no Dashboard;
- Adicionar suporte alternativo a `nftables`;
- Integrar listas de IPs maliciosos conhecidos;
- Adicionar suporte a DNS sobre HTTPS por integração com gateway/proxy autorizado;
- Adicionar geolocalização de IP público;
- Criar timeline forense por IP;
- Exportar evidências em formato mais completo.

---

## Status do projeto

O projeto está funcional e em desenvolvimento contínuo.

Versão atual:

```text
Interface desktop funcional
Interface web integrada
Captura real com Scapy
Persistência em SQLite
Filtros de investigação
Alertas de segurança
Classificação de IPs
Whitelist
Bloqueio manual no firewall local
Blacklist de IPs e domínios
Histórico recente de domínios observados
Relatórios CSV/PDF
```

---

## DEVSEC e equipe

O **DevSec - NetFlow Analyzer** é um projeto da **DEVSEC**.

**Donos do projeto:**

- Gabriel Silva Bastos;
- Matheus Dominato.

**Membros da equipe:**

- Isabelle Guimarães de Andrade;
- Nicolas Urtiaga;
- Pedro Lages da Silva.

O projeto foi criado para fins de estudo, portfólio e prática em:

- Segurança da Informação;
- Blue Team;
- Forense Digital;
- Redes de Computadores;
- Python;
- Desenvolvimento de Software Desktop.

A relação completa de autoria e participação também está disponível em [`AUTHORS.md`](AUTHORS.md).

---

## Licença

Este projeto é distribuído sob a **Licença MIT** em nome da **DEVSEC** e dos integrantes listados acima. Todos constam nos avisos de direitos autorais do projeto.

A licença permite usar, copiar, modificar e distribuir o software, desde que os avisos de direitos autorais e os termos da licença sejam mantidos nas cópias ou partes substanciais do projeto.

Consulte o arquivo [`LICENSE`](LICENSE) para ler os termos completos.

---

## Aviso

Este projeto deve ser utilizado apenas em redes próprias, ambientes autorizados ou laboratórios de estudo.

O uso da ferramenta para monitorar, capturar ou bloquear tráfego em redes de terceiros sem autorização pode violar leis e políticas de segurança.
