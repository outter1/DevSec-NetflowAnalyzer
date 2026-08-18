# DevSec - NetFlow Analyzer

![Status](https://img.shields.io/badge/status-funcional-brightgreen)
![Python](https://img.shields.io/badge/Python-3.12-blue)
![Interface](https://img.shields.io/badge/Interface-CustomTkinter-2f855a)
![Database](https://img.shields.io/badge/Database-SQLite-orange)
![Security](https://img.shields.io/badge/Área-Blue%20Team%20%7C%20Forense%20%7C%20Red%20Team-red)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

---

## 📥 Download

Não quer rodar do código-fonte? Baixe o instalador pronto para Windows:

<p align="left">
  <a href="https://drive.google.com/file/d/1jrWvNNwe7bdMditBk8dexjrOlpg-kHS1/view?usp=sharing">
    <img src="https://img.shields.io/badge/⬇️_Baixar_instalador-DevSecSetup.exe-2f855a?style=for-the-badge" alt="Baixar instalador">
  </a>
</p>

O instalador (`DevSecSetup.exe`) já inclui o **Npcap** e instala tudo automaticamente — só executar como administrador e seguir o assistente.

> ⚠️ **Aviso do Windows/antivírus:** como o executável não é assinado digitalmente, é normal o SmartScreen ou o antivírus do navegador avisarem antes do download. Isso acontece porque o app pede permissão de administrador e mexe em captura de pacotes e regras de firewall — comportamento comum de ferramentas de segurança, mas que aciona heurísticas de proteção. Se o download for bloqueado, escolha "manter mesmo assim" no navegador.

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

## Instalação (a partir do código-fonte)

Prefere rodar direto do Python em vez do instalador? Siga os passos abaixo.

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

---

## Licença

O projeto é disponibilizado sob a **Licença MIT**. O uso, a cópia, a modificação e a distribuição devem preservar os avisos de direitos autorais e os termos da licença.

## Autores

Projeto desenvolvido pela **KillChain**.

- Gabriel Silva Bastos
- Matheus Dominato
- Isabelle Guimarães de Andrade
- Nicolas Urtiaga
- Pedro Lages da Silva
