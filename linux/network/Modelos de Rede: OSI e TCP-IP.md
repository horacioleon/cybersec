# Modelos de Rede: OSI e TCP/IP - Guia Técnico com Linux

## Índice
1. [Introdução](#introdução)
2. [Modelo OSI (7 Camadas)](#modelo-osi-7-camadas)
3. [Modelo TCP/IP (4 Camadas)](#modelo-tcpip-4-camadas)
4. [Comparação entre Modelos](#comparação-entre-modelos)
5. [Comandos Linux por Camada](#comandos-linux-por-camada)
6. [Exemplos Práticos](#exemplos-práticos)
7. [Troubleshooting de Rede](#troubleshooting-de-rede)
8. [Referências](#referências)

---

## Introdução

Os modelos de rede são frameworks conceituais que descrevem como dados são transmitidos através de uma rede. Este documento aborda os dois principais modelos:

- **Modelo OSI (Open Systems Interconnection)**: Modelo teórico de 7 camadas desenvolvido pela ISO
- **Modelo TCP/IP**: Modelo prático de 4 camadas usado na Internet

---

## Modelo OSI (7 Camadas)

O modelo OSI divide a comunicação de rede em 7 camadas hierárquicas, cada uma com funções específicas. Apresentamos as camadas de baixo para cima (camada 1 a 7), seguindo a abordagem bottom-up que reflete como as redes realmente funcionam.

### Camada 1 - Física (Physical Layer)

**Função**: Transmissão de bits brutos através do meio físico.

**Componentes**: Cabos, conectores, hubs, repetidores, sinais elétricos/ópticos

**Aspectos**: Voltagem, taxa de transmissão, distâncias, topologia física

**Comandos Linux**:
```bash
# Status físico da interface
ethtool eth0 | grep -i link

# Ver detalhes de hardware de rede
lspci | grep -i network
lshw -class network

# Informações do driver
ethtool -i eth0

# Teste de cabo (verificar link)
mii-tool eth0

# Estatísticas de PHY
ethtool -S eth0 | grep -i phy

# Ver mensagens do kernel sobre hardware
dmesg | grep -i eth

# Informações USB de adaptadores
lsusb

# Velocidade e duplex
ethtool eth0 | grep -E 'Speed|Duplex'

# Configurar velocidade manualmente
sudo ethtool -s eth0 speed 1000 duplex full autoneg off
```

**Exemplo Prático**:
```bash
# Diagnóstico completo de hardware
sudo lshw -class network -short
sudo ethtool eth0

# Testar diferentes configurações de link
sudo ethtool -s eth0 speed 100 duplex full
sudo ethtool -s eth0 autoneg on

# Monitor de sinal (Wi-Fi)
watch -n 1 'iwconfig wlan0'
wavemon

# Estatísticas de transmissão física
ip -s link show eth0 | grep -E 'RX|TX|errors|dropped'
```

---

### Camada 2 - Enlace de Dados (Data Link Layer)

**Função**: Transferência de dados entre dispositivos na mesma rede, controle de acesso ao meio físico.

**Subcamadas**: 
- **LLC (Logical Link Control)**
- **MAC (Media Access Control)**

**Protocolos**: Ethernet, Wi-Fi (802.11), PPP, HDLC, Frame Relay

**Comandos Linux**:
```bash
# Ver interfaces de rede
ip link show
ifconfig -a

# Ver endereço MAC
ip link show eth0
cat /sys/class/net/eth0/address

# Ativar/desativar interface
sudo ip link set eth0 up
sudo ip link set eth0 down

# Mudar endereço MAC (spoofing)
sudo ip link set dev eth0 down
sudo ip link set dev eth0 address 00:11:22:33:44:55
sudo ip link set dev eth0 up

# Ver estatísticas da interface
ip -s link show eth0
ethtool -S eth0

# Verificar velocidade e duplex
ethtool eth0

# Ver tabela de bridges
brctl show

# Capturar frames Ethernet
sudo tcpdump -i eth0 -e

# Ver VLANs
ip -d link show
```

**Exemplo Prático**:
```bash
# Diagnóstico completo de interface
sudo ethtool eth0
ip -s -d link show eth0

# Criar VLAN
sudo ip link add link eth0 name eth0.10 type vlan id 10
sudo ip addr add 192.168.10.1/24 dev eth0.10
sudo ip link set eth0.10 up

# Monitorar colisões e erros
watch -n 1 'ip -s link show eth0'

# Análise de frames com tcpdump
sudo tcpdump -i eth0 -e -nn -X
```

---

### Camada 3 - Rede (Network Layer)

**Função**: Roteamento de pacotes, endereçamento lógico (IP).

**Protocolos**: IP (IPv4/IPv6), ICMP, IGMP, ARP, OSPF, BGP

**Comandos Linux**:
```bash
# Ver endereço IP
ip addr show
ifconfig

# Ver tabela de roteamento
ip route show
route -n
netstat -rn

# Adicionar rota estática
sudo ip route add 192.168.2.0/24 via 192.168.1.1

# Deletar rota
sudo ip route del 192.168.2.0/24

# Testar conectividade (ICMP)
ping -c 4 8.8.8.8
ping6 2001:4860:4860::8888

# Traçar rota
traceroute google.com
tracepath google.com
mtr google.com

# Ver cache ARP
ip neigh show
arp -a

# Adicionar entrada ARP estática
sudo arp -s 192.168.1.100 00:11:22:33:44:55

# Estatísticas ICMP
netstat -s | grep -i icmp
```

**Exemplo Prático**:
```bash
# Diagnóstico completo de rota
mtr --report google.com

# Capturar pacotes ICMP
sudo tcpdump -i any icmp

# Verificar fragmentação de pacotes
ping -M do -s 1500 google.com

# Habilitar IP forwarding (roteamento)
sudo sysctl -w net.ipv4.ip_forward=1

# Ver tabela de roteamento detalhada
ip route get 8.8.8.8
```

---

### Camada 4 - Transporte (Transport Layer)

**Função**: Transmissão confiável de dados entre hosts, controle de fluxo e erro.

**Protocolos**: TCP (confiável), UDP (não confiável), SCTP

**Características**:
- **TCP**: Orientado à conexão, confiável, controle de fluxo
- **UDP**: Sem conexão, não confiável, baixa latência

**Comandos Linux**:
```bash
# Visualizar todas as portas e conexões
netstat -tuln
ss -tuln

# Conexões TCP estabelecidas
netstat -tan | grep ESTABLISHED
ss -ta

# Escutar em porta TCP
nc -l 8080

# Conectar via TCP
nc 192.168.1.100 8080

# Enviar dados via UDP
echo "mensagem" | nc -u 192.168.1.100 53

# Estatísticas de protocolo
netstat -s
ss -s

# Testar porta específica
telnet example.com 80
nc -zv example.com 22-80
```

**Exemplo Prático**:
```bash
# Servidor TCP simples
nc -l 9999

# Cliente TCP (em outro terminal)
nc localhost 9999

# Scan de portas TCP
nmap -sT -p 1-1000 192.168.1.1

# Capturar pacotes TCP
sudo tcpdump -i eth0 'tcp port 80'

# Ver portas em listening
sudo lsof -i -P -n | grep LISTEN
```

---

### Camada 5 - Sessão (Session Layer)

**Função**: Estabelecimento, gerenciamento e término de sessões entre aplicações.

**Funções**: Controle de diálogo, sincronização, gerenciamento de tokens

**Comandos Linux**:
```bash
# Visualizar sessões ativas
who
w

# Sessões SSH ativas
ss -t state established '( dport = :22 or sport = :22 )'

# Gerenciar sessões com screen
screen -S minha_sessao
screen -ls
screen -r minha_sessao

# Gerenciar sessões com tmux
tmux new -s sessao1
tmux ls
tmux attach -t sessao1

# Sessões de login
last
lastlog
```

**Exemplo Prático**:
```bash
# Criar sessão persistente SSH
tmux new -s remote_work
ssh user@server
# Ctrl+B, D para desconectar
tmux attach -t remote_work

# Monitorar sessões de rede ativas
netstat -tan | grep ESTABLISHED
```

---

### Camada 6 - Apresentação (Presentation Layer)

**Função**: Tradução, compressão e criptografia de dados.

**Funções**: Conversão de formatos, codificação (ASCII, EBCDIC), criptografia (SSL/TLS), compressão

**Comandos Linux**:
```bash
# Codificação Base64
echo "texto secreto" | base64
echo "dGV4dG8gc2VjcmV0bwo=" | base64 -d

# Compressão de dados
gzip arquivo.txt
gunzip arquivo.txt.gz

# Criptografia com OpenSSL
openssl enc -aes-256-cbc -in arquivo.txt -out arquivo.enc
openssl enc -d -aes-256-cbc -in arquivo.enc -out arquivo.txt

# Verificar certificado SSL
openssl x509 -in certificado.pem -text -noout
```

**Exemplo Prático**:
```bash
# Estabelecer conexão SSL/TLS e ver negociação
openssl s_client -connect example.com:443 -tls1_3

# Converter arquivo entre encodings
iconv -f ISO-8859-1 -t UTF-8 arquivo_original.txt > arquivo_utf8.txt

# Criar certificado auto-assinado
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365
```

---

### Camada 7 - Aplicação (Application Layer)

**Função**: Interface entre aplicações de rede e o usuário final.

**Protocolos**: HTTP, HTTPS, FTP, SMTP, DNS, SSH, Telnet, SNMP

**Comandos Linux**:
```bash
# Requisição HTTP
curl -I https://www.google.com

# Transferência FTP
ftp ftp.example.com

# Cliente SSH
ssh user@192.168.1.100

# Consulta DNS
nslookup google.com
dig google.com

# Enviar email via SMTP
telnet smtp.example.com 25

# Cliente HTTP avançado
wget https://example.com/file.zip
```

**Exemplo Prático**:
```bash
# Testar conectividade HTTP e ver headers
curl -v https://api.github.com

# Verificar certificado SSL
openssl s_client -connect google.com:443 -showcerts

# Fazer query DNS específico
dig @8.8.8.8 example.com A
```

---

## Modelo TCP/IP (4 Camadas)

O modelo TCP/IP é o modelo prático usado na Internet, composto por 4 camadas. Apresentamos as camadas seguindo a mesma abordagem bottom-up (camada 1 a 4).

### Comparação com OSI

| TCP/IP | OSI | Descrição |
|--------|-----|-----------|
| 1 - Acesso à Rede | Enlace, Física | Ethernet, Wi-Fi |
| 2 - Internet | Rede | IP, ICMP, ARP |
| 3 - Transporte | Transporte | TCP/UDP |
| 4 - Aplicação | Aplicação, Apresentação, Sessão | Protocolos de aplicação |

---

### Camada 1 - Acesso à Rede (Network Access/Link)

**Equivalente OSI**: Camadas 1 e 2

**Tecnologias**: Ethernet (IEEE 802.3), Wi-Fi (IEEE 802.11), PPP, ARP

**Comandos Linux**:
```bash
# Status de interface
ip link show
ifconfig

# Configurar interface
sudo ip link set eth0 up
sudo ip link set eth0 down
sudo ip link set eth0 mtu 1400

# MAC address
ip link show eth0 | grep link/ether
sudo ip link set dev eth0 address 00:11:22:33:44:55

# Ethernet
ethtool eth0
sudo ethtool -s eth0 speed 1000 duplex full

# Estatísticas
ip -s link show eth0
ethtool -S eth0

# Wi-Fi
iwconfig
iw dev wlan0 info
iw dev wlan0 scan

# Signal strength (Wi-Fi)
watch -n 1 'iw dev wlan0 station dump'

# Criar bridge
sudo ip link add br0 type bridge
sudo ip link set eth0 master br0

# VLAN tagging
sudo ip link add link eth0 name eth0.100 type vlan id 100
```

**Exemplo Prático - Análise Ethernet**:
```bash
# Capturar frames Ethernet
sudo tcpdump -i eth0 -e -n

# Ver tabela MAC (switch)
bridge fdb show

# Monitorar interface em tempo real
sudo iftop -i eth0
sudo nethogs eth0

# Análise detalhada de frames
sudo tcpdump -i eth0 -XX -n

# Estatísticas de erros
watch -n 1 'ethtool -S eth0 | grep -i error'
```

**Exemplo Prático - Wi-Fi**:
```bash
# Scan de redes
sudo iw dev wlan0 scan | grep -E 'SSID|signal'

# Conectar via WPA
sudo wpa_passphrase "SSID" "password" > /etc/wpa_supplicant.conf
sudo wpa_supplicant -B -i wlan0 -c /etc/wpa_supplicant.conf

# Informações de conexão
iw dev wlan0 link
iwconfig wlan0

# Monitor mode (análise de pacotes)
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
```

---

### Camada 2 - Internet (Internet/Network)

**Equivalente OSI**: Camada 3

**Protocolos principais**: 
- **IPv4/IPv6**: Endereçamento e roteamento
- **ICMP**: Mensagens de erro e diagnóstico
- **ARP**: Resolução de endereço IP para MAC
- **IGMP**: Gerenciamento de multicast

**Comandos Linux**:
```bash
# Configuração de IP
ip addr add 192.168.1.100/24 dev eth0
ip addr del 192.168.1.100/24 dev eth0

# IPv6
ip -6 addr show
ip -6 route show

# Roteamento
ip route add default via 192.168.1.1
ip route add 10.0.0.0/8 via 192.168.1.254

# ICMP (ping)
ping -c 4 8.8.8.8
ping -I eth0 192.168.1.1

# Traçar rota
traceroute -I google.com    # ICMP
traceroute -T google.com    # TCP
traceroute -U google.com    # UDP

# MTR (diagnóstico avançado)
mtr --report --report-cycles 10 google.com

# ARP
ip neigh show
arp -n
sudo arping -I eth0 192.168.1.1

# ICMP avançado
sudo hping3 --icmp -c 4 google.com
```

**Exemplo Prático - Análise de Pacotes IP**:
```bash
# Capturar pacotes IP
sudo tcpdump -i any -n ip

# Ver TTL dos pacotes
sudo tcpdump -i any -v ip

# Fragmentação de pacotes
ping -M want -s 2000 8.8.8.8

# Análise de cabeçalho IP
sudo tcpdump -i any -n -X ip

# Roteamento com policy
sudo ip rule add from 192.168.1.0/24 table 100
sudo ip route add default via 192.168.1.1 table 100
```

**Exemplo Prático - NAT e Firewall**:
```bash
# Habilitar IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1

# NAT com iptables
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# Port forwarding
sudo iptables -t nat -A PREROUTING -p tcp --dport 8080 -j REDIRECT --to-port 80

# Ver regras NAT
sudo iptables -t nat -L -n -v
```

---

### Camada 3 - Transporte (Transport)

**Equivalente OSI**: Camada 4

**Protocolos**: TCP, UDP

**TCP - Transmission Control Protocol**:
- Orientado à conexão (handshake de 3 vias)
- Confiável (retransmissão, ACK)
- Controle de fluxo e congestionamento
- Uso: HTTP, HTTPS, SSH, FTP, SMTP

**UDP - User Datagram Protocol**:
- Sem conexão
- Não confiável (sem retransmissão)
- Baixa latência
- Uso: DNS, DHCP, VoIP, streaming, jogos online

**Comandos Linux**:
```bash
# Ver todas as conexões
ss -tan
netstat -tan

# Conexões por protocolo
ss -ta     # TCP all
ss -ua     # UDP all
ss -tl     # TCP listening
ss -ul     # UDP listening

# Conexões por estado
ss -ta state established
ss -ta state time-wait
ss -ta state syn-sent

# Portas em uso
sudo lsof -i TCP
sudo lsof -i UDP
sudo lsof -i :80

# Estatísticas TCP/UDP
netstat -st   # TCP stats
netstat -su   # UDP stats

# Parâmetros TCP do kernel
sysctl net.ipv4.tcp_congestion_control
sysctl -a | grep tcp

# Configurar parâmetros TCP
sudo sysctl -w net.ipv4.tcp_fin_timeout=30
```

**Exemplo Prático - Análise TCP**:
```bash
# Capturar handshake TCP
sudo tcpdump -i any 'tcp[tcpflags] & (tcp-syn|tcp-ack) != 0' -n

# Ver janela TCP e MSS
ss -tn -o

# Teste de throughput TCP
iperf3 -s    # servidor
iperf3 -c 192.168.1.100    # cliente

# Análise de conexões TCP
sudo tcpdump -i eth0 'tcp port 80' -A

# Simular servidor TCP
nc -l -p 9999

# Stress test de conexões
ab -n 1000 -c 10 http://localhost/
```

**Exemplo Prático - UDP**:
```bash
# Servidor UDP
nc -u -l 5000

# Cliente UDP
echo "test message" | nc -u localhost 5000

# Capturar pacotes UDP
sudo tcpdump -i any udp port 53

# Teste de throughput UDP
iperf3 -s -u    # servidor
iperf3 -c 192.168.1.100 -u -b 100M    # cliente
```

---

### Camada 4 - Aplicação (Application)

**Equivalente OSI**: Camadas 5, 6 e 7

**Protocolos principais**: HTTP/HTTPS, FTP, SMTP, DNS, SSH, DHCP, SNMP, Telnet

**Comandos Linux**:
```bash
# Serviços web
curl -X GET https://api.example.com/users
wget -O - https://example.com

# DNS
dig example.com ANY
host example.com
nslookup example.com

# Email
telnet smtp.gmail.com 587

# SSH
ssh -v user@server.com
scp file.txt user@server:/path/

# FTP
lftp ftp://ftp.example.com

# DHCP
sudo dhclient -v eth0

# SNMP
snmpwalk -v2c -c public 192.168.1.1

# HTTP server rápido
python3 -m http.server 8000
```

**Exemplo Prático - Web Scraping e APIs**:
```bash
# GET request com headers
curl -H "Authorization: Bearer TOKEN" \
     -H "Content-Type: application/json" \
     https://api.github.com/user

# POST request
curl -X POST https://api.example.com/data \
     -H "Content-Type: application/json" \
     -d '{"name":"test","value":"123"}'

# Download com retomada
wget -c https://example.com/large-file.iso

# Testar latência DNS
time dig google.com
```

**Exemplo Prático - SSH Avançado**:
```bash
# Túnel SSH (Port Forwarding Local)
ssh -L 8080:localhost:80 user@remote-server

# Túnel SSH (Port Forwarding Remoto)
ssh -R 9090:localhost:3000 user@remote-server

# Túnel SSH Dinâmico (SOCKS Proxy)
ssh -D 1080 user@remote-server

# SSH com execução remota
ssh user@server 'ps aux | grep apache'

# Transferência segura
rsync -avz -e ssh /local/path/ user@server:/remote/path/
```

---

## Comparação entre Modelos

### Tabela Comparativa Completa

| # | OSI | TCP/IP | Protocolos/Tecnologias | Comandos Principais |
|---|-----|--------|------------------------|---------------------|
| 1 | Física | - | Cabos, Hubs | `ethtool`, `lshw` |
| 2 | Enlace | Acesso à Rede | Ethernet, Wi-Fi | `ip link`, `ethtool` |
| 3 | Rede | Internet | IP, ICMP, ARP | `ip`, `ping`, `traceroute` |
| 4 | Transporte | Transporte | TCP, UDP | `netstat`, `ss`, `nc` |
| 5 | Sessão | - | NetBIOS, RPC | `netstat`, `ss` |
| 6 | Apresentação | Aplicação | SSL/TLS, ASCII | `openssl` |
| 7 | Aplicação | - | HTTP, FTP, DNS, SSH | `curl`, `ssh`, `dig` |

### Principais Diferenças

1. **Número de Camadas**: OSI (7) vs TCP/IP (4)
2. **Origem**: OSI (teórico, ISO) vs TCP/IP (prático, Internet)
3. **Adoção**: TCP/IP é o padrão de facto da Internet
4. **Flexibilidade**: OSI é mais detalhado, TCP/IP é mais pragmático

---

## Comandos Linux por Camada

### Suite Completa de Ferramentas

#### Análise de Pacotes
```bash
# tcpdump - captura de pacotes
sudo tcpdump -i any -n
sudo tcpdump -i eth0 -w capture.pcap
sudo tcpdump -r capture.pcap

# Wireshark (linha de comando)
tshark -i eth0 -f "tcp port 80"

# ngrep - grep para rede
sudo ngrep -q -W byline "GET|POST" tcp port 80
```

#### Ferramentas de Rede
```bash
# netstat - estatísticas de rede (deprecated)
netstat -tuln
netstat -rn
netstat -s

# ss - socket statistics (moderno)
ss -tuln
ss -tan state established
ss -s

# ip - configuração completa
ip addr
ip link
ip route
ip neigh

# lsof - arquivos abertos (incluindo sockets)
sudo lsof -i
sudo lsof -i :80
sudo lsof -i TCP:22
```

#### Testes de Conectividade
```bash
# ping - teste ICMP
ping -c 4 google.com
ping -f -c 100 192.168.1.1  # flood ping

# traceroute - traçar rota
traceroute google.com

# mtr - análise de rota em tempo real
mtr google.com

# nc (netcat) - Swiss Army knife de rede
nc -zv google.com 80
nc -l 9999

# telnet - teste de porta TCP
telnet example.com 80

# nmap - scanner de portas
nmap -sT 192.168.1.0/24
nmap -sS -p 1-1000 192.168.1.1
nmap -sV -O 192.168.1.1
```

#### Monitoramento
```bash
# iftop - monitoramento de banda por conexão
sudo iftop -i eth0

# nethogs - uso de banda por processo
sudo nethogs eth0

# iptraf-ng - monitoramento interativo
sudo iptraf-ng

# vnstat - estatísticas de tráfego
vnstat -i eth0
vnstat -l -i eth0  # live

# bmon - monitor de banda
bmon -p eth0
```

#### Performance e Benchmark
```bash
# iperf3 - teste de throughput
iperf3 -s              # servidor
iperf3 -c 192.168.1.100    # cliente

# ab - Apache Benchmark
ab -n 1000 -c 100 http://localhost/

# hping3 - gerador de pacotes
sudo hping3 -S -p 80 -c 10 example.com
```

---

## Exemplos Práticos

### Exemplo 1: Diagnóstico Completo de Conectividade

Quando você tem problemas de rede, siga esta ordem (bottom-up):

```bash
# 1. CAMADA FÍSICA - Verificar hardware
echo "=== Camada Física ==="
ethtool eth0 | grep -E 'Link detected|Speed|Duplex'
ip link show eth0

# 2. CAMADA DE ENLACE - Verificar interface e MAC
echo "=== Camada de Enlace ==="
ip -s link show eth0
ip neigh show

# 3. CAMADA DE REDE - Verificar IP e roteamento
echo "=== Camada de Rede ==="
ip addr show eth0
ip route show
ping -c 4 192.168.1.1    # Gateway
ping -c 4 8.8.8.8        # Internet

# 4. CAMADA DE TRANSPORTE - Verificar portas
echo "=== Camada de Transporte ==="
ss -tuln | grep LISTEN
nc -zv google.com 80 443

# 5. CAMADA DE APLICAÇÃO - Testar serviço
echo "=== Camada de Aplicação ==="
curl -I https://google.com
dig google.com
```

### Exemplo 2: Análise de Latência (Camada 3)

```bash
# Ping básico
ping -c 100 8.8.8.8 | tail -1

# MTR - My Traceroute (melhor que traceroute)
mtr --report --report-cycles 50 google.com

# Hping - customizar pacotes ICMP
sudo hping3 --icmp -c 10 google.com

# Ping com timestamp
ping -c 10 -D 8.8.8.8

# Análise de jitter
ping -i 0.2 -c 50 8.8.8.8 | grep 'time=' | awk '{print $7}' | sed 's/time=//'
```

### Exemplo 3: Captura e Análise de Tráfego HTTP

```bash
# Capturar requisições HTTP
sudo tcpdump -i any -A 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'

# Capturar e salvar
sudo tcpdump -i eth0 -w http_traffic.pcap 'tcp port 80'

# Analisar com tshark
tshark -r http_traffic.pcap -Y http.request -T fields -e http.host -e http.request.uri

# Extrair objetos HTTP
tshark -r http_traffic.pcap --export-objects http,./exported/

# ngrep para ver conteúdo
sudo ngrep -q -W byline "GET|POST" tcp port 80
```

### Exemplo 4: Scanner de Rede Completo

```bash
#!/bin/bash
NETWORK="192.168.1.0/24"

echo "=== Discovery de Hosts ==="
nmap -sn $NETWORK

echo "=== Scan de Portas Comum ==="
nmap -p 22,80,443,3306,5432 $NETWORK

echo "=== Detection de SO e Serviços ==="
sudo nmap -O -sV 192.168.1.1

echo "=== Vulnerabilidades (scripts NSE) ==="
nmap --script vuln 192.168.1.1

echo "=== ARP Scan ==="
sudo arp-scan --interface=eth0 --localnet
```

### Exemplo 5: Monitoramento de Conexões em Tempo Real

```bash
# Terminal 1: Monitor de conexões
watch -n 1 'ss -tan | grep ESTAB | wc -l && ss -tan | grep ESTAB'

# Terminal 2: Monitor de banda
sudo iftop -i eth0

# Terminal 3: Monitor por processo
sudo nethogs eth0

# Script combinado
#!/bin/bash
while true; do
    clear
    echo "=== Conexões Estabelecidas ==="
    ss -tan state established | tail -n +2 | wc -l
    echo ""
    echo "=== Top 5 Conexões ==="
    ss -tan state established | tail -n +2 | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -5
    echo ""
    echo "=== Portas em LISTEN ==="
    ss -tuln | grep LISTEN
    sleep 2
done
```

### Exemplo 6: Teste de Performance TCP

```bash
# Terminal 1 (Servidor)
iperf3 -s -p 5201

# Terminal 2 (Cliente)
# Teste básico
iperf3 -c 192.168.1.100 -t 30

# Teste com múltiplas conexões paralelas
iperf3 -c 192.168.1.100 -P 10 -t 30

# Teste reverso
iperf3 -c 192.168.1.100 -R -t 30

# Teste bidirecional
iperf3 -c 192.168.1.100 --bidir -t 30

# Teste UDP com largura de banda específica
iperf3 -c 192.168.1.100 -u -b 100M -t 30

# Análise JSON
iperf3 -c 192.168.1.100 -J > results.json
```

### Exemplo 7: Configuração de Servidor Web e Análise

```bash
# Iniciar servidor HTTP simples
python3 -m http.server 8080 &
SERVER_PID=$!

# Testar localmente
curl -I http://localhost:8080

# Benchmark
ab -n 10000 -c 100 http://localhost:8080/

# Capturar tráfego durante teste
sudo tcpdump -i lo -w web_traffic.pcap 'port 8080' &
TCPDUMP_PID=$!

# Executar teste
ab -n 1000 -c 50 http://localhost:8080/

# Parar captura
sleep 5
sudo kill $TCPDUMP_PID

# Analisar
tcpdump -r web_traffic.pcap -n | head -20

# Limpar
kill $SERVER_PID
```

### Exemplo 8: Túnel SSH e Proxy

```bash
# Túnel Local: acessa serviço remoto via porta local
# localhost:8080 -> remote-server:80
ssh -L 8080:localhost:80 user@remote-server
# Agora acesse: curl http://localhost:8080

# Túnel Remoto: expõe serviço local remotamente
# remote-server:9090 -> localhost:3000
ssh -R 9090:localhost:3000 user@remote-server

# SOCKS Proxy: todo tráfego via SSH
ssh -D 1080 user@remote-server
# Configure browser para usar SOCKS proxy localhost:1080

# Proxy com curl
curl --socks5 localhost:1080 http://ifconfig.me

# Túnel mantido em background
ssh -f -N -D 1080 user@remote-server

# Túnel com autossh (reconecta automaticamente)
autossh -M 20000 -f -N -D 1080 user@remote-server
```

### Exemplo 9: Análise de DNS

```bash
# Consultas básicas
dig google.com
dig google.com A
dig google.com AAAA
dig google.com MX
dig google.com NS
dig google.com TXT

# DNS específico
dig @8.8.8.8 google.com
dig @1.1.1.1 google.com

# Trace completo
dig +trace google.com

# Resposta curta
dig +short google.com

# Reverse DNS
dig -x 8.8.8.8

# Batch queries
cat << EOF | xargs -I {} dig +short {} A
google.com
facebook.com
twitter.com
EOF

# Tempo de resposta DNS
time dig google.com

# Monitor DNS
watch -n 1 'dig +short google.com'

# nslookup alternativo
nslookup google.com
nslookup google.com 8.8.8.8

# host command
host google.com
host -t MX gmail.com
```

### Exemplo 10: Firewall com iptables (Camadas 3 e 4)

```bash
# Ver regras atuais
sudo iptables -L -n -v
sudo iptables -t nat -L -n -v

# Limpar todas as regras
sudo iptables -F
sudo iptables -X
sudo iptables -t nat -F

# Política padrão
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT

# Permitir loopback
sudo iptables -A INPUT -i lo -j ACCEPT

# Permitir conexões estabelecidas
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Permitir SSH (porta 22)
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Permitir HTTP e HTTPS
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Permitir ping
sudo iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT

# Rate limiting (proteção contra DDoS)
sudo iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT

# Bloquear IP específico
sudo iptables -A INPUT -s 192.168.1.50 -j DROP

# Port forwarding
sudo iptables -t nat -A PREROUTING -p tcp --dport 8080 -j REDIRECT --to-port 80

# NAT/Masquerade
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# Log de pacotes dropados
sudo iptables -A INPUT -j LOG --log-prefix "iptables-dropped: "
sudo iptables -A INPUT -j DROP

# Salvar regras (Debian/Ubuntu)
sudo iptables-save > /etc/iptables/rules.v4

# Ver contador de regras
watch -n 1 'sudo iptables -L -n -v --line-numbers'
```

---

## Troubleshooting de Rede

### Metodologia Bottom-Up (OSI)

#### 1. Camada Física
```bash
# Verificar
ethtool eth0 | grep "Link detected"
ip link show eth0 | grep "state UP"
dmesg | tail -20 | grep eth0

# Problemas comuns:
# - Cabo desconectado
# - Interface desabilitada
# - Driver com problema
```

#### 2. Camada de Enlace
```bash
# Verificar
ip -s link show eth0
ethtool -S eth0 | grep -i error
arp -a

# Problemas comuns:
# - Colisões excessivas
# - Erros de CRC
# - Duplex mismatch
```

#### 3. Camada de Rede
```bash
# Verificar
ip addr show
ip route show
ping -c 4 <gateway>
ping -c 4 8.8.8.8

# Problemas comuns:
# - IP incorreto
# - Máscara errada
# - Gateway inválido
# - Sem rota para a rede
```

#### 4. Camada de Transporte
```bash
# Verificar
ss -tuln | grep LISTEN
nc -zv google.com 80
sudo iptables -L -n

# Problemas comuns:
# - Porta fechada
# - Firewall bloqueando
# - Serviço não rodando
```

#### 5. Camada de Aplicação
```bash
# Verificar
curl -v http://example.com
dig example.com
telnet smtp.gmail.com 587

# Problemas comuns:
# - DNS não resolvendo
# - Serviço mal configurado
# - Autenticação falhando
```

### Comandos de Diagnóstico Rápido

```bash
#!/bin/bash
# Script de diagnóstico completo

echo "=== 1. Hardware e Drivers ==="
lspci | grep -i network
ethtool eth0 2>/dev/null || echo "Interface eth0 não encontrada"

echo -e "\n=== 2. Interfaces de Rede ==="
ip link show

echo -e "\n=== 3. Endereços IP ==="
ip addr show

echo -e "\n=== 4. Rotas ==="
ip route show

echo -e "\n=== 5. DNS ==="
cat /etc/resolv.conf
dig +short google.com A

echo -e "\n=== 6. Conectividade Gateway ==="
GATEWAY=$(ip route | grep default | awk '{print $3}')
ping -c 3 $GATEWAY

echo -e "\n=== 7. Conectividade Internet ==="
ping -c 3 8.8.8.8

echo -e "\n=== 8. Resolução DNS ==="
ping -c 3 google.com

echo -e "\n=== 9. Portas Abertas ==="
ss -tuln | grep LISTEN

echo -e "\n=== 10. Conexões Ativas ==="
ss -tan state established | tail -n +2 | wc -l

echo -e "\n=== 11. Estatísticas de Erros ==="
ip -s link show eth0 | grep -E "RX|TX|errors"

echo -e "\n=== 12. Firewall ==="
sudo iptables -L -n | head -20
```

### Problemas Comuns e Soluções

#### Problema: Sem conectividade
```bash
# 1. Verificar cabo/link
ethtool eth0 | grep "Link detected"

# 2. Ativar interface
sudo ip link set eth0 up

# 3. Obter IP via DHCP
sudo dhclient eth0

# 4. Verificar rota padrão
ip route show
# Se não tiver, adicionar:
sudo ip route add default via 192.168.1.1
```

#### Problema: DNS não funciona
```bash
# 1. Verificar /etc/resolv.conf
cat /etc/resolv.conf

# 2. Testar DNS específico
dig @8.8.8.8 google.com

# 3. Adicionar DNS manualmente
echo "nameserver 8.8.8.8" | sudo tee -a /etc/resolv.conf

# 4. Flush cache DNS
sudo systemd-resolve --flush-caches
```

#### Problema: Alta latência
```bash
# 1. MTR para identificar onde está o problema
mtr --report google.com

# 2. Verificar interface
ip -s link show eth0

# 3. Testar diferentes servidores
ping -c 10 8.8.8.8
ping -c 10 1.1.1.1

# 4. Ver conexões ativas
ss -tan | wc -l
```

#### Problema: Porta não acessível
```bash
# 1. Verificar se está ouvindo
ss -tuln | grep :80

# 2. Testar localmente
nc -zv localhost 80

# 3. Verificar firewall
sudo iptables -L -n | grep 80

# 4. Verificar de fora
nc -zv <seu-ip> 80
```

---

## Referências

### Documentação Oficial
- [RFC 791 - Internet Protocol](https://tools.ietf.org/html/rfc791)
- [RFC 793 - TCP](https://tools.ietf.org/html/rfc793)
- [RFC 768 - UDP](https://tools.ietf.org/html/rfc768)
- [RFC 792 - ICMP](https://tools.ietf.org/html/rfc792)

### Man Pages Importantes
```bash
man ip
man ss
man tcpdump
man iptables
man ethtool
man netstat
man traceroute
```

### Ferramentas e Pacotes
```bash
# Debian/Ubuntu
sudo apt install net-tools iproute2 tcpdump nmap netcat-openbsd \
                 dnsutils iperf3 mtr-tiny ethtool iftop nethogs \
                 traceroute curl wget ngrep arp-scan

# Red Hat/CentOS
sudo yum install net-tools iproute tcpdump nmap nmap-ncat \
                 bind-utils iperf3 mtr ethtool iftop nethogs \
                 traceroute curl wget ngrep arp-scan

# Arch Linux
sudo pacman -S net-tools iproute2 tcpdump nmap gnu-netcat \
               bind-tools iperf3 mtr ethtool iftop nethogs \
               traceroute curl wget ngrep arp-scan
```

### Tabela de Referência Rápida de Portas

| Porta | Protocolo | Serviço |
|-------|-----------|---------|
| 20, 21 | TCP | FTP |
| 22 | TCP | SSH |
| 23 | TCP | Telnet |
| 25 | TCP | SMTP |
| 53 | UDP/TCP | DNS |
| 67, 68 | UDP | DHCP |
| 80 | TCP | HTTP |
| 110 | TCP | POP3 |
| 143 | TCP | IMAP |
| 443 | TCP | HTTPS |
| 465 | TCP | SMTPS |
| 587 | TCP | SMTP (submission) |
| 993 | TCP | IMAPS |
| 995 | TCP | POP3S |
| 3306 | TCP | MySQL |
| 5432 | TCP | PostgreSQL |
| 6379 | TCP | Redis |
| 8080 | TCP | HTTP alternativo |
| 27017 | TCP | MongoDB |

---

## Conclusão

Este documento fornece uma base sólida para entender os modelos de rede OSI e TCP/IP, com ênfase prática em comandos Linux. A compreensão dessas camadas é essencial para:

- **Diagnóstico de problemas**: Abordagem sistemática bottom-up
- **Segurança**: Entender onde aplicar controles
- **Performance**: Otimizar em diferentes níveis
- **Desenvolvimento**: Escolher protocolos apropriados

### Dicas Finais

1. **Sempre comece pela camada física** ao diagnosticar problemas
2. **Use tcpdump/Wireshark** para entender o que realmente está acontecendo
3. **Aprenda iptables** para controle fino de tráfego
4. **Automatize com scripts** as verificações comuns
5. **Pratique com máquinas virtuais** antes de produção

### Próximos Passos

- Estude protocolos específicos em profundidade (TCP, HTTP, DNS)
- Aprenda sobre segurança de rede (TLS, VPN, IDS/IPS)
- Explore ferramentas avançadas (Wireshark, Scapy, nftables)
- Pratique com laboratórios de rede virtuais

---

**Autor**: Documento Técnico de Referência  
**Última Atualização**: 2025  
**Licença**: Open Source


