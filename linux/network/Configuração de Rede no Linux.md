# Configuração de Placas de Rede no Linux (Debian)

## Índice
1. [Introdução](#introdução)
2. [Identificação de Interfaces de Rede](#identificação-de-interfaces-de-rede)
3. [Ferramentas de Configuração](#ferramentas-de-configuração)
4. [Configuração de Rede Cabeada (Ethernet)](#configuração-de-rede-cabeada-ethernet)
5. [Configuração de Rede Sem Fio (Wi-Fi)](#configuração-de-rede-sem-fio-wi-fi)
6. [Configuração Permanente](#configuração-permanente)
7. [Troubleshooting](#troubleshooting)
8. [Scripts Úteis](#scripts-úteis)
9. [Referências](#referências)

---

## Introdução

Este documento é um guia completo e prático para configurar interfaces de rede (cabeadas e sem fio) no Debian Linux através da linha de comando. Abordaremos desde conceitos básicos até configurações avançadas.

### Pré-requisitos

```bash
# Atualizar sistema
sudo apt update && sudo apt upgrade -y

# Instalar ferramentas essenciais
sudo apt install -y net-tools iproute2 wireless-tools \
                    wpasupplicant network-manager \
                    ethtool iw rfkill

# Verificar permissões (necessário root/sudo)
whoami
```

### Nomenclatura de Interfaces no Linux

O Linux usa diferentes esquemas de nomenclatura:

**Sistema Tradicional**:
- `eth0`, `eth1`: Interfaces Ethernet
- `wlan0`, `wlan1`: Interfaces Wi-Fi
- `lo`: Loopback (localhost)

**Sistema Moderno (Predictable Network Interface Names)**:
- `enp0s3`, `enp3s0`: Ethernet PCI
- `ens33`, `ens160`: Ethernet (slot)
- `wlp2s0`, `wlp3s0`: Wi-Fi PCI
- `enx00e04c68xxxx`: Ethernet USB (baseado em MAC)

**Formato**:
- `en` = Ethernet, `wl` = WLAN (wireless)
- `p2s0` = PCI bus 2, slot 0
- `x<MAC>` = MAC address

---

## Identificação de Interfaces de Rede

### Listar Todas as Interfaces

#### Usando `ip` (moderno, recomendado)

```bash
# Listar todas as interfaces
ip link show

# Listar apenas interfaces ativas
ip link show up

# Ver detalhes de interface específica
ip link show eth0

# Formato resumido
ip -br link show

# Com cores
ip -c link show
```

#### Usando `ifconfig` (legado, mas ainda útil)

```bash
# Ver todas as interfaces
ifconfig -a

# Ver apenas interfaces ativas
ifconfig

# Ver interface específica
ifconfig eth0
```

#### Usando comandos específicos

```bash
# Ver apenas interfaces de rede
ls /sys/class/net/

# Informações detalhadas de hardware
lshw -class network

# Dispositivos PCI
lspci | grep -i network

# Dispositivos USB
lsusb | grep -i wireless

# Status de todas as interfaces
ip addr show
```

### Identificar Tipo de Interface

```bash
# Verificar se é cabeada ou sem fio
iw dev          # Apenas wireless
ethtool eth0    # Apenas cabeada

# Ver driver utilizado
ethtool -i eth0

# Ver módulo do kernel carregado
lsmod | grep -E 'e1000|iwlwifi|ath|rtl'
```

### Verificar Status de Hardware

```bash
# Verificar se a interface está detectada
dmesg | grep -i "eth\|wlan\|network"

# Ver link status
ip link show eth0 | grep -i "state"

# Verificar se o cabo está conectado (cabeada)
ethtool eth0 | grep "Link detected"

# Status RF Kill (wireless)
rfkill list
```

---

## Ferramentas de Configuração

### Comparação de Ferramentas

| Ferramenta | Tipo | Status | Uso Principal |
|------------|------|--------|---------------|
| `ip` | Moderno | Recomendado | Configuração completa de rede |
| `ifconfig` | Legado | Deprecated | Visualização rápida |
| `iw` | Moderno | Recomendado | Configuração Wi-Fi |
| `iwconfig` | Legado | Deprecated | Configuração Wi-Fi básica |
| `nmcli` | Moderno | Recomendado | NetworkManager CLI |
| `nmtui` | Moderno | Recomendado | NetworkManager TUI |

### Instalação de Ferramentas

```bash
# Suite iproute2 (ip command)
sudo apt install iproute2

# Ferramentas legacy (net-tools)
sudo apt install net-tools

# Ferramentas wireless modernas
sudo apt install iw wireless-tools

# WPA Supplicant (para WPA/WPA2)
sudo apt install wpasupplicant

# NetworkManager
sudo apt install network-manager

# Ferramentas de diagnóstico
sudo apt install ethtool mtr-tiny tcpdump
```

---

## Configuração de Rede Cabeada (Ethernet)

### Passo 1: Identificar a Interface

```bash
# Listar interfaces
ip link show

# Exemplo de saída:
# 2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
# ou
# 2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
```

### Passo 2: Ativar a Interface

```bash
# Ativar interface
sudo ip link set eth0 up

# Desativar interface
sudo ip link set eth0 down

# Verificar status
ip link show eth0
```

### Passo 3: Configurar Endereço IP

#### A. Configuração via DHCP (Automática)

```bash
# Método 1: dhclient
sudo dhclient eth0

# Método 2: dhcpcd
sudo dhcpcd eth0

# Renovar lease DHCP
sudo dhclient -r eth0  # Release
sudo dhclient eth0     # Renew

# Ver informações DHCP
cat /var/lib/dhcp/dhclient.leases
```

#### B. Configuração IP Estático (Manual)

```bash
# Adicionar IP estático
sudo ip addr add 192.168.1.100/24 dev eth0

# Remover IP
sudo ip addr del 192.168.1.100/24 dev eth0

# Adicionar rota padrão (gateway)
sudo ip route add default via 192.168.1.1

# Verificar configuração
ip addr show eth0
ip route show
```

#### Exemplo Completo - IP Estático

```bash
#!/bin/bash
# Script para configurar IP estático

INTERFACE="eth0"
IP_ADDRESS="192.168.1.100"
NETMASK="24"
GATEWAY="192.168.1.1"
DNS1="8.8.8.8"
DNS2="8.8.4.4"

# Limpar configuração anterior
sudo ip addr flush dev $INTERFACE
sudo ip route flush dev $INTERFACE

# Ativar interface
sudo ip link set $INTERFACE up

# Configurar IP
sudo ip addr add ${IP_ADDRESS}/${NETMASK} dev $INTERFACE

# Configurar gateway
sudo ip route add default via $GATEWAY dev $INTERFACE

# Configurar DNS
echo "nameserver $DNS1" | sudo tee /etc/resolv.conf
echo "nameserver $DNS2" | sudo tee -a /etc/resolv.conf

# Verificar
echo "=== Configuração Aplicada ==="
ip addr show $INTERFACE
ip route show
cat /etc/resolv.conf
```

### Passo 4: Configurar DNS

```bash
# Método 1: Editar /etc/resolv.conf diretamente
sudo nano /etc/resolv.conf

# Adicionar:
nameserver 8.8.8.8
nameserver 8.8.4.4
nameserver 1.1.1.1

# Método 2: Via resolvconf
sudo apt install resolvconf
sudo nano /etc/resolvconf/resolv.conf.d/head

# Método 3: Via systemd-resolved
sudo nano /etc/systemd/resolved.conf
# Adicionar:
[Resolve]
DNS=8.8.8.8 8.8.4.4
FallbackDNS=1.1.1.1

sudo systemctl restart systemd-resolved
```

### Passo 5: Testar Conectividade

```bash
# Testar conectividade com gateway
ping -c 4 192.168.1.1

# Testar conectividade com Internet
ping -c 4 8.8.8.8

# Testar resolução DNS
ping -c 4 google.com

# Verificar rota
traceroute google.com
mtr --report google.com
```

### Configurações Avançadas de Ethernet

#### Alterar MTU

```bash
# Ver MTU atual
ip link show eth0 | grep mtu

# Mudar MTU
sudo ip link set eth0 mtu 9000

# MTU padrão é 1500
```

#### Configurar Velocidade e Duplex

```bash
# Ver configurações atuais
sudo ethtool eth0

# Configurar manualmente
sudo ethtool -s eth0 speed 1000 duplex full autoneg off

# Habilitar autonegociação
sudo ethtool -s eth0 autoneg on

# Verificar
sudo ethtool eth0 | grep -E "Speed|Duplex|Auto-negotiation"
```

#### Bonding (Link Aggregation)

```bash
# Instalar módulo
sudo modprobe bonding

# Carregar módulo no boot
echo "bonding" | sudo tee -a /etc/modules

# Criar interface bond0
sudo ip link add bond0 type bond mode 802.3ad

# Adicionar interfaces escravas
sudo ip link set eth0 down
sudo ip link set eth1 down
sudo ip link set eth0 master bond0
sudo ip link set eth1 master bond0
sudo ip link set bond0 up

# Configurar IP no bond
sudo ip addr add 192.168.1.100/24 dev bond0

# Verificar status
cat /proc/net/bonding/bond0
```

#### VLAN (802.1Q)

```bash
# Carregar módulo
sudo modprobe 8021q

# Criar VLAN
sudo ip link add link eth0 name eth0.10 type vlan id 10

# Configurar IP na VLAN
sudo ip addr add 192.168.10.1/24 dev eth0.10
sudo ip link set eth0.10 up

# Verificar
ip -d link show eth0.10

# Remover VLAN
sudo ip link delete eth0.10
```

#### Bridge (Ponte de Rede)

```bash
# Instalar ferramentas
sudo apt install bridge-utils

# Criar bridge
sudo ip link add br0 type bridge

# Adicionar interfaces à bridge
sudo ip link set eth0 master br0
sudo ip link set eth1 master br0

# Configurar IP na bridge
sudo ip addr add 192.168.1.100/24 dev br0
sudo ip link set br0 up

# Verificar
bridge link show
ip addr show br0

# Usando brctl (legado)
sudo brctl addbr br0
sudo brctl addif br0 eth0
sudo brctl show
```

---

## Configuração de Rede Sem Fio (Wi-Fi)

### Passo 1: Verificar Hardware Wi-Fi

```bash
# Verificar se a interface wireless existe
iw dev

# Listar dispositivos wireless
iwconfig

# Ver informações de hardware
lspci | grep -i wireless
lsusb | grep -i wireless

# Ver driver carregado
lsmod | grep -E 'iwl|ath|rtl|brcm'

# Verificar RF Kill (pode bloquear wireless)
rfkill list

# Desbloquear se necessário
sudo rfkill unblock all
```

### Passo 2: Ativar Interface Wireless

```bash
# Ativar interface
sudo ip link set wlan0 up

# Verificar se está ativa
ip link show wlan0

# Verificar modo operacional
iw dev wlan0 info
```

### Passo 3: Escanear Redes Disponíveis

#### Usando `iw` (moderno)

```bash
# Escanear redes
sudo iw dev wlan0 scan

# Escanear e filtrar SSIDs
sudo iw dev wlan0 scan | grep -E "SSID|signal"

# Formato mais limpo
sudo iw dev wlan0 scan | grep -E "^BSS|SSID|signal|WPA"

# Ver apenas SSIDs
sudo iw dev wlan0 scan | grep SSID | awk '{print $2}'
```

#### Usando `iwlist` (legado)

```bash
# Escanear redes
sudo iwlist wlan0 scan

# Ver SSIDs e qualidade
sudo iwlist wlan0 scan | grep -E "ESSID|Quality"
```

#### Script para Listar Redes Wi-Fi

```bash
#!/bin/bash
# Script para listar redes Wi-Fi de forma organizada

echo "Escaneando redes Wi-Fi..."
sudo iw dev wlan0 scan | awk '
/^BSS/ {
    bssid=$2
}
/SSID:/ {
    ssid=$2
    for(i=3;i<=NF;i++) ssid=ssid" "$i
}
/signal:/ {
    signal=$2
}
/WPA/ {
    security="WPA"
}
/RSN/ {
    security="WPA2"
}
/freq:/ {
    if(ssid && bssid) {
        printf "%-30s %-18s %5s dBm  %s\n", ssid, bssid, signal, security
        ssid=""; bssid=""; signal=""; security="Open"
    }
}
' | sort -k3 -rn | head -20
```

### Passo 4: Conectar a Rede Wi-Fi

#### A. Rede Aberta (Sem Senha)

```bash
# Conectar
sudo iw dev wlan0 connect "NOME_DA_REDE"

# Obter IP via DHCP
sudo dhclient wlan0

# Verificar conexão
iw dev wlan0 link
```

#### B. Rede WEP (Deprecated)

```bash
# Conectar com chave WEP
sudo iw dev wlan0 connect "NOME_DA_REDE" key 0:senha_wep

# OU usando iwconfig
sudo iwconfig wlan0 essid "NOME_DA_REDE" key s:senha_wep
sudo dhclient wlan0
```

#### C. Rede WPA/WPA2 (Método Manual)

**Passo 1: Criar arquivo de configuração**

```bash
# Gerar hash da senha
wpa_passphrase "NOME_DA_REDE" "senha_wifi" | sudo tee /etc/wpa_supplicant/wpa_supplicant.conf

# Saída exemplo:
# network={
#     ssid="NOME_DA_REDE"
#     #psk="senha_wifi"
#     psk=hash_gerado
# }
```

**Passo 2: Conectar usando wpa_supplicant**

```bash
# Matar processos anteriores
sudo killall wpa_supplicant

# Conectar
sudo wpa_supplicant -B -i wlan0 -c /etc/wpa_supplicant/wpa_supplicant.conf

# -B = background
# -i = interface
# -c = arquivo de configuração

# Obter IP via DHCP
sudo dhclient wlan0

# Verificar conexão
iw dev wlan0 link
```

**Passo 3: Verificar conectividade**

```bash
# Ver status
wpa_cli -i wlan0 status

# Testar conexão
ping -c 4 8.8.8.8
```

#### D. Script Completo para Conectar WPA/WPA2

```bash
#!/bin/bash
# Script para conectar em rede Wi-Fi WPA/WPA2

INTERFACE="wlan0"
SSID="NOME_DA_REDE"
PASSWORD="senha_wifi"
CONFIG_FILE="/tmp/wpa_supplicant_temp.conf"

echo "=== Conectando em $SSID ==="

# Desativar NetworkManager temporariamente
sudo systemctl stop NetworkManager 2>/dev/null

# Matar processos wpa_supplicant existentes
sudo killall wpa_supplicant 2>/dev/null
sleep 2

# Ativar interface
sudo ip link set $INTERFACE up

# Gerar configuração
wpa_passphrase "$SSID" "$PASSWORD" > $CONFIG_FILE

# Conectar
echo "Iniciando wpa_supplicant..."
sudo wpa_supplicant -B -i $INTERFACE -c $CONFIG_FILE

# Aguardar conexão
sleep 3

# Obter IP
echo "Obtendo IP via DHCP..."
sudo dhclient $INTERFACE

# Verificar status
echo ""
echo "=== Status da Conexão ==="
iw dev $INTERFACE link
ip addr show $INTERFACE | grep "inet "

# Testar conectividade
echo ""
echo "=== Teste de Conectividade ==="
ping -c 3 8.8.8.8

# Limpar
rm -f $CONFIG_FILE
```

#### E. Usando NetworkManager (nmcli)

```bash
# Escanear redes
nmcli device wifi list

# Conectar em rede WPA/WPA2
nmcli device wifi connect "NOME_DA_REDE" password "senha_wifi"

# Conectar em rede salva anteriormente
nmcli connection up "NOME_DA_REDE"

# Ver conexões salvas
nmcli connection show

# Ver status
nmcli device status

# Desconectar
nmcli device disconnect wlan0

# Deletar conexão salva
nmcli connection delete "NOME_DA_REDE"
```

### Passo 5: Configurações Avançadas Wi-Fi

#### Configuração Manual de IP (Wi-Fi)

```bash
# Depois de conectar, configurar IP estático
sudo ip addr flush dev wlan0
sudo ip addr add 192.168.1.100/24 dev wlan0
sudo ip route add default via 192.168.1.1 dev wlan0

# Configurar DNS
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf
```

#### Verificar Qualidade do Sinal

```bash
# Método 1: iw
watch -n 1 'iw dev wlan0 link'

# Método 2: iwconfig
watch -n 1 'iwconfig wlan0'

# Método 3: Estatísticas detalhadas
watch -n 1 'iw dev wlan0 station dump'

# Ver informações de canal
iw dev wlan0 info
```

#### Mudar Região Wi-Fi

```bash
# Ver região atual
iw reg get

# Configurar região (exemplo: Brasil)
sudo iw reg set BR

# Verificar
iw reg get
```

#### Access Point Mode (Hotspot)

```bash
# Instalar hostapd e dnsmasq
sudo apt install hostapd dnsmasq

# Configurar hostapd
sudo nano /etc/hostapd/hostapd.conf
```

Conteúdo do arquivo:
```conf
interface=wlan0
driver=nl80211
ssid=MeuHotspot
hw_mode=g
channel=6
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=senha123456
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
```

```bash
# Configurar interface
sudo ip addr add 192.168.50.1/24 dev wlan0

# Configurar DHCP (dnsmasq)
sudo nano /etc/dnsmasq.conf
```

Adicionar:
```conf
interface=wlan0
dhcp-range=192.168.50.10,192.168.50.50,12h
```

```bash
# Habilitar IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1

# Configurar NAT
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# Iniciar serviços
sudo systemctl start hostapd
sudo systemctl start dnsmasq

# Verificar
sudo systemctl status hostapd
```

#### Monitor Mode (Análise de Pacotes)

```bash
# Parar NetworkManager
sudo systemctl stop NetworkManager

# Desativar interface
sudo ip link set wlan0 down

# Configurar monitor mode
sudo iw dev wlan0 set type monitor

# Ativar interface
sudo ip link set wlan0 up

# Verificar
iw dev wlan0 info

# Capturar pacotes
sudo tcpdump -i wlan0 -w capture.pcap

# Voltar para modo managed
sudo ip link set wlan0 down
sudo iw dev wlan0 set type managed
sudo ip link set wlan0 up
sudo systemctl start NetworkManager
```

---

## Configuração Permanente

As configurações feitas com `ip` e `iw` são temporárias e se perdem após reboot. Para torná-las permanentes, use um dos métodos abaixo.

### Método 1: /etc/network/interfaces (Tradicional)

#### Configuração Ethernet DHCP

```bash
sudo nano /etc/network/interfaces
```

Adicionar:
```conf
# Interface loopback
auto lo
iface lo inet loopback

# Interface Ethernet com DHCP
auto eth0
iface eth0 inet dhcp
```

#### Configuração Ethernet IP Estático

```conf
# Interface Ethernet com IP estático
auto eth0
iface eth0 inet static
    address 192.168.1.100
    netmask 255.255.255.0
    gateway 192.168.1.1
    dns-nameservers 8.8.8.8 8.8.4.4
```

#### Configuração Wi-Fi

```conf
# Interface Wi-Fi
auto wlan0
iface wlan0 inet dhcp
    wpa-ssid "NOME_DA_REDE"
    wpa-psk "senha_wifi"

# Ou com IP estático
auto wlan0
iface wlan0 inet static
    address 192.168.1.100
    netmask 255.255.255.0
    gateway 192.168.1.1
    dns-nameservers 8.8.8.8 8.8.4.4
    wpa-ssid "NOME_DA_REDE"
    wpa-psk "senha_wifi"
```

#### Aplicar Configurações

```bash
# Reiniciar networking
sudo systemctl restart networking

# OU
sudo ifdown eth0 && sudo ifup eth0

# Verificar
ip addr show
ip route show
```

### Método 2: NetworkManager

NetworkManager é o gerenciador de rede mais usado em desktops Linux modernos.

#### Via nmcli (CLI)

```bash
# Ver conexões
nmcli connection show

# Criar conexão Ethernet DHCP
nmcli connection add type ethernet con-name "Ethernet-DHCP" ifname eth0

# Criar conexão Ethernet estática
nmcli connection add type ethernet con-name "Ethernet-Static" ifname eth0 \
    ip4 192.168.1.100/24 gw4 192.168.1.1

# Configurar DNS
nmcli connection modify "Ethernet-Static" ipv4.dns "8.8.8.8 8.8.4.4"

# Criar conexão Wi-Fi
nmcli connection add type wifi con-name "Meu-WiFi" ifname wlan0 \
    ssid "NOME_DA_REDE" wifi-sec.key-mgmt wpa-psk wifi-sec.psk "senha_wifi"

# Ativar conexão
nmcli connection up "Meu-WiFi"

# Editar conexão
nmcli connection edit "Meu-WiFi"

# Deletar conexão
nmcli connection delete "Meu-WiFi"

# Configurar para conectar automaticamente
nmcli connection modify "Meu-WiFi" connection.autoconnect yes
```

#### Via nmtui (TUI - Interface de Texto)

```bash
# Abrir interface interativa
sudo nmtui

# Navegar com setas e Enter
# Opções:
# - Edit a connection
# - Activate a connection
# - Set system hostname
```

#### Arquivos de Configuração do NetworkManager

```bash
# Ver configurações
ls /etc/NetworkManager/system-connections/

# Editar conexão manualmente
sudo nano /etc/NetworkManager/system-connections/Meu-WiFi.nmconnection
```

Exemplo de arquivo:
```ini
[connection]
id=Meu-WiFi
type=wifi
autoconnect=true

[wifi]
ssid=NOME_DA_REDE
mode=infrastructure

[wifi-security]
key-mgmt=wpa-psk
psk=senha_wifi

[ipv4]
method=auto

[ipv6]
method=auto
```

```bash
# Recarregar configurações
sudo nmcli connection reload

# Aplicar mudanças
sudo nmcli connection up "Meu-WiFi"
```

### Método 3: systemd-networkd

Sistema moderno de gerenciamento de rede, leve e rápido.

#### Habilitar systemd-networkd

```bash
# Desabilitar NetworkManager
sudo systemctl stop NetworkManager
sudo systemctl disable NetworkManager

# Habilitar systemd-networkd
sudo systemctl enable systemd-networkd
sudo systemctl start systemd-networkd
```

#### Configuração Ethernet DHCP

```bash
sudo nano /etc/systemd/network/20-wired.network
```

Conteúdo:
```ini
[Match]
Name=eth0

[Network]
DHCP=yes
```

#### Configuração Ethernet Estática

```bash
sudo nano /etc/systemd/network/20-wired-static.network
```

Conteúdo:
```ini
[Match]
Name=eth0

[Network]
Address=192.168.1.100/24
Gateway=192.168.1.1
DNS=8.8.8.8
DNS=8.8.4.4
```

#### Configuração Wi-Fi

Para Wi-Fi, usar wpa_supplicant com systemd-networkd:

```bash
# Configurar wpa_supplicant
sudo nano /etc/wpa_supplicant/wpa_supplicant-wlan0.conf
```

Conteúdo:
```conf
ctrl_interface=/run/wpa_supplicant
update_config=1

network={
    ssid="NOME_DA_REDE"
    psk="senha_wifi"
}
```

```bash
# Criar arquivo de rede
sudo nano /etc/systemd/network/25-wireless.network
```

Conteúdo:
```ini
[Match]
Name=wlan0

[Network]
DHCP=yes
```

```bash
# Habilitar wpa_supplicant
sudo systemctl enable wpa_supplicant@wlan0
sudo systemctl start wpa_supplicant@wlan0

# Reiniciar networkd
sudo systemctl restart systemd-networkd

# Verificar status
sudo systemctl status systemd-networkd
sudo networkctl status
```

#### Aplicar e Verificar

```bash
# Reiniciar serviço
sudo systemctl restart systemd-networkd

# Ver status
sudo networkctl status

# Ver lista de interfaces
sudo networkctl list

# Debug
sudo journalctl -u systemd-networkd -f
```

### Método 4: Configuração via Scripts de Inicialização

Criar script personalizado que roda no boot.

```bash
# Criar script
sudo nano /usr/local/bin/configure-network.sh
```

Conteúdo:
```bash
#!/bin/bash

# Configurar interface Ethernet
ip link set eth0 up
ip addr add 192.168.1.100/24 dev eth0
ip route add default via 192.168.1.1

# Configurar DNS
echo "nameserver 8.8.8.8" > /etc/resolv.conf
echo "nameserver 8.8.4.4" >> /etc/resolv.conf

# Configurar Wi-Fi
wpa_supplicant -B -i wlan0 -c /etc/wpa_supplicant/wpa_supplicant.conf
dhclient wlan0
```

```bash
# Tornar executável
sudo chmod +x /usr/local/bin/configure-network.sh

# Criar serviço systemd
sudo nano /etc/systemd/system/configure-network.service
```

Conteúdo:
```ini
[Unit]
Description=Configure Network Interfaces
After=network-pre.target
Before=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/configure-network.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```

```bash
# Habilitar e iniciar
sudo systemctl daemon-reload
sudo systemctl enable configure-network.service
sudo systemctl start configure-network.service

# Verificar
sudo systemctl status configure-network.service
```

---

## Troubleshooting

### Problema 1: Interface Não Detectada

```bash
# Verificar se o hardware é reconhecido
lspci | grep -i network
lsusb | grep -i wireless

# Ver mensagens do kernel
dmesg | grep -i "eth\|wlan\|network"

# Verificar módulos carregados
lsmod | grep -E "e1000|iwlwifi|ath|rtl"

# Carregar módulo manualmente
sudo modprobe nome_do_modulo

# Listar módulos disponíveis
find /lib/modules/$(uname -r) -type f -name '*.ko' | grep -i net
```

### Problema 2: Interface Sem Link/Cabo Desconectado

```bash
# Verificar link físico
sudo ethtool eth0 | grep "Link detected"
ip link show eth0

# Ver estatísticas
ip -s link show eth0

# Verificar LED da placa de rede
# - LED apagado: sem link
# - LED aceso/piscando: link OK

# Testar cabo em outra porta/dispositivo
```

### Problema 3: Não Consegue Obter IP via DHCP

```bash
# Verificar se o cliente DHCP está funcionando
sudo dhclient -v eth0

# Ver logs
sudo journalctl -u networking -f
sudo tail -f /var/log/syslog | grep dhcp

# Liberar e renovar
sudo dhclient -r eth0  # Release
sudo dhclient -v eth0  # Request

# Verificar se há servidor DHCP na rede
sudo nmap --script broadcast-dhcp-discover

# Testar com IP estático temporário
sudo ip addr add 192.168.1.100/24 dev eth0
ping 192.168.1.1
```

### Problema 4: Wi-Fi Não Conecta

```bash
# Verificar RF Kill
rfkill list
sudo rfkill unblock all

# Verificar se a interface está ativa
ip link show wlan0
sudo ip link set wlan0 up

# Ver logs do wpa_supplicant
sudo wpa_supplicant -i wlan0 -c /etc/wpa_supplicant/wpa_supplicant.conf -d

# Verificar senha
wpa_passphrase "SSID" "senha"

# Escanear novamente
sudo iw dev wlan0 scan | grep -E "SSID|signal"

# Tentar com outro canal
sudo iw dev wlan0 set channel 6
```

### Problema 5: DNS Não Resolve

```bash
# Verificar /etc/resolv.conf
cat /etc/resolv.conf

# Testar DNS manualmente
dig @8.8.8.8 google.com
nslookup google.com 8.8.8.8

# Configurar DNS temporariamente
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf

# Verificar se o arquivo é gerenciado
ls -la /etc/resolv.conf

# Se for link simbólico para systemd-resolved
sudo systemctl restart systemd-resolved

# Editar configuração permanente
sudo nano /etc/systemd/resolved.conf
# Adicionar:
# DNS=8.8.8.8 8.8.4.4

# Flush cache DNS
sudo systemd-resolve --flush-caches
```

### Problema 6: Rede Lenta

```bash
# Verificar velocidade da interface
sudo ethtool eth0 | grep Speed

# Verificar duplex
sudo ethtool eth0 | grep Duplex

# Verificar erros
ip -s link show eth0
sudo ethtool -S eth0 | grep -i error

# Testar velocidade
sudo apt install speedtest-cli
speedtest-cli

# Verificar MTU
ip link show eth0 | grep mtu

# Testar diferentes MTUs
sudo ip link set eth0 mtu 1400
ping -M do -s 1372 8.8.8.8
```

### Problema 7: Sem Gateway/Rota Padrão

```bash
# Verificar rotas
ip route show

# Adicionar rota padrão
sudo ip route add default via 192.168.1.1

# Verificar conectividade com gateway
ping 192.168.1.1

# Ver tabela ARP
ip neigh show
arp -a
```

### Problema 8: Firewall Bloqueando

```bash
# Verificar regras iptables
sudo iptables -L -n -v

# Limpar temporariamente (CUIDADO!)
sudo iptables -F
sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT ACCEPT

# Verificar nftables
sudo nft list ruleset

# Desabilitar firewall temporariamente
sudo systemctl stop ufw
sudo systemctl stop firewalld
```

### Script de Diagnóstico Completo

```bash
#!/bin/bash
# Script de diagnóstico de rede completo

echo "========================================="
echo "   DIAGNÓSTICO DE REDE - $(date)"
echo "========================================="

echo -e "\n[1] INTERFACES DE REDE"
echo "-----------------------------------"
ip link show

echo -e "\n[2] ENDEREÇOS IP"
echo "-----------------------------------"
ip addr show

echo -e "\n[3] TABELA DE ROTEAMENTO"
echo "-----------------------------------"
ip route show

echo -e "\n[4] DNS"
echo "-----------------------------------"
cat /etc/resolv.conf

echo -e "\n[5] GATEWAY"
echo "-----------------------------------"
GATEWAY=$(ip route | grep default | awk '{print $3}')
echo "Gateway: $GATEWAY"
if [ -n "$GATEWAY" ]; then
    ping -c 3 $GATEWAY
fi

echo -e "\n[6] CONECTIVIDADE INTERNET"
echo "-----------------------------------"
ping -c 3 8.8.8.8

echo -e "\n[7] RESOLUÇÃO DNS"
echo "-----------------------------------"
ping -c 3 google.com

echo -e "\n[8] PORTAS ABERTAS"
echo "-----------------------------------"
ss -tuln | grep LISTEN

echo -e "\n[9] CONEXÕES ATIVAS"
echo "-----------------------------------"
ss -tan state established

echo -e "\n[10] INTERFACES WIRELESS"
echo "-----------------------------------"
if command -v iw &> /dev/null; then
    iw dev
    echo ""
    rfkill list
fi

echo -e "\n[11] ESTATÍSTICAS DE ERROS"
echo "-----------------------------------"
for iface in $(ls /sys/class/net/ | grep -v lo); do
    echo "Interface: $iface"
    ip -s link show $iface | grep -E "RX|TX|errors|dropped"
    echo ""
done

echo -e "\n[12] HARDWARE DE REDE"
echo "-----------------------------------"
lspci | grep -i network
lsusb | grep -i wireless

echo -e "\n[13] MÓDULOS CARREGADOS"
echo "-----------------------------------"
lsmod | grep -E "e1000|iwl|ath|rtl|brcm"

echo "========================================="
echo "   FIM DO DIAGNÓSTICO"
echo "========================================="
```

---

## Scripts Úteis

### Script 1: Configuração Rápida Ethernet

```bash
#!/bin/bash
# quick-eth-config.sh - Configuração rápida de Ethernet

if [ "$#" -ne 4 ]; then
    echo "Uso: $0 <interface> <ip> <gateway> <netmask_bits>"
    echo "Exemplo: $0 eth0 192.168.1.100 192.168.1.1 24"
    exit 1
fi

IFACE=$1
IP=$2
GATEWAY=$3
NETMASK=$4

echo "Configurando $IFACE..."

# Limpar configuração anterior
sudo ip addr flush dev $IFACE
sudo ip route flush dev $IFACE

# Ativar interface
sudo ip link set $IFACE up

# Configurar IP
sudo ip addr add $IP/$NETMASK dev $IFACE

# Configurar gateway
sudo ip route add default via $GATEWAY dev $IFACE

# Configurar DNS
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf
echo "nameserver 8.8.4.4" | sudo tee -a /etc/resolv.conf

echo "Configuração aplicada!"
echo ""
echo "Verificando..."
ip addr show $IFACE
ip route show
ping -c 3 $GATEWAY
```

### Script 2: Conexão Wi-Fi Simplificada

```bash
#!/bin/bash
# wifi-connect.sh - Conectar em rede Wi-Fi

if [ "$#" -lt 2 ]; then
    echo "Uso: $0 <interface> <SSID> [senha]"
    echo "Exemplo: $0 wlan0 MinhaRede senha123"
    exit 1
fi

IFACE=$1
SSID=$2
PASS=$3

# Se não houver senha, rede aberta
if [ -z "$PASS" ]; then
    echo "Conectando em rede aberta: $SSID"
    sudo iw dev $IFACE connect "$SSID"
else
    # Rede com senha WPA/WPA2
    CONFIG="/tmp/wpa_temp_$$.conf"
    
    echo "Gerando configuração..."
    wpa_passphrase "$SSID" "$PASS" > $CONFIG
    
    echo "Conectando em: $SSID"
    sudo killall wpa_supplicant 2>/dev/null
    sudo ip link set $IFACE up
    sudo wpa_supplicant -B -i $IFACE -c $CONFIG
    
    sleep 3
    rm -f $CONFIG
fi

# Obter IP
echo "Obtendo IP via DHCP..."
sudo dhclient $IFACE

# Verificar
echo ""
echo "Status:"
iw dev $IFACE link
ip addr show $IFACE | grep "inet "
```

### Script 3: Monitor de Conexão

```bash
#!/bin/bash
# network-monitor.sh - Monitor de conexão em tempo real

IFACE=${1:-eth0}
INTERVAL=${2:-2}

while true; do
    clear
    echo "========================================="
    echo "   MONITOR DE REDE - $IFACE"
    echo "   $(date)"
    echo "========================================="
    
    echo -e "\n[STATUS DA INTERFACE]"
    ip link show $IFACE | head -2
    
    echo -e "\n[ENDEREÇO IP]"
    ip addr show $IFACE | grep "inet " | awk '{print $2}'
    
    echo -e "\n[GATEWAY]"
    ip route show | grep default
    
    echo -e "\n[ESTATÍSTICAS]"
    ip -s link show $IFACE | grep -A1 "RX:\|TX:"
    
    echo -e "\n[CONEXÕES ATIVAS]"
    ss -tan state established | tail -n +2 | wc -l
    
    if [[ $IFACE == wlan* ]]; then
        echo -e "\n[WI-FI INFO]"
        iw dev $IFACE link 2>/dev/null | grep -E "Connected|signal"
    fi
    
    echo -e "\n[TESTE DE PING]"
    ping -c 1 -W 1 8.8.8.8 >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "✓ Internet: OK"
    else
        echo "✗ Internet: FALHA"
    fi
    
    sleep $INTERVAL
done
```

### Script 4: Backup e Restore de Configuração

```bash
#!/bin/bash
# network-backup.sh - Backup de configuração de rede

BACKUP_DIR="/root/network-backup-$(date +%Y%m%d-%H%M%S)"

echo "Criando backup em: $BACKUP_DIR"
sudo mkdir -p $BACKUP_DIR

# Interfaces
sudo cp /etc/network/interfaces $BACKUP_DIR/ 2>/dev/null

# NetworkManager
sudo cp -r /etc/NetworkManager/system-connections/ $BACKUP_DIR/ 2>/dev/null

# systemd-networkd
sudo cp -r /etc/systemd/network/ $BACKUP_DIR/ 2>/dev/null

# WPA Supplicant
sudo cp -r /etc/wpa_supplicant/ $BACKUP_DIR/ 2>/dev/null

# DNS
sudo cp /etc/resolv.conf $BACKUP_DIR/ 2>/dev/null

# Configuração atual
ip addr show > $BACKUP_DIR/ip-addr.txt
ip route show > $BACKUP_DIR/ip-route.txt
ip link show > $BACKUP_DIR/ip-link.txt

echo "Backup concluído!"
echo "Localização: $BACKUP_DIR"
```

### Script 5: Switcher de Perfis de Rede

```bash
#!/bin/bash
# network-profile.sh - Trocar entre perfis de rede

PROFILE_DIR="/etc/network-profiles"

case $1 in
    save)
        PROFILE_NAME=$2
        if [ -z "$PROFILE_NAME" ]; then
            echo "Uso: $0 save <nome_perfil>"
            exit 1
        fi
        
        sudo mkdir -p $PROFILE_DIR/$PROFILE_NAME
        
        # Salvar configuração atual
        ip addr show > $PROFILE_DIR/$PROFILE_NAME/addr.txt
        ip route show > $PROFILE_DIR/$PROFILE_NAME/route.txt
        cp /etc/resolv.conf $PROFILE_DIR/$PROFILE_NAME/resolv.conf
        
        echo "Perfil '$PROFILE_NAME' salvo!"
        ;;
        
    load)
        PROFILE_NAME=$2
        if [ -z "$PROFILE_NAME" ]; then
            echo "Uso: $0 load <nome_perfil>"
            exit 1
        fi
        
        if [ ! -d "$PROFILE_DIR/$PROFILE_NAME" ]; then
            echo "Perfil não encontrado!"
            exit 1
        fi
        
        echo "Carregando perfil: $PROFILE_NAME"
        
        # Aplicar configuração
        # (implementar lógica de parsing e aplicação)
        
        echo "Perfil aplicado!"
        ;;
        
    list)
        echo "Perfis disponíveis:"
        ls -1 $PROFILE_DIR/ 2>/dev/null || echo "Nenhum perfil salvo"
        ;;
        
    *)
        echo "Uso: $0 {save|load|list} [nome_perfil]"
        exit 1
        ;;
esac
```

---

## Referências

### Documentação Oficial

- [Debian Network Configuration](https://wiki.debian.org/NetworkConfiguration)
- [man ip](https://man7.org/linux/man-pages/man8/ip.8.html)
- [man iw](https://wireless.wiki.kernel.org/en/users/documentation/iw)
- [NetworkManager Documentation](https://networkmanager.dev/docs/)
- [systemd-networkd](https://www.freedesktop.org/software/systemd/man/systemd.network.html)

### Comandos Importantes

```bash
# Man pages essenciais
man ip
man iw
man iwconfig
man wpa_supplicant
man nmcli
man interfaces
man systemd.network
man ethtool
```

### Arquivos de Configuração Importantes

| Arquivo/Diretório | Descrição |
|-------------------|-----------|
| `/etc/network/interfaces` | Configuração tradicional de rede |
| `/etc/NetworkManager/` | Configurações do NetworkManager |
| `/etc/systemd/network/` | Configurações do systemd-networkd |
| `/etc/wpa_supplicant/` | Configurações Wi-Fi WPA/WPA2 |
| `/etc/resolv.conf` | Servidores DNS |
| `/sys/class/net/` | Informações de interfaces (kernel) |
| `/proc/net/` | Estatísticas de rede (kernel) |

### Pacotes Úteis

```bash
# Ferramentas essenciais
sudo apt install net-tools           # ifconfig, netstat, arp
sudo apt install iproute2            # ip, ss, bridge
sudo apt install wireless-tools      # iwconfig, iwlist
sudo apt install iw                  # iw (moderno)
sudo apt install wpasupplicant       # WPA/WPA2
sudo apt install network-manager     # NetworkManager
sudo apt install ethtool             # Diagnóstico ethernet
sudo apt install rfkill              # Gerenciar RF kill switches

# Ferramentas de diagnóstico
sudo apt install dnsutils            # dig, nslookup
sudo apt install iputils-ping        # ping
sudo apt install traceroute          # traceroute
sudo apt install mtr-tiny            # mtr
sudo apt install tcpdump             # Captura de pacotes
sudo apt install nmap                # Scanner de rede

# Servidores
sudo apt install hostapd             # Access Point
sudo apt install dnsmasq             # DHCP/DNS server
```

### Links Úteis

- [Linux Wireless](https://wireless.wiki.kernel.org/)
- [WPA Supplicant Documentation](https://w1.fi/wpa_supplicant/)
- [NetworkManager Wiki](https://wiki.gnome.org/Projects/NetworkManager)
- [systemd-networkd Examples](https://www.freedesktop.org/software/systemd/man/systemd.network.html)

---

## Dicas Finais

1. **Sempre faça backup** das configurações antes de modificar
2. **Use ip em vez de ifconfig** (mais moderno e poderoso)
3. **Para Wi-Fi, use iw em vez de iwconfig** (mais completo)
4. **NetworkManager é ideal para desktops**, systemd-networkd para servidores
5. **Teste configurações temporárias** antes de torná-las permanentes
6. **Mantenha drivers atualizados** para melhor compatibilidade
7. **Documente suas configurações** personalizadas

### Troubleshooting Geral

Ao diagnosticar problemas de rede, siga esta ordem:

1. **Camada Física**: Cabo conectado? LED aceso? Driver carregado?
2. **Camada de Link**: Interface ativa? MAC address OK?
3. **Camada de Rede**: IP configurado? Gateway alcançável?
4. **Camada de Transporte**: Portas abertas? Firewall?
5. **Camada de Aplicação**: DNS resolvendo? Serviço respondendo?

---

**Autor**: Guia Técnico de Configuração de Rede  
**Sistema**: Debian GNU/Linux  
**Última Atualização**: 2025  
**Licença**: Open Source

