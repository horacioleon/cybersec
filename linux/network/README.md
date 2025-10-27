# Documentação de Rede - Linux/Debian

Este diretório contém documentação técnica completa sobre networking em Linux, com foco em Debian, comandos práticos e exemplos reais.

## 📚 Documentos Disponíveis

### 1. [Modelos de Rede: OSI e TCP/IP](./Modelos%20de%20Rede%3A%20OSI%20e%20TCP-IP.md)
Guia técnico completo sobre os modelos de rede OSI (7 camadas) e TCP/IP (4 camadas), com:
- Explicação detalhada de cada camada (bottom-up: camada 1 a 7)
- Protocolos e tecnologias de cada camada
- Comandos Linux específicos para cada camada
- Exemplos práticos e casos de uso
- Comparação entre os modelos
- Troubleshooting sistemático

**Principais tópicos**:
- Camada 1 (Física): Hardware, drivers, ethtool
- Camada 2 (Enlace): MAC, Ethernet, VLANs, bridges
- Camada 3 (Rede): IP, roteamento, ICMP, ARP
- Camada 4 (Transporte): TCP, UDP, portas
- Camada 5 (Sessão): Gerenciamento de sessões
- Camada 6 (Apresentação): Criptografia, compressão
- Camada 7 (Aplicação): HTTP, DNS, SSH, FTP

### 2. [Configuração de Rede no Linux](./Configuração%20de%20Rede%20no%20Linux.md)
Guia completo sobre configuração de interfaces de rede (cabeadas e wireless) no Debian:
- Identificação de interfaces de rede
- Ferramentas modernas: `ip`, `iw`, `nmcli`
- Configuração de rede cabeada (Ethernet)
  - DHCP e IP estático
  - Bonding e VLANs
  - Bridges
- Configuração de rede sem fio (Wi-Fi)
  - WPA/WPA2 com wpa_supplicant
  - NetworkManager
  - Access Point mode
  - Monitor mode
- Configuração permanente
  - /etc/network/interfaces
  - NetworkManager
  - systemd-networkd
- Troubleshooting detalhado

### 3. [Ferramentas de Rede no Debian](./Ferramentas%20de%20Rede%20no%20Debian.md)
Documentação prática com exemplos e casos de uso de ferramentas de rede:
- **Análise e Diagnóstico**: `ip`, `ss`, `ethtool`
- **Captura de Pacotes**: `tcpdump`, `tshark`, `wireshark`
- **Testes de Conectividade**: `ping`, `traceroute`, `mtr`
- **Scan e Discovery**: `nmap`, `netcat`, `arp-scan`
- **Monitoramento**: `iftop`, `nethogs`, `vnstat`, `iptraf-ng`
- **Transferência**: `curl`, `wget`, `rsync`, `scp`
- **DNS**: `dig`, `host`, `nslookup`
- **Performance**: `iperf3`, `speedtest-cli`, `ab`
- **Segurança**: `iptables`, `nftables`, `fail2ban`
- Scripts úteis e automação

### 4. [Acesso Remoto ao Linux](./Acesso%20Remoto%20ao%20Linux.md)
Guia completo sobre todas as formas de acesso remoto a sistemas Linux:
- **SSH (Secure Shell)**
  - Configuração de servidor e cliente
  - Autenticação por chave pública
  - SSH Config file
  - Túneis e port forwarding (local, remote, dynamic)
  - SSH Agent e Agent Forwarding
  - ProxyJump e multiplexing
  - SSHFS
  - Segurança (2FA, Fail2Ban)
- **Telnet** (inseguro, apenas para testes)
- **VNC** (TightVNC, TigerVNC, x11vnc)
- **RDP** (XRDP para Linux)
- **X11 Forwarding**
- **TeamViewer e AnyDesk**
- **Console Serial**
- **Web-based**: Cockpit, Webmin, Guacamole
- Comparação de métodos
- Segurança e boas práticas

## 🎯 Público Alvo

Estes documentos são destinados a:
- Administradores de sistemas Linux
- Estudantes de redes e segurança
- Profissionais de DevOps e SRE
- Entusiastas de Linux e networking
- Preparação para certificações (LPIC, RHCE, etc.)

## 🔧 Pré-requisitos

Para aproveitar ao máximo este material:
- Conhecimento básico de Linux
- Acesso a um sistema Debian/Ubuntu (físico ou VM)
- Permissões sudo/root para executar comandos
- Ambiente de testes (recomendado usar VMs)

## 📖 Como Usar

### Para Iniciantes
1. Comece com "Modelos de Rede: OSI e TCP/IP" para entender os fundamentos
2. Pratique com "Configuração de Rede no Linux" para configurar sua primeira interface
3. Explore "Ferramentas de Rede" para conhecer as principais ferramentas
4. Aprenda "Acesso Remoto" para conectar-se a sistemas remotos

### Para Intermediários/Avançados
- Use como referência rápida para comandos específicos
- Consulte os exemplos práticos e scripts
- Adapte os scripts para suas necessidades
- Explore as seções de troubleshooting

### Para Troubleshooting
1. Use a metodologia bottom-up (camada 1 a 7)
2. Consulte os scripts de diagnóstico automatizado
3. Verifique os problemas comuns e soluções

## 🛠️ Instalação de Ferramentas

Instalar todas as ferramentas mencionadas nos documentos:

```bash
# Atualizar sistema
sudo apt update && sudo apt upgrade -y

# Ferramentas básicas
sudo apt install -y net-tools iproute2 iputils-ping dnsutils

# Análise e captura
sudo apt install -y tcpdump wireshark tshark nmap netcat-openbsd

# Monitoramento
sudo apt install -y iftop nethogs iptraf-ng vnstat bmon

# Wireless
sudo apt install -y wireless-tools wpasupplicant iw rfkill

# Performance
sudo apt install -y iperf3 mtr-tiny speedtest-cli

# Transferência
sudo apt install -y curl wget rsync

# Acesso remoto
sudo apt install -y openssh-server openssh-client

# Outros
sudo apt install -y ethtool bridge-utils vlan ngrep arp-scan socat hping3
```

## 🔗 Links Úteis

### Documentação Oficial
- [Debian Network Configuration](https://wiki.debian.org/NetworkConfiguration)
- [OpenSSH Manual](https://www.openssh.com/manual.html)
- [Linux Networking Guide](https://www.tldp.org/LDP/nag2/)

### RFCs Importantes
- [RFC 791 - Internet Protocol](https://tools.ietf.org/html/rfc791)
- [RFC 793 - TCP](https://tools.ietf.org/html/rfc793)
- [RFC 768 - UDP](https://tools.ietf.org/html/rfc768)
- [RFC 792 - ICMP](https://tools.ietf.org/html/rfc792)

### Man Pages
```bash
man ip
man ss
man tcpdump
man ssh
man iptables
```

## 📝 Convenções

### Comandos
- `$` indica prompt de usuário normal
- `#` ou `sudo` indica necessidade de privilégios root
- Comandos entre `[]` são opcionais
- Comandos entre `<>` devem ser substituídos por valores reais

### Exemplos
- Endereços IP nos exemplos: 192.168.1.x, 10.0.0.x (ranges privados)
- Interfaces: eth0, wlan0, enp0s3 (ajustar conforme seu sistema)
- Domínios: example.com, test.local

## ⚠️ Avisos Importantes

1. **Ambiente de Testes**: Sempre teste comandos em ambiente controlado antes de usar em produção
2. **Backup**: Faça backup de arquivos de configuração antes de modificá-los
3. **Segurança**: Alguns exemplos são para fins educacionais - use com responsabilidade
4. **Permissões**: Muitos comandos requerem root/sudo
5. **Firewall**: Cuidado ao modificar regras de firewall em sistemas remotos

## 🤝 Contribuições

Sugestões de melhorias são bem-vindas:
- Reportar erros ou comandos desatualizados
- Sugerir novos exemplos práticos
- Adicionar casos de uso específicos
- Melhorar explicações

## 📜 Licença

Open Source - Livre para uso educacional e profissional

---

## 📊 Resumo Rápido

| Documento | Páginas | Foco | Nível |
|-----------|---------|------|-------|
| Modelos OSI/TCP-IP | ~1460 linhas | Teoria + Prática | Todos |
| Configuração de Rede | ~1730 linhas | Configuração | Intermediário |
| Ferramentas de Rede | ~1700 linhas | Ferramentas | Intermediário/Avançado |
| Acesso Remoto | ~1500 linhas | SSH, VNC, RDP | Todos |

## 🚀 Quick Start

```bash
# 1. Verificar interface de rede
ip addr show

# 2. Testar conectividade
ping -c 4 8.8.8.8

# 3. Ver rotas
ip route show

# 4. Testar DNS
dig google.com

# 5. Ver portas abertas
sudo ss -tlnp

# 6. Conectar via SSH
ssh user@hostname
```

---

**Última Atualização**: 2025  
**Autor**: Documentação Técnica de Cybersecurity  
**Sistema**: Debian GNU/Linux

