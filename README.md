# 🔐 Cybersecurity & Linux Networking - Documentação Técnica

Repositório de documentação técnica sobre cybersecurity, networking, e administração de sistemas Linux, com foco em exemplos práticos e casos de uso reais.

[![License](https://img.shields.io/badge/license-Open%20Source-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Debian-orange.svg)]()
[![Status](https://img.shields.io/badge/status-Active-green.svg)]()

## 📋 Índice

- [Sobre o Projeto](#sobre-o-projeto)
- [Estrutura do Repositório](#estrutura-do-repositório)
- [Documentação Disponível](#documentação-disponível)
- [Quick Start](#quick-start)
- [Pré-requisitos](#pré-requisitos)
- [Instalação](#instalação)
- [Como Contribuir](#como-contribuir)
- [Roadmap](#roadmap)
- [Licença](#licença)

---

## 🎯 Sobre o Projeto

Este repositório é uma coleção abrangente de documentação técnica focada em:

- **Networking**: Protocolos, configuração, troubleshooting
- **Linux System Administration**: Comandos, ferramentas, automação
- **Cybersecurity**: Boas práticas, ferramentas, metodologias
- **Acesso Remoto**: SSH, VNC, RDP e outras tecnologias

### Objetivos

✅ Fornecer documentação técnica de alta qualidade  
✅ Exemplos práticos e testados  
✅ Scripts e automações úteis  
✅ Referência rápida para profissionais  
✅ Material de estudo para certificações  
✅ Base de conhecimento para troubleshooting  

---

## 📁 Estrutura do Repositório

```
cybersec/
├── README.md                          # Este arquivo
├── LICENSE                            # Licença do projeto
│
└── linux/                             # Documentação Linux
    └── network/                       # Networking e Configuração de Rede
        ├── README.md                  # Índice da seção de networking
        ├── Modelos de Rede: OSI e TCP-IP.md
        ├── Configuração de Rede no Linux.md
        ├── Ferramentas de Rede no Debian.md
        └── Acesso Remoto ao Linux.md
```

---

## 📚 Documentação Disponível

### 🌐 Linux Networking

Documentação completa sobre networking em Linux/Debian com mais de **6000 linhas** de conteúdo técnico.

#### 1. [Modelos de Rede: OSI e TCP/IP](./linux/network/Modelos%20de%20Rede%3A%20OSI%20e%20TCP-IP.md)
**~1600 linhas** | Nível: Todos | ⭐⭐⭐⭐⭐

Guia técnico completo sobre os modelos de rede com abordagem bottom-up (camada 1 → 7):

- **Modelo OSI (7 Camadas)**:
  - Camada 1 (Física): Hardware, drivers, ethtool
  - Camada 2 (Enlace): MAC, Ethernet, VLANs, bridges
  - Camada 3 (Rede): IP, roteamento, ICMP, ARP
  - Camada 4 (Transporte): TCP, UDP, portas, conexões
  - Camada 5 (Sessão): Gerenciamento de sessões
  - Camada 6 (Apresentação): Criptografia, codificação, compressão
  - Camada 7 (Aplicação): HTTP, DNS, SSH, FTP, SMTP

- **Modelo TCP/IP (4 Camadas)**:
  - Acesso à Rede, Internet, Transporte, Aplicação

- **Conteúdo**:
  - Comandos Linux específicos por camada
  - 10+ exemplos práticos completos
  - Scripts de diagnóstico e monitoramento
  - Metodologia de troubleshooting bottom-up
  - Comparação detalhada entre modelos

**Ideal para**: Fundamentos de rede, preparação para certificações, troubleshooting sistemático

---

#### 2. [Configuração de Rede no Linux](./linux/network/Configuração%20de%20Rede%20no%20Linux.md)
**~1730 linhas** | Nível: Intermediário | ⭐⭐⭐⭐⭐

Manual completo de configuração de interfaces de rede (wired e wireless) no Debian:

- **Rede Cabeada (Ethernet)**:
  - Configuração DHCP e IP estático
  - Bonding (Link Aggregation)
  - VLANs (802.1Q)
  - Bridges
  - MTU, velocidade, duplex

- **Rede Sem Fio (Wi-Fi)**:
  - WPA/WPA2 com wpa_supplicant
  - NetworkManager (nmcli, nmtui)
  - Access Point mode
  - Monitor mode
  - Troubleshooting de conexões

- **Configuração Permanente**:
  - /etc/network/interfaces
  - NetworkManager
  - systemd-networkd
  - Scripts personalizados

- **Ferramentas**: `ip`, `iw`, `nmcli`, `ethtool`, `iwconfig`

**Ideal para**: Configurar servidores, workstations, pontos de acesso

---

#### 3. [Ferramentas de Rede no Debian](./linux/network/Ferramentas%20de%20Rede%20no%20Debian.md)
**~1700 linhas** | Nível: Intermediário/Avançado | ⭐⭐⭐⭐⭐

Guia prático com exemplos e casos de uso de 20+ ferramentas essenciais:

- **Análise e Diagnóstico**:
  - `ip` - Configuração moderna de rede
  - `ss` - Socket statistics
  - `ethtool` - Diagnóstico Ethernet

- **Captura de Pacotes**:
  - `tcpdump` - Captura em linha de comando
  - `wireshark`/`tshark` - Análise avançada
  - `ngrep` - Grep para rede

- **Testes de Conectividade**:
  - `ping`, `traceroute`, `mtr`
  - Análise de latência e jitter
  - Descoberta de MTU

- **Scan e Discovery**:
  - `nmap` - Network scanner
  - `netcat` - Swiss Army knife
  - `arp-scan` - Discovery por ARP

- **Monitoramento**:
  - `iftop`, `nethogs`, `vnstat`
  - Estatísticas em tempo real
  - Logs históricos

- **Transferência**:
  - `curl`, `wget`, `rsync`
  - Automação de downloads
  - Backups incrementais

- **Performance**:
  - `iperf3` - Teste de throughput
  - `speedtest-cli` - Velocidade da internet
  - Benchmarks de rede

**Ideal para**: Diagnóstico de problemas, monitoramento, automação

---

#### 4. [Acesso Remoto ao Linux](./linux/network/Acesso%20Remoto%20ao%20Linux.md)
**~1500 linhas** | Nível: Todos | ⭐⭐⭐⭐⭐

Guia completo sobre todas as formas de acesso remoto a sistemas Linux:

- **SSH (Secure Shell)** - ⭐ Principal:
  - Configuração de servidor e cliente OpenSSH
  - Autenticação por chave pública (RSA, Ed25519)
  - SSH Config file (~/.ssh/config)
  - Port Forwarding (Local, Remote, Dynamic)
  - SOCKS Proxy via SSH
  - SSH Agent e Agent Forwarding
  - ProxyJump e Multiplexing
  - SSHFS - Filesystem remoto
  - Two-Factor Authentication (2FA)
  - Fail2Ban e hardening

- **Acesso Gráfico**:
  - VNC (TightVNC, TigerVNC, x11vnc)
  - RDP (XRDP para Linux)
  - X11 Forwarding
  - TeamViewer e AnyDesk

- **Outros Métodos**:
  - Telnet (legado, inseguro)
  - Console Serial
  - Web-based (Cockpit, Webmin, Guacamole)

- **Segurança**:
  - Boas práticas
  - Checklist de hardening
  - Comparação de métodos

**Ideal para**: Administração remota, suporte técnico, automação

---

## 🚀 Quick Start

### Comandos Essenciais

```bash
# 1. Verificar interface de rede
ip addr show
ip link show

# 2. Testar conectividade
ping -c 4 8.8.8.8
ping -c 4 google.com

# 3. Ver rotas e gateway
ip route show

# 4. Testar DNS
dig google.com
nslookup google.com

# 5. Ver conexões ativas
ss -tan
sudo ss -tlnp

# 6. Conectar via SSH
ssh usuario@servidor

# 7. Capturar tráfego
sudo tcpdump -i eth0

# 8. Scan de rede
nmap -sn 192.168.1.0/24

# 9. Monitor de banda
sudo iftop -i eth0

# 10. Teste de velocidade
iperf3 -c servidor
```

### Troubleshooting Rápido

```bash
# Diagnóstico bottom-up (camada por camada)

# Camada 1 - Física
ethtool eth0 | grep "Link detected"

# Camada 2 - Enlace
ip link show eth0
ip -s link show eth0

# Camada 3 - Rede
ip addr show
ip route show
ping -c 4 192.168.1.1  # Gateway

# Camada 4 - Transporte
ss -tuln | grep LISTEN

# Camada 7 - Aplicação
curl -I https://google.com
```

---

## 🔧 Pré-requisitos

### Sistema Operacional
- Linux (Debian, Ubuntu, ou derivados recomendados)
- Kernel 4.x ou superior
- Permissões sudo/root

### Conhecimentos
- Básico de Linux (terminal, comandos básicos)
- Conceitos de rede (IP, portas, protocolos)
- Editor de texto (vim, nano)

### Hardware
- Placa de rede cabeada ou wireless
- Mínimo 2GB RAM (para VMs)
- 10GB espaço em disco

---

## 📥 Instalação

### Clonar Repositório

```bash
git clone https://github.com/seu-usuario/cybersec.git
cd cybersec
```

### Instalar Ferramentas

```bash
# Atualizar sistema
sudo apt update && sudo apt upgrade -y

# Ferramentas essenciais de rede
sudo apt install -y \
    net-tools iproute2 iputils-ping \
    dnsutils traceroute mtr-tiny \
    tcpdump nmap netcat-openbsd \
    curl wget rsync \
    openssh-server openssh-client \
    ethtool wireless-tools wpasupplicant \
    iftop nethogs vnstat iperf3

# Ferramentas avançadas
sudo apt install -y \
    wireshark tshark ngrep \
    arp-scan socat hping3 \
    bridge-utils vlan \
    speedtest-cli
```

### Configurar SSH

```bash
# Gerar chave SSH
ssh-keygen -t ed25519 -C "seu-email@example.com"

# Copiar chave para servidor
ssh-copy-id usuario@servidor

# Testar conexão
ssh usuario@servidor
```

---

## 🎓 Casos de Uso

### Para Estudantes
- Material de estudo para certificações (LPIC, RHCE, CCNA)
- Laboratórios práticos de rede
- Preparação para entrevistas técnicas

### Para Profissionais
- Referência rápida de comandos
- Troubleshooting de problemas de rede
- Scripts de automação
- Documentação de infraestrutura

### Para DevOps/SRE
- Automação de configuração de rede
- Monitoramento e alertas
- Diagnóstico de performance
- Integração CI/CD

### Para Cybersecurity
- Análise de tráfego de rede
- Detecção de anomalias
- Hardening de SSH
- Configuração de firewalls

---

## 📖 Como Usar a Documentação

### Navegação por Nível

**Iniciante**:
1. Modelos de Rede (fundamentos)
2. Configuração de Rede (prática básica)
3. Acesso Remoto (SSH básico)

**Intermediário**:
1. Ferramentas de Rede (diagnóstico)
2. Configuração Avançada (VLANs, bonding)
3. SSH Avançado (túneis, forwarding)

**Avançado**:
1. Scripts de automação
2. Troubleshooting complexo
3. Otimização de performance
4. Segurança avançada

### Busca Rápida

Use `Ctrl+F` nos documentos para encontrar:
- Comandos específicos
- Protocolos
- Problemas comuns
- Exemplos práticos

---

## 🤝 Como Contribuir

Contribuições são bem-vindas! Você pode:

1. **Reportar Issues**:
   - Erros na documentação
   - Comandos desatualizados
   - Links quebrados

2. **Sugerir Melhorias**:
   - Novos exemplos práticos
   - Casos de uso específicos
   - Scripts úteis

3. **Adicionar Conteúdo**:
   - Novos documentos
   - Seções específicas
   - Traduções

### Guidelines

- Use Markdown para formatação
- Teste todos os comandos antes de submeter
- Mantenha a estrutura existente
- Adicione exemplos práticos
- Documente casos de uso

---

## 🗺️ Roadmap

### Em Desenvolvimento

- [ ] **Segurança Linux**
  - Firewall (iptables, nftables)
  - SELinux / AppArmor
  - Auditoria e logs
  - IDS/IPS

- [ ] **Serviços de Rede**
  - DNS (bind9, dnsmasq)
  - DHCP Server
  - Web Servers (Apache, Nginx)
  - Proxy (Squid, HAProxy)

- [ ] **Virtualização e Containers**
  - KVM/QEMU
  - Docker networking
  - Kubernetes networking
  - Network namespaces

- [ ] **VPN e Túneis**
  - OpenVPN
  - WireGuard
  - IPSec
  - SSH Tunneling avançado

- [ ] **Monitoramento e Logging**
  - Prometheus + Grafana
  - ELK Stack
  - Netflow/sFlow
  - SNMP

### Planejado para o Futuro

- [ ] Scripting e Automação (Bash, Python)
- [ ] Certificações (guias de estudo)
- [ ] Laboratórios práticos (VMs configuradas)
- [ ] Vídeos tutoriais
- [ ] Cheat sheets em PDF

---

## 📊 Estatísticas

| Categoria | Documentos | Linhas | Status |
|-----------|------------|--------|--------|
| Networking | 4 | ~6500 | ✅ Completo |
| Configuração | 1 | ~1730 | ✅ Completo |
| Ferramentas | 1 | ~1700 | ✅ Completo |
| Acesso Remoto | 1 | ~1500 | ✅ Completo |
| **Total** | **4** | **~6500** | **✅** |

---

## 🔗 Links Úteis

### Documentação Oficial
- [Debian Networking](https://wiki.debian.org/NetworkConfiguration)
- [OpenSSH Manual](https://www.openssh.com/manual.html)
- [Linux Networking Guide](https://www.tldp.org/LDP/nag2/)
- [Man Pages Online](https://linux.die.net/man/)

### RFCs Importantes
- [RFC 791 - Internet Protocol](https://tools.ietf.org/html/rfc791)
- [RFC 793 - TCP](https://tools.ietf.org/html/rfc793)
- [RFC 768 - UDP](https://tools.ietf.org/html/rfc768)
- [RFC 792 - ICMP](https://tools.ietf.org/html/rfc792)

### Ferramentas Online
- [Subnet Calculator](https://www.subnet-calculator.com/)
- [IP Lookup](https://www.whatismyip.com/)
- [DNS Lookup](https://www.nslookup.io/)
- [Port Checker](https://www.yougetsignal.com/tools/open-ports/)

### Comunidades
- [r/linux](https://reddit.com/r/linux)
- [r/networking](https://reddit.com/r/networking)
- [Stack Overflow](https://stackoverflow.com/questions/tagged/linux)
- [Unix & Linux Stack Exchange](https://unix.stackexchange.com/)

---

## 📝 Convenções

### Formatação de Comandos

```bash
# Prompt de usuário normal
$ comando

# Comando com privilégios root
sudo comando
# ou
# comando

# Variáveis (substituir por valores reais)
<variavel>

# Parâmetros opcionais
[parametro_opcional]

# Múltiplas opções
{opcao1|opcao2|opcao3}
```

### Exemplos de IP e Domínios

- **IPs Privados**: 192.168.1.x, 10.0.0.x, 172.16.0.x
- **IPs Públicos Exemplo**: 203.0.113.x, 198.51.100.x
- **Domínios**: example.com, test.local, lab.internal

### Interfaces de Rede

- **Ethernet**: eth0, enp0s3, ens33
- **Wireless**: wlan0, wlp2s0
- **Loopback**: lo

---

## ⚠️ Avisos e Disclaimers

### Segurança

⚠️ **ATENÇÃO**: 
- Alguns exemplos são para fins educacionais
- Sempre obtenha autorização antes de testar em redes que não são suas
- Use com responsabilidade e ética
- Não use para atividades ilegais

### Ambiente de Testes

✅ **RECOMENDADO**:
- Use VMs para testes (VirtualBox, VMware, KVM)
- Configure um laboratório isolado
- Faça backup antes de modificar configurações
- Documente suas alterações

### Produção

🔴 **CUIDADO**:
- Teste comandos em ambiente controlado primeiro
- Faça backup de arquivos de configuração
- Tenha um plano de rollback
- Evite modificar sistemas críticos sem planejamento

---

## 📜 Licença

Este projeto está sob a licença **Open Source**. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.

**Você pode**:
- ✅ Usar para fins educacionais
- ✅ Usar para fins profissionais
- ✅ Modificar e adaptar
- ✅ Compartilhar e distribuir

**Você deve**:
- 📄 Manter a atribuição
- 🔗 Referenciar o projeto original

---

## 👤 Autor

**Autor:** Horacio Andrés León Encina

- 📧 **Email:** horacio.leon@gmail.com
- 🌐 **GitHub:** [@horacioleon](https://github.com/horacioleon)
- 💼 **LinkedIn:** [in/horacioleonencina](https://www.linkedin.com/in/horacioleonencina)

## 🙏 Agradecimentos

- Comunidade Linux e Open Source
- Desenvolvedores das ferramentas documentadas
- Contribuidores do projeto
- Todos que compartilham conhecimento

---

## 📞 Suporte

Se você tiver dúvidas ou precisar de ajuda:

1. 📖 Consulte a documentação relevante
2. 🔍 Use a função de busca (Ctrl+F)
3. 💬 Abra uma Issue no GitHub
4. 📧 Entre em contato por email

---

## ⭐ Se este projeto foi útil

- Dê uma estrela no GitHub ⭐
- Compartilhe com colegas 📢
- Contribua com melhorias 🤝
- Forneça feedback 💬

---

<div align="center">

**[⬆ Voltar ao topo](#-cybersecurity--linux-networking---documentação-técnica)**

---

Feito com ❤️ para a comunidade de cybersecurity e Linux

**Última atualização**: 2025

</div>
