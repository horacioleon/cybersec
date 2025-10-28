# 🔐 Linux para Cybersecurity - Base Técnica

Documentação técnica completa de Linux focada em cybersecurity. Material prático para quem está começando ou quer aprofundar conhecimentos em administração de sistemas, redes e segurança.

[![License](https://img.shields.io/badge/license-Open%20Source-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux-orange.svg)]()
[![Status](https://img.shields.io/badge/status-Em%20Desenvolvimento-yellow.svg)]()

---

## 📋 Sobre o Projeto

Este repositório é uma **base de conhecimento técnico de Linux** voltada para profissionais e estudantes de **cybersecurity**. 

O objetivo é fornecer documentação prática, exemplos reais e scripts úteis que cobrem desde fundamentos até tópicos avançados de administração de sistemas Linux.

### Por que este projeto?

- 🎯 **Foco em Cybersecurity**: Conteúdo direcionado para segurança da informação
- 📚 **Documentação Prática**: Exemplos testados e casos de uso reais
- 🔧 **Hands-on**: Comandos, scripts e configurações prontas para usar
- 🚀 **Para Iniciantes e Avançados**: Conteúdo organizado por níveis
- 🆓 **Open Source**: Livre para estudar, usar e contribuir

---

## 📁 Estrutura do Repositório

```
cybersec/
├── README.md                    # Este arquivo
├── LICENSE                      # Licença MIT
│
└── linux/                       # Documentação Linux
    │
    ├── network/                 # ✅ Networking e Configuração de Rede
    │   ├── Modelos de Rede: OSI e TCP-IP.md
    │   ├── Protocolos de Rede - Guia Técnico para CyberSecurity.md ⭐ NOVO
    │   ├── Configuração de Rede no Linux.md
    │   ├── Ferramentas de Rede no Debian.md
    │   └── Acesso Remoto ao Linux.md
    │
    ├── storage/                 # 🚧 Armazenamento e Filesystems (em breve)
    ├── access-management/       # 🚧 Controle de Acesso e Permissões (em breve)
    ├── virtualization/          # 🚧 Virtualização e Containers (em breve)
    ├── security/                # 🚧 Segurança e Hardening (em breve)
    ├── monitoring/              # 🚧 Monitoramento e Logs (em breve)
    └── general-config/          # 🚧 Configuração Geral do Sistema (em breve)
```

**Legenda**: ✅ Disponível | 🚧 Em desenvolvimento

---

## 📚 Conteúdo Disponível

### 🌐 Networking (Disponível)

Documentação completa sobre redes no Linux focada em **cybersecurity**.

| Documento | Descrição |
|-----------|-----------|
| [Modelos OSI/TCP-IP](./linux/network/Modelos%20de%20Rede%3A%20OSI%20e%20TCP-IP.md) | Teoria + prática dos modelos de rede (camada 1-7) |
| [Protocolos de Rede](./linux/network/Protocolos%20de%20Rede%20-%20Guia%20Técnico%20para%20CyberSecurity.md) | ⭐ **NOVO!** Protocolos detalhados com foco em segurança |
| [Configuração de Rede](./linux/network/Configuração%20de%20Rede%20no%20Linux.md) | Ethernet, Wi-Fi, DHCP, IP estático, VLANs, bridges |
| [Ferramentas de Rede](./linux/network/Ferramentas%20de%20Rede%20no%20Debian.md) | 20+ ferramentas com exemplos práticos |
| [Acesso Remoto](./linux/network/Acesso%20Remoto%20ao%20Linux.md) | SSH, VNC, RDP, X11, tunneling |

[📖 Ver índice completo de Networking →](./linux/network/README.md)

---

## 🚀 Quick Start

### Instalação Básica

```bash
# Clonar repositório
git clone https://github.com/seu-usuario/cybersec.git
cd cybersec

# Instalar ferramentas essenciais de rede
sudo apt update && sudo apt install -y \
    net-tools iproute2 tcpdump nmap \
    openssh-server curl wget
```

### Comandos Essenciais para Cybersec

```bash
# Diagnóstico de rede
ip addr show                    # Ver IPs
ss -tuln                        # Portas abertas
sudo tcpdump -i any            # Capturar tráfego

# Scan básico
nmap -sn 192.168.1.0/24        # Discovery de hosts
nmap -sV 192.168.1.1           # Versões de serviços

# Acesso remoto seguro
ssh usuario@servidor            # Conectar via SSH
ssh -L 8080:localhost:80 user@host  # Port forwarding

# Análise de logs
sudo tail -f /var/log/auth.log # Logs de autenticação
sudo journalctl -u ssh         # Logs do SSH
```

---

## 🎯 Público Alvo

Este material é ideal para:

- 👨‍🎓 **Estudantes** iniciando em cybersecurity
- 🔒 **Profissionais** de segurança da informação
- 🖥️ **Sysadmins** Linux
- 🔧 **DevOps/SRE** 
- 📚 **Preparação para certificações** (LPIC, Security+, CEH)

---

## 🗺️ Roadmap

### ✅ Completo
- [x] Networking e Configuração de Rede
- [x] Ferramentas de Diagnóstico
- [x] Acesso Remoto (SSH, VNC, RDP)

### 🚧 Em Desenvolvimento
- [ ] **Storage e Filesystems**
  - Particionamento (fdisk, parted, gdisk)
  - LVM (Logical Volume Manager)
  - RAID (mdadm)
  - Filesystems (ext4, xfs, btrfs)
  - Quotas e permissões
  - Backup e recovery

- [ ] **Access Management**
  - Usuários e grupos
  - sudo e políticas
  - PAM (Pluggable Authentication Modules)
  - SELinux / AppArmor
  - SSH keys e certificados

- [ ] **Virtualização e Containers**
  - KVM/QEMU
  - Docker
  - LXC/LXD
  - Networking em containers
  - Orchestration básica

- [ ] **Segurança e Hardening**
  - Firewall (iptables, nftables, ufw)
  - Fail2ban
  - Auditd e logs
  - Hardening checklist
  - Detecção de intrusão

- [ ] **Monitoramento e Logs**
  - Syslog e journald
  - Análise de logs
  - Ferramentas de monitoramento
  - Alertas e notificações

- [ ] **Configuração Geral**
  - Boot process e systemd
  - Serviços e daemons
  - Cron e automação
  - Package management
  - Performance tuning

---

## 📖 Como Usar

### Para Iniciantes

1. **Comece por Networking** → Fundamentos essenciais
2. **Pratique os comandos** → Use VMs para testar
3. **Entenda os conceitos** → Leia a teoria de cada camada
4. **Faça os exemplos** → Todos são testáveis

### Para Estudos

- Use como material complementar para certificações
- Pratique em laboratório virtual
- Adapte os exemplos para seu cenário
- Crie seus próprios scripts baseados nos exemplos

### Para Referência Rápida

- Use `Ctrl+F` para buscar comandos específicos
- Consulte os índices de cada seção
- Copie e adapte os scripts conforme necessidade

---

## 🔧 Ambiente Recomendado

### Hardware
- **Mínimo**: 4GB RAM, 20GB disco
- **Recomendado**: 8GB RAM, 50GB disco, 2+ interfaces de rede

### Software
- **SO**: Debian 11/12, Ubuntu 22.04/24.04 LTS
- **Virtualização**: VirtualBox, VMware, KVM
- **Terminal**: qualquer shell Linux

### Setup de Lab

```bash
# Criar VM com Debian/Ubuntu
# Configurar snapshot para restore rápido
# Ter pelo menos 2 VMs para testar networking
# Isolar do ambiente de produção
```

---

## 🤝 Contribuições

Contribuições são bem-vindas! Você pode:

- 🐛 Reportar erros ou comandos desatualizados
- 💡 Sugerir novos tópicos ou melhorias
- 📝 Adicionar exemplos práticos
- 🔧 Corrigir typos e formatação

### Como Contribuir

1. Fork o projeto
2. Crie uma branch para sua feature
3. Commit suas mudanças
4. Push para a branch
5. Abra um Pull Request

---

## ⚠️ Disclaimer

- ⚙️ **Ambiente de Testes**: Sempre teste em ambiente controlado
- 📋 **Backup**: Faça backup antes de modificar configurações
- 🔒 **Segurança**: Use com responsabilidade e ética
- ⚖️ **Legal**: Apenas em sistemas que você tem autorização

---

## 📜 Licença

Este projeto está sob a licença **MIT**. Veja o arquivo [LICENSE](LICENSE) para detalhes.

---

## 🔗 Links Úteis

### Documentação
- [Debian Docs](https://www.debian.org/doc/)
- [Ubuntu Server Guide](https://ubuntu.com/server/docs)
- [Linux Man Pages](https://linux.die.net/man/)

### Certificações
- [LPIC-1](https://www.lpi.org/our-certifications/lpic-1-overview)
- [CompTIA Linux+](https://www.comptia.org/certifications/linux)
- [RHCSA](https://www.redhat.com/en/services/certification/rhcsa)

### Comunidades
- [r/linuxadmin](https://reddit.com/r/linuxadmin)
- [r/cybersecurity](https://reddit.com/r/cybersecurity)
- [Linux Questions](https://www.linuxquestions.org/)

---

<div align="center">

**Última atualização**: 2025

Feito com ❤️ para a comunidade de cybersecurity

[⬆ Voltar ao topo](#-linux-para-cybersecurity---base-técnica)

</div>
