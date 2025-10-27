# Acesso Remoto ao Linux - Guia Completo

## Índice
1. [Introdução](#introdução)
2. [SSH - Secure Shell](#ssh---secure-shell)
3. [Telnet](#telnet)
4. [VNC - Virtual Network Computing](#vnc---virtual-network-computing)
5. [RDP - Remote Desktop Protocol](#rdp---remote-desktop-protocol)
6. [X11 Forwarding](#x11-forwarding)
7. [TeamViewer e AnyDesk](#teamviewer-e-anydesk)
8. [Console Serial](#console-serial)
9. [Web-Based Access](#web-based-access)
10. [Comparação de Métodos](#comparação-de-métodos)
11. [Segurança](#segurança)
12. [Troubleshooting](#troubleshooting)

---

## Introdução

Este guia apresenta todas as formas de acessar um sistema Linux remotamente, desde as mais seguras e modernas (SSH) até as legadas (Telnet), cobrindo também soluções gráficas e especializadas.

### Requisitos Gerais

```bash
# Atualizar sistema
sudo apt update && sudo apt upgrade -y

# Ferramentas básicas de rede
sudo apt install -y net-tools iproute2 openssh-server
```

---

## SSH - Secure Shell

**SSH** é o protocolo padrão para acesso remoto seguro em sistemas Unix/Linux. Oferece criptografia forte e várias funcionalidades avançadas.

### Instalação e Configuração

#### Servidor SSH (OpenSSH)

```bash
# Instalar servidor SSH
sudo apt install openssh-server

# Verificar status
sudo systemctl status ssh

# Habilitar no boot
sudo systemctl enable ssh

# Iniciar serviço
sudo systemctl start ssh

# Verificar se está escutando na porta 22
sudo ss -tlnp | grep :22
```

#### Cliente SSH

```bash
# Instalar cliente (geralmente já vem instalado)
sudo apt install openssh-client

# Verificar versão
ssh -V
```

### Configuração do Servidor SSH

```bash
# Editar arquivo de configuração
sudo nano /etc/ssh/sshd_config
```

**Configurações Importantes**:
```conf
# Porta SSH (padrão: 22)
Port 22

# Permitir login root (recomendado: no)
PermitRootLogin no

# Autenticação por senha
PasswordAuthentication yes

# Autenticação por chave pública
PubkeyAuthentication yes

# X11 Forwarding
X11Forwarding yes

# Limite de tentativas de autenticação
MaxAuthTries 3

# Tempo máximo para autenticação (segundos)
LoginGraceTime 60

# Manter conexão ativa
ClientAliveInterval 60
ClientAliveCountMax 3

# Permitir apenas usuários específicos
AllowUsers usuario1 usuario2

# Negar usuários específicos
DenyUsers usuario3

# Banner de boas-vindas
Banner /etc/ssh/banner.txt
```

```bash
# Reiniciar SSH após mudanças
sudo systemctl restart ssh

# Verificar configuração
sudo sshd -t
```

### Uso Básico do Cliente SSH

#### Conexão Simples

```bash
# Conectar como usuário atual
ssh hostname

# Conectar como usuário específico
ssh usuario@hostname

# Especificar IP
ssh usuario@192.168.1.100

# Especificar porta
ssh -p 2222 usuario@hostname

# Verbose (debug)
ssh -v usuario@hostname
ssh -vv usuario@hostname  # Mais detalhado
ssh -vvv usuario@hostname # Máximo detalhe
```

#### Executar Comandos Remotos

```bash
# Executar comando único
ssh usuario@hostname 'ls -la'

# Múltiplos comandos
ssh usuario@hostname 'uptime; free -h; df -h'

# Comando com output local
ssh usuario@hostname 'cat /etc/passwd' > usuarios.txt

# Comando interativo
ssh -t usuario@hostname 'sudo apt update && sudo apt upgrade'
```

#### Copiar Arquivos (scp)

```bash
# Copiar arquivo local para remoto
scp arquivo.txt usuario@hostname:/caminho/destino/

# Copiar arquivo remoto para local
scp usuario@hostname:/caminho/arquivo.txt .

# Copiar diretório recursivamente
scp -r /diretorio usuario@hostname:/destino/

# Preservar atributos
scp -p arquivo.txt usuario@hostname:/destino/

# Especificar porta
scp -P 2222 arquivo.txt usuario@hostname:/destino/

# Mostrar progresso
scp -v arquivo.txt usuario@hostname:/destino/

# Limitar largura de banda (KB/s)
scp -l 1000 arquivo.txt usuario@hostname:/destino/
```

#### Transferência com rsync via SSH

```bash
# Sincronizar diretório
rsync -avz -e ssh /local/ usuario@hostname:/remoto/

# Dry-run (simular)
rsync -avzn -e ssh /local/ usuario@hostname:/remoto/

# Mostrar progresso
rsync -avzh --progress -e ssh /local/ usuario@hostname:/remoto/

# Deletar arquivos no destino
rsync -avz --delete -e ssh /local/ usuario@hostname:/remoto/

# Especificar porta SSH
rsync -avz -e "ssh -p 2222" /local/ usuario@hostname:/remoto/
```

### Autenticação por Chave Pública

#### Gerar Par de Chaves

```bash
# Gerar chave RSA (padrão, 3072 bits)
ssh-keygen

# Gerar chave RSA com 4096 bits
ssh-keygen -t rsa -b 4096

# Gerar chave Ed25519 (mais moderna e segura)
ssh-keygen -t ed25519

# Gerar com comentário
ssh-keygen -t ed25519 -C "meu-computador-2025"

# Especificar local e nome
ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa_trabalho

# Sem passphrase (NÃO RECOMENDADO para uso geral)
ssh-keygen -t rsa -b 4096 -N ""
```

#### Copiar Chave Pública para Servidor

```bash
# Método 1: ssh-copy-id (recomendado)
ssh-copy-id usuario@hostname

# Especificar chave
ssh-copy-id -i ~/.ssh/id_ed25519.pub usuario@hostname

# Especificar porta
ssh-copy-id -p 2222 usuario@hostname

# Método 2: Manual
cat ~/.ssh/id_rsa.pub | ssh usuario@hostname 'mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys'

# Método 3: scp
scp ~/.ssh/id_rsa.pub usuario@hostname:~/.ssh/authorized_keys

# Método 4: Copiar e colar conteúdo
cat ~/.ssh/id_rsa.pub
# Copiar output e colar no servidor em ~/.ssh/authorized_keys
```

#### Configurar Permissões Corretas

```bash
# No servidor
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
chmod 600 ~/.ssh/id_rsa
chmod 644 ~/.ssh/id_rsa.pub
```

#### Testar Autenticação por Chave

```bash
# Conectar (não deve pedir senha)
ssh usuario@hostname

# Forçar uso de chave específica
ssh -i ~/.ssh/id_ed25519 usuario@hostname
```

### SSH Config File

Criar arquivo `~/.ssh/config` para simplificar conexões:

```conf
# Servidor de produção
Host prod
    HostName 203.0.113.10
    User admin
    Port 2222
    IdentityFile ~/.ssh/id_rsa_prod

# Servidor de desenvolvimento
Host dev
    HostName 192.168.1.100
    User developer
    IdentityFile ~/.ssh/id_rsa_dev
    ForwardX11 yes

# Bastion/Jump host
Host bastion
    HostName bastion.example.com
    User jumpuser
    IdentityFile ~/.ssh/id_rsa

# Servidor interno via bastion
Host interno
    HostName 10.0.1.50
    User admin
    ProxyJump bastion

# Configurações globais
Host *
    ServerAliveInterval 60
    ServerAliveCountMax 3
    Compression yes
```

Usar configurações:
```bash
# Conectar usando alias
ssh prod
ssh dev
ssh interno  # Automaticamente via bastion
```

### Túneis SSH (Port Forwarding)

#### Local Port Forwarding

Acessa serviço remoto através de porta local.

```bash
# Sintaxe: ssh -L [local_port]:[remote_host]:[remote_port] [user@ssh_server]

# Exemplo: Acessar banco de dados remoto
ssh -L 3306:localhost:3306 usuario@servidor

# Agora conectar localmente:
mysql -h 127.0.0.1 -P 3306 -u user -p

# Múltiplos forwards
ssh -L 3306:db.local:3306 -L 8080:web.local:80 usuario@servidor

# Manter em background
ssh -fN -L 3306:localhost:3306 usuario@servidor
```

**Caso Prático**: Acessar servidor web interno
```bash
# Servidor web roda na porta 80 no servidor remoto
ssh -L 8080:localhost:80 usuario@servidor

# Acessar no navegador local:
# http://localhost:8080
```

#### Remote Port Forwarding

Expõe serviço local para rede remota.

```bash
# Sintaxe: ssh -R [remote_port]:[local_host]:[local_port] [user@ssh_server]

# Exemplo: Expor servidor local na porta 3000
ssh -R 8080:localhost:3000 usuario@servidor

# Agora o servidor remoto pode acessar:
curl http://localhost:8080

# Permitir acesso de qualquer IP (no servidor SSH, configurar GatewayPorts yes)
ssh -R 0.0.0.0:8080:localhost:3000 usuario@servidor
```

**Caso Prático**: Mostrar aplicação local para cliente remoto
```bash
# Sua aplicação roda em localhost:3000
ssh -R 8080:localhost:3000 usuario@servidor-publico

# Cliente pode acessar:
# http://servidor-publico:8080
```

#### Dynamic Port Forwarding (SOCKS Proxy)

Cria proxy SOCKS local que roteia todo tráfego via SSH.

```bash
# Criar proxy SOCKS na porta 1080
ssh -D 1080 usuario@servidor

# Usar com curl
curl --socks5 localhost:1080 https://ifconfig.me

# Configurar navegador:
# Proxy SOCKS5: localhost
# Porta: 1080

# Firefox via CLI
firefox -no-remote -P socks &
```

**Caso Prático**: Navegar com segurança em rede pública
```bash
# Criar túnel
ssh -D 1080 -C -N usuario@servidor-seguro

# -D 1080: SOCKS proxy na porta 1080
# -C: Compressão
# -N: Não executar comando remoto

# Configurar sistema operacional ou navegador para usar proxy SOCKS5 localhost:1080
```

### SSH Agent e Agent Forwarding

#### SSH Agent

Gerencia chaves privadas na memória, evitando digitar passphrase repetidamente.

```bash
# Iniciar agent
eval $(ssh-agent)

# Adicionar chave
ssh-add ~/.ssh/id_rsa

# Adicionar todas as chaves
ssh-add

# Listar chaves carregadas
ssh-add -l

# Remover chave
ssh-add -d ~/.ssh/id_rsa

# Remover todas as chaves
ssh-add -D

# Matar agent
ssh-agent -k
```

#### Agent Forwarding

Permite usar chaves locais em servidores intermediários.

```bash
# Conectar com agent forwarding
ssh -A usuario@servidor

# No servidor, pode usar suas chaves locais
ssh outro-servidor

# Configurar no ~/.ssh/config
Host servidor
    ForwardAgent yes
```

**CUIDADO**: Apenas use agent forwarding em servidores confiáveis!

### SSH Jump Host (ProxyJump)

Acessar servidor através de um intermediário.

```bash
# Método 1: ProxyJump (OpenSSH 7.3+)
ssh -J usuario@bastion usuario@servidor-interno

# Múltiplos jumps
ssh -J usuario@bastion1,usuario@bastion2 usuario@servidor-final

# Método 2: ProxyCommand (versões antigas)
ssh -o ProxyCommand="ssh -W %h:%p usuario@bastion" usuario@servidor-interno

# Método 3: No ~/.ssh/config
Host servidor-interno
    HostName 10.0.1.50
    User admin
    ProxyJump usuario@bastion
```

### SSH Multiplexing

Reutilizar conexão SSH existente para novas sessões.

Configurar em `~/.ssh/config`:
```conf
Host *
    ControlMaster auto
    ControlPath ~/.ssh/sockets/%r@%h-%p
    ControlPersist 600
```

```bash
# Criar diretório para sockets
mkdir -p ~/.ssh/sockets

# Primeira conexão cria o master
ssh usuario@servidor

# Próximas conexões são instantâneas
ssh usuario@servidor
scp arquivo.txt usuario@servidor:/tmp/
```

### SSH Escape Sequences

Durante uma sessão SSH ativa:

- `~.` - Desconectar
- `~^Z` - Background SSH
- `~#` - Listar conexões forwarded
- `~?` - Listar escape sequences disponíveis
- `~C` - Abrir linha de comando SSH

### SSHFS - Montar Filesystem Remoto

```bash
# Instalar
sudo apt install sshfs

# Montar filesystem remoto
sshfs usuario@servidor:/caminho/remoto /mnt/ponto-montagem

# Com opções
sshfs usuario@servidor:/remoto /mnt/local -o allow_other,default_permissions

# Desmontar
fusermount -u /mnt/ponto-montagem

# Montar automaticamente no boot (em /etc/fstab)
usuario@servidor:/remoto /mnt/local fuse.sshfs defaults,_netdev,allow_other 0 0
```

### Segurança do SSH

#### Desabilitar Autenticação por Senha

```bash
# Editar /etc/ssh/sshd_config
sudo nano /etc/ssh/sshd_config

# Configurar
PasswordAuthentication no
ChallengeResponseAuthentication no

# Reiniciar SSH
sudo systemctl restart ssh
```

#### Mudar Porta Padrão

```bash
# Editar /etc/ssh/sshd_config
Port 2222

# Reiniciar SSH
sudo systemctl restart ssh

# Conectar na nova porta
ssh -p 2222 usuario@servidor
```

#### Usar Fail2Ban

```bash
# Instalar
sudo apt install fail2ban

# Configurar
sudo nano /etc/fail2ban/jail.local
```

Conteúdo:
```ini
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600
```

```bash
# Iniciar e habilitar
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

# Ver status
sudo fail2ban-client status sshd
```

#### Two-Factor Authentication (2FA)

```bash
# Instalar Google Authenticator
sudo apt install libpam-google-authenticator

# Configurar para seu usuário
google-authenticator

# Editar /etc/pam.d/sshd
sudo nano /etc/pam.d/sshd

# Adicionar no final
auth required pam_google_authenticator.so

# Editar /etc/ssh/sshd_config
ChallengeResponseAuthentication yes

# Reiniciar SSH
sudo systemctl restart ssh
```

### Scripts Úteis SSH

#### Script 1: Backup Automatizado via SSH

```bash
#!/bin/bash
# backup-ssh.sh - Backup remoto via SSH

REMOTE_USER="backup"
REMOTE_HOST="backup-server.com"
REMOTE_PATH="/backup"
LOCAL_PATH="/dados"
DATE=$(date +%Y%m%d)
BACKUP_NAME="backup_$DATE.tar.gz"

echo "Criando backup..."
tar czf /tmp/$BACKUP_NAME $LOCAL_PATH

echo "Transferindo para servidor remoto..."
scp /tmp/$BACKUP_NAME $REMOTE_USER@$REMOTE_HOST:$REMOTE_PATH/

echo "Limpando arquivo local..."
rm /tmp/$BACKUP_NAME

echo "Backup completo: $REMOTE_PATH/$BACKUP_NAME"
```

#### Script 2: Monitor de Múltiplos Servidores

```bash
#!/bin/bash
# monitor-servers.sh - Monitor SSH de múltiplos servidores

SERVERS=(
    "web1.example.com"
    "web2.example.com"
    "db.example.com"
    "cache.example.com"
)

echo "========================================="
echo "   MONITOR DE SERVIDORES - $(date)"
echo "========================================="

for server in "${SERVERS[@]}"; do
    echo -e "\n=== $server ==="
    
    if ssh -o ConnectTimeout=5 -o BatchMode=yes $server 'exit' 2>/dev/null; then
        UPTIME=$(ssh $server 'uptime')
        LOAD=$(ssh $server "cat /proc/loadavg | awk '{print \$1,\$2,\$3}'")
        MEMORY=$(ssh $server "free -h | grep Mem: | awk '{print \$3 \"/\" \$2}'")
        DISK=$(ssh $server "df -h / | tail -1 | awk '{print \$5}'")
        
        echo "Status: ONLINE"
        echo "Uptime: $UPTIME"
        echo "Load: $LOAD"
        echo "Memory: $MEMORY"
        echo "Disk: $DISK"
    else
        echo "Status: OFFLINE ou inacessível"
    fi
done
```

---

## Telnet

**AVISO**: Telnet é **inseguro** - transmite dados em texto claro. Use apenas em redes isoladas/confiáveis ou para testes.

### Instalação

```bash
# Cliente Telnet
sudo apt install telnet

# Servidor Telnet (NÃO RECOMENDADO)
sudo apt install telnetd
```

### Uso do Cliente Telnet

```bash
# Conectar na porta 23 (padrão)
telnet hostname

# Especificar porta
telnet hostname 80
telnet 192.168.1.100 23

# Testar porta HTTP
telnet example.com 80
# Depois digitar:
GET / HTTP/1.0
Host: example.com
[Enter duas vezes]

# Testar SMTP
telnet smtp.example.com 25

# Testar POP3
telnet pop.example.com 110
```

### Casos de Uso Válidos

**Testar Conectividade de Porta**:
```bash
# Verificar se porta está aberta
telnet 192.168.1.100 22
telnet google.com 80
```

**Testar Protocolos de Texto**:
```bash
# HTTP
telnet example.com 80
GET / HTTP/1.1
Host: example.com

# SMTP
telnet smtp.gmail.com 587
EHLO localhost
QUIT

# POP3
telnet pop.gmail.com 110
USER username
PASS password
LIST
QUIT
```

### Alternativas Seguras ao Telnet

```bash
# Em vez de telnet, use:

# SSH para acesso remoto
ssh usuario@servidor

# nc (netcat) para teste de portas
nc -zv hostname 80

# openssl para protocolos SSL
openssl s_client -connect example.com:443

# curl para HTTP/HTTPS
curl -v http://example.com
```

---

## VNC - Virtual Network Computing

VNC permite acesso gráfico remoto ao desktop Linux.

### Instalação do Servidor VNC

#### TightVNC

```bash
# Instalar
sudo apt install tightvncserver

# Configurar senha
vncpasswd

# Iniciar servidor (criar sessão na :1)
vncserver :1

# Especificar geometria
vncserver :1 -geometry 1920x1080 -depth 24

# Parar servidor
vncserver -kill :1

# Listar sessões
vncserver -list
```

#### TigerVNC

```bash
# Instalar
sudo apt install tigervnc-standalone-server

# Configurar
vncserver

# Editar xstartup
nano ~/.vnc/xstartup
```

Conteúdo:
```bash
#!/bin/sh
xrdb $HOME/.Xresources
startxfce4 &
```

```bash
# Tornar executável
chmod +x ~/.vnc/xstartup

# Iniciar
vncserver :1 -geometry 1920x1080 -depth 24
```

#### x11vnc (Compartilhar Sessão Existente)

```bash
# Instalar
sudo apt install x11vnc

# Configurar senha
x11vnc -storepasswd

# Compartilhar sessão atual
x11vnc -usepw -forever -display :0

# Com mais opções
x11vnc -usepw -forever -display :0 -rfbport 5900 -shared
```

### Cliente VNC

#### Remmina (GUI)

```bash
# Instalar
sudo apt install remmina remmina-plugin-vnc

# Executar
remmina

# Configurar conexão:
# Protocolo: VNC
# Servidor: hostname:5901
# Senha: [senha VNC]
```

#### VNCViewer (RealVNC)

```bash
# Download do site oficial
wget https://downloads.realvnc.com/download/file/viewer.files/VNC-Viewer-*-Linux-x64.deb

# Instalar
sudo dpkg -i VNC-Viewer-*-Linux-x64.deb

# Executar
vncviewer hostname:5901
```

#### Cliente em Linha de Comando

```bash
# Usando vncviewer do TightVNC
sudo apt install xtightvncviewer

# Conectar
vncviewer hostname:5901

# Com opções
vncviewer -quality 9 -compresslevel 9 hostname:5901
```

### VNC via SSH Tunnel (Seguro)

```bash
# Criar túnel SSH
ssh -L 5901:localhost:5901 usuario@servidor

# Em outro terminal, conectar via VNC
vncviewer localhost:5901

# Ou em um comando
ssh -L 5901:localhost:5901 usuario@servidor & \
vncviewer localhost:5901
```

### VNC como Serviço Systemd

Criar arquivo `/etc/systemd/system/vncserver@.service`:

```ini
[Unit]
Description=Start TightVNC server at startup
After=syslog.target network.target

[Service]
Type=forking
User=usuario
PAMName=login
PIDFile=/home/usuario/.vnc/%H:%i.pid
ExecStartPre=-/usr/bin/vncserver -kill :%i > /dev/null 2>&1
ExecStart=/usr/bin/vncserver -depth 24 -geometry 1920x1080 :%i
ExecStop=/usr/bin/vncserver -kill :%i

[Install]
WantedBy=multi-user.target
```

```bash
# Recarregar systemd
sudo systemctl daemon-reload

# Habilitar e iniciar (display :1)
sudo systemctl enable vncserver@1
sudo systemctl start vncserver@1

# Status
sudo systemctl status vncserver@1
```

---

## RDP - Remote Desktop Protocol

RDP é o protocolo de desktop remoto da Microsoft, mas pode ser usado no Linux.

### XRDP - Servidor RDP para Linux

```bash
# Instalar
sudo apt install xrdp

# Iniciar e habilitar
sudo systemctl enable xrdp
sudo systemctl start xrdp

# Verificar status
sudo systemctl status xrdp
sudo ss -tlnp | grep 3389

# Configurar para usar Xfce
echo "startxfce4" > ~/.xsession

# Adicionar usuário ao grupo ssl-cert
sudo adduser xrdp ssl-cert
```

### Conectar via RDP

#### Do Windows

```
1. Executar: mstsc
2. Computador: IP_DO_SERVIDOR
3. Usuário: seu_usuario
4. Conectar
```

#### Do Linux

```bash
# Instalar Remmina
sudo apt install remmina remmina-plugin-rdp

# OU instalar FreeRDP
sudo apt install freerdp2-x11

# Conectar via linha de comando
xfreerdp /v:hostname /u:usuario /p:senha /size:1920x1080

# Com mais opções
xfreerdp /v:hostname /u:usuario /cert:ignore /sound:sys:alsa /size:1920x1080 +clipboard
```

### RDP via SSH Tunnel

```bash
# Criar túnel
ssh -L 3389:localhost:3389 usuario@servidor

# Conectar via RDP para localhost
xfreerdp /v:localhost /u:usuario
```

---

## X11 Forwarding

Executar aplicações gráficas remotas exibidas localmente.

### Configuração do Servidor

```bash
# Editar /etc/ssh/sshd_config
sudo nano /etc/ssh/sshd_config

# Habilitar
X11Forwarding yes
X11DisplayOffset 10
X11UseLocalhost yes

# Reiniciar SSH
sudo systemctl restart ssh
```

### Uso do Cliente

```bash
# Conectar com X11 forwarding
ssh -X usuario@servidor

# X11 trusted (menos seguro, mais compatível)
ssh -Y usuario@servidor

# Executar aplicação gráfica
firefox &
gedit &
nautilus &

# Testar
xclock &
xeyes &
```

### Otimizar Performance

```bash
# Com compressão
ssh -XC usuario@servidor

# Ajustar qualidade
ssh -X -o "Compression yes" -o "CompressionLevel 9" usuario@servidor

# Configurar no ~/.ssh/config
Host servidor
    ForwardX11 yes
    Compression yes
    CompressionLevel 9
```

### Troubleshooting X11

```bash
# Verificar DISPLAY
echo $DISPLAY

# Deve mostrar algo como: localhost:10.0

# Verificar xauth
xauth list

# Adicionar permissão manualmente
xhost +localhost

# Testar
xclock
```

---

## TeamViewer e AnyDesk

Soluções comerciais populares para acesso remoto.

### TeamViewer

```bash
# Download (Debian/Ubuntu)
wget https://download.teamviewer.com/download/linux/teamviewer_amd64.deb

# Instalar
sudo dpkg -i teamviewer_amd64.deb
sudo apt install -f

# Executar
teamviewer

# Iniciar daemon
sudo teamviewer --daemon start

# Ver ID
teamviewer --info

# Conectar via CLI (se já configurado)
teamviewer --id <ID>
```

### AnyDesk

```bash
# Adicionar repositório
wget -qO - https://keys.anydesk.com/repos/DEB-GPG-KEY | sudo apt-key add -
echo "deb http://deb.anydesk.com/ all main" | sudo tee /etc/apt/sources.list.d/anydesk-stable.list

# Instalar
sudo apt update
sudo apt install anydesk

# Executar
anydesk

# Ver ID
anydesk --get-id

# Configurar senha
anydesk --set-password
```

---

## Console Serial

Acesso via porta serial (útil para servidores sem rede).

### Configuração do Servidor

```bash
# Habilitar console serial
sudo systemctl enable serial-getty@ttyS0.service
sudo systemctl start serial-getty@ttyS0.service

# OU editar GRUB
sudo nano /etc/default/grub

# Adicionar
GRUB_CMDLINE_LINUX="console=tty0 console=ttyS0,115200n8"
GRUB_TERMINAL="serial console"
GRUB_SERIAL_COMMAND="serial --speed=115200 --unit=0 --word=8 --parity=no --stop=1"

# Atualizar GRUB
sudo update-grub
```

### Acesso Serial

```bash
# Instalar minicom
sudo apt install minicom

# Configurar
sudo minicom -s

# Configurações:
# - Serial Device: /dev/ttyS0 (ou /dev/ttyUSB0)
# - Baud Rate: 115200
# - Data bits: 8
# - Parity: None
# - Stop bits: 1

# Conectar
sudo minicom

# OU usar screen
sudo apt install screen
sudo screen /dev/ttyS0 115200
```

---

## Web-Based Access

### Cockpit - Web Console

```bash
# Instalar
sudo apt install cockpit

# Habilitar e iniciar
sudo systemctl enable --now cockpit.socket

# Acessar no navegador
https://seu-servidor:9090

# Login com usuário do sistema
```

### Webmin

```bash
# Adicionar repositório
curl -o setup-repos.sh https://raw.githubusercontent.com/webmin/webmin/master/setup-repos.sh
sudo sh setup-repos.sh

# Instalar
sudo apt install webmin

# Acessar
https://seu-servidor:10000

# Configurar firewall
sudo ufw allow 10000
```

### Apache Guacamole

Cliente RDP/VNC/SSH via web.

```bash
# Instalar dependências
sudo apt install docker.io docker-compose

# Criar docker-compose.yml
cat > docker-compose.yml << EOF
version: '3'
services:
  guacd:
    image: guacamole/guacd
    restart: always
  
  guacamole:
    image: guacamole/guacamole
    restart: always
    ports:
      - "8080:8080"
    environment:
      GUACD_HOSTNAME: guacd
    depends_on:
      - guacd
EOF

# Iniciar
sudo docker-compose up -d

# Acessar
http://seu-servidor:8080/guacamole
# Login padrão: guacadmin/guacadmin
```

---

## Comparação de Métodos

| Método | Segurança | Performance | Uso | Gráfico | Criptografia |
|--------|-----------|-------------|-----|---------|--------------|
| **SSH** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | Terminal | ❌ | ✅ |
| **SSH + X11** | ⭐⭐⭐⭐ | ⭐⭐⭐ | Apps Gráficas | ✅ | ✅ |
| **Telnet** | ⭐ | ⭐⭐⭐⭐⭐ | Terminal | ❌ | ❌ |
| **VNC** | ⭐⭐ | ⭐⭐⭐ | Desktop | ✅ | ❌* |
| **VNC+SSH** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | Desktop | ✅ | ✅ |
| **RDP** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | Desktop | ✅ | ✅ |
| **TeamViewer** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | Desktop | ✅ | ✅ |
| **Serial** | ⭐⭐⭐⭐⭐ | ⭐⭐ | Terminal | ❌ | ❌ |

*VNC pode ter criptografia dependendo da implementação

### Quando Usar Cada Método

**SSH**: 
- Administração de servidores
- Automação e scripts
- Túneis seguros
- Transferência de arquivos

**SSH + X11**:
- Executar aplicações gráficas específicas
- Administração com ferramentas GUI

**VNC**:
- Suporte técnico com desktop completo
- Acesso a desktop remoto em LAN

**RDP**:
- Integração com Windows
- Desktop remoto com boa performance

**TeamViewer/AnyDesk**:
- Suporte técnico atravessando firewalls
- Acesso sem configuração de rede

**Serial**:
- Recuperação de sistema
- Acesso sem rede disponível
- Configuração inicial de servidores

---

## Segurança

### Boas Práticas Gerais

```bash
# 1. Usar firewall
sudo ufw enable
sudo ufw allow 22/tcp

# 2. Fail2ban para SSH
sudo apt install fail2ban

# 3. Manter sistema atualizado
sudo apt update && sudo apt upgrade

# 4. Usar chaves SSH em vez de senhas
ssh-keygen -t ed25519
ssh-copy-id usuario@servidor

# 5. Desabilitar root login
# Em /etc/ssh/sshd_config
PermitRootLogin no

# 6. Usar VPN quando possível
sudo apt install openvpn

# 7. Monitorar logs
sudo tail -f /var/log/auth.log

# 8. Two-factor authentication
sudo apt install libpam-google-authenticator
```

### Checklist de Segurança SSH

- [ ] Mudar porta padrão (22)
- [ ] Desabilitar root login
- [ ] Usar apenas autenticação por chave
- [ ] Configurar Fail2Ban
- [ ] Limitar usuários com AllowUsers
- [ ] Usar firewall (UFW/iptables)
- [ ] Habilitar 2FA
- [ ] Manter OpenSSH atualizado
- [ ] Usar SSH v2 apenas
- [ ] Configurar timeout de sessão

---

## Troubleshooting

### SSH Comum Issues

**Problema**: Connection refused
```bash
# Verificar se SSH está rodando
sudo systemctl status ssh

# Verificar porta
sudo ss -tlnp | grep :22

# Verificar firewall
sudo ufw status
```

**Problema**: Permission denied (publickey)
```bash
# Verificar permissões
ls -la ~/.ssh/

# Corrigir permissões
chmod 700 ~/.ssh
chmod 600 ~/.ssh/id_rsa
chmod 644 ~/.ssh/id_rsa.pub
chmod 600 ~/.ssh/authorized_keys

# Debug
ssh -vvv usuario@servidor
```

**Problema**: Host key verification failed
```bash
# Remover entrada antiga
ssh-keygen -R hostname

# Ou editar manualmente
nano ~/.ssh/known_hosts
```

### VNC Common Issues

**Problema**: Grey screen
```bash
# Editar ~/.vnc/xstartup
nano ~/.vnc/xstartup

# Adicionar
#!/bin/sh
xrdb $HOME/.Xresources
startxfce4 &

# Tornar executável
chmod +x ~/.vnc/xstartup

# Reiniciar VNC
vncserver -kill :1
vncserver :1
```

**Problema**: Can't connect
```bash
# Verificar se está rodando
ps aux | grep vnc

# Verificar porta
sudo ss -tlnp | grep 590

# Testar localmente
vncviewer localhost:5901
```

---

## Referências

### Documentação Oficial
- [OpenSSH Manual](https://www.openssh.com/manual.html)
- [SSH.COM Documentation](https://www.ssh.com/academy/ssh)
- [TigerVNC Documentation](https://tigervnc.org/)
- [XRDP Documentation](http://xrdp.org/)

### Livros Recomendados
- "SSH, The Secure Shell: The Definitive Guide" - Daniel J. Barrett
- "Linux Security Cookbook" - Daniel J. Barrett
- "Network Security Through Data Analysis" - Michael Collins

### Man Pages Importantes
```bash
man ssh
man sshd_config
man ssh-keygen
man ssh-copy-id
man scp
man sftp
```

---

**Autor**: Guia Completo de Acesso Remoto Linux  
**Sistema**: Debian GNU/Linux  
**Última Atualização**: 2025  
**Licença**: Open Source

