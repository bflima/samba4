#!/usr/bin/env bash

# Autor: Bruno Lima
# Data de criação: 31/07/2020
# Data de atualização: 07/08/2020
# Versão: 0.9
# Testado e homologado para a versão do Centos 8 X64

################################################################################
###                   Declaração de funções                                  ###
################################################################################

#Função para atualizar os pacotes do sistema e desabilita o firewall e SELINUX
_CONFIGURAR()
{
  FILE="/tmp/inicial.txt"
  if [ ! -e "$FILE" ] ; then
    clear
    #Desabilitar o firewalld
    systemctl stop firewalld && systemctl disable firewalld
    #Desabilitar SELINUX
    setenforce 0
    sed -i 's/^SELINUX=.*/SELINUX=disabled/g' /etc/selinux/config

    #Atualizar sistema
    yum update -y && yum upgrade -y

    #Instalar repositorio EPEL e ferramentas de desenvolvimento e pacotes úteis
    yum install epel-release.noarch -y
    yum install vim dialog wget htop net-tools figlet bash-completion chrony \
    yum-utils "@Development Tools" -y

    # Habilitando o bash completion
    source $(find /etc/ -type f -iname bash_completion.sh)

    # Instala chrony e atualiza a hora
    CHRONY_CONF=$(find /etc/ -type f -iname chrony.conf)
    cp "$CHRONY_CONF"{,.bkp}
    sed -i 's/^pool.*/server\ a.ntp.br\ iburst/' "$CHRONY_CONF"
    sed -i '4s/^/server\ b.ntp.br\ iburst\n/'    "$CHRONY_CONF"
    sed -i 's/^#allow.*/allow\ 0.0.0.0\/0/'      "$CHRONY_CONF"

    #Inicializando chronyd e habilitando serviço
    systemctl enable chronyd --now


    echo "Configuracao realizada, função executada _CONFIGURAR" | tee > "$FILE"
  else
    echo "Configuracao realizada, para repetir a instalacao remover esse arquivo $FILE"
  fi
}
# Fim

################################################################################
# Função para verificar se o script está com privilegios de root
# Caso não estiver finaliza o programa
_VERIFICAR_ROOT()
{
  if [ $(id -u) != 0 ]
    then
    tput setaf 1; tput setab 7
    echo "ERRO: Precisa ter permissao de usuario root para rodar o script"
    tput sgr0
    exit
fi
}
# Fim

################################################################################
# Função para testar ip fornecido, utiliza programa auxiliar ipcalc
# Se o retorno for diferente de sucesso ou tamanho igual a zero sai do programa
function testa_ip()
{
  ipcalc -c "$1" > /dev/null 2>&1

  if [[ $? -ne "0" || ${#1} -eq "0" ]]; then
      tput setaf 1; tput setab 7 ; echo "Erro ao digitar IP $1, Favor Verificar"; tput sgr0
      exit
  fi
}
# Fim

################################################################################
# Função para validar entrada dos campos digitados pelo usuario
# Se o retorno for diferente de sucesso ou tamanho igual a zero sai do programa
function validar()
{
	if [[ $? -ne "0" || ${#1} -eq "0" ]]; then
      tput setaf 1; tput setab 7 ; echo "Erro ao validar informação ${1}, Favor Verificar"; tput sgr0
      exit
  fi
}
# Fim

################################################################################
# Função para testar tamamho e complexidade de senha
# Se o retorno for diferente de sucesso ou tamanho igual a zero sai do programa
function testa_senha()
{
  a=$1
  LEN=${#a}
  if [ $LEN -lt 8 ]; then echo "Senha menor que 8"; exit; fi

  b=`echo $a | egrep "^.{8,255}" | \
               egrep "[ABCDEFGHIJKLMNOPQRSTUVWXYZ]" | \
               egrep "[abcdefghijklmnopqrstuvwxyz"] | \
               egrep "[0-9]" | \
               egrep "[\@\.\!\$\%\&\*\?\<\>\+\=\_\-]"`

# now featuring W in the alphabet string
#if the result string is empty, one of the conditions has failed
  if [ -z $b ]
    then
      tput bold
      echo -e "Senha nao atende complexidade necessario 01 de cada item abaixo\nletra Maiuscula, Minuscula, Caracter especial, digito numerico\nExemplo: Teste@123, P@\$\$word.1"
      tput sgr0
      exit 50
  else
      echo "Senha cadastrada com sucesso"
  fi
}
# Fim

################################################################################
# Função para escolher interface de rede caso exista mais de uma
function INTERFACE()
{
  TMP=$(ip -o -4 route show to default | awk '{print $5}' | uniq)
  TM=$(ip -o -4 route show to default | awk '{print $5}' | uniq | tail -n 1)

  arr=()
  i=0
  for ip in $TMP
  do
    #echo "${ip[i]}"
    arr=("${ip[i]}" "${arr[@]}")
  done


  whiptail_args=(
    --title "Escolha a interface de rede"
    --radiolist "Interface disponivel:"
    10 80 "${#arr[@]}"  # note the use of ${#arrayname[@]} to get count of entries
  )

  i=0
  for db in "${arr[@]}"; do
    whiptail_args+=( "$((++i))" "$db" )
    if [[ $db = "$TM" ]]; then    # only RHS needs quoting in [[ ]]
      whiptail_args+=( "on" )
    else
      whiptail_args+=( "off" )
    fi
  done

  indice=$(whiptail "${whiptail_args[@]}" 3>&1 1>&2 2>&3); whiptail_retval=$?
  #declare -p indice whiptail_retval
  #echo "Interface"
  echo "${arr[${indice}-1]}"
}

# Fim

################################################################################
# Função para escolher ip
function _IP()
{
  TMP=$(ip a | egrep inet[[:space:]] |grep -v 127 | awk '{print $2}')
  TM=$(ip a | egrep inet[[:space:]] |grep -v 127 | awk '{print $2}' | head -n 1)

  arr=()
  i=0
  for ip in $TMP
    do
    #echo "${ip[i]}"
    arr=("${ip[i]}" "${arr[@]}")
    done

  whiptail_args=(
  --title "Escolha endereco de rede"
  --radiolist "Endereco disponivel:"
    10 80 "${#arr[@]}")

  i=0
  for db in "${arr[@]}"; do
    whiptail_args+=( "$((++i))" "$db" )
    if [[ $db = "$TM" ]]; then    # only RHS needs quoting in [[ ]]
      whiptail_args+=( "on" )
    else
      whiptail_args+=( "off" )
    fi
  done

  indice=$(whiptail "${whiptail_args[@]}" 3>&1 1>&2 2>&3); whiptail_retval=$?
  #declare -p indice whiptail_retval
  #echo "Interface"
  echo "${arr[${indice}-1]}"
}
# Fim

################################################################################
# Função para habilitar funcionalidades do VIM
function _VIM()
{
  VIM="$HOME/.vimrc"

  mkdir -p ~/.vim/pack/plugins/start
  cd ~/.vim/pack/plugins/start
  git clone https://github.com/vim-airline/vim-airline.git
  git clone https://github.com/tomasiser/vim-code-dark.git
  git clone https://github.com/mhinz/vim-startify.git
  git clone https://github.com/preservim/nerdtree.git
  git clone https://github.com/Yggdroot/indentLine
  git clone https://github.com/preservim/nerdcommenter
  git clone https://github.com/sheerun/vim-polyglot

  # Adicionando opções no vimrc do usário logado
  echo -e "set bg=dark\nsyntax on\nset number\nset cursorline" > "$VIM"
  echo -e "set autoindent\nset smartindent"                   >> "$VIM"
  echo "set tabstop=2 softtabstop=2 expandtab shiftwidth=2"   >> "$VIM"
  echo "colorscheme codedark"                                 >> "$VIM"
  echo -e "\nlet g:indentLine_enabled = 1"                    >> "$VIM"
  echo "map <c-k>i :IndentLinesToggle<cr>"                    >> "$VIM"
  echo -e "\nfiletype plugin on"                              >> "$VIM"
  echo "let g:NERDSpaceDelims = 1"                            >> "$VIM"
  echo "let g:NERDDefaultAlign = 'left'"                      >> "$VIM"
  echo "map cc <Plug>NERDCommenterInvert"                     >> "$VIM"
}

###################################################INICIO###############################3##################
# Função para configurar o SAMBA
# Solicita informações para o usuario, realiza teste da entrada de dados
function _CONF_SAMBA
{
  FILE="/tmp/conf_samba.txt"

  if [ ! -e "$FILE" ] ; then
    #Criação do banco de dados de variaveis para uso do samba4
    echo > /tmp/samba.db

    clear
    IP_DC_PRIN=$(whiptail --title "Qual IP do servidor DC PRINCIPAL" --inputbox "Digite o Ip:" --fb 10 60 3>&1 1>&2 2>&3)
    testa_ip $IP_DC_PRIN

    echo "Testando a conexão"
    ping -c 3 $IP_DC_PRIN > /dev/null 2>&1
    if [[ $? -ne "0" ]]; then echo "Erro ao se comunicar com o IP $IP_DC_PRIN, Favor Verificar"; exit; fi
    echo "IP_DC_PRIN=$IP_DC_PRIN" >> /tmp/samba.db

    clear
    DOM_DC_PRIN=$(whiptail --title "Qual nome FQDN do DOMINO do DC principal" --inputbox "Exemplo corp.local, empresa.local:" --fb 10 60 3>&1 1>&2 2>&3)
    validar ${DOM_DC_PRIN}
    echo "DOM_DC_PRIN=$DOM_DC_PRIN">> /tmp/samba.db

    #Here document para criar arquivo de dns
    chattr -i /etc/resolv.conf
    cat > /etc/resolv.conf << EOF
search $DOM_DC_PRIN
nameserver $IP_DC_PRIN
EOF
    chattr +i /etc/resolv.conf

    clear
    NOME_DC_PRIN=$(whiptail --title "Qual hostname do DC Principal" --inputbox "Exemplo addc01, dc01, srvad:" --fb 10 60 3>&1 1>&2 2>&3)
    validar $NOME_DC_PRIN

    echo "Testando a conexão"
    ping -c 3 $NOME_DC_PRIN > /dev/null 2>&1
    if [[ $? -ne "0" ]]; then echo "Erro ao se comunicar com o HOSTNAME $NOME_DC_PRIN, Favor Verificar"; exit; fi
    echo "NOME_DC_PRIN=$NOME_DC_PRIN" >> /tmp/samba.db

    clear
    H_NAME=$(whiptail --title "Qual nome da Máquina atual" --inputbox "atual -> $(hostname -s):" --fb 10 60 3>&1 1>&2 2>&3)
    H_NAME=${H_NAME:=$(hostname)}
    validar ${H_NAME}
    echo "HOSTNAME=$H_NAME" >> /tmp/samba.db

    clear
    SENHA_DOM=$(whiptail --title "Qual a senha do admistrador do DOMINIO" --passwordbox "Usar senha complexa:" --fb 10 60 3>&1 1>&2 2>&3)
    SENHA_DOM=${SENHA_DOM:=Senha@123}
    testa_senha ${SENHA_DOM}
    echo "SENHA_DOM=$SENHA_DOM" >> /tmp/samba.db

    clear
    IP=`_IP`
    testa_ip ${IP}
    echo "IP=$IP" >> /tmp/samba.db

    clear
    MASK=$(whiptail --title "Qual mascára de rede" --inputbox "atual -> $(ip a | grep inet | grep -v inet6 | grep -v 127.0.0.* | awk '{print $2}' | cut -d "/" -f 2 | uniq):" --fb 10 60 3>&1 1>&2 2>&3)
    echo "Exemplo: Ex: 8 16 24"
    MASK=${MASK:=$(ip a | grep inet | grep -v inet6 | cut -d "/" -f 2 | egrep -o ^[0-9]{2} |head -n 1)}
    validar $MASK
    echo "Mascara=$MASK" >> /tmp/samba.db

    clear
    GW=$(whiptail --title "Qual endereco do Gateway" --inputbox "atual -> $(ip -o -4 route show to default | awk '{print $3}' | tail -n 1):" --fb 10 60 3>&1 1>&2 2>&3)
    GW=${GW:=$(ip -o -4 route show to default | cut -d " " -f 3 | head -n 1)}
    testa_ip $GW
    echo "GATEWAY=$GW" >> /tmp/samba.db

    clear
    DNS=$(whiptail --title "Qual endereco de DNS" --inputbox "Exemplo: 8.8.8.8, 8.8.4.4:" --fb 10 60 3>&1 1>&2 2>&3)
    DNS=${DNS:=1.1.1.1}
    testa_ip $DNS
    echo "DNS=$DNS" >> /tmp/samba.db

    clear
    INTER_FACE=`INTERFACE`

    echo "REDE=${INTER_FACE}" >> /tmp/samba.db

    clear
    # IP_COMPLETO=$(ip a | grep inet | grep -v inet6 | grep -v 127.0.0* | awk '{print $2}'
    NET=$(ipcalc --all-info ${IP} | grep -i network | awk '{print $2}')
    END_REDE=$(whiptail --title "Qual endereco da REDE e MASCARA usar formato IP/MASCARA" --inputbox "Atual -> ${NET}:" --fb 10 60 3>&1 1>&2 2>&3)
    END_REDE=${END_REDE:=${NET}}
    echo "END_REDE=$END_REDE" >> /tmp/samba.db

    clear
    whiptail --title "Dados informados pelo usuario" --textbox /tmp/samba.db  20 65

    whiptail --title "Deseja continuar" --yesno "Os dados estao corretos SIM ou Nao." 10 50
    if [[ $? -eq 1 ]] ; then tput setaf 1; tput setab 7 ; echo -e "Saindo\nFavor executar novamente o script" ; tput sgr0 ; exit; fi

    hostnamectl set-hostname $H_NAME
    H_NAME_SHORT=$(grep -i "dom_dc_prin" /tmp/samba.db | cut -d "=" -f 2 |cut -d "." -f 1)

# nmcli connection show | grep ${INTER_FACE} | grep -oz [[:xdigit:]]*-[[:xdigit:]]*

    cat >> /etc/hosts << EOF
${IP%/*} $H_NAME.$DOM_DC_PRIN $H_NAME.$H_NAME_SHORT $H_NAME
EOF
    #Here document para criar arquivo de rede
    cat > /etc/sysconfig/network-scripts/ifcfg-${INTER_FACE} << EOF
TYPE=Ethernet
PROXY_METHOD=none
BROWSER_ONLY=no
BOOTPROTO=none
DEFROUTE=yes
IPV4_FAILURE_FATAL=no
IPV6INIT=yes
IPV6_AUTOCONF=yes
IPV6_DEFROUTE=yes
IPV6_FAILURE_FATAL=no
IPV6_ADDR_GEN_MODE=stable-privacy
UUID=$(nmcli connection show | grep ${INTER_FACE} | rev | awk '{print $3}' |rev)
NAME=${INTER_FACE}
DEVICE=${INTER_FACE}
ONBOOT=yes
IPADDR=$IP
PREFIX=$MASK
GATEWAY=$GW
EOF
  #Reiniciar rede
  systemctl restart NetworkManager
  echo "Configuracao realizada, função executada foi _CONF_SAMBA" | tee > $FILE
  else
    echo "Configuracao realizada, para repetir a instalacao remover esse arquivo $FILE"
  fi
}
################################################################################
################################################################################
#Função para instalação das dependecias do samba4
_SAMBA_DEP()
{
  FILE="/tmp/samba_dep.txt"
  if [ ! -e "$FILE" ] ; then
  clear

  #Pacotes necessários
  yum install epel-release.noarch yum-utils "@Development Tools" -y
  yum config-manager --set-enabled PowerTools
  yum update -y && yum upgrade -y

  # Pacotes para necessários para instalar o samba
  yum install docbook-style-xsl gcc gdb gnutls-devel gpgme-devel jansson-devel \
      keyutils-libs-devel krb5-workstation libacl-devel libaio-devel \
      libarchive-devel libattr-devel libblkid-devel libtasn1 libtasn1-tools \
      libxml2-devel libxslt lmdb-devel openldap-devel pam-devel perl \
      perl-ExtUtils-MakeMaker perl-Parse-Yapp popt-devel python3-cryptography \
      python3-dns python3-gpg python36-devel readline-devel rpcgen systemd-devel \
      tar zlib-devel wget krb5-devel -y

  # Versão homologada para a instalação
  cd /opt

  wget https://download.samba.org/pub/samba/stable/samba-4.12.5.tar.gz
  tar -zxvf /opt/samba-4.*.gz -C /opt

  cd /opt/samba-4.12.5

  # Flags de compilação
  CFLAGS="-I/usr/include/tirpc" ./configure -j `nproc` \
  --enable-coverage --disable-cups\
  --with-systemd --systemd-install-services \
  --with-systemddir=/usr/lib/systemd/system \
  --prefix=/usr/local/samba4 \
  --with-pammodulesdir=/usr/lib64/security \
  --sysconfdir=/usr/local/samba4/conf

  make -j $(nproc)
  make install

  find /usr/local/samba4/lib -type d > /etc/ld.so.conf.d/samba4.conf
  echo "/usr/local/samba4/lib64" >> /etc/ld.so.conf.d/samba4.conf

  ldconfig && ldconfig && ldconfig && ldconfig

# Here document
  cat > /etc/profile.d/samba4.sh << EOF
if [ $(id -u) -eq 0 ]
then
  PATH="/usr/local/samba4/sbin:$PATH"
fi

PATH="/usr/local/samba4/bin:$PATH"
export PATH
EOF

  # Recarregar perfil
  source /etc/profile.d/samba4.sh
  systemctl daemon-reload

  echo "exclude=samba*" >> /etc/yum.conf
  echo "Configuracao realizada, função executada foi _SAMBA_DEP" | tee > $FILE
  else
    echo "Configuracao realizada, para repetir a instalacao remover esse arquivo $FILE"
  fi
}
##################################################################################
_SAMBA_INST()
{
  if [[ ! -e /tmp/samba.db ]] || [[ ! -s /tmp/samba.db ]]; then
    echo "samba.db não existe!, verificar a funcao SAMBA_DEP  "
    exit 50
  fi

  FILE="/tmp/samba_inst.txt"
  if [ ! -e "$FILE" ] ; then

      _VIM

      clear

      REINO=$(grep -i "dom_dc_prin" /tmp/samba.db | cut -d "=" -f 2)
      NOME_DC_PRIN=$(grep -i "NOME_DC_PRIN" /tmp/samba.db | cut -d "=" -f 2)
      SENHA_DOM=$(grep -i "SENHA_DOM" /tmp/samba.db | cut -d "=" -f 2)
      DC_JOIN=$(grep -i "dom_dc_prin" /tmp/samba.db | cut -d "=" -f 2)
      IP_DC_PRIN=$(grep -i "ip_dc_prin" /tmp/samba.db | cut -d "=" -f 2)
      H_NAME=$(hostname -s)
      IP=$(hostname -I | sed  s'\ \\')
      WORK=$(grep -i "dom_dc_prin" /tmp/samba.db | cut -d "=" -f 2 | cut -d "." -f 1)

      source /etc/profile.d/samba4.sh
      mv /etc/krb5.conf{,.bkp}

      # Criando arquivos de logs
      mkdir -p /var/log/samba
      touch /var/log/krb5.log
      touch /var/log/samba/log.smbd

      cat > /etc/krb5.conf << EOF
[logging]
  default = FILE:/var/log/krb5.log

[libdefaults]
  default_realm = ${REINO^^}
  dns_lookup_realm = false
  dns_lookup_kdc = true

[kdc]
  check-ticket-addresses = false

[realms]
  ${REINO^^} = {
  kdc = ${NOME_DC_PRIN}.${REINO}
  admin_server = ${NOME_DC_PRIN}.${REINO}
  default_domain = ${REINO^^}
}

[domain_realm]
  .${REINO} = ${REINO^^}
  ${REINO} = ${REINO^^}
EOF

      /usr/local/samba4/sbin/smbd -b | grep "CONFIGFILE" >> /tmp/samba.db
      /usr/local/samba4/sbin/smbd -b | egrep "LOCKDIR|STATEDIR|CACHEDIR|PRIVATE_DIR" >> /tmp/samba.db
      SMB_CONF=$(/usr/local/samba4/sbin/smbd -b | grep "CONFIGFILE" | awk '{print $2}') >> /tmp/samba.db

      if [ ! -f /usr/bin/python3 ]; then
        ln -sf /usr/bin/python3.6 /usr/bin/python3
      fi

      cat > ${SMB_CONF} << EOF
[global]
        netbios name = ${H_NAME^^}
        realm = ${REINO^^}
        server role = member
        workgroup = ${WORK^^}
        idmap_ldb:use rfc2307 = yes
        template shell = /bin/bash
        template homedir = /home/%U
        winbind enum users = yes
        winbind enum groups = yes
        winbind use default domain = yes
        ntlm auth = yes
        winbind nss info = rfc2307
        vfs objects = acl_xattr, recycle
        map acl inherit = Yes
        store dos attributes = Yes
        max log size = 100
        log file = /var/log/samba/log.%m
        encrypt passwords = yes
        security = ADS
        ntlm auth = yes
        ldap server require strong auth = no
        nt acl support = yes
        winbind gid = 10000-20000
EOF

      cp /etc/nsswitch.conf{,.bkp}

      cat >> /etc/nsswitch.conf << EOF
passwd:     files winbind
shadow:     files winbind
group:      files winbind
EOF

      clear

      echo "Validando ticket do DC"
      /usr/bin/kinit Administrator
      echo -e "\n\nListando Ticket no DC"
      /usr/bin/klist

      DC_PRIN=$(grep "DOM_DC" /tmp/samba.db |cut -d "=" -f 2)

      clear
      echo "Adicionando ao dominio $DC_PRIN"
      /usr/local/samba4/bin/net ads join -U Administrator ${DC_PRIN}
      sleep 3

      systemctl enable winbind smb nmb
      systemctl restart winbind smb nmb
      systemctl mask samba.service

      net rpc rights grant "$WORK\Domain Admins" SeDiskOperatorPrivilege -U "$WORK\administrator%$SENHA_DOM"
      net rpc rights list privileges SeDiskOperatorPrivilege -U "$WORK\administrator%$SENHA_DOM"

      smbcontrol all reload-config

      rm -rf /opt/samba*
      echo "Configuracao realizada, função executada foi _SAMBA_INST" | tee > $FILE
      reboot
  else
        echo "Configuracao realizada, para repetir a instalacao remover esse arquivo $FILE"
  fi
}

clear
_VERIFICAR_ROOT
_CONFIGURAR
_CONF_SAMBA
_SAMBA_DEP
_SAMBA_INST
#!/usr/bin/env bash

################################################################################
###                   Declaração de funções                                  ###
################################################################################

#Função para atualizar os pacotes do sistema e desabilita o firewall e SELINUX
_CONFIGURAR()
{
  FILE="/tmp/inicial.txt"
  if [ ! -e "$FILE" ] ; then
    clear
    #Desabilitar o firewalld
    systemctl stop firewalld && systemctl disable firewalld
    #Desabilitar SELINUX
    setenforce 0
    sed -i 's/^SELINUX=.*/SELINUX=disabled/g' /etc/selinux/config

    #Atualizar sistema
    yum update -y && yum upgrade -y

    #Instalar repositorio EPEL e ferramentas de desenvolvimento e pacotes úteis
    yum install epel-release.noarch -y
    yum install vim dialog wget htop net-tools figlet bash-completion chrony \
    yum-utils "@Development Tools" -y

    # Habilitando o bash completion
    source $(find /etc/ -type f -iname bash_completion.sh)

    # Instala chrony e atualiza a hora
    CHRONY_CONF=$(find /etc/ -type f -iname chrony.conf)
    cp "$CHRONY_CONF"{,.bkp}
    sed -i 's/^pool.*/server\ a.ntp.br\ iburst/' "$CHRONY_CONF"
    sed -i '4s/^/server\ b.ntp.br\ iburst\n/'    "$CHRONY_CONF"
    sed -i 's/^#allow.*/allow\ 0.0.0.0\/0/'      "$CHRONY_CONF"

    #Inicializando chronyd e habilitando serviço
    systemctl enable chronyd --now


    echo "Configuracao realizada, função executada _CONFIGURAR" | tee > "$FILE"
  else
    echo "Configuracao realizada, para repetir a instalacao remover esse arquivo $FILE"
  fi
}
# Fim

################################################################################
# Função para verificar se o script está com privilegios de root
# Caso não estiver finaliza o programa
_VERIFICAR_ROOT()
{
  [ "$EUID" -eq 0 ] || { tput setaf 1; tput setab 7; \
    echo "ERRO: Necessita acesso root para rodar o script"; tput sgr0; exit; }
}
# Fim

################################################################################
# Função para testar ip fornecido, utiliza programa auxiliar ipcalc
# Se o retorno for diferente de sucesso ou tamanho igual a zero sai do programa
function testa_ip()
{
  ipcalc -c "$1" > /dev/null 2>&1

  [[ $? -eq "0" ]]; tput setaf 1; tput setab 7 ; \
    echo "Erro ao digitar IP $1, Favor Verificar"; tput sgr0; exit
}
# Fim

################################################################################
# Função para validar entrada dos campos digitados pelo usuario
# Se o retorno for diferente de sucesso ou tamanho igual a zero sai do programa
function validar()
{
	if [[ $? -ne "0" || ${#1} -eq "0" ]]; then
      tput setaf 1; tput setab 7 ; echo "Erro ao validar informação ${1}, Favor Verificar"; tput sgr0
      exit
  fi
}
# Fim

################################################################################
# Função para testar tamamho e complexidade de senha
# Se o retorno for diferente de sucesso ou tamanho igual a zero sai do programa
function testa_senha()
{
  a=$1
  LEN=${#a}
  if [ $LEN -lt 8 ]; then echo "Senha menor que 8"; exit; fi

  b=`echo $a | egrep "^.{8,255}" | \
               egrep "[ABCDEFGHIJKLMNOPQRSTUVWXYZ]" | \
               egrep "[abcdefghijklmnopqrstuvwxyz"] | \
               egrep "[0-9]" | \
               egrep "[\@\.\!\$\%\&\*\?\<\>\+\=\_\-]"`

# now featuring W in the alphabet string
#if the result string is empty, one of the conditions has failed
  if [ -z $b ]
    then
      tput bold
      echo -e "Senha nao atende complexidade necessario 01 de cada item abaixo\nletra Maiuscula, Minuscula, Caracter especial, digito numerico\nExemplo: Teste@123, P@\$\$word.1"
      tput sgr0
      exit 50
  else
      echo "Senha cadastrada com sucesso"
  fi
}
# Fim

################################################################################
# Função para escolher interface de rede caso exista mais de uma
function INTERFACE()
{
  TMP=$(ip -o -4 route show to default | awk '{print $5}' | uniq)
  TM=$(ip -o -4 route show to default | awk '{print $5}' | uniq | tail -n 1)

  arr=()
  i=0
  for ip in $TMP
  do
    #echo "${ip[i]}"
    arr=("${ip[i]}" "${arr[@]}")
  done


  whiptail_args=(
    --title "Escolha a interface de rede"
    --radiolist "Interface disponivel:"
    10 80 "${#arr[@]}"  # note the use of ${#arrayname[@]} to get count of entries
  )

  i=0
  for db in "${arr[@]}"; do
    whiptail_args+=( "$((++i))" "$db" )
    if [[ $db = "$TM" ]]; then    # only RHS needs quoting in [[ ]]
      whiptail_args+=( "on" )
    else
      whiptail_args+=( "off" )
    fi
  done

  indice=$(whiptail "${whiptail_args[@]}" 3>&1 1>&2 2>&3); whiptail_retval=$?
  #declare -p indice whiptail_retval
  #echo "Interface"
  echo "${arr[${indice}-1]}"
}

# Fim

################################################################################
# Função para escolher ip
function _IP()
{
  TMP=$(ip a | egrep inet[[:space:]] |grep -v 127 | awk '{print $2}')
  TM=$(ip a | egrep inet[[:space:]] |grep -v 127 | awk '{print $2}' | head -n 1)

  arr=()
  i=0
  for ip in $TMP
    do
    #echo "${ip[i]}"
    arr=("${ip[i]}" "${arr[@]}")
    done

  whiptail_args=(
  --title "Escolha endereco de rede"
  --radiolist "Endereco disponivel:"
    10 80 "${#arr[@]}")

  i=0
  for db in "${arr[@]}"; do
    whiptail_args+=( "$((++i))" "$db" )
    if [[ $db = "$TM" ]]; then    # only RHS needs quoting in [[ ]]
      whiptail_args+=( "on" )
    else
      whiptail_args+=( "off" )
    fi
  done

  indice=$(whiptail "${whiptail_args[@]}" 3>&1 1>&2 2>&3); whiptail_retval=$?
  #declare -p indice whiptail_retval
  #echo "Interface"
  echo "${arr[${indice}-1]}"
}
# Fim

################################################################################
# Função para habilitar funcionalidades do VIM
function _VIM()
{
  VIM="$HOME/.vimrc"

  mkdir -p ~/.vim/pack/plugins/start
  cd ~/.vim/pack/plugins/start
  git clone https://github.com/vim-airline/vim-airline.git
  git clone https://github.com/tomasiser/vim-code-dark.git
  git clone https://github.com/mhinz/vim-startify.git
  git clone https://github.com/preservim/nerdtree.git
  git clone https://github.com/Yggdroot/indentLine
  git clone https://github.com/preservim/nerdcommenter
  git clone https://github.com/sheerun/vim-polyglot

  # Adicionando opções no vimrc do usário logado
  echo -e "set bg=dark\nsyntax on\nset number\nset cursorline" > "$VIM"
  echo -e "set autoindent\nset smartindent"                   >> "$VIM"
  echo "set tabstop=2 softtabstop=2 expandtab shiftwidth=2"   >> "$VIM"
  echo "colorscheme codedark"                                 >> "$VIM"
  echo -e "\nlet g:indentLine_enabled = 1"                    >> "$VIM"
  echo "map <c-k>i :IndentLinesToggle<cr>"                    >> "$VIM"
  echo -e "\nfiletype plugin on"                              >> "$VIM"
  echo "let g:NERDSpaceDelims = 1"                            >> "$VIM"
  echo "let g:NERDDefaultAlign = 'left'"                      >> "$VIM"
  echo "map cc <Plug>NERDCommenterInvert"                     >> "$VIM"
}

###################################################INICIO###############################3##################
# Função para configurar o SAMBA
# Solicita informações para o usuario, realiza teste da entrada de dados
function _CONF_SAMBA
{
  FILE="/tmp/conf_samba.txt"

  if [ ! -e "$FILE" ] ; then
    #Criação do banco de dados de variaveis para uso do samba4
    echo > /tmp/samba.db

    clear
    IP_DC_PRIN=$(whiptail --title "Qual IP do servidor DC PRINCIPAL" --inputbox "Digite o Ip:" --fb 10 60 3>&1 1>&2 2>&3)
    testa_ip $IP_DC_PRIN

    echo "Testando a conexão"
    ping -c 3 $IP_DC_PRIN > /dev/null 2>&1
    if [[ $? -ne "0" ]]; then echo "Erro ao se comunicar com o IP $IP_DC_PRIN, Favor Verificar"; exit; fi
    echo "IP_DC_PRIN=$IP_DC_PRIN" >> /tmp/samba.db

    clear
    DOM_DC_PRIN=$(whiptail --title "Qual nome FQDN do DOMINO do DC principal" --inputbox "Exemplo corp.local, empresa.local:" --fb 10 60 3>&1 1>&2 2>&3)
    validar ${DOM_DC_PRIN}
    echo "DOM_DC_PRIN=$DOM_DC_PRIN">> /tmp/samba.db

    #Here document para criar arquivo de dns
    chattr -i /etc/resolv.conf
    cat > /etc/resolv.conf << EOF
search $DOM_DC_PRIN
nameserver $IP_DC_PRIN
EOF
    chattr +i /etc/resolv.conf

    clear
    NOME_DC_PRIN=$(whiptail --title "Qual hostname do DC Principal" --inputbox "Exemplo addc01, dc01, srvad:" --fb 10 60 3>&1 1>&2 2>&3)
    validar $NOME_DC_PRIN

    echo "Testando a conexão"
    ping -c 3 $NOME_DC_PRIN > /dev/null 2>&1
    if [[ $? -ne "0" ]]; then echo "Erro ao se comunicar com o HOSTNAME $NOME_DC_PRIN, Favor Verificar"; exit; fi
    echo "NOME_DC_PRIN=$NOME_DC_PRIN" >> /tmp/samba.db

    clear
    H_NAME=$(whiptail --title "Qual nome da Máquina atual" --inputbox "atual -> $(hostname -s):" --fb 10 60 3>&1 1>&2 2>&3)
    H_NAME=${H_NAME:=$(hostname)}
    validar ${H_NAME}
    echo "HOSTNAME=$H_NAME" >> /tmp/samba.db

    clear
    SENHA_DOM=$(whiptail --title "Qual a senha do admistrador do DOMINIO" --passwordbox "Usar senha complexa:" --fb 10 60 3>&1 1>&2 2>&3)
    SENHA_DOM=${SENHA_DOM:=Senha@123}
    testa_senha ${SENHA_DOM}
    echo "SENHA_DOM=$SENHA_DOM" >> /tmp/samba.db

    clear
    IP=`_IP`
    testa_ip ${IP}
    echo "IP=$IP" >> /tmp/samba.db

    clear
    MASK=$(whiptail --title "Qual mascára de rede" --inputbox "atual -> $(ip a | grep inet | grep -v inet6 | grep -v 127.0.0.* | awk '{print $2}' | cut -d "/" -f 2 | uniq):" --fb 10 60 3>&1 1>&2 2>&3)
    echo "Exemplo: Ex: 8 16 24"
    MASK=${MASK:=$(ip a | grep inet | grep -v inet6 | cut -d "/" -f 2 | egrep -o ^[0-9]{2} |head -n 1)}
    validar $MASK
    echo "Mascara=$MASK" >> /tmp/samba.db

    clear
    GW=$(whiptail --title "Qual endereco do Gateway" --inputbox "atual -> $(ip -o -4 route show to default | awk '{print $3}' | tail -n 1):" --fb 10 60 3>&1 1>&2 2>&3)
    GW=${GW:=$(ip -o -4 route show to default | cut -d " " -f 3 | head -n 1)}
    testa_ip $GW
    echo "GATEWAY=$GW" >> /tmp/samba.db

    clear
    DNS=$(whiptail --title "Qual endereco de DNS" --inputbox "Exemplo: 8.8.8.8, 8.8.4.4:" --fb 10 60 3>&1 1>&2 2>&3)
    DNS=${DNS:=1.1.1.1}
    testa_ip $DNS
    echo "DNS=$DNS" >> /tmp/samba.db

    clear
    INTER_FACE=`INTERFACE`

    echo "REDE=${INTER_FACE}" >> /tmp/samba.db

    clear
    # IP_COMPLETO=$(ip a | grep inet | grep -v inet6 | grep -v 127.0.0* | awk '{print $2}'
    NET=$(ipcalc --all-info ${IP} | grep -i network | awk '{print $2}')
    END_REDE=$(whiptail --title "Qual endereco da REDE e MASCARA usar formato IP/MASCARA" --inputbox "Atual -> ${NET}:" --fb 10 60 3>&1 1>&2 2>&3)
    END_REDE=${END_REDE:=${NET}}
    echo "END_REDE=$END_REDE" >> /tmp/samba.db

    clear
    whiptail --title "Dados informados pelo usuario" --textbox /tmp/samba.db  20 65

    whiptail --title "Deseja continuar" --yesno "Os dados estao corretos SIM ou Nao." 10 50
    if [[ $? -eq 1 ]] ; then tput setaf 1; tput setab 7 ; echo -e "Saindo\nFavor executar novamente o script" ; tput sgr0 ; exit; fi

    hostnamectl set-hostname $H_NAME
    H_NAME_SHORT=$(grep -i "dom_dc_prin" /tmp/samba.db | cut -d "=" -f 2 |cut -d "." -f 1)

# nmcli connection show | grep ${INTER_FACE} | grep -oz [[:xdigit:]]*-[[:xdigit:]]*

    cat >> /etc/hosts << EOF
${IP%/*} $H_NAME.$DOM_DC_PRIN $H_NAME.$H_NAME_SHORT $H_NAME
EOF
    #Here document para criar arquivo de rede
    cat > /etc/sysconfig/network-scripts/ifcfg-${INTER_FACE} << EOF
TYPE=Ethernet
PROXY_METHOD=none
BROWSER_ONLY=no
BOOTPROTO=none
DEFROUTE=yes
IPV4_FAILURE_FATAL=no
IPV6INIT=yes
IPV6_AUTOCONF=yes
IPV6_DEFROUTE=yes
IPV6_FAILURE_FATAL=no
IPV6_ADDR_GEN_MODE=stable-privacy
UUID=$(nmcli connection show | grep ${INTER_FACE} | rev | awk '{print $3}' |rev)
NAME=${INTER_FACE}
DEVICE=${INTER_FACE}
ONBOOT=yes
IPADDR=$IP
PREFIX=$MASK
GATEWAY=$GW
EOF
  #Reiniciar rede
  systemctl restart NetworkManager
  echo "Configuracao realizada, função executada foi _CONF_SAMBA" | tee > $FILE
  else
    echo "Configuracao realizada, para repetir a instalacao remover esse arquivo $FILE"
  fi
}
################################################################################
################################################################################
#Função para instalação das dependecias do samba4
_SAMBA_DEP()
{
  FILE="/tmp/samba_dep.txt"
  if [ ! -e "$FILE" ] ; then
  clear

  #Pacotes necessários
  yum install epel-release.noarch yum-utils "@Development Tools" -y
  yum config-manager --set-enabled PowerTools
  yum update -y && yum upgrade -y

  # Pacotes para necessários para instalar o samba
  yum install docbook-style-xsl gcc gdb gnutls-devel gpgme-devel jansson-devel \
      keyutils-libs-devel krb5-workstation libacl-devel libaio-devel \
      libarchive-devel libattr-devel libblkid-devel libtasn1 libtasn1-tools \
      libxml2-devel libxslt lmdb-devel openldap-devel pam-devel perl \
      perl-ExtUtils-MakeMaker perl-Parse-Yapp popt-devel python3-cryptography \
      python3-dns python3-gpg python36-devel readline-devel rpcgen systemd-devel \
      tar zlib-devel wget krb5-devel -y

  # Versão homologada para a instalação
  cd /opt

  wget https://download.samba.org/pub/samba/stable/samba-4.12.5.tar.gz
  tar -zxvf /opt/samba-4.*.gz -C /opt

  cd /opt/samba-4.12.5

  # Flags de compilação
  CFLAGS="-I/usr/include/tirpc" ./configure -j `nproc` \
  --enable-coverage --disable-cups\
  --with-systemd --systemd-install-services \
  --with-systemddir=/usr/lib/systemd/system \
  --prefix=/usr/local/samba4 \
  --with-pammodulesdir=/usr/lib64/security \
  --sysconfdir=/usr/local/samba4/conf

  make -j $(nproc)
  make install

  find /usr/local/samba4/lib -type d > /etc/ld.so.conf.d/samba4.conf
  echo "/usr/local/samba4/lib64" >> /etc/ld.so.conf.d/samba4.conf

  ldconfig && ldconfig && ldconfig && ldconfig

# Here document
  cat > /etc/profile.d/samba4.sh << EOF
if [ $(id -u) -eq 0 ]
then
  PATH="/usr/local/samba4/sbin:$PATH"
fi

PATH="/usr/local/samba4/bin:$PATH"
export PATH
EOF

  # Recarregar perfil
  source /etc/profile.d/samba4.sh
  systemctl daemon-reload

  echo "exclude=samba*" >> /etc/yum.conf
  echo "Configuracao realizada, função executada foi _SAMBA_DEP" | tee > $FILE
  else
    echo "Configuracao realizada, para repetir a instalacao remover esse arquivo $FILE"
  fi
}
##################################################################################
_SAMBA_INST()
{
  if [[ ! -e /tmp/samba.db ]] || [[ ! -s /tmp/samba.db ]]; then
    echo "samba.db não existe!, verificar a funcao SAMBA_DEP  "
    exit 50
  fi

  FILE="/tmp/samba_inst.txt"
  if [ ! -e "$FILE" ] ; then

      _VIM

      clear

      REINO=$(grep -i "dom_dc_prin" /tmp/samba.db | cut -d "=" -f 2)
      NOME_DC_PRIN=$(grep -i "NOME_DC_PRIN" /tmp/samba.db | cut -d "=" -f 2)
      SENHA_DOM=$(grep -i "SENHA_DOM" /tmp/samba.db | cut -d "=" -f 2)
      DC_JOIN=$(grep -i "dom_dc_prin" /tmp/samba.db | cut -d "=" -f 2)
      IP_DC_PRIN=$(grep -i "ip_dc_prin" /tmp/samba.db | cut -d "=" -f 2)
      H_NAME=$(hostname -s)
      IP=$(hostname -I | sed  s'\ \\')
      WORK=$(grep -i "dom_dc_prin" /tmp/samba.db | cut -d "=" -f 2 | cut -d "." -f 1)

      source /etc/profile.d/samba4.sh
      mv /etc/krb5.conf{,.bkp}

      # Criando arquivos de logs
      mkdir -p /var/log/samba
      touch /var/log/krb5.log
      touch /var/log/samba/log.smbd

      cat > /etc/krb5.conf << EOF
[logging]
  default = FILE:/var/log/krb5.log

[libdefaults]
  default_realm = ${REINO^^}
  dns_lookup_realm = false
  dns_lookup_kdc = true

[kdc]
  check-ticket-addresses = false

[realms]
  ${REINO^^} = {
  kdc = ${NOME_DC_PRIN}.${REINO}
  admin_server = ${NOME_DC_PRIN}.${REINO}
  default_domain = ${REINO^^}
}

[domain_realm]
  .${REINO} = ${REINO^^}
  ${REINO} = ${REINO^^}
EOF

      /usr/local/samba4/sbin/smbd -b | grep "CONFIGFILE" >> /tmp/samba.db
      /usr/local/samba4/sbin/smbd -b | egrep "LOCKDIR|STATEDIR|CACHEDIR|PRIVATE_DIR" >> /tmp/samba.db
      SMB_CONF=$(/usr/local/samba4/sbin/smbd -b | grep "CONFIGFILE" | awk '{print $2}') >> /tmp/samba.db

      if [ ! -f /usr/bin/python3 ]; then
        ln -sf /usr/bin/python3.6 /usr/bin/python3
      fi

      cat > ${SMB_CONF} << EOF
[global]
        netbios name = ${H_NAME^^}
        realm = ${REINO^^}
        server role = member
        workgroup = ${WORK^^}
        idmap_ldb:use rfc2307 = yes
        template shell = /bin/bash
        template homedir = /home/%U
        winbind enum users = yes
        winbind enum groups = yes
        winbind use default domain = yes
        ntlm auth = yes
        winbind nss info = rfc2307
        vfs objects = acl_xattr, recycle
        map acl inherit = Yes
        store dos attributes = Yes
        max log size = 100
        log file = /var/log/samba/log.%m
        encrypt passwords = yes
        security = ADS
        ntlm auth = yes
        ldap server require strong auth = no
        nt acl support = yes
        winbind gid = 10000-20000
EOF

      cp /etc/nsswitch.conf{,.bkp}

      cat >> /etc/nsswitch.conf << EOF
passwd:     files winbind
shadow:     files winbind
group:      files winbind
EOF

      clear

      echo "Validando ticket do DC"
      /usr/bin/kinit Administrator
      echo -e "\n\nListando Ticket no DC"
      /usr/bin/klist

      DC_PRIN=$(grep "DOM_DC" /tmp/samba.db |cut -d "=" -f 2)

      clear
      echo "Adicionando ao dominio $DC_PRIN"
      /usr/local/samba4/bin/net ads join -U Administrator ${DC_PRIN}
      sleep 3

      systemctl enable winbind smb nmb
      systemctl restart winbind smb nmb
      systemctl mask samba.service

      net rpc rights grant "$WORK\Domain Admins" SeDiskOperatorPrivilege -U "$WORK\administrator%$SENHA_DOM"
      net rpc rights list privileges SeDiskOperatorPrivilege -U "$WORK\administrator%$SENHA_DOM"

      smbcontrol all reload-config

      rm -rf /opt/samba*
      echo "Configuracao realizada, função executada foi _SAMBA_INST" | tee > $FILE
      reboot
  else
        echo "Configuracao realizada, para repetir a instalacao remover esse arquivo $FILE"
  fi
}

clear
_VERIFICAR_ROOT
_CONFIGURAR
_CONF_SAMBA
_SAMBA_DEP
_SAMBA_INST
