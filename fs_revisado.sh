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

    echo "Configuracao realizada, função executada _CONFIGURAR" | tee > "$FILE"
  else
    echo "Configuracao realizada, para repetir a instalacao remover $FILE"
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
      tput setaf 1; tput setab 7
      echo "Erro ao digitar IP $1, Favor Verificar"; tput sgr0
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
      tput setaf 1; tput setab 7
      echo "Erro ao validar informação ${1}, Favor Verificar"; tput sgr0
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
      echo "Senha nao atende complexidade necessario 01 de cada item abaixo:
            letra Maiuscula, Minuscula, Caracter especial, digito numerico
            Exemplo: Teste@123, P@\$\$word.1"
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
    10 80 "${#arr[@]}"
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
function _VIM()
{
  VIM="$HOME/.vimrc"
  FILE="/tmp/conf_vim.txt"
  if [ ! -e "$FILE" ] ; then
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
    echo "Configuracao realizada, função executada _CONF_SAMBA" | tee > $FILE
  else
    echo "Configuracao realizada, para repetir a instalacao remover $FILE"
  fi
}
# Fim

################################################################################
###                             INICIO                                       ###
# Função para configurar o SAMBA
# Solicita informações para o usuario, realiza teste da entrada de dados
function _CONF_SAMBA
{
  FILE="/tmp/conf_samba.txt"

  if [ ! -e "$FILE" ] ; then
    #Criação do banco de dados de variaveis para uso do samba4
    echo > /tmp/samba_info.db

    clear
    H_NAME=$(whiptail --title "Qual nome da Máquina atual" \
            --inputbox "atual -> $(hostname -s):" --fb 10 60 3>&1 1>&2 2>&3)

    H_NAME=${H_NAME:=$(hostname)}
    validar ${H_NAME}
    echo "HOSTNAME=$H_NAME" >> /tmp/samba_info.db

    clear
    IP=`_IP`
    testa_ip ${IP}
    echo "IP=$IP" >> /tmp/samba_info.db

    clear
    MASK=$(whiptail --title "Qual mascára de rede" \
          --inputbox "atual -> $(ip a | grep inet | grep -v inet6 | grep -v 127.0.0.* | awk '{print $2}' | cut -d "/" -f 2 | uniq):" \
          --fb 10 60 3>&1 1>&2 2>&3)

    echo "Exemplo: Ex: 8 16 24"
    MASK=${MASK:=$(ip a | grep inet | grep -v inet6 | cut -d "/" -f 2 | egrep -o ^[0-9]{2} |head -n 1)}
    validar $MASK
    echo "Mascara=$MASK" >> /tmp/samba_info.db

    clear
    GW=$(whiptail --title "Qual endereco do Gateway" \
        --inputbox "atual -> $(ip -o -4 route show to default | awk '{print $3}' | tail -n 1):" \
        --fb 10 60 3>&1 1>&2 2>&3)

    GW=${GW:=$(ip -o -4 route show to default | cut -d " " -f 3 | head -n 1)}
    testa_ip $GW
    echo "GATEWAY=$GW" >> /tmp/samba_info.db

    clear
    DNS=$(whiptail --title "Qual endereco de DNS" \
        --inputbox "Exemplo: 8.8.8.8, 8.8.4.4:" --fb 10 60 3>&1 1>&2 2>&3)

    DNS=${DNS:=1.1.1.1}
    testa_ip $DNS
    echo "DNS=$DNS" >> /tmp/samba_info.db

    clear
    INTER_FACE=`INTERFACE`

    echo "REDE=${INTER_FACE}" >> /tmp/samba_info.db

    clear
    # IP_COMPLETO=$(ip a | grep inet | grep -v inet6 | grep -v 127.0.0* | awk '{print $2}'
    NET=$(ipcalc --all-info ${IP} | grep -i network | awk '{print $2}')
    END_REDE=$(whiptail --title "Qual endereco da REDE e MASCARA usar formato IP/MASCARA" \
             --inputbox "Atual -> ${NET}:" --fb 10 60 3>&1 1>&2 2>&3)

    END_REDE=${END_REDE:=${NET}}
    echo "END_REDE=$END_REDE" >> /tmp/samba_info.db

    clear
    whiptail --title "Dados informados pelo usuario" \
             --textbox /tmp/samba_info.db  20 65

    whiptail --title "Deseja continuar" \
             --yesno "Os dados estao corretos SIM ou Nao." 10 50

   if [[ $? -eq 1 ]]
        then tput setaf 1; tput setab 7
        echo -e "Saindo\nFavor executar novamente o script" ; tput sgr0
        exit;
   fi

    hostnamectl set-hostname $H_NAME

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
IPADDR=${IP%/*}
PREFIX=$MASK
GATEWAY=$GW
EOF
  #Reiniciar rede
  systemctl restart NetworkManager
  sleep 2
  echo "Configuracao realizada, função executada foi _CONF_SAMBA" | tee > $FILE
  else
    echo "Configuracao realizada, para repetir a instalacao remover $FILE"
  fi
}
# Fim
################################################################################

#Função para instalação das dependecias do samba4
_SAMBA_DEP()
{
  FILE="/tmp/samba_dep.txt"

  if [ ! -e "$FILE" ] ; then
  clear
  #Pacotes necessários
  yum update -y
  yum install -y dnf-plugins-core
  yum install -y epel-release

  yum config-manager --set-enabled PowerTools -y
  yum config-manager --set-enabled Devel -y
  yum update -y

  # Pacotes SAMBA
    yum install -y                                                             \
      --setopt=install_weak_deps=False "@Development Tools"                    \
      acl attr autoconf avahi-devel bind-utils binutils bison ccache chrpath   \
      cups-devel curl dbus-devel docbook-dtds docbook-style-xsl flex gawk gcc  \
      gdb git glib2-devel glibc-common glibc-langpack-en glusterfs-api-devel   \
      glusterfs-devel gnutls-devel gpgme-devel gzip hostname jansson-devel     \
      htop keyutils-libs-devel krb5-devel krb5-server libacl-devel wget tar    \
      libarchive-devel libattr-devel libblkid-devel libbsd-devel libcap-devel  \
      libcephfs-devel libicu-devel libnsl2-devel libpcap-devel libtasn1-devel  \
      libtasn1-tools libtirpc-devel libunwind-devel libuuid-devel libxslt      \
      lmdb lmdb-devel make mingw64-gcc ncurses-devel openldap-devel pam-devel  \
      patch perl perl-Archive-Tar perl-ExtUtils-MakeMaker perl-Parse-Yapp      \
      perl-Test-Simple perl-generators perl-interpreter pkgconfig procps-ng    \
      python3 python3-cryptography python3-devel python3-dns python3-gpg       \
      python3-libsemanage  python3-policycoreutils python3-pyasn1 rpcgen       \
      quota-devel readline-devel redhat-lsb rng-tools rpcsvc-proto-devel       \
      systemd-devel popt-devel tree which xfsprogs-devel yum-utils             \
      zlib-devel rsync sed sudo python3-markdown psmisc bind krb5-workstation

yum clean all

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
  find /usr/local/samba4/ -type d -iname lib64 >> /etc/ld.so.conf.d/samba4.conf
  /usr/sbin/ldconfig

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
    echo "Configuracao realizada, para repetir a instalacao remover $FILE"
  fi
}

############################    INSTALANDO SAMBA   #############################
_SAMBA_INST()
{
  if [[ ! -e /tmp/samba_info.db ]] || [[ ! -s /tmp/samba_info.db ]]; then
    echo "Arquivo samba_info.db não existe!, verificar a funcao SAMBA_DEP  "
    exit
  fi

  FILE="/tmp/samba_inst.txt"
  PATH_SAMBA=$(find /usr -type d -iname samba4 | grep samba4)

  if [ ! -e "$FILE" ] ; then

    source /etc/profile.d/samba4.sh

    clear
    SAMBA_DOM=$(whiptail --title "Inicio de configuracao do SAMBA" \
              --inputbox "Informar o DOMINIO EX: LAB.LOCAL, EMPRESA.LOCAL" --fb 10 60 3>&1 1>&2 2>&3)

    validar "${SAMBA_DOM^^}"

    clear
    SENHA=$(whiptail --title "Qual a senha do admistrador do DOMINIO" \
          --passwordbox "Usar senha complexa:" --fb 10 60 3>&1 1>&2 2>&3)

    SENHA=${SENHA:=Senha@123}
    testa_senha ${SENHA}

    SAMBA_REINO=(${SAMBA_DOM%%.*})
    clear

    echo "" > /tmp/samba.db
    echo "DOMINIO=${SAMBA_DOM}"     >> /tmp/samba.db
    echo "REINO..=${SAMBA_REINO}"   >> /tmp/samba.db
    echo "SENHA..=${SENHA}"         >> /tmp/samba.db

    clear
    whiptail --title "Dados informados:" --textbox /tmp/samba.db  20 65

    whiptail --title "Deseja continuar" \
             --yesno "Os dados estao corretos SIM ou Nao." 10 50

    if [[ $? -eq 1 ]]
      then tput setaf 1; tput setab 7 ;
      echo -e "Saindo\nFavor executar novamente o script" ; tput sgr0
      exit
    fi

    SAMBA_TOOL=$(find /usr -iname samba-tool)
    "$SAMBA_TOOL" domain provision --server-role=dc --use-rfc2307 --dns-backend=BIND9_DLZ --realm=${SAMBA_DOM^^} --domain=${SAMBA_REINO^^} --adminpass=$SENHA

    sed -i 's/^passwd.*/passwd:\ files\ winbind/g' /etc/nsswitch.conf
    sed -i 's/^group.*/group:\ files\ winbind/g' /etc/nsswitch.conf

    # Instala chrony e atualiza a hora
    CHRONY_CONF=$(find /etc/ -type f -iname chrony.conf)
    cp "$CHRONY_CONF"{,.bkp}


    cat > "$CHRONY_CONF" << EOF
server a.st1.ntp.br iburst
server b.st1.ntp.br iburst
server a.ntp.br iburst
server b.ntp.br iburst

driftfile /var/lib/chrony/drift
makestep 1.0 3
rtcsync
keyfile /etc/chrony.keys
logdir /var/log/chrony
log measurements statistics tracking
maxupdateskew 100.0
hwclockfile /etc/adjtime

bindcmdaddress $(grep -i ip /tmp/samba_info.db | cut -d "=" -f 2 | cut -d "/" -f 1)
allow $(grep -i end_rede /tmp/samba_info.db |cut -d "=" -f 2)

ntpsigndsocket $PATH_SAMBA/var/lib/ntp_signd
EOF
    # Criar arquivos para uso do servidor de horas
    mkdir -p $PATH_SAMBA/var/lib/ntp_signd/
    chmod 0750 $PATH_SAMBA/var/lib/ntp_signd/
    chown root.chrony $PATH_SAMBA/var/lib/ntp_signd/
    systemctl enable --now chronyd

    # Criar arquivos para o do bind9
    touch /var/named/data/named_mem_stats.txt
    touch /var/named/data/named_stats.txt
    touch /var/named/data/cache_dump.db
    chown named.named /var/named -R
    cp $PATH_SAMBA/bind-dns/named.conf{,.bkp}
    chown named.named $PATH_SAMBA/bind-dns/named.conf
    chown named.named $PATH_SAMBA/bind-dns -R

    NAMED_VERSION=$(rpm -qa bind |cut -d "-" -f 2 |cut -d "." -f 2)
    echo "$NAMED_VERSION"

    if [ $NAMED_VERSION -eq 10 ]
         then
            echo "dlz \"AD DNS Zone\" {" > $PATH_SAMBA/bind-dns/named.conf
            echo "database \"dlopen $PATH_SAMBA/lib/bind9/dlz_bind9_${NAMED_VERSION}.so\";" >> $PATH_SAMBA/bind-dns/named.conf
            echo "};" >> $PATH_SAMBA/bind-dns/named.conf
    fi


    if [ $NAMED_VERSION -eq 11 ]
         then
            echo "dlz \"AD DNS Zone\" {" > $PATH_SAMBA/bind-dns/named.conf
            echo "database \"dlopen $PATH_SAMBA/lib/bind9/dlz_bind9_${NAMED_VERSION}.so\";" >> $PATH_SAMBA/bind-dns/named.conf
            echo "};" >> $PATH_SAMBA/bind-dns/named.conf
    fi


    if [ $NAMED_VERSION -eq 12 ]
        then
            echo "dlz \"AD DNS Zone\" {" > $PATH_SAMBA/bind-dns/named.conf
            echo "database \"dlopen $PATH_SAMBA/lib/bind9/dlz_bind9_${NAMED_VERSION}.so\";" >> $PATH_SAMBA/bind-dns/named.conf
            echo "};" >> $PATH_SAMBA/bind-dns/named.conf
    fi

    cp /etc/named.conf{,.bkp}

    cat > /etc/named.conf << EOF
options {
  listen-on port 53 { any; };
  listen-on-v6 port 53 { none; };
  directory "/var/named";
  dump-file "/var/named/data/cache_dump.db";
  statistics-file "/var/named/data/named_stats.txt";
  memstatistics-file "/var/named/data/named_mem_stats.txt";
  allow-query { any; };

  recursion yes;
  allow-recursion { any; };

  allow-transfer { none; };

  dnssec-enable no;
  dnssec-validation no;

  managed-keys-directory "/var/named/dynamic";
  pid-file "/run/named/named.pid";
  tkey-gssapi-keytab "$PATH_SAMBA/bind-dns/dns.keytab";

  forwarders {
         1.1.1.1;
         8.8.8.8;
  };

};

logging {
  channel default_debug {
    file "data/named.run";
    severity dynamic;
  };
};

zone "." IN {
  type hint;
  file "named.ca";
};

include "/etc/named.rfc1912.zones";
include "/etc/named.root.key";
include "/usr/local/samba4/bind-dns/named.conf";
EOF

    echo "KRB5RCACHETYPE=\"none\"" >> /etc/sysconfig/named

    echo -e "\n[kdc]" >> "$PATH_SAMBA"/private/krb5.conf
    echo -e "\tcheck-ticket-addresses = false" >> "$PATH_SAMBA"/private/krb5.conf

    mv /etc/krb5.conf{,.bkp}
    cp "$PATH_SAMBA"/private/krb5.conf /etc/

    systemctl enable --now named
    clear

    IP=$(grep -i "ip" /tmp/samba_info.db | cut -d "=" -f 2 | cut -d "/" -f1)
    DOM=$(grep -i "dominio" /tmp/samba.db | cut -d "=" -f 2)

    chattr -i /etc/resolv.conf

    cat > /etc/resolv.conf << EOF
search ${DOM,,}
nameserver $IP
EOF

    chattr +i /etc/resolv.conf
    HN=$(grep -i hostname /tmp/samba_info.db | cut -d "=" -f 2)

    cat >> /etc/hosts << EOF
$IP $HN $HN.${DOM,,}
EOF

    cp $PATH_SAMBA/conf/smb.conf{,.bkp}

    sed -i '26i dns=none' /etc/NetworkManager/NetworkManager.conf

    cat > /lib/systemd/system/samba-dc.service << EOF
[Unit]
Description= Samba 4 Active Directory
After=syslog.target network.target remote-fs.target nss-lookup.target

[Service]
Type=forking
LimitNOFILE=16384
ExecStart=/usr/local/samba4/sbin/samba -D
ExecReload=/usr/bin/kill -HUP $MAINPID
PIDFile=/usr/local/samba4/var/run/samba.pid

[Install]
WantedBy=multi-user.target
EOF

    systemctl enable --now samba-dc

    "$PATH_SAMBA"/sbin/samba_dnsupdate --verbose

    clear
    echo "Validando o ticket"
    /usr/bin/kinit Administrator

    echo "Mostrando o ticket"
    /usr/bin/klist
    sleep 5

cat > /usr/local/samba4/conf/smb.conf << EOF
[global]
        netbios name = $HN
        realm = ${SAMBA_DOM^^}
        server role = active directory domain controller
        server services = s3fs, rpc, nbt, wrepl, ldap, cldap, kdc, drepl, winbindd, ntp_signd, kcc, dnsupdate
        workgroup = ${SAMBA_REINO^^}
        idmap_ldb:use rfc2307 = yes
        #bind interfaces only = yes
        template shell = /bin/bash
        template homedir = /home/%U
        winbind enum users = yes
        winbind enum groups = yes
        winbind use default domain = yes
        ntlm auth = yes
        ldap server require strong auth = no
        winbind nss info = rfc2307
        vfs objects = acl_xattr, recycle, dfs_samba4
        map acl inherit = Yes
        store dos attributes = Yes

[sysvol]
        path = $PATH_SAMBA/var/locks/sysvol
        read only = No

[netlogon]
        path = $PATH_SAMBA/var/locks/sysvol/${SAMBA_DOM,,}/scripts
        read only = No
EOF

  clear
  whiptail --title "Dados informados pelo usuario" --textbox /usr/local/samba4/conf/smb.conf  40 120 --scrolltext
  whiptail --title "Deseja continuar" --yesno "Os dados estao corretos SIM ou Nao." 10 50
  if [[ $? -eq 1 ]]
    then tput setaf 1; tput setab 7
    echo -e "Saindo\nFavor executar novamente o script"
    tput sgr0
    exit
  fi

  clear

  "$PATH_SAMBA"/bin/samba-tool domain passwordsettings set --complexity=off
  "$PATH_SAMBA"/bin/samba-tool domain passwordsettings set --history-length=0
  "$PATH_SAMBA"/bin/samba-tool domain passwordsettings set --min-pwd-age=0
  "$PATH_SAMBA"/bin/samba-tool domain passwordsettings set --max-pwd-age=0
  "$PATH_SAMBA"/bin/samba-tool domain passwordsettings show

  "$PATH_SAMBA"/bin/net rpc rights grant "${SAMBA_REINO^^}\Domain Admins" SeDiskOperatorPrivilege -U"${SAMBA_REINO^^}\administrator%$SENHA"
  "$PATH_SAMBA"/bin/net rpc rights list accounts -U"${SAMBA_REINO}\administrator%$SENHA"

  /usr/local/samba4/bin/smbcontrol all reload-config

  which figlet > /dev/null || yum install figlet 2> /dev/null
  clear
  echo "Favor criar a zona reversa e adicionar a rede no Services and Sites new subnet" | figlet -cf standard

  cat > /srv/named.sh << EOF
#!/bin/bash

sleep 45
systemctl restart named.service
echo "named restart" >> /tmp/named.
EOF

  echo -e "@reboot /srv/named.sh\n" >> /var/spool/cron/root
  chmod +x /srv/named.sh
  echo "Configuracao realizada, função executada foi _SAMBA_DEP" | tee > $FILE
  reboot
else
      echo "Configuracao realizada, para repetir a instalacao remover $FILE"
fi
}

#####Principal

#Funções
_VERIFICAR_ROOT
_CONFIGURAR
_VIM
_CONF_SAMBA
_SAMBA_DEP
_SAMBA_INST
