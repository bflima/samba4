#!/usr/bin/env bash

#!/usr/bin/env bash

## samba_dc.sh - Insere maquina no AD, para criação de file server
## Escrito por: Bruno Lima
## E-mail: bfdonga@gmail.com
## Centos 8 GNU/Linux

# Exemplo de uso: ./samba_4.13_dc.sh

# Funcionamento:
# Script instala dependencias necessarias para uso do samba 
# Posteiormente realiza a inclussão no domnínio Active Directory, para ser usado
# Como servidor de arquivos

################################################################################
###                        Declaração de funções                             ###
################################################################################


# Função para verificar se o script está com privilegios de root, Caso não estiver finaliza o programa
_VERIFICAR_ROOT()
{
  [ "$EUID" -eq 0 ] || { tput setaf 1; tput setab 7; \
    echo "ERRO: Necessita acesso root para rodar o script $0"; tput sgr0; exit; }
}
# Fim

################################################################################
# Função para testar ip fornecido, utiliza programa auxiliar ipcalc
# Se o retorno for diferente de sucesso ou tamanho igual a zero sai do programa
function testa_ip()
{
  LOG_ERRO="/tmp/erro_inicial.txt"
  which ipcalc 1> /dev/null 2>> $LOG_ERRO || yum -y install ipcalc 1> /dev/null 2>> $LOG_ERRO
  IPCALC=$(which ipcalc) 1> /dev/null 2>> $LOG_ERRO
  if ! "$IPCALC" -c "$1" ; then { tput setaf 1; tput setab 7 ; echo "Erro ao digitar IP $1, Favor Verificar"; tput sgr0; exit 1 ; } fi
}
# Fim

################################################################################
# Função para validar ip reverso para criação do dns
function _REVERSO()
{
  IP=$(grep -i "ip" /tmp/samba.db | cut -d "=" -f 2)
  ARPA="in-addr.arpa"
  RES=$(ipcalc -p "${IP}")

  if [[ ${RES##*=} -ge "17" ]] && [[ ${RES##*=} -le "24" ]]
    then
      IP1=$(cut -d"." -f 1 <<< "${IP}")
      IP2=$(cut -d"." -f 2 <<< "${IP}")
      IP3=$(cut -d"." -f 3 <<< "${IP}")
      REV=("${IP3}"\."${IP2}"\."${IP1}"\."${ARPA}")

 elif [[ ${RES##*=} -ge "9" ]] && [[ ${RES##*=} -le "16" ]]
    then
      IP1=$(cut -d"." -f 1 <<< "${IP}")
      IP2=$(cut -d"." -f 2 <<< "${IP}")
      REV=("${IP2}"\."${IP1}"\."${ARPA}")

  else [[ ${RES##*=} -ge "1" ]] && [[ ${RES##*=} -le "8" ]]
      IP1=$(cut -d"." -f 1 <<< "${IP}")
      REV=("${IP1}"\."${ARPA}")

  fi
  echo "${REV[@]}"
}
# Fim

################################################################################
# Função para validar entrada dos campos digitados pelo usuario
# Se o retorno for diferente de sucesso ou tamanho igual a zero sai do programa
function validar()
{
	if [[ "$?" -ne "0" || ${#1} -eq "0" ]]
    then
      tput setaf 1; tput setab 7
      echo "Erro ao validar informação ${1}, Favor Verificar"
      tput sgr0
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
  if [ "$LEN" -lt 8 ]; then { echo "Senha menor que 8"; exit; } fi

  b=$(echo "$a" | grep -E "^.{8,255}" | \
                  grep -E "[ABCDEFGHIJKLMNOPQRSTUVWXYZ]" | \
                  grep -E "[abcdefghijklmnopqrstuvwxyz"] | \
                  grep -E "[0-9]" | \
                  grep -E "[\@\.\!\$\%\&\*\?\<\>\+\=\_\-]")

# Letras alfabeticas
#Se o resultado for vazio ou, uma condição tenha falhada
  if [ -z "$b" ]
    then
      tput bold
      cat << EOF
      Senha nao atende criterio de complexidade:
      Necessario 01 de cada item 
      letra Maiuscula
      letra Minuscula
      Caracter especial
      Digito numerico
      Exemplo: Teste@123, P@\$\$word.1"
EOF
      tput sgr0
      exit 50
  else
      echo "Senha validada com sucesso"
  fi
}
# Fim

################################################################################
# Função para escolher interface de rede caso exista mais de uma
# Gerado uma lista com os nomes das interfaces de rede, caso existir mais de um.
function _INTERFACE()
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

  indice=$(whiptail "${whiptail_args[@]}" 3>&1 1>&2 2>&3)
  #whiptail_retval=$?
  #declare -p indice whiptail_retval
  #echo "Interface"
  echo "${arr[${indice}-1]}"
}

# Fim

################################################################################
# Função para escolher ip
# Gerado uma lista com os nomes dos endereços ips, caso existir mais de um.
function _IP()
{
  TMP=$(ip a | grep -E "inet[[:space:]]" |grep -v 127 | awk '{print $2}')
  TM=$(ip a  | grep -E "inet[[:space:]]" |grep -v 127 | awk '{print $2}' | head -n 1)

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

  indice=$(whiptail "${whiptail_args[@]}" 3>&1 1>&2 2>&3)
  #whiptail_retval=$?
  #declare -p indice whiptail_retval
  #echo "Interface"
  echo "${arr[${indice}-1]}"
}
# Fim

################################################################################
# Função para configuração de pacotes e ajuste no chrony
function _CONFIGURAR()
{
  _VERIFICAR_ROOT
  FILE="/tmp/configurar.txt"
  if [ ! -e "$FILE" ] ; then
    LOG_ERRO="/tmp/erro_inicial.txt"
    SE_LINUX="/etc/selinux/config"

    # Desabilitar o firewalld
    systemctl stop firewalld 2>> $LOG_ERRO && systemctl disable firewalld 2>> $LOG_ERRO
    
    # Desabilitar SELINUX
    cp $SE_LINUX{,.bak}
    sed -i 's/^SELINUX=.*/SELINUX=disabled/g' $SE_LINUX
    setenforce 0

    #Atualizar sistema
    yum -y update && yum -y upgrade

    #Pacotes necessários
    curl -s https://gitlab.com/samba-team/devel/samba/-/raw/master/bootstrap/generated-dists/centos8/bootstrap.sh?inline=false -o /tmp/bootstrap.sh
    bash /tmp/bootstrap.sh

    #Instalar repositorio EPEL e ferramentas de desenvolvimento e pacotes úteis
    yum install vim dialog net-tools figlet wget bash-completion chrony htop bind-utils bind expect yum-utils krb5-workstation -y

    # Instala chrony e atualiza a hora
    CHRONY_CONF=$(find /etc/ -type f -iname chrony.conf)
    cp "$CHRONY_CONF"{,.bkp}
    sed -i 's/^pool.*/server\ a.ntp.br\ iburst/' "$CHRONY_CONF"
    sed -i '4s/^/server\ b.ntp.br\ iburst\n/'    "$CHRONY_CONF"
    sed -i 's/^#allow.*/allow\ 0.0.0.0\/0/'      "$CHRONY_CONF"

    #Inicializando chronyd e habilitando serviço
    systemctl enable chronyd --now 1> /dev/null 2>> $LOG_ERRO

    #Compilando Samba4 Versão homologada para a instalação
    VERSAO="4.13.0"
    wget https://download.samba.org/pub/samba/stable/samba-"$VERSAO".tar.gz

    tar -zxvf samba-"$VERSAO".tar.gz -C /opt

    cd /opt/samba-$VERSAO || { tput setaf 1; tput setab 7 ; echo "Erro ao acessar diretorio"; tput sgr0; exit 1 ; }

    # Flags de compilação
    CAMINHO_SAMBA="/usr/local/samba"
    
    CFLAGS="-I/usr/include/tirpc" ./configure -j "$(nproc)" \
    --enable-coverage --disable-cups\
    --with-systemd --systemd-install-services \
    --with-systemddir=/usr/lib/systemd/system \
    --prefix="$CAMINHO_SAMBA" \
    --with-pammodulesdir=/usr/lib64/security \
    --sysconfdir="$CAMINHO_SAMBA"/conf
    
    make -j "$(nproc)"
    make install

    find "$CAMINHO_SAMBA"/lib -type d > /etc/ld.so.conf.d/samba4.conf
    echo "$CAMINHO_SAMBA"/lib64 >> /etc/ld.so.conf.d/samba4.conf
    ldconfig

    echo export PATH="$CAMINHO_SAMBA"/bin:"$CAMINHO_SAMBA"/sbin:"${PATH}" >> /etc/profile

    echo "exclude=samba*" >> /etc/yum.conf

    echo "Configuracao realizada, função executada $FILE" | tee > "$FILE"
  else
    echo "Configuracao realizada, para repetir a instalacao remover o arquivo $FILE"
  fi
}
# Fim

################################################################################
function _CONF_SAMBA()
{
  _VERIFICAR_ROOT
  FILE="/tmp/conf_samba.txt"

  if [ ! -e "$FILE" ] ; then
    LOG_ERRO="/tmp/erro_conf_samba.txt"
    clear

    #Definição e criação do banco de dados de variáveis para uso do samba4
    SAMBA_DB="/tmp/samba.db"

    echo "Samba Info" > $SAMBA_DB

    # Veririca se o arquivo foi criado com sucesso, caso contrario sai do programa
    if [ ! -e "$SAMBA_DB" ] ; then { echo "Erro ao criar arquivo $SAMBA_DB, Favor Verificar"; exit; } fi

    IP_SAMBA=$(whiptail --title "Servidor Samba " \
    --inputbox "Digite o endereco Ip. Atual $(hostname -I | sed 's/ //'):"                  \
    --fb 10 60 3>&1 1>&2 2>&3) 1> /dev/null 2>> $LOG_ERRO
    
    IP_SAMBA=${IP_SAMBA:=$(hostname -I | sed 's/ //')}
    
    # Função para validar ip informado pelo usuário
    testa_ip "$IP_SAMBA"

    echo "Testando a conexão"
    if ! ping -c 1 "$IP_SAMBA" ; then { echo "Erro ao se comunicar com o IP $IP_SAMBA, Favor Verificar"; exit 1 ; } ; fi 1> /dev/null 2>> $LOG_ERRO

    HOSTNAME=$(whiptail --title "Digite o hostname do Servidor"   \
    --inputbox "Exemplo addc01, dc01, srvad. Hostame Atual -> $(hostname):" \
    --fb 10 60 3>&1 1>&2 2>&3) 1> /dev/null 2>> $LOG_ERRO
    
    HOSTNAME=${HOSTNAME:=$(hostname)}
    validar "${HOSTNAME}"
    
    DOMINIO=$(whiptail --title "Digite o DOMINIO do Servidor"   \
    --inputbox "Exemplo lab.local, lab.intra:" \
    --fb 10 60 3>&1 1>&2 2>&3) 1> /dev/null 2>> $LOG_ERRO
    
    validar "${DOMINIO}" 

    SENHA_DOM=$(whiptail --title "Qual a senha do admistrador do DOMINIO" \
    --passwordbox "Usar senha complexa:"             \
    --fb 10 60 3>&1 1>&2 2>&3)
    
    SENHA_DOM=${SENHA_DOM:=Senha@123}
    
    # Caso a senha não atender os requisitos de complexidade, COMENTAR A LINHA ABAIXO
    testa_senha ${SENHA_DOM}

    MASK=$(whiptail --title "Qual mascára de rede" \
    --inputbox "atual -> $(ip a | grep inet | grep -v inet6 | grep -v "127.0.0.*" | awk '{print $2}' | cut -d "/" -f 2 | uniq):" \
    --fb 10 60 3>&1 1>&2 2>&3) 1> /dev/null 2>> $LOG_ERRO
    
    MASK=${MASK:=$(ip a | grep inet | grep -v inet6 | grep -v "127.0.0.*" | grep -o "/[[:digit:]]*" | sed s'|/||')}

    GW=$(whiptail --title "Qual endereco do Gateway" \
    --inputbox "atual -> $(ip -o -4 route show to default | awk '{print $3}' | tail -n 1):" \
    --fb 10 60 3>&1 1>&2 2>&3) 1> /dev/null 2>> $LOG_ERRO
    
    GW=${GW:=$(ip -o -4 route show to default | cut -d " " -f 3 | head -n 1)}
    testa_ip "$GW"


    DNS=$(whiptail --title "Qual endereco de DNS EXTERNO"   \
    --inputbox "Exemplo: 8.8.8.8, 8.8.4.4:" \
    --fb 10 60 3>&1 1>&2 2>&3) 1> /dev/null 2>> $LOG_ERRO 
    
    DNS=${DNS:=1.1.1.1}
    testa_ip $DNS

    IP=$(_IP)
    INTER_FACE=$(_INTERFACE)

    NET=$(ipcalc --all-info "${IP}" | grep -i network | awk '{print $2}')
    END_REDE=$(whiptail --title "Qual endereco da REDE e MASCARA usar formato IP/MASCARA" \
    --inputbox "Atual -> ${NET}:"                                     \
    --fb 10 60 3>&1 1>&2 2>&3) 1> /dev/null 2>> $LOG_ERRO

    END_REDE=${END_REDE:=${NET}}

    whiptail --title "Dados informados pelo usuario" \
    --msgbox "IP........=$IP\nMASCARA...=$MASK\nGATEWAY...=$GW\nDNS.......=$DNS\nHOSTNAME..=$HOSTNAME\nDOMINIO...=$DOMINIO \
    \nSENHA_DOM.=$SENHA_DOM\nREDE......=${INTER_FACE}\nEND_REDE..=$END_REDE" --fb 30 90

    whiptail --title "Deseja continuar" --yesno "Os dados estao corretos SIM ou Nao." 10 50 
    if [[ $? -eq 1 ]] ; then tput setaf 1; tput setab 7 ; { echo -e "Saindo\nFavor executar novamente o script" ; tput sgr0 ; exit; } fi

    hostnamectl set-hostname "$HOSTNAME" 1> /dev/null 2>> $LOG_ERRO
    
    echo "IP........=${IP}"           >> "$SAMBA_DB"
    echo "MASCARA...=${MASK}"         >> "$SAMBA_DB"
    echo "GATEWAY...=${GW}"           >> "$SAMBA_DB"
    echo "DNS.......=${DNS}"          >> "$SAMBA_DB"
    echo "HOSTNAME..=${HOSTNAME}"     >> "$SAMBA_DB"
    echo "DOMINIO...=${DOMINIO}"      >> "$SAMBA_DB"
    echo "SENHA_DOM.=${SENHA_DOM}"    >> "$SAMBA_DB"
    echo "REDE......=${INTER_FACE}"   >> "$SAMBA_DB"
    echo "END_REDE..=${END_REDE}"     >> "$SAMBA_DB"

    SAMBA_IPSRV=$(grep -i "ip"       $SAMBA_DB | cut -d "=" -f 2 | cut -d "/" -f 1)
    SAMBA_HOSTN=$(grep -i "hostname" $SAMBA_DB | cut -d "=" -f 2)
    SAMBA_DOMIN=$(grep -i "dominio"  $SAMBA_DB | cut -d "=" -f 2 | cut -d "." -f 1)
    SAMBA_REALM=$(grep -i "dominio"  $SAMBA_DB | cut -d "=" -f 2)
    SAMBA_INTER=$(grep -i "^rede"    $SAMBA_DB | cut -d "=" -f 2)
    SAMBA_UUID=$(nmcli connection show | grep -i "${SAMBA_INTER}" | head -n 1 |rev | awk '{print $3}' | rev)

    cat >> /etc/hosts << EOF
${SAMBA_IPSRV%/*} ${SAMBA_HOSTN}.${SAMBA_REALM} ${SAMBA_HOSTN}.${SAMBA_DOMIN} ${SAMBA_HOSTN}
EOF

    #Here document para criar arquivo de rede
    cat > /etc/sysconfig/network-scripts/ifcfg-"${SAMBA_INTER}" << EOF
TYPE=Ethernet
PROXY_METHOD=none
BROWSER_ONLY=no
BOOTPROTO=none
DEFROUTE=yes
IPV4_FAILURE_FATAL=no
UUID=
NAME=${INTER_FACE}
DEVICE=${INTER_FACE}
ONBOOT=yes
IPADDR=$IP
PREFIX=$MASK
GATEWAY=$GW
IPV6_DISABLED=yes
EOF

    sed -i "s/UUID.*/UUID=${SAMBA_UUID}/" /etc/sysconfig/network-scripts/ifcfg-"${SAMBA_INTER}"

    #Reiniciar rede
    systemctl restart NetworkManager 1> /dev/null 2>> $LOG_ERRO
    echo "Configuracao realizada, função executada foi $FILE" | tee > $FILE
  else
    echo "Configuracao realizada, para repetir a instalacao remover esse arquivo $FILE"
  fi
}
# Fim

################################################################################
_SAMBA_INST()
{
  _VERIFICAR_ROOT
  FILE="/tmp/samba_inst.txt"

  if [ ! -e "$FILE" ] ; then
    LOG_ERRO="/tmp/erro_install_samba.txt"
    SAMBA_DB="/tmp/samba.db"
    CAMINHO_SAMBA="/usr/local/samba"

    if [ ! -e "$SAMBA_DB" ] ; then { echo "Erro ao criar arquivo $SAMBA_DB, Favor Verificar"; exit; } fi
    
    SAMBA_DOMIN=$(grep -i "dominio" /tmp/samba.db | cut -d "=" -f 2 | cut -d "." -f 1)
    SAMBA_REALM=$(grep -i "dominio" /tmp/samba.db | cut -d "=" -f 2)
    SAMBA_SENHA=$(grep -i "senha" /tmp/samba.db | cut -d "=" -f 2)
    SAMBA_IPSRV=$(grep -i "ip" /tmp/samba.db | cut -d "=" -f 2 | cut -d "/" -f 1)
    SAMBA_HOSTN=$(grep -i "hostname" /tmp/samba.db | cut -d "=" -f 2)
    
    whiptail --title "Os dados estao corretos ?" \
    --yesno "Dominio.= [ ${SAMBA_DOMIN^^} ]\nReino...= [ ${SAMBA_REALM^^} ]\nSenha...= [ ${SAMBA_SENHA} ]" --fb 15 40
    if [[ $? -eq 1 ]] ; then tput setaf 1; tput setab 7 ; { echo -e "Saindo\nFavor executar novamente o script" ; tput sgr0 ; exit; } fi

    "$CAMINHO_SAMBA"/bin/samba-tool domain provision --server-role=dc --realm="${SAMBA_REALM^^}" --domain="$SAMBA_DOMIN" --dns-backend=BIND9_DLZ --use-rfc2307 --adminpass="$SAMBA_SENHA"

    CHRONY_CONF=$(find /etc/ -type f -iname chrony.conf) 1> /dev/null 2>> $LOG_ERRO

    cat >> "$CHRONY_CONF" << EOF
log measurements statistics tracking
maxupdateskew 100.0
hwclockfile /etc/adjtime
ntpsigndsocket $CAMINHO_SAMBA/var/lib/ntp_signd
EOF
    systemctl restart chronyd 1> /dev/null 2>> $LOG_ERRO

    cp /etc/nsswitch.conf{,.bkp}
    sed -i 's/^passwd.*/passwd:\ files\ winbind/g' /etc/nsswitch.conf
    sed -i 's/^group.*/group:\ files\ winbind/g'   /etc/nsswitch.conf
    
    mkdir -p $CAMINHO_SAMBA/var/lib/ntp_signd/
    chmod 0750 $CAMINHO_SAMBA/var/lib/ntp_signd/
    chown root.chrony $CAMINHO_SAMBA/var/lib/ntp_signd/

    touch /var/named/data/named_mem_stats.txt
    touch /var/named/data/named_stats.txt 
    touch /var/named/data/cache_dump.db
    chown named.named /var/named -R
    cp $CAMINHO_SAMBA/bind-dns/named.conf{,.bkp}

    NAMED_VERSION=$(rpm -qa bind |cut -d "-" -f 2 |cut -d "." -f 2)
    chown named.named $CAMINHO_SAMBA/bind-dns/named.conf
    chown named.named $CAMINHO_SAMBA/bind-dns -R
    chown root.named $CAMINHO_SAMBA/lib/bind9/dlz_bind9_"$NAMED_VERSION".so
 
    cat > $CAMINHO_SAMBA/bind-dns/named.conf  << EOF
dlz "AD DNS Zone" {
database "dlopen $CAMINHO_SAMBA/lib/bind9/dlz_bind9_$NAMED_VERSION.so";
};
EOF

    NAMED=$(find /etc/ -iname named.conf)
    cp "$NAMED"{,.bkp}

    cat > "$NAMED" << EOF
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
  tkey-gssapi-keytab "/usr/local/samba/bind-dns/dns.keytab";

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
include "$CAMINHO_SAMBA/bind-dns/named.conf";
EOF

    echo "KRB5RCACHETYPE=\"none\"" >> /etc/sysconfig/named
    echo -e "\n[kdc]\n\tcheck-ticket-addresses = false" >> $CAMINHO_SAMBA/private/krb5.conf

    \cp /usr/local/samba/private/krb5.conf /etc/
    cp $CAMINHO_SAMBA/conf/smb.conf{,.bkp}

    systemctl start named && systemctl enable --now named
    sed -i '26i dns=none' /etc/NetworkManager/NetworkManager.conf

    cp /usr/lib/systemd/system/samba.service /root/samba.service.bkp
    sed -i 's/notify/forking/' /usr/lib/systemd/system/samba.service
    sed -i 's/--.*/-D/' /usr/lib/systemd/system/samba.service

    systemctl daemon-reload
    systemctl enable --now samba
    
    #Here document para criar arquivo de dns
    chattr -i /etc/resolv.conf
    cat > /etc/resolv.conf << EOF
search $SAMBA_REALM
nameserver $SAMBA_IPSRV
EOF
    chattr +i /etc/resolv.conf

    KINIT=$(which kinit)

    sleep 1
    expect -c "
    spawn $KINIT Administrator
    expect \"Password for Administrator@${SAMBA_REALM^^}:\"
    send \"$SAMBA_SENHA\r\"
    interact"
    sleep 1
    
    SAMBA_CFSMB=$(find "${CAMINHO_SAMBA}" -iname smb.conf)

    # Configuração do arquivo smb.conf
    cat > "${SAMBA_CFSMB}" << EOF
[global]
        netbios name = ${SAMBA_HOSTN^^}
        realm = ${SAMBA_REALM^^}
        server role = active directory domain controller
        server services = s3fs, rpc, nbt, wrepl, ldap, cldap, kdc, drepl, winbindd, ntp_signd, kcc, dnsupdate
        workgroup = ${SAMBA_DOMIN^^}
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
        path = $CAMINHO_SAMBA/var/locks/sysvol
        read only = No

[netlogon]
        path = $CAMINHO_SAMBA/var/locks/sysvol/${SAMBA_REALM,,}/scripts
        read only = No
EOF

    ${CAMINHO_SAMBA}/bin/samba-tool domain passwordsettings set --complexity=off    1> /dev/null 2>> ${LOG_ERRO}
    ${CAMINHO_SAMBA}/bin/samba-tool domain passwordsettings set --history-length=0  1> /dev/null 2>> ${LOG_ERRO}
    ${CAMINHO_SAMBA}/bin/samba-tool domain passwordsettings set --min-pwd-age=0     1> /dev/null 2>> ${LOG_ERRO}
    ${CAMINHO_SAMBA}/bin/samba-tool domain passwordsettings set --max-pwd-age=0     1> /dev/null 2>> ${LOG_ERRO}

    whiptail --title "Politica de senha" --msgbox "$($CAMINHO_SAMBA/bin/samba-tool domain passwordsettings show)" --fb 20 50  

    "$CAMINHO_SAMBA"/bin/net rpc rights grant "${SAMBA_DOMIN^^}\Domain Admins" SeDiskOperatorPrivilege -U"${SAMBA_DOMIN^^}\administrator%$SAMBA_SENHA"
    "$CAMINHO_SAMBA"/bin/net rpc rights list accounts -U"${SAMBA_DOMIN^^}\administrator%${SAMBA_SENHA}" 1> /dev/null 2>> "$LOG_ERRO"
    "$CAMINHO_SAMBA"/bin/smbcontrol all reload-config 1> /dev/null 2>> "$LOG_ERRO"

    IP_REVERSO=$(_REVERSO)
    SAMBA_TOOL=$(find /usr -iname samba-tool)
    "$SAMBA_TOOL" dns zonecreate "${SAMBA_HOSTN}" "${IP_REVERSO}" -UAdministrator%"${SAMBA_SENHA}"
    "$SAMBA_TOOL" dns add "${SAMBA_HOSTN}" "${IP_REVERSO}" "${SAMBA_IPSRV##*.}" PTR "${SAMBA_HOSTN}.${SAMBA_REALM}" -UAdministrator%"${SAMBA_SENHA}"

    $CAMINHO_SAMBA/sbin/samba_dnsupdate
    systemctl restart samba.service 1> /dev/null 2>> "$LOG_ERRO"
    systemctl restart named.service 1> /dev/null 2>> "$LOG_ERRO"

    sed -i '8i After=samba.service' /lib/systemd/system/named.service 1> /dev/null 2>> ${LOG_ERRO}
    systemctl daemon-reload 1> /dev/null 2>> ${LOG_ERRO}

    if whiptail --title "Aplicar Configurações - SAMBA4" --yesno "Deseja reiniciar o servidor" 10 50 ; then reboot ; fi 

    clear
    echo "Configuracao realizada, função executada foi _CONF_SAMBA" | tee > $FILE
  else
    echo "Configuracao realizada, para repetir a instalacao remover esse arquivo $FILE"
  fi
}

_CONFIGURAR
_CONF_SAMBA
_SAMBA_INST
