#!/usr/bin/env bash

set -xueo pipefail


# Inicio das funções
################################################################################
# Função para mostrar mensagem de erro
_MSG_ERRO_INFO() { clear ; whiptail --title "Erro" --msgbox "$1" 0 0 ; exit 20 ; }

################################################################################
# Função para mostrar mensagem de alerta
_MSG_INFO(){ clear ; whiptail --title "Atenção" --msgbox "$1" 0 0 ; }

################################################################################
# Função para mostrar mensagem de erro e sair do script com código de erro 30
_MSG_SAIR(){ clear ; whiptail --title "Aviso" --msgbox "$1" 0 0 ; exit 30 ; }

################################################################################
# Função para verificar se o script está com privilegios de root, Caso não estiver finaliza o programa.
_VERIFICAR_ROOT(){ [[ "$EUID" -eq 0 ]] || _MSG_ERRO_INFO "Necessita permissão de root" ; }

################################################################################
# Função para verificar o sistema operacional Rocky Linux e versão
_VERIFICAR_OS(){  grep -oq "rocky" /etc/os-release || _MSG_ERRO_INFO "Sistema operacional não homologado, Favor usar Rocky Linux" ; }

################################################################################
# Função para verificar acesso a internet para baixar os pacotes necessários
_VERIFICAR_INTERNET(){ ping -c 2 -w 5 "kernel.org" > /dev/null || _MSG_ERRO_INFO "Acesso a internet não está disponível" ; }

################################################################################
# Função para testar ip fornecido, utiliza programa auxiliar ipcalc
_TESTA_IP()
{
  which ipcalc 1> /dev/null || yum -y install ipcalc 1> /dev/null
  IPCALC=$(which ipcalc) 1> /dev/null
  "$IPCALC" -c "$1" || _MSG_ERRO_INFO "Favor verificar o Endereço IP informado"
}

################################################################################
# Função para validar ip reverso para criação do dns no DC
_REVERSO()
{
  IP=$(sqlite3 -batch "$DB_ARQ_CONF" " SELECT ip    FROM samba_config;")
  MSK=$(sqlite3 -batch "$DB_ARQ_CONF" " SELECT mask FROM samba_config;")
  REV=$(ipcalc --reverse-dns "${IP}/${MSK}" | cut -d "=" -f 2)
  echo "$REV"
}

################################################################################
# Função para escolher interface de rede caso exista mais de uma
# Gerado uma lista com os nomes das interfaces de rede
_INTERFACE()
{
  NOME_IFACE_TMP=$(ip -o -4 route show to default | awk '{print $5}' | uniq)
  NOME_IFACE=$(ip -o -4 route show to default     | awk '{print $5}' | uniq | tail -n 1)

  arr=()
  i=0
  for ip in $NOME_IFACE_TMP
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
    if [[ $db = "$NOME_IFACE" ]]; then
      whiptail_args+=( "on" )
    else
      whiptail_args+=( "off" )
    fi
  done

  indice=$(whiptail "${whiptail_args[@]}" 3>&1 1>&2 2>&3)
  echo "${arr[${indice}-1]}"
}

################################################################################
# Função para escolher ip
# Gerado uma lista com os nomes dos endereços ips, caso existir mais de um.
_IP()
{
  END_IP_IFACE=$(ip a      | grep -E "inet[[:space:]]" |grep -v 127 | awk '{print $2}')
  END_IP_IFACE_TMP=$(ip a  | grep -E "inet[[:space:]]" |grep -v 127 | awk '{print $2}' | head -n 1)

  arr=()
  i=0
  for ip in $END_IP_IFACE
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
    if [[ $db = "$END_IP_IFACE_TMP" ]]; then
      whiptail_args+=( "on" )
    else
      whiptail_args+=( "off" )
    fi
  done

  indice=$(whiptail "${whiptail_args[@]}" 3>&1 1>&2 2>&3)
  echo "${arr[${indice}-1]}"
}

################################################################################
# Função testar requisitos de senha para promoção do DC
_VALIDAR_SENHA() {
  senha="$1"
  tamanho_minimo=8

  # Verificar o comprimento da senha
  [[ "${#senha}" -lt "$tamanho_minimo" ]] && _MSG_ERRO_INFO "Tamanho da senha informado é menor que 8 caracteres"

  # Verificar a complexidade da senha usando expressões regulares
  if ! echo "$senha" | grep -E '.*[A-Z].*' \
                     | grep -E '.*[a-z].*' \
                     | grep -E '.*[0-9].*' \
                     | grep -E '.*[@.!$%&*?<>+=_-].*'; then

MSG_COMPLEXIDADE="Senha não atende aos critérios de complexidade:
Necessário pelo menos um de cada item:
  - Letra maiúscula
  - Letra minúscula
  - Dígito numérico
  - Caractere especial
Exemplos: 'Teste@123', 'P@\$\$word.1'
"
_MSG_ERRO_INFO "$MSG_COMPLEXIDADE"

  fi
}

################################################################################
# Funções para buscar caminhos de arquivos e/ou executáveis
# e realizar ajustes nas configurações
################################################################################

# Função para desabilitar SELINUX
_DESATIVAR_SELINUX()
{
  SELINUX_CONF=$(find /etc/ -type f -iname config | grep selinux) || 
  cp "$SELINUX_CONF"{,.bak}
  sed -i 's/^SELINUX=.*/SELINUX=disabled/g' "$SELINUX_CONF"
  setenforce 0
}

################################################################################
# Função para liberar acesso aos serviços referente ao samba usando firewalld
_CONFIGURAR_PORTAS_FIREWALL()
{
  # Desativar AllowZoneDrifting
  FIREWALL_CONF=$(find /etc/ -iname firewalld.conf)
  sed -i 's/^AllowZoneDrifting=.*/AllowZoneDrifting=no/' "$FIREWALL_CONF"
 
  # Verificar se firewalld está em execução
  systemctl status firewalld.service | grep -iq running || _MSG_INFO "Firewalld não está em execução"

  # Liberar portas de funciomanento do Samba
  firewall-cmd --permanent --add-service={dns,ldap,ldaps,kerberos}
  
  # Portas TCP 
  firewall-cmd --permanent --zone=public --add-port={53/tcp,135/tcp,139/tcp,389/tcp,445/tcp,465/tcp,636/tcp,3268/tcp,3269/tcp,49152-65535/tcp}
  
  # Portas UDP
  firewall-cmd --permanent --zone=public --add-port={53/udp,88/udp,123/udp,137/udp,138/udp,389/udp,464/udp}

  # Recarregar firewalld
  firewall-cmd --reload || _MSG_ERRO_INFO "Erro ao reiniciar firewalld"
}

################################################################################
# Função para atualizar o chronyd
_CONFIGURAR_CHRONY()
{
  # Atualiza servidores de hora
  CHRONY_CONF=$(find /etc/ -type f -iname chrony.conf)
  cp "$CHRONY_CONF"{,.bkp}
  sed -i 's/^pool.*/server\ a.ntp.br\ iburst/' "$CHRONY_CONF" 
  sed -i '4s/^/server\ b.ntp.br\ iburst\n/'    "$CHRONY_CONF"
  sed -i 's/^#allow.*/allow\ 0.0.0.0\/0/'      "$CHRONY_CONF"
  timedatectl set-timezone America/Sao_Paulo

  # Inicializando chronyd e habilitando serviço
  systemctl enable chronyd --now 1> /dev/null

}

################################################################################
# Função coletar hostname
_FHOSTNAME()
{
  # Verificar se hostname está correto
  HOSTNAME=$(whiptail --title "${MSG_WHIP[hostname]}" \
            --inputbox "${MSG_WHIP[msg_hostname]}" --fb 10 60 3>&1 1>&2 2>&3) || _MSG_SAIR 'Operação cancelada'  

  # Se campo ficar em branco o nome será alterado para dc_samba
  HOSTNAME=${HOSTNAME:-dc01} 

  # Verificando tamanho do nome do DC
  [[ "${#HOSTNAME}" -le 15 ]] || _MSG_ERRO_INFO 'Nome do DC maior que 15 caracteres'

  echo "$HOSTNAME"
}

################################################################################
# Função para configurar Domínio 
_FDOMINIO()
{
  # Configurar Domínio  
  DOMINIO=$(whiptail --title "${MSG_WHIP[dominio]}" \
            --inputbox "${MSG_WHIP[msg_dominio]}" --fb 10 60 3>&1 1>&2 2>&3) || _MSG_SAIR 'Operação cancelada'  
  
  # Se campo ficar em branco o nome será alterado para samba.intra
  DOMINIO=${DOMINIO:-samba.intra}

  # Verificar se domínio possui pontos e não é menor que três caracteres
  [[ "${#DOMINIO}" -ge 3 ]]                      || _MSG_ERRO_INFO 'DOMINIO menor que 3 caracteres'
  [[ $(grep -cE "[.]" <<< "${DOMINIO}") -eq 0 ]] && _MSG_ERRO_INFO 'Erro ao informar dominio'

  echo "$DOMINIO"
}

################################################################################
# Função para validadar e cadastrar IP
_FIP_SAMBA()
{
  # Obter ip em uso atualmente
  IP_ATUAL=$(hostname -I | sed 's/ //')
  IP_SAMBA=$(whiptail --title "${MSG_WHIP[ip]}" \
            --inputbox "${MSG_WHIP[msg_ip]}" --fb 10 60 3>&1 1>&2 2>&3) || _MSG_SAIR 'Operação Cancelada'
  
  # Define como ip atual se campo estiver em branco
  IP_SAMBA=${IP_SAMBA:-$IP_ATUAL}
    
  # Verificar se ip é valido 
  which ipcalc 1> /dev/null || yum -y install ipcalc 1> /dev/null
  IPCALC=$(which ipcalc)
  "$IPCALC" -c "$IP_SAMBA" || _MSG_ERRO_INFO "$IP_ATUAL está incorreto"
  echo "$IP_SAMBA"
}

################################################################################
# Função para validadar e cadastrar Máscara de rede
_FMASK()
{
  # Valor da mascara de rede atual
  MASK_ATUAL=$(ip a | grep inet | grep -v inet6 | grep -v "127.0.0.*" | awk '{print $2}' | cut -d "/" -f 2 | uniq)
  MASK=$(whiptail --title "${MSG_WHIP[mascara]}" \
        --inputbox "${MSG_WHIP[msg_mascara]}" --fb 10 60 3>&1 1>&2 2>&3) || _MSG_SAIR 'Operação cancelada'
  
  # Define mascara atual do sistema se campo estiver em branco
  MASK=${MASK:=$MASK_ATUAL}

  # Validando máscara de rede e ip.
  which ipcalc 1> /dev/null || yum -y install ipcalc 1> /dev/null
  IPCALC=$(which ipcalc)
  "$IPCALC" -c "$IP_SAMBA"/"$MASK" || _MSG_ERRO_INFO "IP: $IP_SAMBA/$MASK está incorreto"
  echo "$MASK"
}

################################################################################
# Função para validadar e cadastrar gateway
_FGW()
{
  # Gateway padrao  
  GW_ATUAL=$(ip -o -4 route show to default | awk '{print $3}' | head -n 1)
  GW=$(whiptail --title "${MSG_WHIP[gateway]}"\
      --inputbox "${MSG_WHIP[msg_gateway]}" --fb 10 60 3>&1 1>&2 2>&3) || _MSG_SAIR 'Operação cancelada'
  
  # Define gateway atual do sistema se campo estiver em branco
  GW=${GW:-$GW_ATUAL}
  
  # Verificar se GW é valido
  which ipcalc 1> /dev/null || yum -y install ipcalc 1> /dev/null
  IPCALC=$(which ipcalc)
  "$IPCALC" -c "$GW" || { whiptail --title "Erro" --msgbox "GATEWAY: $GW está incorreto" 12 50 ; exit 1 ; }
  echo "$GW"
}

################################################################################
# Função para validadar e cadastrar DNS
_FDNS()
{
    # Verificar DNS externo
  DNS=$(whiptail --title "${MSG_WHIP[dns]}" \
       --inputbox "${MSG_WHIP[msg_dns]}" --fb 10 60 3>&1 1>&2 2>&3) || _MSG_SAIR 'Saindo\nFavor executar novamente o script'  
  
  # Define DNS se campo estiver em branco
  DNS=${DNS:=1.1.1.1}
  
  # Verificar se DNS informado é valido
  which ipcalc 1> /dev/null || yum -y install ipcalc 1> /dev/null
  IPCALC=$(which ipcalc)
  "$IPCALC" -c "$DNS" 
  ping -q -c 2 "$DNS" > /dev/null || _MSG_ERRO_INFO "DNS: $DNS está incorreto ou inacessível"
  echo "$DNS"
}

################################################################################
# Função para validar Senha informada
_SENHA_DOM()
{
  # Informar senha do usuário administrador
  SENHA_DOM=$(whiptail --title "${MSG_WHIP[senha]}" \
            --passwordbox "${MSG_WHIP[msg_senha]}" --fb 10 60 3>&1 1>&2 2>&3) || _MSG_SAIR 'Saindo\nFavor executar novamente o script'

  # Caso senha for em branco assume o valor abaixo
  SENHA_DOM=${SENHA_DOM:=Senha@123}

  # Validar requisitos da senha
  # Caso a senha não atender os requisitos de complexidade, COMENTAR A LINHA ABAIXO
  _VALIDAR_SENHA "$SENHA_DOM"

}

################################################################################
# Função para obter o endereço de rede formato 192.168.0.0/24
_FEND_REDE()
{
# Endereço de rede
  END_REDE=$(ip route | tail -n +2 | awk '{print $1}') || _MSG_SAIR 'Saindo\nFavor executar novamente o script'
  echo "$END_REDE"
}

################################################################################
# Função para obter pacotes essenciais e atualizar o sistema
_ATUALIZAR_BASE()
{
  # Atualizar sistema
  yum -y update && yum -y upgrade

  # Instalar repositorio EPEL e ferramentas de desenvolvimento e pacotes úteis
  yum install tar vim ipcalc net-tools wget bash-completion chrony bind-utils bind expect yum-utils krb5-workstation rsyslog sqlite -y

}

################################################################################
# Função para cadastrar os valores básicos do samba usando sqlite
_SAMBA_DB_CONFIG()
{
  DB_DIR='/srv'
  DB_ARQ_CONF='/srv/samba.db'

  # Verificar se diretorio existe
  [[ -d "$DB_DIR" ]] || mkdir -p "$DB_DIR" || _MSG_ERRO_INFO "Erro criar diretorio para o banco de dados"

  # Verificar se banco de dados existe, se não será criado
  [[ -f "$DB_ARQ_CONF" ]] || { touch "$DB_ARQ_CONF" || _MSG_ERRO_INFO "$DB_ARQ_CONF" ; }

  # Inserir valores padrão
  sqlite3 -batch "$DB_ARQ_CONF" "CREATE TABLE IF NOT EXISTS samba_config (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    samba_path_install TEXT    UNIQUE,
    samba_temp_dir     TEXT    UNIQUE,
    ip                 TEXT    UNIQUE,
    mask               TEXT    UNIQUE,
    gateway            TEXT    UNIQUE,
    dns                TEXT    UNIQUE,
    hostname           TEXT    UNIQUE,
    dominio            TEXT    UNIQUE,
    senha              TEXT    UNIQUE,
    rede               TEXT    UNIQUE,
    end_rede           TEXT    UNIQUE,
    inicializado       TEXT    UNIQUE);"

  # Verificar se banco de dados teve os valores de configuração adicionados
  START_CONIF=$(sqlite3 -batch "$DB_ARQ_CONF" "select inicializado FROM samba_config")

  if [[ ${START_CONIF,,} != 'sim' ]]
   then
    # Inserir valores padrão
    sqlite3 -batch "$DB_ARQ_CONF" "INSERT OR REPLACE INTO samba_config (
        samba_temp_dir,
        samba_path_install,
        inicializado)
      VALUES (
        '/opt',
        '/usr/local/samba',
        'sim');"
  fi 
}

################################################################################
# Função para verificar se bd existe
_CHECK_DATABASE_CONF()
{
  # Carregar informações
  DB_ARQ_CONF='/srv/samba.db'
  [[ -f $DB_ARQ_CONF ]] || _MSG_ERRO_INFO "O Arquivo $DB_ARQ_CONF não está acessível.\nInstalação finalizada"  
  echo "$DB_ARQ_CONF"
}

################################################################################
# Função para cadastrar ou atualizar informações
_SAMBA_CADASTRO_CONFIG()
{
  # Arquivo de configuração do banco de dados
  DB_ARQ_CONF=$(_CHECK_DATABASE_CONF)
  
  # Verificar se banco de dados existe
  [[ -f $DB_ARQ_CONF ]] || _MSG_ERRO_INFO "O Arquivo $DB_ARQ_CONF não está acessível.\nInstalação finalizada"  

  CONTROLE="/tmp/controle_conf_samba.txt"

  # Cadastro de perguntas para cadastr o do SAMBA
  declare -A MSG_WHIP=(
    [hostname]="Digite o HOSTNAME desejado:"
    [msg_hostname]="Exemplo srvad, dc01, srvsamba\nHostname Atual -> $(hostname):" 
    [dominio]="Digite o DOMINIO desejado:"
    [msg_dominio]="Exemplo lab.local, lab.intra:"
    [ip]="Digite o endereço IP desejado:"
    [msg_ip]="Aperte enter para usar IP atual\nIp. Atual $(hostname -I)"
    [mascara]="Digite a máscara de rede:"
    [msg_mascara]="atual -> $(ip a | grep inet | grep -v inet6 | grep -v "127.0.0.*" | awk '{print $2}' | cut -d "/" -f 2 | uniq)"
    [gateway]="Digite o gateway da rede:"
    [msg_gateway]="atual -> $(ip -o -4 route show to default | awk '{print $3}' | head -n 1):"
    [dns]="Digite o DNS EXTERNO desejado:"
    [msg_dns]="Exemplo: 8.8.8.8, 8.8.4.4:"
    [senha]="Qual a senha do admistrador do DOMINIO"
    [msg_senha]="Usar senha complexa:"
  )
  # Mensagem de cancelamento
  SAMBA_ERRO_MSG="Saindo\nFavor executar novamente o script"

  # Verificar se o arquivo controle existe, se existir a execução será abortada
  [[ -f $CONTROLE ]] && _MSG_ERRO_INFO "Script já executado, favor remover o arquivo para contiunuar $CONTROLE"

  # Verificar se existe mais de um ip cadastrado
  CONN=$(nmcli connection show | awk '{print $4}' | grep -v -i device)
  [[ $(wc -l <<< "${CONN}") -eq 1 ]] || _MSG_ERRO_INFO 'Mais de um ip ativo, favor desativar a interface para continuar'

  # Informar hostaname
  HOSTNAME=$(_FHOSTNAME)    || _MSG_SAIR "$SAMBA_ERRO_MSG"

  # Informar dominio
  DOMINIO=$(_FDOMINIO)      || _MSG_SAIR "$SAMBA_ERRO_MSG"

  # Informar IP
  IP_SAMBA=$(_FIP_SAMBA)    || _MSG_SAIR "$SAMBA_ERRO_MSG"
  
  # Informar máscara de rede
  MASK=$(_FMASK)            || _MSG_SAIR "$SAMBA_ERRO_MSG"

  # Informar gateway
  GW=$(_FGW)                || _MSG_SAIR "$SAMBA_ERRO_MSG"

  # Informar DNS
  DNS=$(_FDNS)              || _MSG_SAIR "$SAMBA_ERRO_MSG"

  # Informar senha de usuário administrator
  SENHA_DOM=$(_SENHA_DOM)   || _MSG_SAIR "$SAMBA_ERRO_MSG"

  # nome da interface
  INTERFACE=$(_INTERFACE)   || _MSG_SAIR "$SAMBA_ERRO_MSG"

  # Endereço de rede
  END_REDE=$(_FEND_REDE)    || _MSG_SAIR "$SAMBA_ERRO_MSG"

  # Verificar dados fornecidos
  if ! whiptail --title "Dados informados pelo usuario" \
    --yesno "Os dados estao corretos SIM ou Nao
    IP........=$IP_SAMBA
    MASCARA...=$MASK
    GATEWAY...=$GW
    DNS.......=$DNS
    HOSTNAME..=$HOSTNAME
    DOMINIO...=$DOMINIO
    SENHA_DOM.=$SENHA_DOM
    REDE......=$INTERFACE
    END_REDE..=$END_REDE" --fb 30 90
  
  then
    _MSG_SAIR "$SAMBA_ERRO_MSG"
  
  fi 
  
  # Gravar arquivo para uso do samba 
  sqlite3 -batch "$DB_ARQ_CONF" "UPDATE samba_config set ip       = '$IP_SAMBA'  WHERE id = 1;" || _MSG_ERRO_INFO "Erro ao inserir informações no banco de dados"
  sqlite3 -batch "$DB_ARQ_CONF" "UPDATE samba_config set mask     = '$MASK'      WHERE id = 1;" || _MSG_ERRO_INFO "Erro ao inserir informações no banco de dados"
  sqlite3 -batch "$DB_ARQ_CONF" "UPDATE samba_config set gateway  = '$GW'        WHERE id = 1;" || _MSG_ERRO_INFO "Erro ao inserir informações no banco de dados"
  sqlite3 -batch "$DB_ARQ_CONF" "UPDATE samba_config set dns      = '$DNS'       WHERE id = 1;" || _MSG_ERRO_INFO "Erro ao inserir informações no banco de dados"
  sqlite3 -batch "$DB_ARQ_CONF" "UPDATE samba_config set hostname = '$HOSTNAME'  WHERE id = 1;" || _MSG_ERRO_INFO "Erro ao inserir informações no banco de dados"
  sqlite3 -batch "$DB_ARQ_CONF" "UPDATE samba_config set dominio  = '$DOMINIO'   WHERE id = 1;" || _MSG_ERRO_INFO "Erro ao inserir informações no banco de dados"
  sqlite3 -batch "$DB_ARQ_CONF" "UPDATE samba_config set senha    = '$SENHA_DOM' WHERE id = 1;" || _MSG_ERRO_INFO "Erro ao inserir informações no banco de dados"
  sqlite3 -batch "$DB_ARQ_CONF" "UPDATE samba_config set rede     = '$INTERFACE' WHERE id = 1;" || _MSG_ERRO_INFO "Erro ao inserir informações no banco de dados"
  sqlite3 -batch "$DB_ARQ_CONF" "UPDATE samba_config set end_rede = '$END_REDE'  WHERE id = 1;" || _MSG_ERRO_INFO "Erro ao inserir informações no banco de dados"

}

################################################################################
# Função _CONFIGURAR -> Descrição:
# Função para instalação de pacotes necessários para o funcionamento do samba4
# Após a execução é criado um arquivo na pasta /tmp.
# Caso o arquivo exista o script é finalizado,
# necessário remover arquivo para liberar execução.
################################################################################

_CONFIGURAR()
{
  clear
  # Realizar testes antes de iniciar o script
  _VERIFICAR_OS
  _VERIFICAR_ROOT
  _VERIFICAR_INTERNET
  
  # Verificar se versão instalada é 8
  OS_RELEASE=$(grep -i platform /etc/os-release | grep -o "[0-9]")
  [[ "$OS_RELEASE" -eq 8 ]] || _MSG_ERRO_INFO "Versão homologada para Rocky Linux 8"

  # Variáveis
  DB_ARQ_CONF=$(_CHECK_DATABASE_CONF)
  CONTROLE='/tmp/controle_configurar.txt'

  # Verificar se o arquivo controle existe, se existir a execução será abortada
  [[ -f $CONTROLE ]] && _MSG_ERRO_INFO "Script já executado, favor remover o arquivo para contiunuar $CONTROLE"

  # Iniciar banco de dados
  _SAMBA_DB_CONFIG

  # Local onde o arquivo será salvo
  SAMBA_DOWN=$(sqlite3 -batch "$DB_ARQ_CONF" "SELECT samba_temp_dir FROM samba_config;")     || _MSG_ERRO_INFO "$DB_ARQ_CONF não encontrado"
  
  # Diretório de instalação do SAMBA
  SAMBA_PATH=$(sqlite3 -batch "$DB_ARQ_CONF" "SELECT samba_path_install FROM samba_config;") || _MSG_ERRO_INFO "$DB_ARQ_CONF não encontrado"

  # Desabilitar SELINUX
  _DESATIVAR_SELINUX

  # Atualizar servidor de hora e reiniciar
  _CONFIGURAR_CHRONY

  # Baixar Samba
  wget https://download.samba.org/pub/samba/samba-latest.tar.gz || _MSG_ERRO_INFO "Erro ao baixar arquivo"
  tar zxvf samba-latest.tar.gz -C "$SAMBA_DOWN"                 || _MSG_ERRO_INFO "Erro ao descompactar arquivo"
  
  # Realizar instalação de pacotes do Samba usando bootstap
  SAMBA_BOOTSTRAP=$(find "$SAMBA_DOWN" -iname bootstrap.sh | grep centos"$OS_RELEASE")
  bash "$SAMBA_BOOTSTRAP" || _MSG_ERRO_INFO "Erro ao executar arquivo de bootstrap"

  SAMBA_VERSAO=$(find /opt/ -maxdepth 1 -type d | grep "samba-[0-9]*")
  cd "$SAMBA_VERSAO" || _MSG_ERRO_INFO "Erro ao acessar pasta $SAMBA_VERSAO"

  #Compilando Samba4 Versão homologada para a instalação
  # Flags de compilação
  CFLAGS="-I/usr/include/tirpc" ./configure -j "$(nproc)" \
  --enable-coverage --disable-cups                        \
  --with-systemd --systemd-install-services               \
  --with-systemddir=/usr/lib/systemd/system               \
  --prefix="$SAMBA_PATH"                                  \
  --with-pammodulesdir=/usr/lib64/security                \
  --sysconfdir="$SAMBA_PATH"/conf || _MSG_ERRO_INFO "Erro ao compilar o Samba na pasta $SAMBA_VERSAO"

  # Compilar e instalar  
  make -j "$(nproc)" || _MSG_ERRO_INFO "Erro ao executar o make"
  make install       || _MSG_ERRO_INFO "Erro ao executar a instalação"

  # Adicionar bibliotecas
  find "$SAMBA_PATH"/lib -type d > /etc/ld.so.conf.d/samba4.conf
  echo "$SAMBA_PATH"/lib64      >> /etc/ld.so.conf.d/samba4.conf
  ldconfig

  # Adicionar variáveis da ambiente ao path
  echo export PATH="$SAMBA_PATH"/bin:"$SAMBA_PATH"/sbin:"${PATH}" >> /etc/profile
  echo "exclude=samba*" >> /etc/yum.conf
  
  # Gravando arquivo de controle
  echo "Configuracao realizada, função executada foi _CONFIGURAR" | tee > $CONTROLE
}
# Fim

################################################################################
_CONF_SAMBA()
{
  clear
  _VERIFICAR_OS
  _VERIFICAR_ROOT

  # Campo de controle
  CONTROLE='/tmp/controle_conf_samba.txt'

  # Valores informados
  IP_SAMBA=$(sqlite3 -batch "$DB_ARQ_CONF"  "select ip       from samba_config WHERE id = 1;")
  MASK=$(sqlite3 -batch "$DB_ARQ_CONF"      "select mask     from samba_config WHERE id = 1;")
  GW=$(sqlite3 -batch "$DB_ARQ_CONF"        "select gateway  from samba_config WHERE id = 1;")
  HOSTNAME=$(sqlite3 -batch "$DB_ARQ_CONF"  "select hostname from samba_config WHERE id = 1;")
  DOMINIO=$(sqlite3 -batch "$DB_ARQ_CONF"   "select dominio  from samba_config WHERE id = 1;")
  INTERFACE=$(sqlite3 -batch "$DB_ARQ_CONF" "select rede     from samba_config WHERE id = 1;")
  
  # Configurar hostname
  hostnamectl set-hostname "$HOSTNAME" 1> /dev/null

  # Adicionar arquivo de hosts
  cat >> /etc/hosts << EOF
${IP_SAMBA} ${HOSTNAME}.${DOMINIO} ${HOSTNAME}
EOF

  # Obter o UUID da placa de rede
  SAMBA_UUID=$(nmcli connection show | grep -i "${INTERFACE}" | head -n 1 |rev | awk '{print $3}' | rev)

  #Here document para criar arquivo de rede
  cat > /etc/sysconfig/network-scripts/ifcfg-"${INTERFACE}" << EOF
TYPE=Ethernet
PROXY_METHOD=none
BROWSER_ONLY=no
BOOTPROTO=none
DEFROUTE=yes
IPV4_FAILURE_FATAL=no
UUID=
NAME=${INTERFACE}
DEVICE=${INTERFACE}
ONBOOT=yes
IPADDR=$IP_SAMBA
PREFIX=$MASK
GATEWAY=$GW
IPV6_DISABLED=yes
EOF
  # Adicionar o UUID
  sed -i "s/UUID.*/UUID=${SAMBA_UUID}/" /etc/sysconfig/network-scripts/ifcfg-"${INTERFACE}"

  # Criar arquivo de controle
  echo "Configuracao realizada, função executada foi $CONTROLE" | tee > $CONTROLE

  # Se o endereço configurado for diferente do ip atual, o servidor será reiniciado
  IP_ATUAL=$(hostname -I | sed 's/ //')
  [[ "$IP_ATUAL" = "$IP_SAMBA" ]] || { _MSG_INFO "O Servidor vai ser reiniciado para ajuste no endereço de rede.\n\nfavor executar script novamente para continuar a instalação" ; reboot ; }
}
# Fim

################################################################################
_SAMBA_INST()
{
  _VERIFICAR_OS
  _VERIFICAR_ROOT

  CONTROLE="/tmp/controle_samba_inst.txt"
  [[ -f $CONTROLE ]] && _MSG_ERRO_INFO "Samba já instalado, caso deseje continuar favor remover o arquivo $CONTROLE"
  
  DB_ARQ_CONF=$(_CHECK_DATABASE_CONF)

  # Valores padrão
  SAMBA_DOMIN=$(sqlite3 -batch "$DB_ARQ_CONF" " SELECT dominio  FROM samba_config;"              | cut -d "." -f 1) || _MSG_ERRO_INFO "Erro ao buscar informações no banco de dados"
  SAMBA_REALM=$(sqlite3 -batch "$DB_ARQ_CONF" " SELECT dominio  FROM samba_config;")            || _MSG_ERRO_INFO "Erro ao buscar informações no banco de dados"
  SAMBA_HOSTN=$(sqlite3 -batch "$DB_ARQ_CONF" " SELECT hostname FROM samba_config;")            || _MSG_ERRO_INFO "Erro ao buscar informações no banco de dados"
  SAMBA_SENHA=$(sqlite3 -batch "$DB_ARQ_CONF" " SELECT senha    FROM samba_config;")            || _MSG_ERRO_INFO "Erro ao buscar informações no banco de dados"
  SAMBA_IPSRV=$(sqlite3 -batch "$DB_ARQ_CONF" " SELECT ip       FROM samba_config;")            || _MSG_ERRO_INFO "Erro ao buscar informações no banco de dados"
  SAMBA_MASCA=$(sqlite3 -batch "$DB_ARQ_CONF" " SELECT mask     FROM samba_config;")            || _MSG_ERRO_INFO "Erro ao buscar informações no banco de dados"
  SAMBA_IFACE=$(sqlite3 -batch "$DB_ARQ_CONF" " SELECT rede     FROM samba_config;")            || _MSG_ERRO_INFO "Erro ao buscar informações no banco de dados"
  SAMBA_PATH=$(sqlite3  -batch "$DB_ARQ_CONF" " SELECT samba_path_install FROM samba_config;")  || _MSG_ERRO_INFO "Erro ao buscar informações no banco de dados"

  # Ativar firewall e liberar serviços
  _CONFIGURAR_PORTAS_FIREWALL

  # Testando Ip do Samba
  ping -c 2 -w 5 "$SAMBA_IPSRV" || _MSG_ERRO_INFO "O IP $SAMBA_IPSRV não está acessível.\nInstalação finalizada" 

  whiptail --title "Os dados estao corretos ?" \
  --yesno "Dominio.= [ ${SAMBA_DOMIN^^} ]\nReino...= [ ${SAMBA_REALM^^} ]\nSenha...= [ ${SAMBA_SENHA} ]" --fb 15 40
  
  [[ $? -eq 1 ]] && _MSG_SAIR "Instalação Cancelada"

  # Parametros SAMBA
  "$SAMBA_PATH"/bin/samba-tool domain provision --server-role=dc --realm="${SAMBA_REALM^^}" --domain="$SAMBA_DOMIN" --dns-backend=BIND9_DLZ --use-rfc2307 --adminpass="$SAMBA_SENHA"

  CHRONY_CONF=$(find /etc/ -type f -iname chrony.conf)

  cat >> "$CHRONY_CONF" << EOF
# Configuração adicional
log measurements statistics tracking
maxupdateskew 100.0
hwclockfile /etc/adjtime
ntpsigndsocket $SAMBA_PATH/var/lib/ntp_signd
EOF

  # Reiniciar servidor de hora
  systemctl restart chronyd 1> /dev/null || _MSG_ERRO_INFO "Erro ao reiniciar chronyd"

  NSSWITCH_CONF=$(find /etc/ -type f -iname nsswitch.conf)
  cp "$NSSWITCH_CONF"{,.bkp}
  sed -i 's/^passwd.*/passwd:\ files\ winbind/g' "$NSSWITCH_CONF"
  sed -i 's/^group.*/group:\ files\ winbind/g'   "$NSSWITCH_CONF"

  mkdir -p "$SAMBA_PATH"/var/lib/ntp_signd/ || _MSG_ERRO_INFO "Erro ao criar pasta"
  chmod 0750 "$SAMBA_PATH"/var/lib/ntp_signd/
  chown root.chrony "$SAMBA_PATH"/var/lib/ntp_signd/

  touch /var/named/data/named_mem_stats.txt || _MSG_ERRO_INFO "Erro ao arquivo named_mem_stats"
  touch /var/named/data/named_stats.txt     || _MSG_ERRO_INFO "Erro ao arquivo named_stats"
  touch /var/named/data/cache_dump.db       || _MSG_ERRO_INFO "Erro ao arquivo cache_dump"
  chown named.named /var/named -R           || _MSG_ERRO_INFO "Erro ao dar permissão para a pasta var/named"
  cp "$SAMBA_PATH"/bind-dns/named.conf{,.bkp}

  NAMED_VERSION=$(rpm -qa bind |cut -d "-" -f 2 |cut -d "." -f 2) || _MSG_ERRO_INFO "Versão named não encontrada"
  chown named.named "$SAMBA_PATH"/bind-dns/named.conf
  chown named.named "$SAMBA_PATH"/bind-dns -R
  chown root.named "$SAMBA_PATH"/lib/bind9/dlz_bind9_"$NAMED_VERSION".so
 
  cat > "$SAMBA_PATH"/bind-dns/named.conf  << EOF
dlz "AD DNS Zone" {
database "dlopen $SAMBA_PATH/lib/bind9/dlz_bind9_$NAMED_VERSION.so";
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
         9.9.9.9;
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
include "$SAMBA_PATH/bind-dns/named.conf";
EOF

  echo "KRB5RCACHETYPE=\"none\"" >> /etc/sysconfig/named
  echo -e "\n[kdc]\n\tcheck-ticket-addresses = false" >> "$SAMBA_PATH"/private/krb5.conf

  \cp /usr/local/samba/private/krb5.conf /etc/
  cp "$SAMBA_PATH"/conf/smb.conf{,.bkp}

  systemctl enable --now named || _MSG_ERRO_INFO "Erro reinicar o serviço named"
  sed -i '26i dns=none' /etc/NetworkManager/NetworkManager.conf

  cp /usr/lib/systemd/system/samba.service /root/samba.service.bkp
  sed -i 's/notify/forking/'  /usr/lib/systemd/system/samba.service
  sed -i 's/--.*/-D/'         /usr/lib/systemd/system/samba.service

  systemctl daemon-reload
  systemctl enable --now samba || _MSG_ERRO_INFO "Erro ao iniciar o serviço do SAMBA"
    
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
  sleep 2
    
  SAMBA_CFSMB=$(find "${SAMBA_PATH}" -iname smb.conf)
  \cp "$SAMBA_CFSMB" /root/smb.conf.bkp

  # Configuração do arquivo smb.conf
  cat > "${SAMBA_CFSMB}" << EOF
[global]
        netbios name = ${SAMBA_HOSTN^^}
        realm = ${SAMBA_REALM^^}
        server role = active directory domain controller
        server services = s3fs, rpc, nbt, wrepl, ldap, cldap, kdc, drepl, winbindd, ntp_signd, kcc, dnsupdate
        workgroup = ${SAMBA_DOMIN^^}
        idmap_ldb:use rfc2307 = yes
        interfaces=lo ${SAMBA_IFACE}
        bind interfaces only = yes
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
        path = $SAMBA_PATH/var/locks/sysvol
        read only = No

[netlogon]
        path = $SAMBA_PATH/var/locks/sysvol/${SAMBA_REALM,,}/scripts
        read only = No
EOF

  # Ajustar conforme o ambiente                             ##### Melhorar com opção de configuração realizar perguntas
  SAMBA_TOOL=$(find "$SAMBA_PATH" -iname samba-tool)
  "$SAMBA_TOOL" domain passwordsettings set --complexity=off    > /dev/null 2>&1
  "$SAMBA_TOOL" domain passwordsettings set --history-length=0  > /dev/null 2>&1
  "$SAMBA_TOOL" domain passwordsettings set --min-pwd-age=0     > /dev/null 2>&1
  "$SAMBA_TOOL" domain passwordsettings set --min-pwd-length=3  > /dev/null 2>&1
  "$SAMBA_TOOL" domain passwordsettings set --max-pwd-age=0     > /dev/null 2>&1

  whiptail --title "Politica de senha" --msgbox "$("$SAMBA_PATH"/bin/samba-tool domain passwordsettings show)" --fb 20 50  

  "$SAMBA_PATH"/bin/net rpc rights grant "${SAMBA_DOMIN^^}\Domain Admins" SeDiskOperatorPrivilege -U"${SAMBA_DOMIN^^}\administrator%$SAMBA_SENHA"
  "$SAMBA_PATH"/bin/net rpc rights list accounts -U"${SAMBA_DOMIN^^}\administrator%${SAMBA_SENHA}"
  "$SAMBA_PATH"/bin/smbcontrol all reload-config

  IP_REVERSO=$(_REVERSO)
  "$SAMBA_TOOL" dns zonecreate "${SAMBA_HOSTN}" "${IP_REVERSO}" -UAdministrator%"${SAMBA_SENHA}"
  "$SAMBA_TOOL" dns add "${SAMBA_HOSTN}" "${IP_REVERSO}" "${SAMBA_IPSRV##*.}" PTR "${SAMBA_HOSTN}.${SAMBA_REALM}" -UAdministrator%"${SAMBA_SENHA}"
  
  # Criar rede sites e serviços
  SITE_NAME=$("$SAMBA_TOOL" sites list)
  NETWORK=$(ipcalc -n "$SAMBA_IPSRV"/"$SAMBA_MASCA" | cut -d "=" -f 2)
  "$SAMBA_TOOL" sites subnet create "$NETWORK"/"$SAMBA_MASCA" "$SITE_NAME"

  # Deletar registros ipv6 da pesquisa, se utilizar ipv6 remover as 2 linhas abaixo, se usar ipv6 na rede ignorar as 2 linhas abaixo
  \cp /var/named/named.ca /root/
  sed -i '/AAAA/d' /var/named/named.ca

  "$SAMBA_PATH"/sbin/samba_dnsupdate
  systemctl restart samba.service 1> /dev/null || _MSG_ERRO_INFO "Erro ao reiniciar samba"
  systemctl restart named.service 1> /dev/null || _MSG_ERRO_INFO "Erro ao reiniciar dns"

  sed -i '8i After=samba.service' /lib/systemd/system/named.service 1> /dev/null
  systemctl daemon-reload 1> /dev/null

  echo "Configuracao realizada, função executada foi _CONF_SAMBA" | tee > $CONTROLE

  # Realizar testes
  clear
  SMB_LIST=$(klist)                                         1> /dev/null
  SMB_HOST=$(host -t A "$SAMBA_REALM")                      1> /dev/null
  SMB_LDAP=$(host -t SRV _ldap._tcp."$SAMBA_REALM")         1> /dev/null
  SMB_KERB=$(host -t SRV _kerberos._udp."$SAMBA_REALM".)    1> /dev/null
  SMB_VER="$("$SAMBA_PATH"/bin/smbclient --version)"        1> /dev/null
  sleep 1
  SMB_COMP=$("$SAMBA_PATH"/bin/smbclient -L localhost -U%)  1> /dev/null
  
  # Exibir informações
  whiptail --title "Informações" --msgbox \
   "\n[Versão...:] $SMB_VER 
    \n[Share....:] $SMB_COMP
    \n[Host.....:] $SMB_HOST
    \n[Ldap.....:] $SMB_LDAP
    \n[Kerberos.:] $SMB_KERB
    \n[klist....:] $SMB_LIST " --fb 30 100


  if whiptail --title "Aplicar Configurações - SAMBA $("$SAMBA_PATH"/bin/smbclient --version | awk '{print$2}')" --yesno "Deseja reiniciar o servidor" 10 50 ; then reboot ; fi 
}
# Fim

################################################################################
_SAMBA_CHECK()
{
  clear
  #realizar testes
  echo 'Verificando configurações'
  sleep 2

  # Verificar informações do banco de dados
  DB_ARQ_CONF=$(_CHECK_DATABASE_CONF)

  # Carregar arq install samba
  SAMBA_PATH=$(sqlite3 -batch "$DB_ARQ_CONF" " SELECT samba_path_install  FROM samba_config;") || _MSG_ERRO_INFO "Erro ao buscar informações no banco de dados"

  MSG_TESTE="
  Será realizado as seguintes operações:

  Verificação e correção banco de dados.....-> (dbcheck)
  Verificação e correção volume do systema..-> (sysvol)
  Atualização dos registros de dns..........-> (samba_dns)
  Recarregar as configurações do SAMBA......-> (reload)"

  SMBCLIENT=$(find "$SAMBA_PATH" -iname smbclient)
  if ! whiptail --title "Validar recursos SAMBA $("$SMBCLIENT" --version | awk '{print$2}')" --yesno "$MSG_TESTE" 20 65 ; then exit 20 ; fi 

  WBINFO=$(find "$SAMBA_PATH" -iname wbinfo)
  SAMBA_TOOL=$(find "$SAMBA_PATH" -iname samba-tool)
  DNS_UPDATE=$(find "$SAMBA_PATH" -iname samba_dnsupdate)
  SMBCONTROL=$(find "$SAMBA_PATH" -iname smbcontrol)
  SAMBA_SENHA=$(sqlite3 -batch "$DB_ARQ_CONF" " SELECT senha    FROM samba_config;") || _MSG_ERRO_INFO "Erro ao buscar informações no banco de dados"
  SAMBA_REALM=$(sqlite3 -batch "$DB_ARQ_CONF" " SELECT dominio  FROM samba_config;") || _MSG_ERRO_INFO "Erro ao buscar informações no banco de dados"

  # Realizando checagens
  clear
  "$SAMBA_TOOL" dbcheck                                             && { sleep 2; echo -e "\nVerificando" ; }
  "$SAMBA_TOOL" dbcheck --cross-ncs                                 && { sleep 2; echo -e "\nVerificando" ; }
  "$SAMBA_TOOL" dbcheck --cross-ncs --fix --yes                     && { sleep 2; echo -e "\nVerificando" ; }
  "$SAMBA_TOOL" dbcheck --cross-ncs --reset-well-known-acls --fix   && { sleep 2; echo -e "\nVerificando" ; }
  "$SAMBA_TOOL" ntacl sysvolcheck                                   && { sleep 2; echo -e "\nVerificando" ; }
  "$SAMBA_TOOL" ntacl sysvolreset                                   && { sleep 2; echo -e "\nVerificando" ; }

  getent passwd Administrator                 && { sleep 2; echo -e "\nVerificando" ; }
  host -t SRV _ldap._tcp."$SAMBA_REALM".      && { sleep 2; echo -e "\nVerificando" ; }
  host -t SRV _kerberos._udp."$SAMBA_REALM".  && { sleep 2; echo -e "\nVerificando" ; }
  host -t A "$(hostname)"."$SAMBA_REALM".     && { sleep 2; echo -e "\nVerificando" ; }
  "$WBINFO" --ping-dc                         && { sleep 2; echo -e "\nVerificando" ; }

  "$SAMBA_TOOL" dns query "$(hostname)" "$SAMBA_REALM" @ ALL -UAdministrator%"${SAMBA_SENHA}"  && { sleep 2; echo -e "\nVerificando" ; }
  host -t SRV _ldap._tcp.Default-First-Site-Name._sites.ForestDnsZones."$SAMBA_REALM".         && { sleep 2; echo -e "\nVerificando" ; }
  
  clear
  "$DNS_UPDATE" --verbose         && { sleep 2; echo -e "\nVerificando" ; } && { sleep 2; echo -e "Atualizando\n" ; }
  "$SMBCONTROL" all reload-config && { sleep 2; echo -e "\nVerificando" ; } && { sleep 2; echo -e "Recarregando\n" ; }
}
# Fim declaração de função

#############################################################################################################################
#                                                 Inicio do script                                                          #
#############################################################################################################################

# Arquivos globais


# Atualiza os sitema e baixa os programas essencias para o funcionamento do script
_ATUALIZAR_BASE

# Menu principal
_Menu() {
    # Carregar configuraçoes do SAMBA
    _SAMBA_DB_CONFIG

    # Verifica se o pacote whiptail está instalado
    which whiptail > /dev/null || yum install -y newt > /dev/null 

    SEL=$(whiptail --title "Menu" --fb --menu "Escolha uma opção" 15 60 6 \
        "1" "Instalar Samba "           \
        "2" "Baixar pacotes e compilar" \
        "3" "Configurar"                \
        "4" "Instalar"                  \
        "5" "Realizar Teste do Samba"   \
        "9" "Sair" 3>&1 1>&2 2>&3)
    case $SEL in
        1)
            echo "Escolhida 1"
            _SAMBA_CADASTRO_CONFIG
            _CONFIGURAR
            _CONF_SAMBA
            _SAMBA_INST
            _SAMBA_CHECK
        ;;
        2)
            echo "Escolhida 2"
            _CONFIGURAR
        ;;
        3)
            echo "Escolhida 3"
          _SAMBA_CADASTRO_CONFIG
           _CONF_SAMBA
        ;;
        4)
            echo "Escolhida 4"
           _SAMBA_INST
        ;;
        5)
            echo "Escolhida 4"
           _SAMBA_CHECK
        ;;
        9)
            echo "Escolhida 5"
            exit
        ;;
    esac
}

# Função para instalar
_Menu
