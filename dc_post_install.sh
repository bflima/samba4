#!/usr/bin/env bash

SAMBA_TOOL=$(find /usr -iname samba-tool)
"$SAMBA_TOOL" domain info $(hostname) > /tmp/samba_dc_info

SAMBA_DOM=$(grep -i ^domain /tmp/samba_dc_info | awk '{print $3}')

PATH_SAMBA=$(find /usr -type d -iname samba4 | grep samba4)


clear
"$SAMBA_TOOL" dbcheck
sleep 1
"$SAMBA_TOOL" dbcheck --cross-ncs
sleep 1
"$SAMBA_TOOL" dbcheck --cross-ncs --fix --yes
sleep 1
"$SAMBA_TOOL" dbcheck --cross-ncs --reset-well-known-acls --fix
sleep 1
"$SAMBA_TOOL" ntacl sysvolcheck
sleep 1
"$SAMBA_TOOL" ntacl sysvolreset

echo -e "\n\n\n"
read -p "Para continuar precisone qualquer tecla" RET

clear
smbclient -L localhost -U%

echo -e "\n\n\n"
getent passwd Administrator
host -t SRV _ldap._tcp.Default-First-Site-Name._sites.ForestDnsZones."$SAMBA_DOM".
# samba-tool dns query $(hostname) "$SAMBA_DOM" @ ALL
host -t SRV _ldap._tcp."$SAMBA_DOM".
host -t SRV _kerberos._udp."$SAMBA_DOM".
host -t A $(hostname)."$SAMBA_DOM".
wbinfo --ping-dc

echo -e "\n\n\n"
read -p "Para continuar precisone qualquer tecla" RET

"$PATH_SAMBA"/sbin/samba_dnsupdate --verbose
"$PATH_SAMBA"/bin/smbcontrol all reload-config
