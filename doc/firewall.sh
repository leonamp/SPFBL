#!/bin/bash
################################################################################
# Script firewall SPFBL
# ajcorrea@gmail.com
# Release inicial: 10 Setembro 2017
#
################################################################################
# Portas utilizadas pelo servidor
## 9875 TCP = ADMIN
## 9876 TCP = ADMIN SSL
## 9877 TCP = SPFBL
## 9878 TCP = SPFBLS
## 9877 UDP = P2P
## 9878 UDP = P2P SSL
################################################################################
# Configuracoes
#
# Portas,Protocolos,Chains
_Ports='tcp:9875:SPFBL-ADMIN tcp:9876:SPFBL-ADMIN tcp:9877:SPFBL-SPFBL tcp:9878:SPFBL-SPFBL udp:9877:SPFBL-P2P udp:9878:SPFBL-P2P'
# IPs permitidos ao ADMIN
_chainADMIN='SPFBL-ADMIN'
_accADMIN='127.0.0.1 169.254.1.1'
# IPs permitidos ao SPFBL
_chainSPFBL='SPFBL-SPFBL'
_accSPFBL='127.0.0.1 169.254.1.2'
# IPs permitidos ao P2P
_chainP2P='SPFBL-P2P'
_accSP2P='127.0.0.1 169.254.1.3'
# FIM das configuracoes
################################################################################
# Uso do script (nao alterar):
_IPT=`which iptables`
_AWK=`which awk`
################################################################################
# Script run.
_chains='SPFBL-ADMIN SPFBL-SPFBL SPFBL-P2P'
for _x in $_Ports; do
        _str=$(echo $_x | $_AWK -F":" '{print $1,$2,$3}')
        set -- $_str
        if [ "$1" == "udp" ]; then
           $_IPT -t filter -D INPUT -p $1 --dport $2 -j $3 > /dev/null 2>&1
        else
           $_IPT -t filter -D INPUT -p $1 --dport $2 --tcp-flags ALL SYN -j $3 > /dev/null 2>&1
        fi
done
for _x in $_chains; do
   $_IPT -t filter -F $_x > /dev/null 2>&1
   $_IPT -t filter -X $_x > /dev/null 2>&1
   $_IPT -t filter -N $_x > /dev/null 2>&1
done
for _x in $_Ports; do
        _str=$(echo $_x | $_AWK -F":" '{print $1,$2,$3}')
        set -- $_str
        if [ "$1" == "udp" ]; then
           $_IPT -t filter -I INPUT -p $1 --dport $2 -j $3 > /dev/null 2>&1
        else
           $_IPT -t filter -I INPUT -p $1 --dport $2 --tcp-flags ALL SYN -j $3 > /dev/null 2>&1
        fi
done
for _x in $_accADMIN; do
   $_IPT -A $_chainADMIN -s $_x -j ACCEPT > /dev/null 2>&1
done
for _x in $_accSPFBL; do
   $_IPT -A $_chainSPFBL -s $_x -j ACCEPT > /dev/null 2>&1
done
for _x in $_accSP2P; do
   $_IPT -A $_chainP2P -s $_x -j ACCEPT > /dev/null 2>&1
done

 $_IPT -A $_chainADMIN -j DROP > /dev/null 2>&1
 $_IPT -A $_chainSPFBL -j DROP > /dev/null 2>&1
 $_IPT -A $_chainP2P -j DROP > /dev/null 2>&1
