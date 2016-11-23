#!/bin/bash
#
# This file is part of SPFBL.
# and open the template in the editor.
#
# SPFBL is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# SPFBL is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with SPFBL.  If not, see <http://www.gnu.org/licenses/>.
#
# Projeto SPFBL - Copyright Leandro Carlos Rodrigues - leandro@spfbl.net
# https://github.com/leonamp/SPFBL
#
# Atenção! Para utilizar este serviço, solicite a liberação das consultas
# no servidor matrix.spfbl.net através do endereço leandro@spfbl.net
# ou altere o matrix.spfbl.net deste script para seu servidor SPFBL próprio.
# 
# Atenção! Para utilizar este script é necessário ter o Qmail-SPP instalado:
#
#   http://qmail-spp.sourceforge.net/doc/
#
# Atenção! Para utilizar este script é necessário ter o netcat instalado:
#
#   sudo apt-get install netcat
#
# Se estiver usando a autenticação por OTP, prencha a constante OTP_SECRET
# com a chave secreta fornecida pelo serviço SPFBL e mantenha a variável 
# OTP_SECRET vazia. É necessário oathtool para usar esta autenticação:
#
#   sudo apt-get install oathtool
#

### CONFIGURACOES ###
IP_SERVIDOR="matrix.spfbl.net"
PORTA_SERVIDOR="9877"
OTP_SECRET=""

### PARAMETROS QMAIL-SSP ###
ip=${TCPREMOTEIP}
port=${TCPLOCALPORT}
sender=${SMTPMAILFROM}
helo=${SMTPHELOHOST}
recipient=${SMTPRCPTTO}

if [ $port -eq 25 ]; then

	# Definição da senha OPT.
	if [[ $OTP_SECRET == "" ]]; then
		OTP_CODE=""
	else
		OTP_CODE="$(oathtool --totp -b -d 6 $OTP_SECRET) "
	fi

	result=$(echo $OTP_CODE"SPF '$ip' '$sender' '$helo' '$recipient'" | nc -w 20 $IP_SERVIDOR $PORTA_SERVIDOR)

	if [[ $result == "" ]]; then
	
		# Log SPFBL connection error.
		echo "SPFBL NO CONNECTION" >&2
		echo "EA transient error occurred when checking SPF record. Try again later."
		
	elif [[ $result == "NXDOMAIN" ]]; then
	
		# Reject NXDOMAIN.
		echo "R551 5.7.1 SPFBL sender has non-existent internet domain."
		
	elif [[ $result == "GREYLIST" ]]; then
	
		# Defer for greylisting.
		echo "E451 4.7.1 SPFBL you are greylisted on this server."
		
	elif [[ $result == "INVALID" ]]; then
	
		# Reject invalid identificators.
		echo "R551 5.7.1 SPFBL IP or sender is invalid."
		
	elif [[ $result == "INVALID "* ]]; then
	
		# Log SPFBL invalid query.
		echo "SPFBL $result" >&2
		echo "EA transient error occurred when checking SPF record. Try again later."
		
	elif [[ $result == "LAN" ]]; then
	
		# Accept mail from local network.
		echo "A"
		
	elif [[ $result == "FLAG" ]]; then
	
		# Add spam flag header and accept message.
		echo "HX-Spam-Flag: YES"
		echo "Sspam=1"
		echo "A"
		
	elif [[ $result == "SPAMTRAP" ]]; then
	
		# Discard spamtrap message with maildrop or sieve.
		echo "HReceived-SPFBL: SPAMTRAP"
		echo "A"
		
	elif [[ $result == "BLOCKED "* ]]; then
	
		# Reject blocked sender.
		echo "R551 $result"
		
	elif [[ $result == "BLOCKED" ]]; then
	
		# Reject blocked sender.
		echo "R551 5.7.1 SPFBL you are permanently blocked in this server."
		
	elif [[ $result == "LISTED "* ]]; then
	
		# Defer listed sender.
		echo "E451 4.7.2 SPFBL you are temporarily blocked on this server."
		
	elif [[ $result == "LISTED" ]]; then
	
		# Defer listed sender.
		echo "E451 4.7.2 SPFBL $result"
			
	elif [[ $result == "ERROR: "* ]]; then
	
		# Log SPFBL error.
		echo "SPFBL $result" >&2
		echo "EA transient error occurred when checking SPF record. Try again later."
		
	elif [[ $result == "NONE "* ]]; then
	
		# Add SPFBL header.
		echo "HReceived-SPFBL: $result"
		echo "N"
		
	elif [[ $result == "PASS "* ]]; then
	
		# Add SPFBL header.
		echo "HReceived-SPFBL: $result"
		echo "N"
		
	elif [[ $result == "WHITE "* ]]; then
	
		# Add SPFBL header.
		echo "HReceived-SPFBL: $result"
		echo "A"
		
	elif [[ $result == "FAIL "* ]]; then
	
		# Retornou FAIL com ticket então
		# significa que está em whitelist.
		# Retornar como se fosse SOFTFAIL.
		echo "HReceived-SPFBL: $result"
		echo "N"
		
	elif [[ $result == "FAIL" ]]; then
	
		# Reject failed SPF.
		echo "R551 5.7.1 SPFBL $sender is not allowed to send mail from $ip."
		
	elif [[ $result == "SOFTFAIL "* ]]; then
	
		# Add SPFBL header.
		echo "HReceived-SPFBL: $result"
		echo "N"
		
	elif [[ $result == "NEUTRAL "* ]]; then
	
		# Add SPFBL header.
		echo "HReceived-SPFBL: $result"
		echo "N"
		
	else
	
		# Log an unknow SPFBL error.
		echo "SPFBL ERROR: UNKNOWN" >&2
		echo "EA transient error occurred when checking SPF record. Try again later."
		
	fi

fi
