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
# Atenção! Para utilizar este script é necessário ter o nmap instalado:
#
#   sudo apt-get install nmap ncat
#
# Caso esteja usando o freebsb, instale o nmap por este método:
#
#   cd /usr/ports/security/nmap
#   make all install clean
#

### CONFIGURACOES ###
IP_SERVIDOR="matrix4.spfbl.net"
# Endereço da porta administrativa: o próprio servidor SPFBL, pelo loopback IPv6.
IP_ADMIN="::1"
PORTA_SERVIDOR="9877"
PORTA_ADMIN="9875"
SECURED="false"
DUMP_PATH="/tmp"
# Tempo máximo de qualquer consulta, em segundos. Igual ao limite do
# proxy da Cloudflare (100 segundos até a origem começar a responder):
# esperar mais que isso não adianta, porque o proxy já terá desistido.
QUERY_TIMEOUT="100"
MAX_TIMEOUT="256"
# Análise profunda por inteligência artificial no comando scan, para os
# casos que o algoritmo do SPFBL não decide sozinho. Gera custo por
# mensagem analisada. Valores: "true" (padrão) ou "false".
DEEP_ANALYSIS="true"
LOGPATH=/var/log/spfbl/
# Servidor SPFBL das consultas HTTPS.
URL_SERVIDOR="https://matrix.spfbl.net"

# Configuração local, criada pelo spfbl.irondome.sh e preservada nas
# atualizações deste script. Sem ela, o cliente é identificado pelo IP
# (cadastro CIDR), como nas versões anteriores. Com ela, cada consulta
# leva a chave de acesso e o hostname da máquina por cabeçalho HTTPS,
# em IPv4 ou IPv6. Só os nomes abaixo são lidos; o arquivo não é
# executado. Formato: NOME=valor, uma linha por parâmetro.
SPFBL_CONF="/etc/spfbl/spfbl.conf"
SPFBL_KEY=""
# Protocolo das consultas com chave: vazio (IPv4 ou IPv6, o que o curl
# conseguir), 4 ou 6. O spfbl.irondome.sh grava 4 quando o hostname não
# tem AAAA com o IPv6 do servidor, e 6 no caso inverso.
IP_VERSION=""
if [[ -r $SPFBL_CONF ]]; then
	while IFS='=' read -r name value; do
		value=${value%$'\r'}
		value=${value#\"}
		value=${value%\"}
		case "$name" in
			SPFBL_KEY)
				[[ $value =~ ^spfbl_[A-Za-z0-9_-]+$ ]] && SPFBL_KEY=$value
				;;
			URL_SERVIDOR)
				[[ $value =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?$ ]] && URL_SERVIDOR=$value
				;;
			QUERY_TIMEOUT)
				[[ $value =~ ^[0-9]+$ ]] && QUERY_TIMEOUT=$value
				;;
			MAX_TIMEOUT)
				[[ $value =~ ^[0-9]+$ ]] && MAX_TIMEOUT=$value
				;;
			DEEP_ANALYSIS)
				[[ $value =~ ^(true|false)$ ]] && DEEP_ANALYSIS=$value
				;;
			IP_VERSION)
				[[ $value =~ ^[46]?$ ]] && IP_VERSION=$value
				;;
			IP_SERVIDOR)
				[[ $value =~ ^[A-Za-z0-9.:-]+$ ]] && IP_SERVIDOR=$value
				;;
			IP_ADMIN)
				# Endereço dos comandos administrativos (porta admin). Padrão:
				# ::1, o loopback IPv6 do próprio servidor SPFBL.
				[[ $value =~ ^[A-Za-z0-9.:-]+$ ]] && IP_ADMIN=$value
				;;
			PORTA_ADMIN)
				[[ $value =~ ^[0-9]+$ ]] && PORTA_ADMIN=$value
				;;
			SECURED)
				[[ $value =~ ^(true|false)$ ]] && SECURED=$value
				;;
		esac
	done < "$SPFBL_CONF"
fi
# Hostname enviado ao servidor: o nome em uso agora no kernel, lido a
# cada execução, sem processo novo e sem DNS. Uma troca de hostname
# chega ao SPFBL na consulta seguinte. O hostname do servidor precisa
# ser o FQDN (hostnamectl set-hostname mx.exemplo.com); nome curto é
# recusado pelo servidor e as mensagens passam sem filtro.
LOCAL_HOSTNAME=""
if [[ -r /proc/sys/kernel/hostname ]]; then
	read -r LOCAL_HOSTNAME < /proc/sys/kernel/hostname
elif [[ -n $SPFBL_KEY ]]; then
	# Fora do Linux (FreeBSD): comando hostname.
	LOCAL_HOSTNAME=$(hostname 2> /dev/null)
fi
LOCAL_HOSTNAME=${LOCAL_HOSTNAME,,}
# Chave e hostname para o curl -K, entregues por um descritor (3<<<):
# não aparecem na linha de comando nem no ps.
CURL_KEY_CONFIG="header = \"Authorization: Bearer $SPFBL_KEY\""$'\n'"header = \"X-SPFBL-Hostname: $LOCAL_HOSTNAME\""
# IP de saída das consultas com chave, quando o do sistema não é um IP do
# hostname (ver keyCurl).
INTERFACE_FILE="/tmp/SPFBL_INTERFACE"

# Timeouts de cada consulta:
#   -w 3                      tempo máximo para conectar.
#   timeout QUERY_TIMEOUT     tempo máximo da consulta inteira. Sem ele, uma
#                             conexão que cai no meio do caminho deixa o ncat
#                             aberto para sempre. O -i do ncat não serve: no
#                             ncat 6.x ele espera o tempo todo mesmo depois de
#                             o servidor fechar a conexão.
if [[ $SECURED == "true" ]]; then
	NCAT="timeout -k 2 $QUERY_TIMEOUT ncat -w 3 --ssl-verify"
else
	NCAT="timeout -k 2 $QUERY_TIMEOUT ncat -w 3"
fi

# Canal das consultas ao servidor SPFBL sem chave no spfbl.conf (pelo IP).
# Com chave, as consultas passam pela função spfbl_query.
COMMAND="curl -4 -s -f --connect-timeout 3 -m $QUERY_TIMEOUT --data-binary @- $URL_SERVIDOR/spfbl/"
# Para consultar via ncat, comente a linha acima e descomente a abaixo.
# O comando scan continua usando HTTPS pelo URL_SERVIDOR.
# COMMAND="$NCAT $IP_SERVIDOR $PORTA_SERVIDOR"

export PATH=/sbin:/usr/sbin:/bin:/usr/bin:/usr/local/sbin:/usr/local/bin
version="3.09"

# Contador de timeouts seguidos. Guarda também o estado MAINTENANCE,
# gravado quando a primeira falha de um evento coincide com a janela de
# manutenção publicada em https://status.spfbl.net. A primeira consulta
# bem-sucedida volta tudo para zero.
TIMEOUT_FILE="/tmp/SPFBL_TIMEOUT_COUNT"

# Monitor do serviço no HetrixTools. A chave só tem leitura e está
# limitada ao status deste monitor, dado já público em status.spfbl.net.
HETRIX_URL="https://api.hetrixtools.com/v3/uptime-monitors?id=acf42641d16137913fcef0a2b40b4d41"
HETRIX_KEY="2e8532718d586454d2ee2bafe98a4bc9"

if [ ! -f "$TIMEOUT_FILE" ]; then
    touch "$TIMEOUT_FILE"
    chmod 777 "$TIMEOUT_FILE"
fi

function suppression_manual() {
	printf "Suppression list: addresses that must not receive messages from SPFBL.net.\n"
	printf "\n"
	printf "Syntax:\n"
	printf "    $0 suppression TYPE key       add the key with this type\n"
	printf "    $0 suppression drop key [TYPE]\n"
	printf "    $0 suppression show key\n"
	printf "    $0 suppression list TYPE\n"
	printf "\n"
	printf "Example:\n"
	printf "    $0 suppression abuse user@domain.com\n"
	printf "\n"
	printf "Keys:\n"
	printf "    user@domain.com    one address\n"
	printf "    user@              this local part in any domain\n"
	printf "    @domain.com        every address of the domain\n"
	printf "    .domain.com        every address of the domain and its subdomains\n"
	printf "    (the last three forms are always NONCOMPLIANT)\n"
	printf "\n"
	printf "Types (days without use before expiring, messages blocked):\n"
	printf "    inexistent     365  all      address does not exist (also leaves the abuse contacts)\n"
	printf "    rejected        90  all      the server of the address rejects our messages\n"
	printf "    unsubscribed   365  all      the owner asked not to receive messages\n"
	printf "    complaint      365  all      the owner complained about our messages\n"
	printf "    malware         30  malware  malware notices only\n"
	printf "    abuse          180  abuse    abuse reports only\n"
	printf "    quota            7  all      mailbox full\n"
	printf "    hold           180  hold     hold notices only\n"
	printf "    spammer        180  all      address used to send spam\n"
	printf "    noncompliant   365  all      domain or local part keys\n"
	printf "\n"
	printf "Entries added here have origin ADMIN. Each blocked delivery counts as use.\n"
	printf "The old \"noreply\" command was replaced by \"suppression\":\n"
	printf "    noreply add user@domain.com  ->  suppression unsubscribed user@domain.com\n"
}

function billing_manual() {
	printf "Billing: users' invoices, counters and prices (administration port).\n"
	printf "\n"
	printf "Syntax:\n"
	printf "    $0 billing create user@domain.com   create the billing and its current invoice\n"
	printf "    $0 billing show user@domain.com     billing, invoices and every counter\n"
	printf "    $0 billing close user@domain.com    close the current invoice now; today becomes the closing day\n"
	printf "    $0 billing drop user@domain.com     remove the billing (tests)\n"
	printf "    $0 billing list                     users with billing\n"
	printf "    $0 billing paid INVOICE CUR VALUE   record the payment of what is due on a closed invoice (USD, EUR or BRL)\n"
	printf "    $0 billing pix user@domain.com      enable PIX and the BRL currency (permanent)\n"
	printf "    $0 billing credit add user@domain.com USD   add credit (used at once on pending invoices)\n"
	printf "    $0 billing credit drop user@domain.com USD  reverse credit added by mistake\n"
	printf "    $0 billing element add INVOICE ITEM ELEMENT\n"
	printf "                                        add an element to a set item of an unpaid invoice\n"
	printf "    $0 billing element drop INVOICE ITEM ELEMENT\n"
	printf "                                        remove an element from a set item of an unpaid invoice\n"
	printf "    $0 billing invoice price INVOICE ITEM VALUE\n"
	printf "                                        change the price of an item in an unpaid invoice (0 = free)\n"
	printf "    $0 billing invoice edit INVOICE     open (or renew) the edition of an unpaid invoice for 1 hour\n"
	printf "    $0 billing invoice done INVOICE     end the edition now and settle the invoice\n"
	printf "    $0 billing price set ITEM VALUE     create or change a price\n"
	printf "    $0 billing price drop ITEM          remove a price (the item becomes zero)\n"
	printf "    $0 billing price show               current price table\n"
	printf "    $0 billing price apply [ITEM]       apply the price table to every current invoice (one item or all)\n"
	printf "\n"
	printf "Examples:\n"
	printf "    $0 billing price set spfbl_client_set 2\n"
	printf "    $0 billing price set spfbl_envelope_count 0.01/K    (K or M, or the unit price)\n"
	printf "    $0 billing price set spfbl_incoming_bytes 0.01/MB   (B, KB, MB, GB or TB)\n"
	printf "    $0 billing paid MWVTZOAG BRL 10.68\n"
	printf "    $0 billing element drop MWVTZOAG spfbl_domain_set example.com\n"
	printf "    $0 billing element add MWYYPW7R spfbl_client_set mx.example.com\n"
	printf "    $0 billing invoice price MWYYPW7R spfbl_header_count 0.01/K\n"
	printf "\n"
	printf "An invoice copies the price table when it is created and keeps it until it\n"
	printf "closes: a new price only applies to the invoices created after it, unless\n"
	printf "\"price apply\" copies it to the current invoices.\n"
	printf "Every element or price change opens the edition of the invoice for 1 hour\n"
	printf "(renewed at each change): meanwhile the credit is not used nor returned, the\n"
	printf "invoice is not settled and the cycle does not close. At the end, any credit\n"
	printf "used beyond the new total returns to the balance as an adjustment.\n"
	printf "Users only see items with quantity and price greater than zero.\n"
	printf "\n"
	printf "Items:\n"
	printf "    spfbl_user_set spfbl_client_set spfbl_domain_set spfbl_envelope_count\n"
	printf "    spfbl_header_count spfbl_malware_count spfbl_scan_bytes spfbl_analysis_bytes\n"
	printf "    spfbl_complain_count spfbl_firewall_count spfbl_incoming_bytes\n"
	printf "    spfbl_delivery_count spfbl_delivery_bytes spfbl_routing_count spfbl_hold_count\n"
	printf "    spfbl_release_count spfbl_alert_count spfbl_imap_count spfbl_api_count\n"
	printf "    spfbl_whois_count spfbl_query_count spfbl_dns_count spfbl_sample_count\n"
	printf "    spfbl_sample_bytes admin_support_count\n"
	printf "    dnswl_fqdn_set dnsal_domain_set dnsal_fqdn_set   (DNS listings)\n"
}

function listing_manual() {
	printf "Listing: DNS listings contracted by users (administration port).\n"
	printf "\n"
	printf "Syntax:\n"
	printf "    $0 listing show user@domain.com           records of the user\n"
	printf "    $0 listing list { dnswl | dnsal }         all records of the type\n"
	printf "    $0 listing drop { dnswl | dnsal } user@domain.com VALUE\n"
	printf "                                              remove a record (the user receives an alert)\n"
	printf "\n"
	printf "DNSWL values are FQDNs; DNSAL values are a root domain or an FQDN.\n"
	printf "The administrator's own lists (white and abuse contacts) stay as they are.\n"
}

function admin_manual() {
	# Ajuda dos comandos administrativos repassados à porta administrativa.
	local family=$1
	printf "Administration command (passed through to the administration port).\n"
	printf "Family and subcommand may be typed in lowercase; values go as typed.\n"
	printf "\n"
	printf "Syntax:\n"
	case $family in
		'thread'|'memory')
			printf "    $0 $family show\n"
		;;
		'service')
			printf "    $0 service start { IPinfoIO | RIPE | ... }\n"
		;;
		'log')
			printf "    $0 log level { ERROR | WARN | INFO | DEBUG | TRACE }\n"
			printf "    $0 log dns { true | false }\n"
			printf "    $0 log p2p { true | false }\n"
		;;
		'owner')
			printf "    $0 owner get domain\n"
			printf "    $0 owner set domain email\n"
		;;
		'locale')
			printf "    $0 locale get email\n"
			printf "    $0 locale set email locale\n"
		;;
		'icann'|'private')
			printf "    $0 $family { add value | drop value | show }\n"
		;;
		'dnsbl'|'uribl'|'dnswl'|'score'|'dnsal'|'since')
			printf "    $0 $family add zone ...\n"
			printf "    $0 $family set zone ...\n"
			printf "    $0 $family drop { zone | all }\n"
			printf "    $0 $family show\n"
		;;
		'fqdn')
			printf "    $0 fqdn { add ... | white ... | drop ... | show ... }\n"
		;;
		'gateway')
			printf "    $0 gateway show [domain]\n"
			printf "    $0 gateway add user domain server1 [... serverN]\n"
			printf "    $0 gateway set domain server1 [... serverN]\n"
			printf "    $0 gateway drop domain\n"
			printf "    $0 gateway import file\n"
			printf "    $0 gateway key { add host | show | drop id }\n"
		;;
		'recipient')
			printf "    $0 recipient add user recipient [TYPE]\n"
			printf "    $0 recipient set user recipient { TYPE | locale }\n"
			printf "    $0 recipient drop user { recipient | @domain [TYPE] }\n"
			printf "    $0 recipient drop user email\n"
			printf "    $0 recipient show { attack | catchall | node user }\n"
		;;
		'guess')
			printf "    $0 guess { add ... | drop { value | all } | show }\n"
		;;
		'dictionary')
			printf "    $0 dictionary add lang word\n"
			printf "    $0 dictionary put ...\n"
			printf "    $0 dictionary compile ...\n"
			printf "    $0 dictionary flag ...\n"
			printf "    $0 dictionary rep ...\n"
			printf "    $0 dictionary drop { key | word | regex | flag | rep } ...\n"
			printf "    $0 dictionary show { set | map | regex | flag }\n"
		;;
		'certificate'|'stack'|'reload'|'queue')
			printf "    $0 $family\n"
		;;
		'split')
			printf "    $0 split cidr\n"
		;;
		'suspect')
			printf "    $0 suspect token\n"
		;;
		'licence')
			printf "    $0 licence email mx\n"
		;;
		'invitation')
			printf "    $0 invitation [user:]recipient ...\n"
		;;
		'transport')
			printf "    $0 transport user add index smtp hostname [port] [username] [password]\n"
			printf "    $0 transport user { set | put } ...\n"
			printf "    $0 transport user drop index\n"
			printf "    $0 transport user show\n"
		;;
	esac
}

function upperKeyword() {
	# Devolve o token em maiúsculas só quando ele é uma das palavras-chave
	# informadas; qualquer outro valor segue exatamente como foi digitado.
	local token=$1
	shift
	local upper=$(echo "$token" | tr '[:lower:]' '[:upper:]')
	local keyword
	for keyword in "$@"; do
		if [[ $upper == "$keyword" ]]; then
			echo "$upper"
			return 0
		fi
	done
	echo "$token"
	return 1
}

function head(){

	echo "SPFBL v$version - by Leandro Rodrigues - leandro@spfbl.net"
}

function incrementTimeout() {

	local COUNT=$(cat "$TIMEOUT_FILE" 2> /dev/null)

	# Valor que não é número (MAINTENANCE) fica como está.
	if [[ -z $COUNT || $COUNT =~ ^[0-9]+$ ]]; then
		COUNT=$(( ${COUNT:-0} + 1 ))
		echo "${COUNT}" > "$TIMEOUT_FILE"
	fi

	# Devolve a contagem pela saída padrão: o "return" do bash
	# só vai até 255 e daria a volta, nunca passando de MAX_TIMEOUT.
	echo "${COUNT}"

}

function resetTimeout() {

	echo "0" > "$TIMEOUT_FILE"

}

function isMaintenance() {

	# O monitor está em janela de manutenção? Tempo curto: a consulta
	# acontece dentro da transação SMTP. Sem resposta, não é manutenção.
	local status=$(curl -s -f --connect-timeout 2 -m 3 \
		-H "Authorization: Bearer $HETRIX_KEY" "$HETRIX_URL" 2> /dev/null)
	[[ $status =~ \"monitor_status\"[[:space:]]*:[[:space:]]*\"maint\" ]]

}

function emptyResponse() {

	# Resposta vazia. Uma conexão recusada (porta fechada ou REJECT do
	# firewall) ou um erro HTTP (curl -f) volta em menos de 2 segundos.
	# Um timeout leva pelo menos os 3 segundos do -w 3 (conexão) ou os
	# QUERY_TIMEOUT segundos do timeout (consulta inteira).
	# $SECONDS conta os segundos desde o início do script; é lido antes
	# da consulta ao HetrixTools, que também leva tempo.
	local ELAPSED=$SECONDS
	local STATE=$(cat "$TIMEOUT_FILE" 2> /dev/null)

	if [[ $STATE == "MAINTENANCE" ]]; then
		echo "MAINTENANCE"
		return
	elif [[ ${STATE:-0} == "0" ]] && isMaintenance; then
		# Primeira falha do evento: uma única consulta ao HetrixTools.
		echo "MAINTENANCE" > "$TIMEOUT_FILE"
		echo "MAINTENANCE"
		return
	fi

	# Toda falha conta, inclusive a rápida: com o contador acima de zero,
	# as próximas falhas do mesmo evento não consultam o HetrixTools.
	local COUNT=$(incrementTimeout)

	if [[ $COUNT == "MAINTENANCE" ]]; then
		echo "MAINTENANCE"
	elif [ "$ELAPSED" -lt 2 ]; then
		echo "OUT OF SERVICE"
	elif [ "$COUNT" -le "$MAX_TIMEOUT" ]; then
		echo "TIMEOUT"
	else
		echo "OUT OF SERVICE"
	fi

}

function httpUnavailable() {

	# Código HTTP de serviço indisponível: 000 (sem conexão ou timeout do
	# curl), erro de gateway ou página de erro do Cloudflare (52x e 530).
	# Os erros do próprio SPFBL (400, 403, 404, 413, 500) trazem resposta.
	[[ $1 =~ ^(000|502|503|504|52[0-9]|530)$ ]]

}

function keyRefusal() {

	# Recusa da chave ou do hostname pelo servidor: código 400, 403, 422
	# ou 429 com o motivo no corpo. Os demais erros seguem o caminho de
	# serviço indisponível.
	local REASON=${2%%$'\n'*}
	[[ $1 =~ ^(400|403|422|429)$ ]] &&
	[[ $REASON =~ ^(INVALID\ KEY|KEY\ REVOKED|KEY\ HTTPS|BANNED|HOSTNAME\ REQUIRED|INVALID\ FQDN.*)$ ]]

}

function logKeyRefusal() {

	# Registra no syslog (mail.warning) o motivo da recusa, no máximo uma
	# vez por minuto. Gravação no mesmo arquivo, sem mv: o /tmp tem
	# sticky bit e o arquivo pode ser de outro usuário (exim, root).
	local FILE="/tmp/SPFBL_KEY_REFUSED"
	local NOW
	printf -v NOW '%(%s)T' -1
	local LAST=$(cat "$FILE" 2> /dev/null)
	if [[ ! $LAST =~ ^[0-9]+$ ]] || (( NOW - LAST >= 60 )); then
		if [ ! -f "$FILE" ]; then
			touch "$FILE" 2> /dev/null
			chmod 666 "$FILE" 2> /dev/null
		fi
		echo "$NOW" > "$FILE" 2> /dev/null
		logger -t spfbl -p mail.warning "SPFBL refused this server ($LOCAL_HOSTNAME): HTTP $1 ${2%%$'\n'*}. Messages pass without filtering. Check $SPFBL_CONF and the SPFBL panel." 2> /dev/null
	fi

}

function readInterface() {

	# IP de saída das consultas com chave, guardado em /tmp/SPFBL_INTERFACE.
	# Arquivo ausente, vazio ou com outro conteúdo: sem IP fixo. Leitura
	# com o read do bash, sem processo novo.
	local IP=""
	[[ -r $INTERFACE_FILE ]] && read -r IP < "$INTERFACE_FILE" 2> /dev/null
	[[ $IP =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ || $IP =~ ^[0-9A-Fa-f:]+:[0-9A-Fa-f:.]*$ ]] && echo "$IP"

}

function writeInterface() {

	# Grava (ou esvazia, sem argumento) o IP de saída. Mesmo arquivo, sem
	# mv nem rm: o /tmp tem sticky bit e o arquivo pode ser de outro
	# usuário (exim, root).
	if [ ! -f "$INTERFACE_FILE" ]; then
		touch "$INTERFACE_FILE" 2> /dev/null
		chmod 666 "$INTERFACE_FILE" 2> /dev/null
	fi
	echo "$1" > "$INTERFACE_FILE" 2> /dev/null

}

function findInterface() {

	# Um IP do hostname (DNS) que também esteja nesta máquina. Só roda
	# depois de um 422 INVALID FQDN IP_MISMATCH, nunca a cada consulta.
	local LOCAL_IPS IP
	LOCAL_IPS=$(ip -o addr show 2> /dev/null | awk '{sub(/\/.*/, "", $4); print $4}')
	[[ -z $LOCAL_IPS ]] && LOCAL_IPS=$(ifconfig 2> /dev/null | awk '$1 ~ /^inet6?$/ {sub(/\/.*/, "", $2); sub(/^addr:/, "", $2); print $2}')
	for IP in $(getent ahosts${IP_VERSION:+v$IP_VERSION} "$LOCAL_HOSTNAME" 2> /dev/null | awk '{print $1}' | sort -u); do
		if grep -qxF "$IP" <<< "$LOCAL_IPS"; then
			echo "$IP"
			return 0
		fi
	done
	return 1

}

function isMismatch() {

	# Resposta (corpo + código na última linha) de hostname cujo A/AAAA
	# não contém o IP de saída da consulta.
	local CODE=${1##*$'\n'}
	local BODY=${1%$'\n'*}
	[[ $CODE == "422" && ${BODY%%$'\n'*} == "INVALID FQDN IP_MISMATCH" ]]

}

function keyCurlOnce() {

	# Uma requisição com a chave. $1: função que escreve o corpo; $2: URL;
	# $3: IP de saída (vazio: o do sistema); $4: auto ou none (cabeçalho
	# X-SPFBL-Interface); demais: argumentos do curl.
	local BODY=$1 URL=$2 IFACE=$3 MODE=$4
	shift 4
	$BODY | curl "$@" ${IFACE:+--interface "$IFACE"} -H "X-SPFBL-Interface: $MODE" \
		-w '\n%{http_code}' -K /dev/fd/3 "$URL" 3<<< "$CURL_KEY_CONFIG" 2> /dev/null

}

function keyCurl() {

	# Requisição com a chave e escolha do IP de saída. Saída: o corpo e o
	# código HTTP na última linha, como o -w '\n%{http_code}'.
	#
	# Sem /tmp/SPFBL_INTERFACE, o curl sai pelo IP do sistema. Num 422
	# INVALID FQDN IP_MISMATCH, procura nesta máquina um IP do hostname;
	# achando, grava no arquivo e repete a consulta saindo por ele. Com o
	# arquivo, o curl já sai pelo IP gravado; num novo 422 (ou se o IP não
	# existir mais), tenta sem o IP: se der certo, esvazia o arquivo; se
	# não, procura de novo. Sem IP do hostname na máquina, avisa o servidor
	# (none), que tenta confirmar o hostname pelo banner SMTP deste IP.
	local BODY=$1 URL=$2
	shift 2
	local IFACE OUT CODE FOUND
	IFACE=$(readInterface)
	if [[ -n $IFACE ]]; then
		OUT=$(keyCurlOnce "$BODY" "$URL" "$IFACE" auto "$@")
		CODE=${OUT##*$'\n'}
		if [[ $CODE != "000" ]] && ! isMismatch "$OUT"; then
			printf '%s\n' "$OUT"
			return
		fi
	fi
	OUT=$(keyCurlOnce "$BODY" "$URL" "" auto "$@")
	if ! isMismatch "$OUT"; then
		CODE=${OUT##*$'\n'}
		# Sem o IP gravado deu certo: as interfaces foram corrigidas.
		[[ -n $IFACE && $CODE != "000" ]] && writeInterface
		printf '%s\n' "$OUT"
		return
	fi
	FOUND=$(findInterface)
	if [[ -n $FOUND && $FOUND != "$IFACE" ]]; then
		writeInterface "$FOUND"
		OUT=$(keyCurlOnce "$BODY" "$URL" "$FOUND" auto "$@")
		if ! isMismatch "$OUT"; then
			printf '%s\n' "$OUT"
			return
		fi
	fi
	[[ -n $IFACE || -n $FOUND ]] && writeInterface
	keyCurlOnce "$BODY" "$URL" "" none "$@"

}

function spfbl_query() {

	# Consulta ao servidor SPFBL: lê a consulta da entrada padrão e
	# escreve a resposta, como o antigo $COMMAND.
	# Sem chave no spfbl.conf: canal antigo, identificado pelo IP.
	if [[ -z $SPFBL_KEY ]]; then
		$COMMAND
		return
	fi

	local query response code body
	IFS= read -r query
	queryBody() {
		printf '%s\n' "$query"
	}
	response=$(keyCurl queryBody "$URL_SERVIDOR/spfbl/" ${IP_VERSION:+-$IP_VERSION} -s \
		--connect-timeout 3 -m "$QUERY_TIMEOUT" --data-binary @-)
	code=${response##*$'\n'}
	body=${response%$'\n'*}

	if [[ $code == "200" ]]; then
		printf '%s\n' "$body"
	elif keyRefusal "$code" "$body"; then
		# Chave ou hostname recusado: a mensagem passa sem filtro.
		#   SPF e CHECK: LAN (mesmo fluxo de uma origem local);
		#   HOLDING: HOLD (mantém congelada; nunca remove);
		#   demais: OUT OF SERVICE (como o serviço fora do ar).
		logKeyRefusal "$code" "$body"
		case "${query%% *}" in
			SPF|CHECK) echo "LAN" ;;
			HOLDING) echo "HOLD" ;;
			*) echo "OUT OF SERVICE" ;;
		esac
	fi
	# Outros códigos: sem saída, como o curl -f; quem chamou trata a
	# resposta vazia (timeout, fora do ar ou manutenção).

}

function maintenanceExit() {

	# Serviço em manutenção programada: mesmo código em todos os comandos.
	if [[ $1 == "MAINTENANCE" ]]; then
		echo "MAINTENANCE"
		exit 26
	fi

}


###########################################################################
# Diagnóstico da conexão com o SPFBL (spfbl diagnose) e aviso local ao
# postmaster (spfbl monitor). Mesmas verificações do
# "spfbl.irondome.sh diagnose", mais a consulta com a chave de acesso.
###########################################################################

# Contato mostrado no resumo do diagnóstico e no aviso ao postmaster.
DIAG_CONTACT="contact@spfbl.net"
# Estado do aviso ao postmaster: "<início da falha> <último aviso>", em
# segundos. Fora do /tmp para sobreviver a um reinício.
MONITOR_FILE="/var/tmp/SPFBL_MONITOR"
DIAG_PROBLEMS=()

function diag_host() {
	# Hostname do servidor SPFBL das consultas HTTPS (URL_SERVIDOR).
	local host=${URL_SERVIDOR#https://}
	host=${host%%/*}
	echo "${host%%:*}"
}

function diag_port() {
	# Porta HTTPS do URL_SERVIDOR (443 sem porta explícita).
	local host=${URL_SERVIDOR#https://}
	host=${host%%/*}
	if [[ $host == *:* ]]; then
		echo "${host##*:}"
	else
		echo "443"
	fi
}

function spfblStatus() {
	# Estado do SPFBL no monitor da HetrixTools (o mesmo do status.spfbl.net):
	# o primeiro "uptime_status" da resposta é o geral (os seguintes são das
	# localidades). Saída: maint (manutenção programada), up, down ou
	# unknown (sem resposta: este servidor também não alcança a HetrixTools).
	local status
	status=$(curl -s -f --connect-timeout 5 -m 10 \
		-H "Authorization: Bearer $HETRIX_KEY" "$HETRIX_URL" 2> /dev/null)
	if [[ $status =~ \"monitor_status\"[[:space:]]*:[[:space:]]*\"maint\" ]]; then
		echo "maint"
	elif [[ $status =~ \"uptime_status\"[[:space:]]*:[[:space:]]*\"(up|down)\" ]]; then
		echo "${BASH_REMATCH[1]}"
	else
		echo "unknown"
	fi
}

function spfblStatusLine() {
	# Linha do estado do SPFBL para o diagnóstico e o aviso ao postmaster.
	case "$1" in
		up) echo "SPFBL is online (status.spfbl.net): the problem is on this server or on its path to SPFBL." ;;
		down) echo "SPFBL is offline (status.spfbl.net): nothing to fix on this server; the messages pass unfiltered until it is back." ;;
		maint) echo "SPFBL is under scheduled maintenance (status.spfbl.net): try again in a few minutes." ;;
		*) echo "SPFBL status unknown: this server could not reach status.spfbl.net either." ;;
	esac
}

function diag_problem() {
	# Uma causa provável e o que fazer, guardada para o resumo.
	DIAG_PROBLEMS+=("$1")
	echo "   PROBLEM: $1"
}

function diag_now() {
	# Milissegundos desde a época.
	echo $(( $(date +%s%N) / 1000000 ))
}

function diag_ipv4_in() {
	# O IPv4 $1 está dentro do CIDR $2?
	local ip=$1 net=${2%/*} bits=${2#*/} a b c d x y mask
	[[ $ip =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
	IFS=. read -r a b c d <<< "$ip"
	x=$(( (a << 24) | (b << 16) | (c << 8) | d ))
	IFS=. read -r a b c d <<< "$net"
	y=$(( (a << 24) | (b << 16) | (c << 8) | d ))
	mask=$(( (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF ))
	[ $(( x & mask )) -eq $(( y & mask )) ]
}

function diag_cloudflare() {
	# $1 é um IP da Cloudflare? O matrix.spfbl.net fica sempre atrás dela:
	# outro IP indica /etc/hosts ou um DNS respondendo outra coisa.
	local ip=$1 cidr
	if [[ $ip == *:* ]]; then
		[[ ${ip,,} =~ ^(2400:cb00|2606:4700|2803:f800|2405:b500|2405:8100|2c0f:f248|2a06:98c[0-7]): ]]
		return
	fi
	for cidr in 173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 \
		141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 \
		197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 \
		104.24.0.0/14 172.64.0.0/13 131.0.72.0/22; do
		diag_ipv4_in "$ip" "$cidr" && return 0
	done
	return 1
}

function diag_resolvers() {
	# Servidores DNS usados de fato. Com o systemd-resolved, o 127.0.0.53
	# do /etc/resolv.conf esconde os reais, que ficam em
	# /run/systemd/resolve/resolv.conf.
	local file=/etc/resolv.conf
	if grep -qE '^[[:space:]]*nameserver[[:space:]]+127\.0\.0\.53' /etc/resolv.conf 2> /dev/null \
			&& [ -r /run/systemd/resolve/resolv.conf ]; then
		file=/run/systemd/resolve/resolv.conf
	fi
	awk '$1 == "nameserver" && $2 != "" {print $2}' "$file" 2> /dev/null | awk '!seen[$0]++'
}

function diag_dns_query() {
	# Pergunta ao DNS $1 o registro A do servidor SPFBL, esperando no máximo
	# 3 segundos. Saída: OK <respostas>, EMPTY, ERROR <status> ou TIMEOUT.
	# Com o dig quando existe; senão, uma consulta UDP montada pelo próprio
	# bash, sem dependência.
	local server=$1 host out status answers reply bytes qname label
	host=$(diag_host)
	if command -v dig > /dev/null; then
		out=$(dig @"$server" "$host" A +time=3 +tries=1 2> /dev/null) || { echo "TIMEOUT"; return; }
		status=$(grep -o 'status: [A-Z]*' <<< "$out" | command head -n 1 | cut -d' ' -f2)
		answers=$(awk '!/^;/ && $4 == "A"' <<< "$out" | wc -l)
		if [ -z "$status" ]; then
			echo "TIMEOUT"
		elif [ "$status" != "NOERROR" ]; then
			echo "ERROR $status"
		elif [ "$answers" -gt 0 ]; then
			echo "OK $answers"
		else
			echo "EMPTY"
		fi
		return
	fi
	# Cabeçalho (ID, recursão, 1 pergunta) e a pergunta <host> IN A. Na
	# resposta, o byte 4 traz o status (RCODE) e os bytes 7-8 as respostas.
	qname=""
	IFS=. read -r -a labels <<< "$host"
	for label in "${labels[@]}"; do
		qname+=$(printf '\\x%02x' "${#label}")$label
	done
	reply=$( { exec 3<> "/dev/udp/$server/53" || exit 1
		printf "\x53\x50\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00${qname}\x00\x00\x01\x00\x01" >&3
		timeout 3 dd bs=512 count=1 <&3 2> /dev/null | od -An -tu1 -N12; } 2> /dev/null )
	read -r -a bytes <<< "$reply"
	if [ "${#bytes[@]}" -lt 12 ]; then
		echo "TIMEOUT"
	elif [ $(( bytes[3] & 15 )) -ne 0 ]; then
		case $(( bytes[3] & 15 )) in
			2) echo "ERROR SERVFAIL" ;;
			3) echo "ERROR NXDOMAIN" ;;
			5) echo "ERROR REFUSED" ;;
			*) echo "ERROR RCODE$(( bytes[3] & 15 ))" ;;
		esac
	elif [ $(( bytes[6] * 256 + bytes[7] )) -gt 0 ]; then
		echo "OK $(( bytes[6] * 256 + bytes[7] ))"
	else
		echo "EMPTY"
	fi
}

function diag_https() {
	# HTTPS ao servidor SPFBL no IP $2 por IPv$1, sem DNS no caminho
	# (--resolve). Saída: "<saída do curl> <código HTTP> <segundos para
	# conectar> <corpo>"; os cabeçalhos vão para o arquivo $3 (relógio).
	local version=$1 ip=$2 headers=$3 target out rc host port
	host=$(diag_host)
	port=$(diag_port)
	target=$ip
	[ "$version" = "6" ] && target="[$ip]"
	out=$(curl -"$version" -s --connect-timeout 5 -m 15 -D "$headers" \
		--resolve "$host:$port:$target" -w '\n%{http_code} %{time_connect}' \
		"$URL_SERVIDOR/whatsmyip/" 2> /dev/null)
	rc=$?
	echo "$rc ${out##*$'\n'} $(command head -n 1 <<< "${out%$'\n'*}" | tr -cd '0-9a-fA-F:.')"
}

function diag_curl_error() {
	# Significado de um código de saída do curl.
	case "$1" in
		5) echo "the proxy could not be resolved" ;;
		6) echo "the name could not be resolved" ;;
		7) echo "the connection was refused or there is no route" ;;
		28) echo "no answer in time (timeout)" ;;
		35) echo "the TLS handshake failed" ;;
		51|60) echo "the certificate could not be verified" ;;
		52|56) echo "the connection was closed with no answer" ;;
		*) echo "curl error $1" ;;
	esac
}

function diag_key_reason() {
	# Explicação de uma recusa da chave ou do hostname ($1: corpo).
	case "$1" in
		"INVALID FQDN NO_ADDRESS")
			echo "the hostname $LOCAL_HOSTNAME has no A/AAAA record in DNS. Create it with the IP of this server." ;;
		"INVALID FQDN IP_MISMATCH")
			echo "the DNS of $LOCAL_HOSTNAME does not point to the IP this server uses to reach SPFBL. Fix the A/AAAA record." ;;
		"INVALID FQDN GENERIC")
			echo "$LOCAL_HOSTNAME is a generic provider name. Set a hostname of its own on this server." ;;
		"INVALID FQDN RESERVED_IP")
			echo "this server reaches SPFBL from a private or reserved IP." ;;
		"INVALID FQDN"*)
			echo "the hostname $LOCAL_HOSTNAME is invalid. Set the full hostname (FQDN) of this server." ;;
		*"KEY REVOKED"*)
			echo "the SPFBL access key was revoked or expired. Create a new key in the SPFBL panel and run spfbl.irondome.sh (option Change the SPFBL access key)." ;;
		*"INVALID KEY"*|*"KEY HTTPS"*)
			echo "the SPFBL access key is invalid. Create a new key in the SPFBL panel and run spfbl.irondome.sh (option Change the SPFBL access key)." ;;
		*BANNED*)
			echo "too many failures from this IP. Wait a few minutes." ;;
		"HOSTNAME REQUIRED")
			echo "this server has no hostname. Set its full hostname (FQDN)." ;;
		*)
			echo "unexpected answer: $1" ;;
	esac
}

function diagnose() {
	# Diagnóstico somente leitura da conexão deste servidor com o SPFBL.
	# Nada é alterado. Saída 0 sem problema encontrado, 1 com problema.
	DIAG_PROBLEMS=()
	local host line ip start ms result server servers count status
	host=$(diag_host)
	status=$(spfblStatus)
	echo "SPFBL v$version - connection diagnosis of $LOCAL_HOSTNAME (nothing is changed)"
	echo "$(spfblStatusLine "$status")"
	echo ""

	# 1. /etc/hosts: uma linha para *.spfbl.net fixa um IP, geralmente
	# antigo, e passa por cima do DNS.
	echo "[1/7] /etc/hosts"
	line=$(grep -Ev '^[[:space:]]*#' /etc/hosts 2> /dev/null | grep -Ei "(^|[[:space:]])([a-z0-9-]+\.)*${host//./\\.}([[:space:]]|$)|(^|[[:space:]])([a-z0-9-]+\.)*spfbl\.net([[:space:]]|$)")
	if [ -n "$line" ]; then
		echo "   $line"
		diag_problem "/etc/hosts fixes an IP for $host. Remove that line: DNS gives the right IPs."
	else
		echo "   OK: no line for $host."
	fi

	# 2. Cada DNS sozinho: um DNS morto faz toda consulta esperar o tempo
	# dele antes de o próximo responder.
	echo "[2/7] DNS servers"
	servers=$(diag_resolvers)
	if [ -z "$servers" ]; then
		diag_problem "No DNS server (nameserver) in /etc/resolv.conf."
	fi
	for server in $servers; do
		start=$(diag_now)
		result=$(diag_dns_query "$server")
		ms=$(( $(diag_now) - start ))
		case "$result" in
			OK*)
				echo "   $server: OK (${ms} ms)"
				[ "$ms" -gt 1000 ] && diag_problem "The DNS server $server is slow (${ms} ms). Check it or replace it in /etc/resolv.conf."
				;;
			TIMEOUT)
				echo "   $server: no answer"
				diag_problem "The DNS server $server does not answer. Fix it or remove it from /etc/resolv.conf: every lookup waits for it before the next one."
				;;
			EMPTY)
				echo "   $server: empty answer"
				diag_problem "The DNS server $server has no address for $host. Check its filters or replace it."
				;;
			*)
				echo "   $server: ${result#ERROR }"
				diag_problem "The DNS server $server answers ${result#ERROR } for $host. Check it or replace it."
				;;
		esac
	done
	line=$(grep -E '^[[:space:]]*options' /etc/resolv.conf 2> /dev/null)
	[ -n "$line" ] && echo "   /etc/resolv.conf: $line"

	# 3. A resolução do sistema (/etc/hosts e DNS, na ordem do
	# /etc/nsswitch.conf), como o curl faz.
	echo "[3/7] Name resolution of this server"
	local ips4="" ips6=""
	start=$(diag_now)
	ips4=$(timeout 30 getent ahostsv4 "$host" 2> /dev/null | awk '{print $1}' | awk '!seen[$0]++')
	ms=$(( $(diag_now) - start ))
	if [ -z "$ips4" ]; then
		echo "   IPv4: not resolved (${ms} ms)"
		diag_problem "This server cannot resolve $host. Check the DNS servers above."
	else
		echo "   IPv4: $(echo $ips4) (${ms} ms)"
		[ "$ms" -gt 2000 ] && diag_problem "Resolving $host takes ${ms} ms: each query gives up after a few seconds counting the lookup. A DNS server above is dead or slow."
		if [ "$host" = "matrix.spfbl.net" ]; then
			for ip in $ips4; do
				diag_cloudflare "$ip" || diag_problem "$host resolves to $ip, which is not an SPFBL (Cloudflare) IP. Check /etc/hosts and the DNS servers."
			done
		fi
	fi
	ips6=$(timeout 30 getent ahostsv6 "$host" 2> /dev/null | awk '{print $1}' | grep ':' | grep -v '^::ffff:' | awk '!seen[$0]++')
	if [ -n "$ips6" ]; then
		echo "   IPv6: $(echo $ips6)"
	else
		echo "   IPv6: not resolved"
	fi

	# 4. HTTPS direto em cada IP: separa a rede do DNS.
	echo "[4/7] HTTPS to $host"
	local headers ok4="" ok6="" rc code connect body skew remote
	headers=$(mktemp)
	[ -z "$ips4" ] && echo "   IPv4: not tested (name not resolved)."
	for ip in $ips4; do
		read -r rc code connect body <<< "$(diag_https 4 "$ip" "$headers")"
		if [ "$rc" = "0" ] && [[ $body =~ ^[0-9.]+$|: ]]; then
			ok4=1
			echo "   IPv4 $ip: OK (${connect}s), this server goes out as $body"
		elif [ "$rc" = "0" ]; then
			echo "   IPv4 $ip: HTTP $code"
		else
			echo "   IPv4 $ip: $(diag_curl_error "$rc")"
		fi
		[ -n "$ok4" ] && break
	done
	if [ -n "$ips6" ] && ip -6 route get 2606:4700::1 > /dev/null 2>&1; then
		for ip in $ips6; do
			read -r rc code connect body <<< "$(diag_https 6 "$ip" "$headers")"
			if [ "$rc" = "0" ] && [[ $body =~ ^[0-9.]+$|: ]]; then
				ok6=1
				echo "   IPv6 $ip: OK (${connect}s), this server goes out as $body"
			elif [ "$rc" = "0" ]; then
				echo "   IPv6 $ip: HTTP $code"
			else
				echo "   IPv6 $ip: $(diag_curl_error "$rc")"
			fi
			[ -n "$ok6" ] && break
		done
		[ -z "$ok6" ] && echo "   IPv6 has a route here but does not reach SPFBL: the queries use IPv4."
	else
		echo "   IPv6: no route on this server (the queries use IPv4)."
	fi
	if [ -z "$ok4" ] && [ -z "$ok6" ] && [ -n "$ips4$ips6" ]; then
		if [ "$status" = "down" ]; then
			# O SPFBL caiu: a falha não é deste servidor.
			diag_problem "SPFBL is offline (status.spfbl.net). Nothing to fix here: wait until it is back."
		elif [[ $code =~ ^(52[0-9]|530|502|503|504)$ ]]; then
			if [ "$status" = "maint" ]; then
				diag_problem "SPFBL is under scheduled maintenance (https://status.spfbl.net). Try again in a few minutes."
			else
				diag_problem "Cloudflare answers, but SPFBL does not (HTTP $code). Try again in a few minutes."
			fi
		elif [ "$rc" = "51" ] || [ "$rc" = "60" ]; then
			diag_problem "The certificate of $host could not be verified. Check the clock of this server and update the CA certificates (ca-certificates)."
		elif [ "$rc" = "35" ]; then
			diag_problem "The TLS handshake with $host fails. A proxy or firewall inspecting HTTPS, or a very old OpenSSL, is in the way."
		else
			diag_problem "This server does not reach $host on port $(diag_port) ($(diag_curl_error "$rc")). Allow outgoing TCP $(diag_port) in the firewall."
		fi
	fi

	# 5. Relógio: data errada quebra o TLS.
	echo "[5/7] Clock"
	remote=$(grep -i '^date:' "$headers" 2> /dev/null | command head -n 1 | cut -d' ' -f2- | tr -d '\r')
	rm -f "$headers"
	if [ -n "$remote" ] && remote=$(date -d "$remote" +%s 2> /dev/null); then
		skew=$(( $(date +%s) - remote ))
		if [ "${skew#-}" -gt 300 ]; then
			echo "   This server is ${skew}s off SPFBL."
			diag_problem "The clock of this server is ${skew#-} seconds off. Turn on NTP: timedatectl set-ntp true"
		else
			echo "   OK: ${skew}s off SPFBL."
		fi
	else
		echo "   Not checked: no answer from SPFBL. Local time: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
	fi

	# 6. Proxy e firewall: o curl segue o https_proxy e o ~/.curlrc; o CSF
	# bloqueia as portas de saída fora do TCP_OUT.
	echo "[6/7] Proxy and firewall"
	count=0
	local proxies
	proxies=$(printf '%s\n' "${https_proxy:-}" "${HTTPS_PROXY:-}" "${all_proxy:-}" "${ALL_PROXY:-}" | awk 'NF && !seen[$0]++')
	for line in $proxies; do
		echo "   curl goes through the proxy $line (environment)."
		count=1
	done
	if grep -qiE '^[[:space:]]*-?-?(proxy|x)[[:space:]=]' ~/.curlrc 2> /dev/null; then
		echo "   ~/.curlrc sets a proxy for curl."
		count=1
	fi
	[ "$count" = "0" ] && echo "   No proxy for curl."
	if [ -f /etc/csf/csf.conf ]; then
		line=$(grep -E '^[[:space:]]*TCP_OUT[[:space:]]*=' /etc/csf/csf.conf | command head -n 1)
		if [[ $line =~ [\",]443[\",] ]]; then
			echo "   CSF: outgoing TCP 443 allowed."
		else
			echo "   CSF: $line"
			diag_problem "CSF does not allow outgoing TCP 443 (TCP_OUT). Add 443 to TCP_OUT in /etc/csf/csf.conf and run: csf -r"
		fi
	fi

	# 7. A consulta de verdade, com a chave de acesso e o hostname: mostra a
	# recusa da chave (revogada, inválida) e do hostname (DNS).
	echo "[7/7] Query with the access key"
	if [[ -z $SPFBL_KEY ]]; then
		echo "   No access key in $SPFBL_CONF: this server queries by IP (legacy)."
		result=$(echo "VERSION" | spfbl_query 2> /dev/null)
		if [[ $result == SPFBL-* ]]; then
			echo "   OK: $result"
		else
			diag_problem "The query by IP does not work. Update Irondome (option Update) to use an SPFBL access key."
		fi
	else
		versionBody() {
			printf 'VERSION\n'
		}
		local out
		out=$(keyCurl versionBody "$URL_SERVIDOR/spfbl/" ${IP_VERSION:+-$IP_VERSION} -s \
			--connect-timeout 5 -m 30 --data-binary @-)
		code=${out##*$'\n'}
		body=${out%$'\n'*}
		body=${body%%$'\n'*}
		if [[ $code == "200" && $body == SPFBL-* ]]; then
			echo "   OK: $body (hostname $LOCAL_HOSTNAME)"
		elif [[ $code =~ ^(400|403|422|429)$ ]]; then
			echo "   HTTP $code: $body"
			diag_problem "SPFBL refuses the queries of this server: $(diag_key_reason "$body")"
		elif [[ $code == "000" ]]; then
			echo "   no connection"
			[ "${#DIAG_PROBLEMS[@]}" -eq 0 ] && diag_problem "The query with the access key does not reach SPFBL, although the tests above pass. Check the outgoing firewall for this process and try again."
		else
			echo "   HTTP $code"
			[ "${#DIAG_PROBLEMS[@]}" -eq 0 ] && diag_problem "SPFBL answers HTTP $code. Try again in a few minutes."
		fi
	fi

	echo ""
	if [ "${#DIAG_PROBLEMS[@]}" -eq 0 ]; then
		echo "No problem found in the connection of this server to SPFBL."
		echo "If the failure goes on, send this output to $DIAG_CONTACT."
		return 0
	fi
	echo "Probable cause$([ "${#DIAG_PROBLEMS[@]}" -gt 1 ] && echo "s"):"
	for line in "${DIAG_PROBLEMS[@]}"; do
		echo " - $line"
	done
	echo "After fixing it, run \"spfbl diagnose\" again. Questions: $DIAG_CONTACT"
	return 1
}

function monitor_mail() {
	# Aviso local ao postmaster desta máquina, pelo MTA dela: chega mesmo
	# quando o servidor não alcança nada lá fora. $1: assunto; o corpo vem
	# da entrada padrão.
	local sendmail
	sendmail=$(command -v sendmail || ls /usr/sbin/sendmail /usr/lib/sendmail 2> /dev/null | command head -n 1)
	[[ -z $sendmail ]] && return 1
	{
		printf 'To: postmaster\n'
		printf 'Subject: %s\n' "$1"
		printf 'Content-Type: text/plain; charset=UTF-8\n'
		printf 'Auto-Submitted: auto-generated\n'
		printf '\n'
		cat
	} | "$sendmail" -t
}

function monitor() {
	# Verificação de hora em hora (cron do Irondome), só com chave de
	# acesso: os clientes antigos, por IP, ficam de fora. Sem resposta do
	# SPFBL e sem manutenção programada, espera a próxima hora para
	# confirmar; confirmada, roda o diagnóstico e avisa o postmaster, no
	# máximo uma vez por dia. Quando volta, avisa a volta.
	[[ -z $SPFBL_KEY ]] && return 0
	local response now first mailed report
	response=$(echo "VERSION" | spfbl_query 2> /dev/null)
	now=$(date +%s)
	first=""
	mailed=""
	[[ -r $MONITOR_FILE ]] && read -r first mailed < "$MONITOR_FILE"
	if [[ $response == SPFBL-* ]]; then
		resetTimeout
		if [[ ${mailed:-0} -gt 0 ]]; then
			{
				printf 'This server (%s) is querying SPFBL again since %s.\n' "$LOCAL_HOSTNAME" "$(date '+%Y-%m-%d %H:%M %Z')"
				printf 'The incoming messages are filtered by SPFBL again.\n\n'
				printf 'SPFBL v%s\n' "$version"
			} | monitor_mail "[SPFBL] $LOCAL_HOSTNAME is reaching SPFBL again"
		fi
		rm -f "$MONITOR_FILE"
		return 0
	fi
	if isMaintenance; then
		# Manutenção programada (status.spfbl.net): sem aviso.
		return 0
	fi
	if [[ -z $first ]]; then
		# Primeira falha: confirma na próxima hora.
		echo "$now 0" > "$MONITOR_FILE"
		return 1
	fi
	if [[ ${mailed:-0} -eq 0 || $(( now - mailed )) -ge 86400 ]]; then
		report=$(diagnose 2>&1)
		{
			printf 'This server (%s) cannot query SPFBL since %s.\n' "$LOCAL_HOSTNAME" "$(date -d "@$first" '+%Y-%m-%d %H:%M %Z')"
			printf 'Meanwhile, the incoming messages pass without the SPFBL filter.\n\n'
			printf '%s\n\n' "$report"
			printf 'This notice repeats once a day while the problem lasts.\n'
		} | monitor_mail "[SPFBL] $LOCAL_HOSTNAME cannot reach SPFBL"
		echo "$first $now" > "$MONITOR_FILE"
	fi
	return 1
}

case $1 in
	'start')
		echo "Iniciando serviço do SPFBL"
        	cd /opt/spfbl/
        	/usr/bin/java -jar /opt/spfbl/SPFBL.jar &
		echo "OK"
	;;
	'stop')
		echo "Parando o serviço do SPFBL"
		echo "STORE" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null
		echo "SHUTDOWN" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null
		echo "OK"
	;;
	'restart')
		echo "Reiniciando serviço do SPFBL"
		cd /opt/spfbl/
		echo "STORE" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null
		echo "SHUTDOWN" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null
		/usr/bin/java -jar /opt/spfbl/SPFBL.jar &
		echo "OK"
	;;
	'version')
		# Verifica a versão do servidor SPPFBL.
		#
		# Códigos de saída:
		#
		#    0: versão adquirida com sucesso.
		#    1: erro ao tentar adiquirir versão.
		#    2: timeout de conexão.
		#    3: out of service.
		#   26: serviço em manutenção programada (status.spfbl.net).


		response=$(echo "VERSION" | spfbl_query 2> /dev/null)

		if [[ $response == "" ]]; then
			response=$(emptyResponse)
			maintenanceExit "$response"
		else
			resetTimeout
		fi

		echo "$response"

		if [[ $response == "OUT OF SERVICE" ]]; then
			exit 3
		elif [[ $response == "TIMEOUT" ]]; then
			exit 2
		elif [[ $response == "SPFBL-"* ]]; then
			exit 0
		else
			exit 1
		fi
	;;
	'diagnose')
		# Diagnóstico da conexão deste servidor com o SPFBL: /etc/hosts,
		# cada DNS, resolução, HTTPS por IPv4 e IPv6, relógio, proxy e
		# firewall e a consulta com a chave de acesso. Não muda nada.
		#
		# Códigos de saída:
		#
		#    0: nenhum problema encontrado.
		#    1: há problema; as causas prováveis saem no fim.

		diagnose
		exit $?
	;;
	'monitor')
		# Verificação de hora em hora, pelo cron do Irondome, só para quem
		# tem chave de acesso. Sem conexão com o SPFBL (fora da manutenção
		# programada) em duas verificações seguidas, avisa o postmaster desta
		# máquina com o diagnóstico; repete uma vez por dia e avisa a volta.
		#
		# Códigos de saída:
		#
		#    0: consulta funcionando (ou sem chave, ou em manutenção).
		#    1: sem conexão com o SPFBL.

		monitor
		exit $?
	;;
	'firewall')
		# Constroi um firewall pelo SPPFBL.
		#
		# Códigos de saída:
		#
		#    0: firwall adquirido com sucesso.
		#    1: erro ao tentar adiquirir firewall.
		#    2: timeout de conexão.
		#    3: out of service.
		#   26: serviço em manutenção programada (status.spfbl.net).


		response=$(echo "FIREWALL" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

		if [[ $response == "" ]]; then
			response=$(emptyResponse)
			maintenanceExit "$response"
		else
			resetTimeout
		fi

		echo "$response"

		if [[ $response == "OUT OF SERVICE" ]]; then
			exit 3
		elif [[ $response == "TIMEOUT" ]]; then
			exit 2
		elif [[ $response == "#!/bin/bash"* ]]; then
			exit 0
		else
			exit 1
		fi
	;;
	'shutdown')
		# Finaliza Serviço.
		#
		# Códigos de saída:
		#
		#    0: fechamento de processos realizado com sucesso.
		#    1: houve falha no fechamento dos processos.
		#    2: timeout de conexão.
		#    3: out of service.
		#   26: serviço em manutenção programada (status.spfbl.net).


		response=$(echo "SHUTDOWN" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

		if [[ $response == "" ]]; then
			response=$(emptyResponse)
			maintenanceExit "$response"
		else
			resetTimeout
		fi

		echo "$response"

		if [[ $response == "OUT OF SERVICE" ]]; then
			exit 3
		elif [[ $response == "TIMEOUT" ]]; then
			exit 2
		elif [[ $response == "OK" ]]; then
			exit 0
		else
			exit 1
		fi
	;;
	'store')
		# Comando para gravar o cache em disco.
		#
		# Códigos de saída:
		#
		#    0: gravar o cache em disco realizado com sucesso.
		#    1: houve falha ao gravar o cache em disco.
		#    2: timeout de conexão.
		#    3: out of service.
		#   26: serviço em manutenção programada (status.spfbl.net).


		response=$(echo "STORE" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

		if [[ $response == "" ]]; then
			response=$(emptyResponse)
			maintenanceExit "$response"
		else
			resetTimeout
		fi

		echo "$response"

		if [[ $response == "OUT OF SERVICE" ]]; then
			exit 3
		elif [[ $response == "TIMEOUT" ]]; then
			exit 2
		elif [[ $response == "OK" ]]; then
			exit 0
		else
			exit 1
		fi
	;;
	'test')
		# Comando para testar uma nova funcionalidade em desenvolvimento.
		#
		# Códigos de saída:
		#
		#    0: processo iniciado com sucesso.
		#    1: processo anterior não finalizado.
		#    2: timeout de conexão.
		#    3: out of service.
		#   26: serviço em manutenção programada (status.spfbl.net).


		response=$(echo "TEST" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

		if [[ $response == "" ]]; then
			response=$(emptyResponse)
			maintenanceExit "$response"
		else
			resetTimeout
		fi

		echo "$response"

		if [[ $response == "OUT OF SERVICE" ]]; then
			exit 3
		elif [[ $response == "TIMEOUT" ]]; then
			exit 2
		elif [[ $response == "STARTING TEST" ]]; then
			exit 0
		else
			exit 1
		fi
	;;
	'tld')
		case $2 in
			'add')
				# Parâmetros de entrada:
				#
				#    1. tld: endereço do tld.
				#
				# Códigos de saída:
				#
				#    0: adicionado com sucesso.
				#    1: erro ao tentar adiciona.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 tld add tld\n"
				else
					tld=$3

					response=$(echo "TLD ADD $tld" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "ADDED" ]]; then
						exit 0
					else
						exit 1
					fi
				fi
			;;
			'drop')
				# Parâmetros de entrada:
				#
				#    1. tld: endereço do tld.
				#
				# Códigos de saída:
				#
				#    0: removido com sucesso.
				#    1: erro ao tentar remover.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 tld drop tld\n"
				else
					tld=$3

					response=$(echo "TLD DROP $tld" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "DROPPED" ]]; then
						exit 0
					else
						exit 1
					fi
				fi
			;;
			'show')

				# Códigos de saída:
				#
				#    0: visualizado com sucesso.
				#    1: erro ao tentar visualizar.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "2" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 tld show\n"
				else

					response=$(echo "TLD SHOW" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					else
						exit 0
					fi
				fi
			;;
			*)
				head
				printf "Syntax:\n    $0 tld add tld\n    $0 tld drop tld\n    $0 tld show\n"
			;;
		esac
	;;
	'provider')
		case $2 in
			'add')
				# Parâmetros de entrada:
				#
				#    1. provedor: endereço do provedor de e-mail.
				#
				# Códigos de saída:
				#
				#    0: adicionado com sucesso.
				#    1: erro ao tentar adiciona.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 provider add sender\n"
				else
					provider=$3

					response=$(echo "PROVIDER ADD $provider" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "ADDED" ]]; then
						exit 0
					else
						exit 1
					fi
				fi
			;;
			'drop')
				# Parâmetros de entrada:
				#
				#    1. provedor: endereço do provedor de e-mail.
				#
				# Códigos de saída:
				#
				#    0: removido com sucesso.
				#    1: erro ao tentar remover.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 provider drop sender\n"
				else
					provider=$3

					response=$(echo "PROVIDER DROP $provider" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "DROPPED" ]]; then
						exit 0
					else
						exit 1
					fi
				fi
			;;
			'show')

				# Códigos de saída:
				#
				#    0: visualizado com sucesso.
				#    1: erro ao tentar visualizar.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "2" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 provider show\n"
				else

					response=$(echo "PROVIDER SHOW" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					else
						exit 0
					fi
				fi
			;;
			*)
				head
				printf "Syntax:\n    $0 provider add sender\n    $0 provider drop sender\n    $0 provider show\n"
			;;
		esac
	;;
	'ignore')
		case $2 in
			'add')
				# Parâmetros de entrada:
				#
				#    1. sender: o remetente que deve ser ignorado, com endereço completo.
				#    1. domínio: o domínio que deve ser ignorado, com arroba (ex: @dominio.com.br)
				#
				# Códigos de saída:
				#
				#    0: adicionado com sucesso.
				#    1: erro ao tentar adiciona.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 ignore add sender\n"
				else
					ignore=$3

					response=$(echo "IGNORE ADD $ignore" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "ADDED" ]]; then
						exit 0
					else
						exit 1
					fi
				fi
			;;
			'drop')
				# Parâmetros de entrada:
				#
				#    1. sender: o remetente ignorado, com endereço completo.
				#    1. domínio: o domínio ignorado, com arroba (ex: @dominio.com.br)
				#
				# Códigos de saída:
				#
				#    0: removido com sucesso.
				#    1: erro ao tentar remover.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 ignore drop sender\n"
				else
					ignore=$3

					response=$(echo "IGNORE DROP $ignore" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "DROPPED" ]]; then
						exit 0
					else
						exit 1
					fi
				fi
			;;
			'show')

				# Códigos de saída:
				#
				#    0: visualizado com sucesso.
				#    1: erro ao tentar visualizar.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "2" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 ignore show\n"
				else

					response=$(echo "IGNORE SHOW" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					else
						exit 0
					fi
				fi
			;;
			*)
				head
				printf "Syntax:\n    $0 ignore add sender\n    $0 ignore drop sender\n    $0 ignore show\n"
			;;
		esac
	;;
	'block')
		case $2 in
			'add')
				# Parâmetros de entrada:
				#
				#    1. sender: o remetente que deve ser bloqueado, com endereço completo.
				#    2. domínio: o domínio que deve ser bloqueado, com arroba (ex: @dominio.com.br)
				#    3. caixa postal: a caixa postal que deve ser bloqueada, com arroba (ex: www-data@)
				#
				#
				# Códigos de saída:
				#
				#    0: adicionado com sucesso.
				#    1: erro ao tentar adicionar bloqueio.
				#    2: registro já incluido.
				#    3: timeout de conexão.
				#    4: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 block add sender\n"
				else
					sender=$3

					response=$(echo "BLOCK ADD $sender" | spfbl_query 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "ADDED" ]]; then
						exit 0
					elif [[ $response == "ALREADY EXISTS" ]]; then
						exit 2
					else
						exit 1
					fi
				fi
			;;
			'drop')
				# Parâmetros de entrada:
				#
				#    1. sender: o remetente que deve ser desbloqueado, com endereço completo.
				#    2. domínio: o domínio que deve ser desbloqueado, com arroba (ex: @dominio.com.br)
				#    3. caixa postal: a caixa postal que deve ser desbloqueada, com arroba (ex: www-data@)
				#
				#
				# Códigos de saída:
				#
				#    0: desbloqueado com sucesso.
				#    1: erro ao tentar adicionar bloqueio.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 block drop sender\n"
				else
					sender=$3

					response=$(echo "BLOCK DROP $sender" | spfbl_query 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "DROPPED" ]]; then
						exit 0
					else
						exit 1
					fi
				fi
			;;
			'show')
				# Parâmetros de entrada:
				#    1: ALL: lista os bloqueios gerais (opcional)
				#
				# Códigos de saída:
				#
				#    0: visualizado com sucesso.
				#    1: erro ao tentar visualizar bloqueio.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "2" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 block show [all]\n"
				else
					if [ "$3" == "all" ]; then
						response=$(echo "BLOCK SHOW ALL" | spfbl_query 2> /dev/null)
					else
						response=$(echo "BLOCK SHOW" | spfbl_query 2> /dev/null)
					fi

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					else
						exit 0
					fi
				fi
			;;
			'find')
				# Parâmetros de entrada:
				#    1: <token>: um e-mail, host ou IP.
				#
				# Códigos de saída:
				#
				#    0: sem registro.
				#    1: registro encontrado.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 block find token\n"
				else
					token=$3
					response=$(echo "BLOCK FIND $token" | spfbl_query 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "NONE" ]]; then
						exit 0
					else
						exit 1
					fi
				fi
			;;
			*)
				head
				printf "Syntax:\n    $0 block add recipient\n    $0 block drop recipient\n    $0 block show\n"
			;;
		esac
	;;
	'superblock')
		case $2 in
			'add')
				# Parâmetros de entrada:
				#
				#    1. sender: o remetente que deve ser bloqueado, com endereço completo.
				#    1. domínio: o domínio que deve ser bloqueado, com arroba (ex: @dominio.com.br)
				#    1. caixa postal: a caixa postal que deve ser bloqueada, com arroba (ex: www-data@)
				#
				#
				# Códigos de saída:
				#
				#    0: adicionado com sucesso.
				#    1: erro ao tentar adicionar bloqueio.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 superblock add sender\n"
				else
					sender=$3

					response=$(echo "BLOCK ADD $sender" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "ADDED" ]]; then
						exit 0
					else
						exit 1
					fi
				fi
			;;
			'split')
				# Parâmetros de entrada:
				#
				#    1. cidr: o bloco que deve ser utilizado.
				#
				# Códigos de saída:
				#
				#    0: adicionado com sucesso.
				#    1: erro ao tentar adicionar bloqueio.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 superblock split CIDR\n"
				else
					sender=$3

					response=$(echo "BLOCK SPLIT $sender" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "DROPPED" ]]; then
						exit 0
					else
						exit 1
					fi
				fi
			;;
			'overlap')
				# Parâmetros de entrada:
				#
				#    1. cidr: o bloco que deve ser utilizado.
				#
				# Códigos de saída:
				#
				#    0: adicionado com sucesso.
				#    1: erro ao tentar adicionar bloqueio.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).


				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 superblock overlap CIDR\n"
				else
					sender=$3

					response=$(echo "BLOCK OVERLAP $sender" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "ADDED" ]]; then
						exit 0
					else
						exit 1
					fi
				fi
			;;
			'extract')
				# Parâmetros de entrada:
				#
				#    1. cidr: o bloco que deve ser utilizado.
				#
				# Códigos de saída:
				#
				#    0: adicionado com sucesso.
				#    1: erro ao tentar adicionar bloqueio.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 superblock extract IP\n"
				else
					sender=$3

					response=$(echo "BLOCK EXTRACT $sender" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "EXTRACTED"* ]]; then
						exit 0
					else
						exit 1
					fi
				fi
			;;
			'drop')
				# Parâmetros de entrada:
				#
				#    1. sender: o remetente que deve ser desbloqueado, com endereço completo.
				#    1. domínio: o domínio que deve ser desbloqueado, com arroba (ex: @dominio.com.br)
				#    1. caixa postal: a caixa postal que deve ser desbloqueada, com arroba (ex: www-data@)
				#
				#
				# Códigos de saída:
				#
				#    0: desbloqueado com sucesso.
				#    1: erro ao tentar adicionar bloqueio.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 superblock drop sender\n"
				else
					sender=$3

					response=$(echo "BLOCK DROP $sender" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "DROPPED" ]]; then
						exit 0
					else
						exit 1
					fi
				fi
			;;
			'show')
				# Parâmetros de entrada:
				#    1: ALL: lista os bloqueios gerais (opcional)
				#
				# Códigos de saída:
				#
				#    0: visualizado com sucesso.
				#    1: erro ao tentar visualizar bloqueio.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "2" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 superblock show [all]\n"
				else
					if [ "$3" == "all" ]; then
						response=$(echo "BLOCK SHOW ALL" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)
					else
						response=$(echo "BLOCK SHOW" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)
					fi

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					else
						exit 0
					fi
				fi
			;;
			*)
				head
				printf "Syntax:\n    $0 superblock add recipient\n    $0 superblock drop recipient\n    $0 superblock split cidr\n    $0 superblock overlap cidr\n    $0 superblock extract cidr\n    $0 superblock show\n"
			;;
		esac
	;;
	'generic')
		case $2 in
			'add')
				# Parâmetros de entrada:
				#
				#
				# Códigos de saída:
				#
				#    0: adicionado com sucesso.
				#    1: erro ao tentar adicionar generico.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "3" ]; then
					head
					printf "Faltando parametro(s).\nSintaxe: $0 generic add sender\n"
				else
					sender=$3

					response=$(echo "GENERIC ADD $sender" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "ADDED" ]]; then
						exit 0
					else
						exit 1
					fi
				fi
			;;
			'find')
				# Códigos de saída:
				#
				#    0: adicionado com sucesso.
				#    1: erro ao tentar adicionar generico.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "3" ]; then
					head
					printf "Faltando parametro(s).\nSintaxe: $0 generic find <token>\n"
				else
					token=$3

					response=$(echo "GENERIC FIND $token" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					else
						exit 0
					fi
				fi
			;;
			'drop')
				# Parâmetros de entrada:
				#
				#
				#
				# Códigos de saída:
				#
				#    0: desbloqueado com sucesso.
				#    1: erro ao tentar adicionar generico.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "3" ]; then
					head
					printf "Faltando parametro(s).\nSintaxe: $0 generic drop sender\n"
				else
					sender=$3

					response=$(echo "GENERIC DROP $sender" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "DROPPED" ]]; then
						exit 0
					else
						exit 1
					fi
				fi
			;;
			'show')
				# Parâmetros de entrada:
				#    1: ALL: lista os reversos genericos (opcional)
				#
				# Códigos de saída:
				#
				#    0: visualizado com sucesso.
				#    1: erro ao tentar visualizar generico.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "2" ]; then
					head
					printf "Faltando parametro(s).\nSintaxe: $0 generic show [all]\n"
				else
					if [ "$3" == "all" ]; then
						response=$(echo "GENERIC SHOW ALL" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)
					else
						response=$(echo "GENERIC SHOW" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)
					fi

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					else
						exit 0
					fi
				fi
			;;
			*)
				head
				printf "Syntax:\n    $0 generic add recipient\n    $0 generic drop recipient\n    $0 generic show [all]\n"
			;;
		esac
	;;
	'dynamic')
		case $2 in
			'add')
				# Parâmetros de entrada:
				#
				#
				# Códigos de saída:
				#
				#    0: adicionado com sucesso.
				#    1: erro ao tentar adicionar dynamic.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "3" ]; then
					head
					printf "Faltando parametro(s).\nSintaxe: $0 dynamic add host\n"
				else
					host=$3

					response=$(echo "DYNAMIC ADD $host" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "ADDED" ]]; then
						exit 0
					else
						exit 1
					fi
				fi
			;;
			'find')
				# Códigos de saída:
				#
				#    0: adicionado com sucesso.
				#    1: erro ao tentar adicionar dynamic.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "3" ]; then
					head
					printf "Faltando parametro(s).\nSintaxe: $0 dynamic find <token>\n"
				else
					token=$3

					response=$(echo "DYNAMIC FIND $token" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					else
						exit 0
					fi
				fi
			;;
			'drop')
				# Parâmetros de entrada:
				#
				#
				#
				# Códigos de saída:
				#
				#    0: desbloqueado com sucesso.
				#    1: erro ao tentar adicionar dynamic.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "3" ]; then
					head
					printf "Faltando parametro(s).\nSintaxe: $0 dynamic drop host\n"
				else
					host=$3

					response=$(echo "DYNAMIC DROP $host" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "DROPPED" ]]; then
						exit 0
					else
						exit 1
					fi
				fi
			;;
			'show')
				# Códigos de saída:
				#
				#    0: visualizado com sucesso.
				#    1: erro ao tentar visualizar dynamic.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "2" ]; then
					head
					printf "Faltando parametro(s).\nSintaxe: $0 dynamic show\n"
				else
					response=$(echo "DYNAMIC SHOW" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					else
						exit 0
					fi
				fi
			;;
			*)
				head
				printf "Syntax:\n    $0 dynamic add recipient\n    $0 dynamic drop recipient\n    $0 dynamic show\n"
			;;
		esac
	;;
	'white')
		case $2 in
			'add')
				# Parâmetros de entrada:
				#
				#    1. recipient: o destinatário que deve ser bloqueado, com endereço completo.
				#
				#
				# Códigos de saída:
				#
				#    0: adicionado com sucesso.
				#    1: erro ao tentar adicionar bloqueio.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 white add recipient\n"
				else
					recipient=$3

					response=$(echo "WHITE ADD $recipient" | spfbl_query 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "ADDED" ]]; then
						exit 0
					else
						exit 1
					fi
				fi
			;;
			'sender')
				# Parâmetros de entrada:
				#
				#    1. sender: o remetente que deve ser liberado, com endereço completo.
				#
				#
				# Códigos de saída:
				#
				#    0: adicionado com sucesso.
				#    1: erro ao tentar adicionar bloqueio.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 white sender recipient\n"
				else
					sender=$3

					response=$(echo "WHITE SENDER $sender" | spfbl_query 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "ADDED "* ]]; then
						exit 0
					elif [[ $response == "ALREADY "* ]]; then
						exit 0
					else
						exit 1
					fi
				fi
			;;
			'drop')
				# Parâmetros de entrada:
				#
				#    1. recipient: o destinatário que deve ser desbloqueado, com endereço completo.
				#
				#
				# Códigos de saída:
				#
				#    0: desbloqueado com sucesso.
				#    1: erro ao tentar adicionar bloqueio.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 white drop recipient\n"
				else
					recipient=$3

					response=$(echo "WHITE DROP $recipient" | spfbl_query 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "DROPPED" ]]; then
						exit 0
					else
						exit 1
					fi
				fi
			;;
			'show')
				# Parâmetros de entrada: nenhum.
				#
				# Códigos de saída:
				#
				#    0: visualizado com sucesso.
				#    1: erro ao tentar visualizar bloqueio.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "2" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 white show\n"
				else
					response=$(echo "WHITE SHOW" | spfbl_query 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					else
						exit 0
					fi
				fi
			;;
			*)
				head
				printf "Syntax:\n    $0 white add recipient\n    $0 white sender recipient\n    $0 white drop recipient\n    $0 white show\n"
			;;
		esac
	;;
	'superwhite')
		case $2 in
			'add')
				# Parâmetros de entrada:
				#
				#    1. recipient: o destinatário que deve ser bloqueado, com endereço completo.
				#
				#
				# Códigos de saída:
				#
				#    0: adicionado com sucesso.
				#    1: erro ao tentar adicionar bloqueio.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 superwhite add recipient\n"
				else
					recipient=$3

					response=$(echo "WHITE ADD $recipient" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "ADDED" ]]; then
						exit 0
					else
						exit 1
					fi
				fi
			;;
			'drop')
				# Parâmetros de entrada:
				#
				#    1. recipient: o destinatário que deve ser desbloqueado, com endereço completo.
				#
				#
				# Códigos de saída:
				#
				#    0: desbloqueado com sucesso.
				#    1: erro ao tentar adicionar bloqueio.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 superwhite drop recipient\n"
				else
					recipient=$3

					response=$(echo "WHITE DROP $recipient" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "DROPPED" ]]; then
						exit 0
					else
						exit 1
					fi
				fi
			;;
			'show')
				# Parâmetros de entrada: nenhum.
				#
				# Códigos de saída:
				#
				#    0: visualizado com sucesso.
				#    1: erro ao tentar visualizar bloqueio.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "2" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 superwhite show [all]\n"
				else
					if [ "$3" == "all" ]; then
						response=$(echo "WHITE SHOW ALL" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)
					else
						response=$(echo "WHITE SHOW" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)
					fi

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					else
						exit 0
					fi
				fi
			;;
			*)
				head
				printf "Syntax:\n    $0 superwhite add recipient\n    $0 superwhite drop recipient\n    $0 superwhite show [all]\n"
			;;
		esac
	;;
	'client')
		case $2 in
			'add')
				# Parâmetros de entrada:
				#
				#    1. cidr: chave primária - endereço do host de acesso.
				#    2. domain: organizador do cadastro
				#	 3. option: opções de acesso -> NONE, SPFBL ou DNSBL
				#    4. email: [opcional] e-mail do cliente
				#
				# Códigos de saída:
				#
				#    0: adicionado com sucesso.
				#    1: erro ao tentar adiciona.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "5" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 client add cidr domain option [email]\n"
				else
					cidr=$3
					domain=$4
					option=$5
					email=""

					if [ -n "$6" ]; then
						email=$6
					fi

					response=$(echo "CLIENT ADD $cidr $domain $option $email" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "ADDED" ]]; then
						exit 0
					else
						exit 1
					fi
				fi
			;;
			'set')
				# Parâmetros de entrada:
				#
				#    1. cidr: chave primária - endereço do host de acesso.
				#    2. domain: organizador do cadastro
				#	 3. option: opções de acesso -> NONE, SPFBL ou DNSBL
				#    4. email: [opcional] e-mail do cliente
				#
				# Códigos de saída:
				#
				#    0: adicionado com sucesso.
				#    1: erro ao tentar adiciona.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "5" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 client set cidr domain option [email]\n"
				else
					cidr=$3
					domain=$4
					option=$5
					email=""

					if [ -n "$6" ]; then
						email=$6
					fi

					response=$(echo "CLIENT SET $cidr $domain $option $email" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					else
						exit 0
					fi
				fi
			;;
			'drop')
				# Parâmetros de entrada:
				#
				#    1. cidr: chave primária - endereço do host de acesso.
				#
				# Códigos de saída:
				#
				#    0: removido com sucesso.
				#    1: erro ao tentar remover.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 client drop cidr\n"
				else
					cidr=$3

					response=$(echo "CLIENT DROP $cidr" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "DROPPED" ]]; then
						exit 0
					else
						exit 1
					fi
				fi
			;;
			'show')
				# Códigos de saída:
				#
				#    0: visualizado com sucesso.
				#    1: erro ao tentar visualizar.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "2" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 client show\n"
				else

					response=$(echo "CLIENT SHOW" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					else
						exit 0
					fi
				fi
			;;
			*)
				head
				printf "Syntax:\n    $0 client add cidr domain option [email] \n    $0 client set cidr domain option [email] \n    $0 client drop cidr\n    $0 client show\n"
			;;
		esac
	;;
	'user')
		case $2 in
			'add')
				# Parâmetros de entrada:
				#
				#    1. email: E-mail do usuário.
				#    2. nome: Nome do usuário.
				#
				# Códigos de saída:
				#
				#    0: adicionado com sucesso.
				#    1: erro ao tentar adiciona.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "4" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 user add email nome\n"
				else
					email=$3
					nome="${@:4}"

					response=$(echo "USER ADD $email $nome" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == ADDED* ]]; then
						exit 0
					else
						exit 1
					fi
				fi
			;;
			'drop')
				# Parâmetros de entrada:
				#
				#    1. email: E-mail do usuário.
				#
				# Códigos de saída:
				#
				#    0: removido com sucesso.
				#    1: erro ao tentar remover.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 user drop email\n"
				else
					email=$3

					response=$(echo "USER DROP $email" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "DROPPED" ]]; then
						exit 0
					else
						exit 1
					fi
				fi
			;;
			'show')

				# Códigos de saída:
				#
				#    0: visualizado com sucesso.
				#    1: erro ao tentar visualizar.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "2" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 user show\n"
				else
					response=$(echo "USER SHOW" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					else
						exit 0
					fi
				fi
			;;
			'send-totp')
				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 user send-totp <email>\n"
				else
					response=$(echo "USER SEND $3 TOTP" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == TOTP\ SENT* ]]; then
						exit 0
					else
						exit 1
					fi
				fi
			;;
			'copy')
				# Copia os dados estáticos de um usuário para outro já existente:
				# preferências, recipient, trap, block, white e ignore. Não copia
				# credenciais, nome, transporte SMTP, clientes de MTA nem histórico.
				if [ $# -ne "4" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 user copy origem destino\n"
					exit 1
				else
					response=$(echo "USER COPY $3 $4" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == COPIED* ]]; then
						exit 0
					else
						exit 1
					fi
				fi
			;;
			'move')
				# Troca o e-mail da conta: o destino não pode existir. Leva
				# senha, TOTP, chaves, clientes de MTA, MX Gateway, Listing e
				# Billing; copia recipient, trap, block, white e ignore; apaga
				# a origem. O histórico não é movido.
				if [ $# -ne "4" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 user move origem destino\n"
					exit 1
				else
					response=$(echo "USER MOVE $3 $4" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == MOVED* ]]; then
						exit 0
					else
						exit 1
					fi
				fi
			;;
			'property')
				# Propriedades administrativas da conta (ex.: spamcenter_api_key).
				# O SHOW mostra só os 4 primeiros caracteres de cada valor.
				#
				# Códigos de saída:
				#
				#    0: sucesso (SHOW, CHANGED ou DROPPED).
				#    1: conta ou propriedade não encontrada, valor igual ou erro.
				#    2: timeout de conexão.
				#    3: out of service.
				action=$(echo "$4" | tr '[:lower:]' '[:upper:]')
				if [[ $action == "SHOW" && $# -eq 4 ]]; then
					command="USER PROPERTY $3 SHOW"
				elif [[ $action == "SET" && $# -ge 6 ]]; then
					command="USER PROPERTY $3 SET $5 ${*:6}"
				elif [[ $action == "DROP" && $# -eq 5 ]]; then
					command="USER PROPERTY $3 DROP $5"
				else
					head
					printf "Invalid Parameters. Syntax:\n    $0 user property email show\n    $0 user property email set nome valor\n    $0 user property email drop nome\n"
					exit 1
				fi

				response=$(echo "$command" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

				if [[ $response == "" ]]; then
					response=$(emptyResponse)
					maintenanceExit "$response"
				else
					resetTimeout
				fi

				echo "$response"

				if [[ $response == "OUT OF SERVICE" ]]; then
					exit 3
				elif [[ $response == "TIMEOUT" ]]; then
					exit 2
				elif [[ $response =~ ^(NOT\ FOUND|NOT\ CHANGED|INVALID|ERROR) ]]; then
					exit 1
				else
					exit 0
				fi
			;;
			*)
				head
				printf "Syntax:\n    $0 user add email nome\n    $0 user drop email\n    $0 user copy origem destino\n    $0 user move origem destino\n    $0 user property email { show | set nome valor | drop nome }\n    $0 user show\n"
			;;
		esac
	;;
	'peer')
		case $2 in
			'add')
				# Parâmetros de entrada:
				#
				#    1. host: Endereço do peer.
				#    2. email: E-mail do administrador.
				#
				# Códigos de saída:
				#
				#    0: adicionado com sucesso.
				#    1: erro ao tentar adicionar.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 peer add host [email]\n"
				else
					host=$3

					if [ -f "$4" ]; then
						email=$4
						response=$(echo "PEER ADD $host $email" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)
					else
						response=$(echo "PEER ADD $host" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)
					fi

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "ADDED" ]]; then
						exit 0
					else
						exit 1
					fi
				fi
			;;
			'drop')
				# Parâmetros de entrada:
				#
				#    1. host: Endereço do peer.
				#
				# Códigos de saída:
				#
				#    0: removido com sucesso.
				#    1: erro ao tentar remover.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 peer drop { host | all }\n"
				else
					host=$3

					if [ "$host" == "all" ]; then
						response=$(echo "PEER DROP ALL" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)
					else
						response=$(echo "PEER DROP $host" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)
					fi

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "DROPPED" ]]; then
						exit 0
					else
						exit 1
					fi
				fi
			;;
			'show')

				# Códigos de saída:
				#
				#    0: visualizado com sucesso.
				#    1: erro ao tentar visualizar.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "2" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 peer show [host]\n"
				else

					if [ -f "$3" ]; then
						host=$3
						response=$(echo "PEER SHOW $host" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)
					else
						response=$(echo "PEER SHOW" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)
					fi

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					else
						exit 0
					fi
				fi
			;;
			'set')
				# Parâmetros de entrada:
				#
				#    1. host: Endereço do peer.
				#    2. send: Opções para envio (##??##).
				#    3. receive: Opções para recebimento (##??##).
				#
				# Códigos de saída:
				#
				#    0: setado com sucesso.
				#    1: erro ao tentar setar opções.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "5" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 peer set host send receive\n"
				else
					host=$3
					send=$4
					receive=$5

					response=$(echo "PEER SET $host $send $receive" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					else
						exit 0
					fi
				fi
			;;
			'ping')
				# Parâmetros de entrada:
				#
				#    1. host: Endereço do peer.
				#
				# Códigos de saída:
				#
				#    0: executado com sucesso.
				#    1: erro ao tentar executar.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 peer ping host\n"
				else
					host=$3

					response=$(echo "PEER PING $host" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					else
						exit 0
					fi
				fi
			;;
			'send')
				# Parâmetros de entrada:
				#
				#    1. host: Endereço do peer.
				#
				# Códigos de saída:
				#
				#    0: executado com sucesso.
				#    1: erro ao tentar executar.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 peer send host\n"
				else
					host=$3

					response=$(echo "PEER SEND $host" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					else
						exit 0
					fi
				fi
			;;
			*)
				head
				printf "Syntax:\n    $0 peer add host [email]\n    $0 peer drop { host | all }\n    $0 peer show [host]\n    $0 peer set host send receive\n    $0 peer ping host\n    $0 peer send host\n"
			;;
		esac
	;;
	'reputation')
		# Parâmetros de entrada: nenhum
		#
		# Códigos de saída:
		#
		#    0: listado com sucesso.
		#    1: lista vazia.
		#    2: timeout de conexão.
		#    3: out of service.
		#   26: serviço em manutenção programada (status.spfbl.net).

		if [[ $2 == "cidr" ]]; then
			response=$(echo "REPUTATION CIDR" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)
		else
			response=$(echo "REPUTATION" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)
		fi

		if [[ $response == "" ]]; then
			response=$(emptyResponse)
			maintenanceExit "$response"
		else
			resetTimeout
		fi

		echo "$response"

		if [[ $response == "OUT OF SERVICE" ]]; then
			exit 3
		elif [[ $response == "TIMEOUT" ]]; then
			exit 2
		elif [[ $response == "EMPTY" ]]; then
			exit 0
		else
			exit 1
		fi
	;;
	'abuse')
		# Parâmetros de entrada:
		#
		#    1. In-Reply-To: o message ID da mensagem denunciada.
		#    2. From: o e-mail do denunciante.
		#
		#
		# Códigos de saída:
		#
		#    0: processado com sucesso.
		#    1: erro durante o processamento.
		#    3: timeout de conexão.
		#    4: out of service.
		#   26: serviço em manutenção programada (status.spfbl.net).

		if [ $# -lt "2" ]; then
			head
			printf "Invalid Parameters. Syntax: $0 abuse In-Reply-To:<messageID> From:<from>\n"
		else
			messageID=$2
			from=$3

			response=$(echo "ABUSE $messageID $from" | spfbl_query 2> /dev/null)

			if [[ $response == "" ]]; then
				response=$(emptyResponse)
				maintenanceExit "$response"
			else
				resetTimeout
			fi

			echo "$response"

			if [[ $response == "OUT OF SERVICE" ]]; then
				exit 3
			elif [[ $response == "TIMEOUT" ]]; then
				exit 2
			elif [[ $response == "COMPLAINED "* ]]; then
				exit 0
			elif [[ $response == "BLOCKED "* ]]; then
				exit 0
			elif [[ $response == "ALREADY "* ]]; then
				exit 0
			else
				exit 1
			fi
		fi
	;;
	'clear')
		# Parâmetros de entrada:
		#
		#    1. hostname: o nome do host cujas denúncias devem ser limpadas.
		#
		#
		# Códigos de saída:
		#
		#    0: limpado com sucesso.
		#    1: registro não encontrado em cache.
		#    2: erro ao processar atualização.
		#    3: timeout de conexão.
		#    4: out of service.
		#   26: serviço em manutenção programada (status.spfbl.net).

		if [ $# -lt "2" ]; then
			head
			printf "Invalid Parameters. Syntax: $0 clear hostname\n"
		else
			hostname=$2

			response=$(echo "CLEAR $hostname" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

			if [[ $response == "" ]]; then
				response=$(emptyResponse)
				maintenanceExit "$response"
			else
				resetTimeout
			fi

			echo "$response"

			if [[ $response == "OUT OF SERVICE" ]]; then
				exit 3
			elif [[ $response == "TIMEOUT" ]]; then
				exit 2
			else
				exit 0
			fi
		fi
	;;
	'refresh')
		# Parâmetros de entrada:
		#
		#    1. hostname: o nome do host cujo registro SPF que deve ser atualizado.
		#
		#
		# Códigos de saída:
		#
		#    0: atualizado com sucesso.
		#    1: registro não encontrado em cache.
		#    2: erro ao processar atualização.
		#    3: timeout de conexão.
		#    4: out of service.
		#   26: serviço em manutenção programada (status.spfbl.net).

		if [ $# -lt "2" ]; then
			head
			printf "Invalid Parameters. Syntax: $0 refresh hostname\n"
		else
			hostname=$2

			response=$(echo "REFRESH $hostname" | spfbl_query 2> /dev/null)

			if [[ $response == "" ]]; then
				response=$(emptyResponse)
				maintenanceExit "$response"
			else
				resetTimeout
			fi

			echo "$response"

			if [[ $response == "OUT OF SERVICE" ]]; then
				exit 3
			elif [[ $response == "TIMEOUT" ]]; then
				exit 2
			else
				exit 0
			fi
		fi
	;;
	'analise')
		# Parâmetros de entrada:
		#
		#    1. IP: o IP a ser analisado.
		#
		#
		# Códigos de saída:
		#
		#    0: atualizado com sucesso.
		#    1: registro não encontrado em cache.
		#    2: erro ao processar atualização.
		#    3: timeout de conexão.
		#    4: out of service.
		#   26: serviço em manutenção programada (status.spfbl.net).

		case $2 in
			'show')
				response=$(echo "ANALISE SHOW" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

				if [[ $response == "" ]]; then
					response=$(emptyResponse)
					maintenanceExit "$response"
				else
					resetTimeout
				fi

				echo "$response"

				if [[ $response == "OUT OF SERVICE" ]]; then
					exit 3
				elif [[ $response == "TIMEOUT" ]]; then
					exit 2
				else
					exit 0
				fi
			;;
			'dump')
				response=$(echo "ANALISE DUMP $3" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

				if [[ $response == "" ]]; then
					response=$(emptyResponse)
					maintenanceExit "$response"
				else
					resetTimeout
				fi

				echo "$response"

				if [[ $response == "OUT OF SERVICE" ]]; then
					exit 3
				elif [[ $response == "TIMEOUT" ]]; then
					exit 2
				else
					exit 0
				fi
			;;
			'drop')

				response=$(echo "ANALISE DROP $3" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

				if [[ $response == "" ]]; then
					response=$(emptyResponse)
					maintenanceExit "$response"
				else
					resetTimeout
				fi

				echo "$response"

				if [[ $response == "OUT OF SERVICE" ]]; then
					exit 3
				elif [[ $response == "TIMEOUT" ]]; then
					exit 2
				else
					exit 0
				fi
			;;
			*)
				ip=$2
				list=$3

				response=$(echo "ANALISE $ip $list" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

				if [[ $response == "" ]]; then
					response=$(emptyResponse)
					maintenanceExit "$response"
				else
					resetTimeout
				fi

				echo "$response"

				if [[ $response == "OUT OF SERVICE" ]]; then
					exit 3
				elif [[ $response == "TIMEOUT" ]]; then
					exit 2
				else
					exit 0
				fi
			;;
		esac
	;;
	'check')
		# Parâmetros de entrada:
		#
		#    1. IP: o IPv4 ou IPv6 do host de origem.
		#    2. email: o email do remetente.
		#    3. HELO: o HELO passado pelo host de origem.
		#
		# Saídas com qualificadores e os tokens com suas probabilidades:
		#
		#    <quaificador>\n
		#    <token> <probabilidade>\n
		#    <token> <probabilidade>\n
		#    <token> <probabilidade>\n
		#    ...
		#
		# Códigos de saída:
		#
		#    0: não especificado.
		#    1: qualificador NEUTRAL.
		#    2: qualificador PASS.
		#    3: qualificador FAIL.
		#    4: qualificador SOFTFAIL.
		#    5: qualificador NONE.
		#    6: erro temporário.
		#    7: erro permanente.
		#    8: listado em lista negra.
		#    9: timeout de conexão.
		#    10: domínio inexistente.
		#    11: parâmetros inválidos.
		#    12: out of service.
		#   26: serviço em manutenção programada (status.spfbl.net).
		#    13: remetente inexistente.

		if [ $# -lt "4" ]; then
			head
			printf "Invalid Parameters. Syntax: $0 check ip email helo\n"
		else
			ip=$2
			email=$3
			helo=$4
			recipient=$5

			qualifier=$(echo "CHECK '$ip' '$email' '$helo' '$recipient'" | spfbl_query 2> /dev/null)

			if [[ $qualifier == "" ]]; then
				qualifier=$(emptyResponse)
				maintenanceExit "$qualifier"
			else
				resetTimeout
			fi

			echo "$qualifier"

			if [[ $qualifier == "OUT OF SERVICE" ]]; then
				exit 12
			elif [[ $qualifier == "TIMEOUT" ]]; then
				exit 9
			elif [[ $qualifier == "NXDOMAIN" ]]; then
				exit 10
			elif [[ $qualifier == "NXSENDER" ]]; then
				exit 13
			elif [[ $qualifier == "LISTED"* ]]; then
				exit 8
			elif [[ $qualifier == "INVALID" ]]; then
				exit 11
			elif [[ $qualifier == "ERROR: HOST NOT FOUND" ]]; then
				exit 6
			elif [[ $qualifier == "ERROR: QUERY" ]]; then
				exit 11
			elif [[ $qualifier == "ERROR: "* ]]; then
				exit 7
			elif [[ $qualifier == "NONE"* ]]; then
				exit 5
			elif [[ $qualifier == "PASS"* ]]; then
				exit 2
			elif [[ $qualifier == "FAIL" ]]; then
				exit 3
			elif [[ $qualifier == "SOFTFAIL"* ]]; then
				exit 4
			elif [[ $qualifier == "NEUTRAL"* ]]; then
				exit 1
			else
				exit 0
			fi
		fi
	;;
	'supercheck')
		# Mesma consulta do check, pela porta administrativa (CHECK). Lá dentro, o
		# SPFBL usa o mesmo método da porta de cliente (SPF.processSPF).
		#
		# Parâmetros de entrada:
		#
		#    1. IP: o IPv4 ou IPv6 do host de origem.
		#    2. email: o email do remetente.
		#    3. HELO: o HELO passado pelo host de origem.
		#
		# Saídas com qualificadores e os tokens com suas probabilidades:
		#
		#    <quaificador>\n
		#    <token> <probabilidade>\n
		#    <token> <probabilidade>\n
		#    <token> <probabilidade>\n
		#    ...
		#
		# Códigos de saída:
		#
		#    0: não especificado.
		#    1: qualificador NEUTRAL.
		#    2: qualificador PASS.
		#    3: qualificador FAIL.
		#    4: qualificador SOFTFAIL.
		#    5: qualificador NONE.
		#    6: erro temporário.
		#    7: erro permanente.
		#    8: listado em lista negra.
		#    9: timeout de conexão.
		#    10: domínio inexistente.
		#    11: parâmetros inválidos.
		#    12: out of service.
		#   26: serviço em manutenção programada (status.spfbl.net).
		#    13: remetente inexistente.

		if [ $# -lt "4" ]; then
			head
			printf "Invalid Parameters. Syntax: $0 supercheck ip email helo [recipient]\n"
		else
			ip=$2
			email=$3
			helo=$4
			recipient=$5

			qualifier=$(echo "CHECK '$ip' '$email' '$helo' '$recipient'" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

			if [[ $qualifier == "" ]]; then
				qualifier=$(emptyResponse)
				maintenanceExit "$qualifier"
			else
				resetTimeout
			fi

			echo "$qualifier"

			if [[ $qualifier == "OUT OF SERVICE" ]]; then
				exit 12
			elif [[ $qualifier == "TIMEOUT" ]]; then
				exit 9
			elif [[ $qualifier == "NXDOMAIN" ]]; then
				exit 10
			elif [[ $qualifier == "NXSENDER" ]]; then
				exit 13
			elif [[ $qualifier == "LISTED"* ]]; then
				exit 8
			elif [[ $qualifier == "INVALID" ]]; then
				exit 11
			elif [[ $qualifier == "ERROR: HOST NOT FOUND" ]]; then
				exit 6
			elif [[ $qualifier == "ERROR: QUERY" ]]; then
				exit 11
			elif [[ $qualifier == "ERROR: "* ]]; then
				exit 7
			elif [[ $qualifier == "NONE"* ]]; then
				exit 5
			elif [[ $qualifier == "PASS"* ]]; then
				exit 2
			elif [[ $qualifier == "FAIL" ]]; then
				exit 3
			elif [[ $qualifier == "SOFTFAIL"* ]]; then
				exit 4
			elif [[ $qualifier == "NEUTRAL"* ]]; then
				exit 1
			else
				exit 0
			fi
		fi
	;;
	'spam')
		# Este comando procura e extrai o ticket de consulta SPFBL de uma mensagem de e-mail se o parâmetro for um arquivo.
		#
		# Com posse do ticket, ele envia a reclamação ao serviço SPFBL para contabilização de reclamação.
		#
		# Parâmetros de entrada:
		#  1. o arquivo de e-mail com o ticket ou o ticket sozinho.
		#
		# Códigos de saída:
		#  0. Ticket enviado com sucesso.
		#  1. Arquivo inexistente.
		#  2. Arquivo não contém ticket.
		#  3. Erro no envio do ticket.
		#  4. Timeout no envio do ticket.
		#  5. Parâmetro inválido.
		#  6. Ticket inválido.

		if [ $# -lt "2" ]; then
			head
			printf "Invalid Parameters. Syntax: $0 spam [ticketid or file]\n"
		else
			if [[ $2 =~ ^https?://.+/[a-zA-Z0-9%_-]{44,}$ ]]; then
				# O parâmentro é uma URL de denúncia SPFBL.
				url=$2
			elif [[ $2 =~ ^[a-zA-Z0-9/+=_-]{44,1024}$ ]]; then
				# O parâmentro é um ticket SPFBL.
				ticket=$2
			elif [ -f "$2" ]; then
				# O parâmetro é um arquivo.
				file=$2

				if [ -e "$file" ]; then
					# Extrai o ticket incorporado no arquivo.
					ticket=$(grep -Pom 1 "^Received-SPFBL: (PASS|SOFTFAIL|NEUTRAL|NONE|WHITE|FLAG|HOLD) \K([0-9a-zA-Z:/._-]+)$" $file)

					if [ $? -gt 0 ]; then

						# Extrai o ticket incorporado no arquivo.
						url=$(grep -Pom 1 "^Received-SPFBL: (PASS|SOFTFAIL|NEUTRAL|NONE|WHITE|FLAG|HOLD) \K(https?://.+/[0-9a-zA-Z_-]+)" $file)

						if [ $? -gt 0 ]; then
							echo "Nenhum ticket SPFBL foi encontrado na mensagem."
							exit 2
						fi
					fi
				else
					echo "O arquivo não existe."
					exit 1
				fi
			else
				echo "O parâmetro passado não corresponde a um arquivo nem a um ticket."
				exit 5
			fi

			if [[ -z $url ]]; then
				if [[ -z $ticket ]]; then
					echo "Ticket SPFBL inválido."
					exit 6
				else
					# Registra reclamação SPFBL.
					resposta=$(echo "SPAM $ticket" | spfbl_query 2> /dev/null)

					if [[ $resposta == "" ]]; then
						resposta=$(emptyResponse)
						maintenanceExit "$resposta"
						echo "A reclamação SPFBL não foi enviada por timeout."
						exit 4
					elif [[ $resposta == "OK"* ]]; then
						echo "Reclamação SPFBL enviada com sucesso."
						exit 0
					elif [[ $resposta == "ERROR: DECRYPTION" ]]; then
						echo "Ticket SPFBL inválido."
						exit 6
					else
						echo "A reclamação SPFBL não foi enviada: $resposta"
						exit 3
					fi
				fi
			else
				# Registra reclamação SPFBL via HTTP.
				resposta=$(curl -X PUT -s -m 3 -w '\n%{http_code}' $url)
				code=${resposta##*$'\n'}
				resposta=$(printf '%s' "${resposta%$'\n'*}")
				if httpUnavailable "$code"; then
					resposta=$(emptyResponse)
					maintenanceExit "$resposta"
				else
					resetTimeout
				fi
				if httpUnavailable "$code"; then
					echo "A reclamação SPFBL não foi enviada por timeout."
					exit 4
				elif [[ $resposta == "OK"* ]]; then
					echo "Reclamação SPFBL enviada com sucesso."
					exit 0
				elif [[ $resposta == "ERROR: DECRYPTION" ]]; then
					echo "Ticket SPFBL inválido."
					exit 6
				else
					echo "A reclamação SPFBL não foi enviada: $resposta"
					exit 3
				fi
			fi
		fi
	;;
	'link')
		# Códigos de saída:
		#
		#    0: nenhum bloqueio encontrado.
		#    1: pelo meno um link está bloqueado e o ticket foi denunciado.
		#    2: timeout de conexão.
		#    3: consulta inválida.
		#    4: out of service.
		#   26: serviço em manutenção programada (status.spfbl.net).
		#    5: hold message.
		#    6: flag message.

		if [ $# -lt "2" ]; then
			head
			printf "Faltando parametro(s).\nSintaxe: $0 link <ticket> <links>\n"
		else
			ticket=$2
			links=$3

			response=$(echo "LINK $ticket $links" | spfbl_query 2> /dev/null)

			if [[ $response == "" ]]; then
				response=$(emptyResponse)
				maintenanceExit "$response"
			else
				resetTimeout
			fi

			echo "$response"

			if [[ $response == "OUT OF SERVICE" ]]; then
				exit 4
			elif [[ $response == "TIMEOUT" ]]; then
				exit 2
			elif [[ $response == "CLEAR" ]]; then
				exit 0
			elif [[ $response == "HOLD" ]]; then
				exit 5
			elif [[ $response == "FLAG" ]]; then
				exit 6
                        elif [[ $response == "REJECT" ]]; then
                                exit 1
 			elif [[ $response == "BLOCKED"* ]]; then
				exit 1
			else
				exit 3
			fi
		fi
	;;
	'signer')
		# Códigos de saída:
		#
		#    0: registro incluído.
		#    1: consulta não encontrada.
		#    2: timeout de conexão.
		#    3: consulta inválida.
		#    4: out of service.
		#   26: serviço em manutenção programada (status.spfbl.net).

		if [ $# -lt "2" ]; then
			head
			printf "Faltando parametro(s).\nSintaxe: $0 signer <ticket> <address>\n"
		else
			ticket=$2
			signer=$3

			response=$(echo "SIGNER $ticket $signer" | spfbl_query 2> /dev/null)

			if [[ $response == "" ]]; then
				response=$(emptyResponse)
				maintenanceExit "$response"
			else
				resetTimeout
			fi

			echo "$response"

			if [[ $response == "OUT OF SERVICE" ]]; then
				exit 4
			elif [[ $response == "TIMEOUT" ]]; then
				exit 2
			elif [[ $response == "ADDED" ]]; then
				exit 0
			elif [[ $response == "NOT FOUND" ]]; then
				exit 1
			else
				exit 3
			fi
		fi
	;;
	'malware')
		# Este comando procura e extrai o ticket de consulta SPFBL de uma mensagem de e-mail se o parâmetro for um arquivo.
		#
		# Com posse do ticket, ele envia a reclamação ao serviço SPFBL para contabilização de reclamação como malware encontrado.
		#
		# Parâmetros de entrada:
		#  1. o arquivo de e-mail com o ticket ou o ticket sozinho.
		#
		# Códigos de saída:
		#  0. Ticket enviado com sucesso.
		#  1. Arquivo inexistente.
		#  2. Arquivo não contém ticket.
		#  3. Erro no envio do ticket.
		#  4. Timeout no envio do ticket.
		#  5. Parâmetro inválido.
		#  6. Ticket inválido.
                #  7. Aceitar por exceção.

		if [ $# -lt "2" ]; then
			head
			printf "Invalid Parameters. Syntax: $0 malware [ticketid or file]\n"
		else
			if [[ $2 =~ ^https?://.+/[a-zA-Z0-9%_-]{44,}$ ]]; then
				# O parâmentro é uma URL de denúncia SPFBL.
				url=$2
			elif [[ $2 =~ ^(https?://.+/)?[a-zA-Z0-9/+=_\;-]{44,}$ ]]; then
				# O parâmentro é um ticket SPFBL.
				ticket=$2
			elif [ -f "$2" ]; then
				# O parâmetro é um arquivo.
				file=$2

				if [ -e "$file" ]; then
					# Extrai o ticket incorporado no arquivo.
					ticket=$(grep -Pom 1 "^Received-SPFBL: (PASS|SOFTFAIL|NEUTRAL|NONE|WHITE|FLAG|HOLD) \K([0-9a-zA-Z\+/=]+)$" $file)

					if [ $? -gt 0 ]; then

						# Extrai o ticket incorporado no arquivo.
						url=$(grep -Pom 1 "^Received-SPFBL: (PASS|SOFTFAIL|NEUTRAL|NONE|WHITE|FLAG|HOLD) \K(https?://.+/[0-9a-zA-Z\+/=]+)$" $file)

						if [ $? -gt 0 ]; then
							echo "Nenhum ticket SPFBL foi encontrado na mensagem."
							exit 2
						fi
					fi
				else
					echo "O arquivo não existe."
					exit 1
				fi
			else
				echo "O parâmetro passado não corresponde a um arquivo nem a um ticket."
				exit 5
			fi

			if [[ -z $url ]]; then
				if [[ -z $ticket ]]; then
					echo "Ticket SPFBL inválido."
					exit 6
				else
					# Registra reclamação SPFBL como malware.
					resposta=$(echo "MALWARE $ticket $3" | spfbl_query 2> /dev/null)

					if [[ $resposta == "" ]]; then
						resposta=$(emptyResponse)
						maintenanceExit "$resposta"
						echo "A reclamação SPFBL não foi enviada por timeout."
						exit 4
					elif [[ $resposta == "OK"* ]]; then
						echo "Reclamação SPFBL enviada com sucesso."
						exit 0
                                        elif [[ $resposta == "ACCEPT" ]]; then
                                                echo "Reclamação ignorada por exceção."
                                                exit 7
					elif [[ $resposta == "ERROR: DECRYPTION" ]]; then
						echo "Ticket SPFBL inválido."
						exit 6
					else
						echo "A reclamação SPFBL não foi enviada: $resposta"
						exit 3
					fi
				fi
			else
				### Atenção! Reclamaão de malware não implementada em HTTP ainda.
				# Registra reclamação SPFBL via HTTP.
				resposta=$(curl -X PUT -s -m 3 -w '\n%{http_code}' $url)
				code=${resposta##*$'\n'}
				resposta=$(printf '%s' "${resposta%$'\n'*}")
				if httpUnavailable "$code"; then
					resposta=$(emptyResponse)
					maintenanceExit "$resposta"
				else
					resetTimeout
				fi
				if httpUnavailable "$code"; then
					echo "A reclamação SPFBL não foi enviada por timeout."
					exit 4
				elif [[ $resposta == "OK"* ]]; then
					echo "Reclamação SPFBL enviada com sucesso."
					exit 0
				elif [[ $resposta == "ERROR: DECRYPTION" ]]; then
					echo "Ticket SPFBL inválido."
					exit 6
				else
					echo "A reclamação SPFBL não foi enviada: $resposta"
					exit 3
				fi
			fi
		fi
	;;
	'from')
		# Códigos de saída:
		#
		#    0: nenhum bloqueio encontrado.
		#    1: pelo meno um endereço está bloqueado e o ticket foi denunciado.
		#    2: timeout de conexão.
		#    3: consulta inválida.
		#    4: out of service.
		#   26: serviço em manutenção programada (status.spfbl.net).
		#   17: remetente colocado em lista branca.

		if [ $# -lt "3" ]; then
			head
			printf "Faltando parametro(s).\nSintaxe: $0 from <ticket> From:<from> Reply-To:<replyto> List-Unsubscribe:<url>\n"
		else
			ticket=$2
			from=$3
			replyto=$4
			unsubscribe=$5

			response=$(echo "FROM $ticket $from $replyto $unsubscribe" | spfbl_query 2> /dev/null)

			if [[ $response == "" ]]; then
				response=$(emptyResponse)
				maintenanceExit "$response"
			else
				resetTimeout
			fi

			echo "$response"

			if [[ $response == "OUT OF SERVICE" ]]; then
				exit 4
			elif [[ $response == "TIMEOUT" ]]; then
				exit 2
			elif [[ $response == "CLEAR" ]]; then
				exit 0
			elif [[ $response == "WHITE" ]]; then
				exit 17
			elif [[ $response == "BLOCKED"* ]]; then
				exit 1
			else
				exit 3
			fi
		fi
	;;
	'header')
		# Códigos de saída:
		#
		#    0: nenhum bloqueio encontrado.
		#    1: pelo meno um endereço está bloqueado e o ticket foi denunciado.
		#    2: timeout de conexão.
		#    3: consulta inválida.
		#    4: out of service.
		#   26: serviço em manutenção programada (status.spfbl.net).
		#    5: mensagem rejeitada pelo conteudo.
		#    6: marcar como SPAM.
		#    7: congelar a entrega da mensagem.
		#   17: remetente colocado em lista branca.

		if [ $# -lt "3" ]; then
			head
			printf "Faltando parametro(s).\nSintaxe: $0 header <ticket> 'From:[<from>]' 'Reply-To:[<replyto>]' 'Message-ID:[<messageid>]' 'In-Reply-To:[<inreplyto>]' 'Date:[<date>]' 'Subject:[<subject>]' 'List-Unsubscribe:[<url>]' 'Queue-ID:[<queueid>]'\n"
		else
			ticket=$2
			from=$3
			replyto=$4
			messageID=$5
			date=$6
			subject=$7
			unsubscribe=$8
			queueID=$9

			response=$(echo "HEADER $ticket $from $replyto $messageID $date $subject $unsubscribe $queueID" | spfbl_query 2> /dev/null)

			if [[ $response == "" ]]; then
				response=$(emptyResponse)
				maintenanceExit "$response"
			else
				resetTimeout
			fi

			echo "$response"

			if [[ $response == "OUT OF SERVICE" ]]; then
				exit 4
			elif [[ $response == "TIMEOUT" ]]; then
				exit 2
			elif [[ $response == "CLEAR" ]]; then
				exit 0
			elif [[ $response == "WHITE" ]]; then
				exit 17
			elif [[ $response == "REJECT" ]]; then
				exit 5
			elif [[ $response == "FLAG" ]]; then
				exit 6
			elif [[ $response == "HOLD" ]]; then
				exit 7
			elif [[ $response == "BLOCKED"* ]]; then
				exit 1
			else
				exit 3
			fi
		fi
	;;
	'scan')
		# Envia a mensagem completa, ainda na ACL de DATA do Exim,
		# para inspeção no SPFBL via HTTPS.
		#
		# Parâmetros de entrada:
		#
		#    1. queueid: o Queue-ID do Exim ($message_exim_id).
		#    2. spool: [opcional] o $spool_directory do Exim.
		#    3. tickets: [opcional] o conjunto de tickets da consulta,
		#       separados por ponto e vírgula ($acl_c_spfblticketset).
		#
		# Códigos de saída (mesmos do comando header):
		#
		#    0: nenhum bloqueio encontrado.
		#    1: pelo meno um endereço está bloqueado e o ticket foi denunciado.
		#    2: timeout de conexão.
		#    3: consulta inválida.
		#    4: out of service.
		#   26: serviço em manutenção programada (status.spfbl.net).
		#    5: mensagem rejeitada pelo conteudo.
		#    6: marcar como SPAM.
		#    7: congelar a entrega da mensagem.
		#   17: remetente colocado em lista branca.
		#  255: erro no processamento do servidor.

		if [ $# -lt "2" ]; then
			head
			printf "Faltando parametro(s).\nSintaxe: $0 scan <queueid> [spool_directory] [ticketset]\n"
		else
			QUEUEID=$2
			SPOOL=${3:-/var/spool/exim}
			FILE="$SPOOL/scan/$QUEUEID/$QUEUEID.eml"

			# Reduz cada ticket ao último segmento (descarta o prefixo de URL)
			# e mantém só caracteres de ticket, para o cabeçalho HTTP ficar
			# curto e não aceitar quebra de linha nem outro caractere estranho.
			TICKETS=$(printf '%s' "$4" | tr ';' '\n' | sed 's#.*/##' | tr -cd 'A-Za-z0-9_=\n-' | grep -v '^$' | paste -sd ';' -)

			if [[ -n $SPFBL_KEY ]]; then
				# Com chave: IPv4 ou IPv6 (ou o IP_VERSION do spfbl.conf),
				# chave e hostname pelo descritor 3.
				CURL_ARGS=(${IP_VERSION:+-$IP_VERSION} -s --connect-timeout 3 -m "$QUERY_TIMEOUT" -H "Content-Type: message/rfc822" -H "Content-Encoding: gzip")
			else
				CURL_ARGS=(-4 -s --connect-timeout 3 -m "$QUERY_TIMEOUT" -H "Content-Type: message/rfc822" -H "Content-Encoding: gzip")
			fi
			if [ -n "$TICKETS" ]; then
				CURL_ARGS+=(-H "X-SPFBL-Tickets: $TICKETS")
			fi
			if [ "$DEEP_ANALYSIS" == "true" ]; then
				CURL_ARGS+=(-H "X-SPFBL-Deep-Analysis: true")
			fi

			if [[ ! $QUEUEID =~ ^[0-9a-zA-Z]{6}-([0-9a-zA-Z]{11}-[0-9a-zA-Z]{4}|[0-9a-zA-Z]{6}-[0-9a-zA-Z]{2})$ ]]; then
				response="INVALID QUEUE-ID"
			elif [ ! -f "$FILE" ]; then
				response="NOT FOUND"
			else
				# EML puro: descarta a linha separadora "From " do MBOX, se houver.
				scanBody() {
					sed '1{/^From /d}' "$FILE" | gzip --no-name --quiet --to-stdout
				}
				if [[ -n $SPFBL_KEY ]]; then
					response=$(keyCurl scanBody "$URL_SERVIDOR/scan/$QUEUEID" "${CURL_ARGS[@]}" --data-binary @-)
				else
					response=$(scanBody | curl "${CURL_ARGS[@]}" -w '\n%{http_code}' --data-binary @- "$URL_SERVIDOR/scan/$QUEUEID" 2> /dev/null)
				fi
				code=${response##*$'\n'}
				response=$(printf '%s' "${response%$'\n'*}")

				if [[ -n $SPFBL_KEY ]] && keyRefusal "$code" "$response"; then
					# Chave ou hostname recusado: a mensagem passa sem filtro.
					logKeyRefusal "$code" "$response"
					response="OUT OF SERVICE"
				elif httpUnavailable "$code" || [[ $response == "" && $code == "200" ]]; then
					# Sem conexão, timeout ou página de erro do Cloudflare.
					response=$(emptyResponse)
					maintenanceExit "$response"
				elif [[ $response == "" ]]; then
					# Recusa do próprio SPFBL (400, 403, 413): o serviço respondeu.
					resetTimeout
					response="INVALID"
				else
					resetTimeout
				fi
			fi

			echo "$response"

			if [[ $response == "OUT OF SERVICE" ]]; then
				exit 4
			elif [[ $response == "TIMEOUT" ]]; then
				exit 2
			elif [[ $response == "CLEAR" ]]; then
				exit 0
			elif [[ $response == "WHITE" ]]; then
				exit 17
			elif [[ $response == "REJECT" ]]; then
				exit 5
			elif [[ $response == "FLAG" ]]; then
				exit 6
			elif [[ $response == "HOLD" ]]; then
				exit 7
			elif [[ $response == "BLOCKED"* ]]; then
				exit 1
			elif [[ $response == "ERROR" ]]; then
				exit 255
			else
				exit 3
			fi
		fi
	;;
	'message')
		# Códigos de saída:
		#
		#    0: gravado com sucesso.
		#    1: registro de consulta não encontrado.
		#    2: arquivo grande demais.
		#    3: erro desconhecido.

		if [ $# -lt "2" ]; then
			head
			printf "Faltando parametro(s).\nSintaxe: $0 message <queueid>\n"
		else
			QUEUEID=$2
			MESSAGE=$(exim -Mvc $QUEUEID)
			
			if [ $? -eq 0 ]; then
			
                                ENCODED=$(echo "$MESSAGE" | gzip --no-name --quiet --to-stdout | base64 --wrap=0)
                                LENGTH=${#ENCODED}

				if [ "$LENGTH" -gt "65535" ]; then
					response="TOO BIG"
				else
					response=$(echo "MESSAGE $QUEUEID $ENCODED" | spfbl_query 2> /dev/null)
				fi
			else
				response="NOT FOUND"
			fi


			if [[ $response == "" ]]; then
				response=$(emptyResponse)
				maintenanceExit "$response"
			else
				resetTimeout
			fi

			echo "$response"

			if [[ $response == "STORED" ]]; then
				exit 0
			elif [[ $response == "NOT FOUND" ]]; then
				exit 1
			elif [[ $response == "TOO BIG" ]]; then
				exit 2
			else
				exit 3
			fi
		fi
	;;
	'body')
		# Códigos de saída:
		#
		#    0: modificado com sucesso.
		#    1: o parâmetro não é um arquivo.
		#    2: registro de consulta não encontrado.
		#    3: arquivo grande demais.
		#    4: erro desconhecido.

		if [ $# -lt "4" ]; then
			head
			printf "Faltando parametro(s).\nSintaxe: $0 body <ticket> <file> <charset>\n"
		else
			TICKET=$2
			FILE=$3
                        CHARSET=$4

			if [ -f "$FILE" ]; then

                                #iconv -s -f $CHARSET -t utf-8 $FILE > $FILE.conv
                                #if [ $? -eq "0" ]; then
                                #    FILE=$FILE.conv
                                #else
                                #    rm $FILE.conv
                                #fi

                                cat $FILE | gzip --no-name --quiet --to-stdout > $FILE.gz
                                LENGTH=$(wc -c < "$FILE.gz")

				if [ "$LENGTH" -gt "65535" ]; then
					response="TOO BIG"
				else
					ENCODED=$(base64 --wrap=0 $FILE.gz)
					response=$(echo "BODY $TICKET $ENCODED $CHARSET" | spfbl_query 2> /dev/null)
				fi
			else
				response="NOT A FILE"
			fi


			if [[ $response == "" ]]; then
				response=$(emptyResponse)
				maintenanceExit "$response"
			else
				resetTimeout
			fi

			echo "$response"

			if [[ $response == "CHANGED" ]]; then
				exit 0
			elif [[ $response == "NOT A FILE" ]]; then
				exit 1
			elif [[ $response == "NOT FOUND" ]]; then
				exit 2
			elif [[ $response == "TOO BIG" ]]; then
				exit 3
			else
				exit 4
			fi
		fi
	;;
	'holding')
	     # Queue ID do Exim: formato antigo (ate 4.96, 16 caracteres, ex.: 1aBcDe-FgHiJk-Lm)
	     # e formato novo (4.97+, 23 caracteres, ex.: 16VDhn-000000001bo-D342).
	     QUEUE_ID_RE='^[0-9a-zA-Z]{6}-([0-9a-zA-Z]{11}-[0-9a-zA-Z]{4}|[0-9a-zA-Z]{6}-[0-9a-zA-Z]{2})$'
		 
	     if [ $# -eq 1 ]; then
	     
	            run=0;
	            if [ -f "/var/tmp/SPFBL_HOLDING" ]; then
	                elapsed=$(($(date +%s) - $(date +%s -r /var/tmp/SPFBL_HOLDING)))
	                if [ $elapsed -gt 3600 ]; then
	                    run=1;
	                fi
	            else
	                run=1;
	            fi
	            if [ $run -eq 1 ]; then
	
	                touch /var/tmp/SPFBL_HOLDING
			which exiqgrep > /dev/null
	
			if [ $? -eq 0 ]; then
	
				list=$(exiqgrep -z -i | egrep "$QUEUE_ID_RE")
	
				if [ $? -eq 0 ]; then
	
					while read -r message; do
	
						ticket=$(exim -Mvh $message | grep -Pom 1 "^(PASS|SOFTFAIL|NEUTRAL|NONE|WHITE|HOLD|FLAG) (https?://.+/)?\K([0-9a-zA-Z_-]{44,})$")
	
						if [ $? -eq 0 ]; then
	
							response=$(echo "HOLDING $ticket" | spfbl_query 2> /dev/null)

							if [[ $response == "" ]]; then

								# Manter a mensagem congelada.
								response=$(emptyResponse)
								if [[ $response == "MAINTENANCE" ]]; then
									echo "SPFBL under maintenance: message $message keep frozen."
								else
									echo "Message $message keep frozen."
								fi

							elif [[ $response == "WHITE" ]]; then

								# Liberar a mensagem congelada 
								# e entregar imedatamente.
								exim -Mt $message
								exim -M $message &

							elif [[ $response == "ACCEPT" ]]; then

								# Liberar a mensagem congelada.
								exim -Mt $message

							elif [[ $response == "ERROR" ]]; then

								# Manter a mensagem congelada.
								echo "Message $message keep frozen."

							elif [[ $response == "HOLD" ]]; then

								# Manter a mensagem congelada.
								echo "Message $message keep frozen."

							elif [[ $response == "FLAG" ]]; then

								# Liberar a mensagem congelada.
								exim -Mt $message

							else

								# Remover a mensagem congelada.
								exim -Mrm $message

							fi
						fi
					done <<< "$list"
				fi
			fi
	                rm /var/tmp/SPFBL_HOLDING
	          fi
	          
	     elif [ $# -eq 2 ]; then
	     
	          if [[ $2 =~ $QUEUE_ID_RE ]]; then
	          
	          	message=$2
	          	ticket=$(exim -Mvh $message | grep -Pom 1 "^(PASS|SOFTFAIL|NEUTRAL|NONE|WHITE|HOLD|FLAG) (https?://.+/)?\K([0-9a-zA-Z_-]{44,})$")
	
			if [ $? -eq 0 ]; then
	
				response=$(echo "HOLDING $ticket" | spfbl_query 2> /dev/null)

				if [[ $response == "" ]]; then

					# Manter a mensagem congelada.
					response=$(emptyResponse)
					if [[ $response == "MAINTENANCE" ]]; then
						echo "SPFBL under maintenance: message $message keep frozen."
					else
						echo "Message $message keep frozen."
					fi

				elif [[ $response == "WHITE" ]]; then

					# Liberar a mensagem congelada 
					# e entregar imedatamente.
					exim -Mt $message &
					exim -M $message &

				elif [[ $response == "ACCEPT" ]]; then

					# Liberar a mensagem congelada.
					exim -Mt $message &

				elif [[ $response == "ERROR" ]]; then

					# Manter a mensagem congelada.
					echo "Message $message keep frozen."

				elif [[ $response == "HOLD" ]]; then

					# Manter a mensagem congelada.
					echo "Message $message keep frozen."

				elif [[ $response == "FLAG" ]]; then

					# Liberar a mensagem congelada.
					exim -Mt $message &

				else

					# Remover a mensagem congelada.
					exim -Mrm $message &

				fi
				
				exit 0;
		  	else
		  		echo "Message $message not found."
		  		exit 1;
			fi
	          fi
             fi
	;;
	'ham')
		# Este comando procura e extrai o ticket de consulta SPFBL de uma mensagem de e-mail se o parâmetro for um arquivo.
		#
		# Com posse do ticket, ele solicita a revogação da reclamação ao serviço SPFBL.
		#
		# Parâmetros de entrada:
		#  1. o arquivo de e-mail com o ticket ou o ticket sozinho.
		#
		# Códigos de saída:
		#  0. Reclamação revogada com sucesso.
		#  1. Arquivo inexistente.
		#  2. Arquivo não contém ticket.
		#  3. Erro no envio do ticket.
		#  4. Timeout no envio do ticket.
		#  5. Parâmetro inválido.
		#  6. Ticket inválido.

		if [ $# -lt "2" ]; then
			head
			printf "Invalid Parameters. Syntax: $0 ham [ticketid or file]\n"
		else
			if [[ $2 =~ ^https?://.+/[a-zA-Z0-9%_-]{44,}$ ]]; then
				# O parâmentro é uma URL de denúncia SPFBL.
				url=$2
			elif [[ $2 =~ ^[a-zA-Z0-9/+=_-]{44,1024}$ ]]; then
				# O parâmentro é um ticket SPFBL.
				ticket=$2
			elif [ -f "$2" ]; then
				# O parâmetro é um arquivo.
				file=$2

				if [ -e "$file" ]; then
					# Extrai o ticket incorporado no arquivo.
					ticket=$(grep -Pom 1 "^Received-SPFBL: (PASS|SOFTFAIL|NEUTRAL|NONE|WHITE|FLAG|HOLD) \K([0-9a-zA-Z\+/=]+)$" $file)

					if [ $? -gt 0 ]; then

						# Extrai o ticket incorporado no arquivo.
						url=$(grep -Pom 1 "^Received-SPFBL: (PASS|SOFTFAIL|NEUTRAL|NONE|WHITE|FLAG|HOLD) \K(https?://.+/[0-9a-zA-Z\+/=]+)$" $file)

						if [ $? -gt 0 ]; then
							echo "Nenhum ticket SPFBL foi encontrado na mensagem."
							exit 2
						fi
					fi
				else
					echo "O arquivo não existe."
					exit 1
				fi
			else
				echo "O parâmetro passado não corresponde a um arquivo nem a um ticket."
				exit 5
			fi

			if [[ -z $url ]]; then
				if [[ -z $ticket ]]; then
					echo "Ticket SPFBL inválido."
					exit 6
				else
					# Registra reclamação SPFBL.
					resposta=$(echo "HAM $ticket" | spfbl_query 2> /dev/null)

					if [[ $resposta == "" ]]; then
						resposta=$(emptyResponse)
						maintenanceExit "$resposta"
						echo "A revogação SPFBL não foi enviada por timeout."
						exit 4
					elif [[ $resposta == "OK"* ]]; then
						echo "Revogação SPFBL enviada com sucesso."
						exit 0
					elif [[ $resposta == "ERROR: DECRYPTION" ]]; then
						echo "Ticket SPFBL inválido."
						exit 6
					else
						echo "A revogação SPFBL não foi enviada: $resposta"
						exit 3
					fi
				fi
			else
				# Registra reclamação SPFBL via HTTP.
				spamURL=/spam/
				hamURL=/ham/
				url=${url/$spamURL/$hamURL}
				resposta=$(curl -X PUT -s -m 3 -w '\n%{http_code}' $url)
				code=${resposta##*$'\n'}
				resposta=$(printf '%s' "${resposta%$'\n'*}")
				if httpUnavailable "$code"; then
					resposta=$(emptyResponse)
					maintenanceExit "$resposta"
				else
					resetTimeout
				fi
				if httpUnavailable "$code"; then
					echo "A revogação SPFBL não foi enviada por timeout."
					exit 4
				elif [[ $resposta == "OK"* ]]; then
					echo "Revogação SPFBL enviada com sucesso."
					exit 0
				elif [[ $resposta == "ERROR: DECRYPTION" ]]; then
					echo "Ticket SPFBL inválido."
					exit 6
				else
					echo "A revogação SPFBL não foi enviada: $resposta"
					exit 3
				fi

			fi
		fi
	;;
	'query')
		# A saída deste programa deve ser incorporada ao cabeçalho
		# Received-SPFBL da mensagem de e-mail que gerou a consulta.
		#
		# Exemplo:
		#
		#    Received-SPFBL: PASS urNq9eFn65wKwDFGNsqCNYmywnlWmmilhZw5jdtvOr5jYk6mgkiWgQC1w696wT3ylP3r8qZnhOjwntTt5mCAuw==
		#
		# A informação que precede o qualificador é o ticket da consulta SPFBL.
		# Com o ticket da consulta, é possível realizar uma reclamação ao serviço SPFBL,
		# onde esta reclamação vai contabilizar a reclamação nos contadores do responsável pelo envio da mensagem.
		# O ticket da consulta só é gerado nas saídas cujos qualificadores sejam: PASS, SOFTFAIL, NEUTRAL, NONE e WHITE.
		#
		# Parâmetros de entrada:
		#
		#    1. IP: o IPv4 ou IPv6 do host de origem.
		#    2. email: o email do remetente (opcional).
		#    3. HELO: o HELO passado pelo host de origem.
		#    4. recipient: o destinátario da mensagem (opcional se não utilizar spamtrap).
		#
		# Saídas com qualificadores e as ações:
		#
		#    PASS <ticket>: permitir o recebimento da mensagem.
		#    FAIL: rejeitar o recebimento da mensagem e informar à origem o descumprimento do SPF.
		#    SOFTFAIL <ticket>: permitir o recebimento da mensagem mas marcar como suspeita.
		#    NEUTRAL <ticket>: permitir o recebimento da mensagem.
		#    NONE <ticket>: permitir o recebimento da mensagem.
		#    LISTED: atrasar o recebimento da mensagem e informar à origem a listagem em blacklist por sete dias.
		#    BLOCKED: rejeitar o recebimento da mensagem e informar à origem o bloqueio permanente.
		#    FLAG: aceita o recebimento e redirecione a mensagem para a pasta SPAM.
		#    SPAMTRAP: discaratar silenciosamente a mensagem e informar à origem que a mensagem foi recebida com sucesso.
		#    INEXISTENT: rejeitar a mensagem e informar que o destinatário não existe.
		#    GREYLIST: atrasar a mensagem informando à origem ele está em greylisting.
		#    NXDOMAIN: o domínio do remetente é inexistente.
		#    NXSENDER: a conta do remetente é inexistente.
		#    INVALID: o endereço do remetente é inválido.
		#    WHITE: aceitar imediatamente a mensagem.
		#    HOLD: congelar a entrega da mensagem.
		#    BANNED: rejeitar a mensagem e derrubar a conexão.
		#    RELEASE: liberar mensagem congelada na fila.
		#    REMOVE: remover mensagem congelada na fila.
		#
		# Códigos de saída:
		#
		#    0: não especificado.
		#    1: qualificador NEUTRAL.
		#    2: qualificador PASS.
		#    3: qualificador FAIL.
		#    4: qualificador SOFTFAIL.
		#    5: qualificador NONE.
		#    6: erro temporário.
		#    7: erro permanente.
		#    8: listado em lista negra.
		#    9: timeout de conexão.
		#    10: bloqueado permanentemente.
		#    11: spamtrap.
		#    12: greylisting.
		#    13: domínio inexistente.
		#    14: IP ou remetente inválido.
		#    15: mensagem originada de uma rede local.
		#    16: mensagem marcada como SPAM.
		#    17: remetente em lista branca.
		#    18: congelar mensagem.
		#    19: inexistente.
		#    20: out of service.
		#   26: serviço em manutenção programada (status.spfbl.net).
		#    21: remetente inexistente.
		#    22: remetente banido.
		#    23: mensagem liberada.
		#    24: mensagem removida.
		#    25: mensagem não encontrada.

		if [ $# -lt "5" ]; then
			head
			printf "Invalid Parameters. Syntax: $0 query ip email helo recipient\n"
		else
			ip=$2
			email=$3
			helo=$4
			recipient=$5
			exists=$6

			case "$ip" in
				127.0.0.1|::1|0:0:0:0:0:0:0:1|::ffff:127.0.0.1)
					# Origem localhost: responde LAN sem consultar o servidor.
					qualifier="LAN"
					;;
				*)
					qualifier=$(echo "SPF '$ip' '$email' '$helo' '$recipient' $exists" | spfbl_query 2> /dev/null)

					if [[ $qualifier == "" ]]; then
						qualifier=$(emptyResponse)
						maintenanceExit "$qualifier"
					else
						resetTimeout
					fi
					;;
			esac

			echo "$qualifier"

			if [[ $qualifier == "OUT OF SERVICE" ]]; then
				exit 20
			elif [[ $qualifier == "TIMEOUT" ]]; then
				exit 9
			elif [[ $qualifier == "NXDOMAIN" ]]; then
				exit 13
			elif [[ $qualifier == "NXSENDER" ]]; then
				exit 21
			elif [[ $qualifier == "BANNED" ]]; then
				exit 22
			elif [[ $qualifier == "GREYLIST" ]]; then
				exit 12
			elif [[ $qualifier == "INVALID" ]]; then
				exit 14
			elif [[ $qualifier == "INVALID "* ]]; then
				exit 7
			elif [[ $qualifier == "LAN" ]]; then
				exit 15
			elif [[ $qualifier == "FLAG"* ]]; then
				exit 16
			elif [[ $qualifier == "HOLD"* ]]; then
				exit 18
			elif [[ $qualifier == "SPAMTRAP" ]]; then
				exit 11
			elif [[ $qualifier == "INEXISTENT" ]]; then
				exit 19
			elif [[ $qualifier == "BLOCKED"* ]]; then
				exit 10
			elif [[ $qualifier == "LISTED"* ]]; then
				exit 8
			elif [[ $qualifier == "TOO MANY CONNECTIONS" ]]; then
				exit 6
			elif [[ $qualifier == "HOST NOT FOUND" ]]; then
				exit 6
			elif [[ $qualifier == "ERROR: "* ]]; then
				exit 7
			elif [[ $qualifier == "NONE "* ]]; then
				exit 5
			elif [[ $qualifier == "PASS "* ]]; then
				exit 2
			elif [[ $qualifier == "WHITE "* ]]; then
				exit 17
			elif [[ $qualifier == "FAIL "* ]]; then
				# Retornou FAIL com ticket então
				# significa que está em whitelist.
				# Retornar como se fosse SOFTFAIL.
				exit 4
			elif [[ $qualifier == "FAIL" ]]; then
				exit 3
			elif [[ $qualifier == "SOFTFAIL "* ]]; then
				exit 4
			elif [[ $qualifier == "NEUTRAL "* ]]; then
				exit 1
			elif [[ $qualifier =~ ^RELEASE[[:space:]](.+)$ ]]; then
				queueid="${BASH_REMATCH[1]}"
				which exim > /dev/null
			        if [ $? -eq 0 ]; then
			            exim -Mt $queueid > /dev/null
			            if [ $? -eq 0 ]; then
			                exit 23
			            fi
			        fi
				exit 25
			elif [[ $qualifier =~ ^REMOVE[[:space:]](.+)$ ]]; then
				queueid="${BASH_REMATCH[1]}"
				which exim > /dev/null	
			        if [ $? -eq 0 ]; then
			            exim -Mrm $queueid > /dev/null
			            if [ $? -eq 0 ]; then
			                exit 24
			            fi
			        fi
				exit 25
			else
				exit 0
			fi
		fi
	;;
	'trap')
		case $2 in
			'add')
				# Parâmetros de entrada:
				#
				#    1. recipient: o destinatário que deve ser considerado armadilha.
				#
				#
				# Códigos de saída:
				#
				#    0: adicionado com sucesso.
				#    1: erro ao tentar adicionar armadilha.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 trap add recipient\n"
				else
					recipient=$3

					response=$(echo "TRAP ADD $recipient" | spfbl_query 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "ADDED" ]]; then
						exit 0
					else
						exit 1
					fi
				fi
			;;
			'drop')
				# Parâmetros de entrada:
				#
				#    1. recipient: o destinatário que deve ser considerado armadilha.
				#
				#
				# Códigos de saída:
				#
				#    0: desbloqueado com sucesso.
				#    1: erro ao tentar adicionar armadilha.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 trap drop recipient\n"
				else
					recipient=$3

					response=$(echo "TRAP DROP $recipient" | spfbl_query 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "DROPPED" ]]; then
						exit 0
					else
						exit 1
					fi
				fi
			;;
			'show')
				# Parâmetros de entrada: nenhum.
				#
				# Códigos de saída:
				#
				#    0: visualizado com sucesso.
				#    1: erro ao tentar visualizar armadilhas.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "2" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 trap show\n"
				else
					response=$(echo "TRAP SHOW" | spfbl_query 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					else
						exit 0
					fi
				fi
			;;
			*)
				head
				printf "Syntax:\n    $0 trap add recipient\n    $0 trap drop recipient\n    $0 trap show\n"
			;;
		esac
	;;
	'inexistent')
		case $2 in
			'add')
				# Parâmetros de entrada:
				#
				#    1. recipient: o destinatário que deve ser considerado inexistente.
				#
				#
				# Códigos de saída:
				#
				#    0: adicionado com sucesso.
				#    1: erro ao tentar adicionar destinatário inexistente.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 inexistent add recipient\n"
				else
					recipient=$3

					response=$(echo "INEXISTENT ADD $recipient" | spfbl_query 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "ADDED" ]]; then
						exit 0
					else
						exit 1
					fi
				fi
			;;
			'drop')
				# Parâmetros de entrada:
				#
				#    1. recipient: o destinatário que não deve ser considerado inexistente.
				#
				#
				# Códigos de saída:
				#
				#    0: removido com sucesso.
				#    1: erro ao tentar remover endereço.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 inexistent drop recipient\n"
				else
					recipient=$3

					response=$(echo "INEXISTENT DROP $recipient" | spfbl_query 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "DROPPED" ]]; then
						exit 0
					else
						exit 1
					fi
				fi
			;;
			'show')
				# Parâmetros de entrada: nenhum.
				#
				# Códigos de saída:
				#
				#    0: visualizado com sucesso.
				#    1: erro ao tentar visualizar inexistentes.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "2" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 inexistent show\n"
				else
					response=$(echo "INEXISTENT SHOW" | spfbl_query 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					else
						exit 0
					fi
				fi
			;;
			'is')
				# Parâmetros de entrada: nenhum.
				#
				# Códigos de saída:
				#
				#    0: não é inexistente.
				#    1: é inexistente.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 inexistent is <recipient>\n"
				else
					recipient=$3
					response=$(echo "INEXISTENT IS $recipient" | spfbl_query 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "TRUE" ]]; then
						exit 1
					else
						exit 0
					fi
				fi
			;;
			*)
				head
				printf "Syntax:\n    $0 inexistent add recipient\n    $0 inexistent drop recipient\n    $0 inexistent show\n"
			;;
		esac
	;;
	'superinexistent')
		case $2 in
			'add')
				# Parâmetros de entrada:
				#
				#    1. recipient: o destinatário que deve ser considerado inexistente.
				#
				#
				# Códigos de saída:
				#
				#    0: adicionado com sucesso.
				#    1: erro ao tentar adicionar destinatário inexistente.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 inexistent add recipient\n"
				else
					recipient=$3

					response=$(echo "INEXISTENT ADD $recipient" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "ADDED" ]]; then
						exit 0
					else
						exit 1
					fi
				fi
			;;
			'drop')
				# Parâmetros de entrada:
				#
				#    1. recipient: o destinatário que não deve ser considerado inexistente.
				#
				#
				# Códigos de saída:
				#
				#    0: removido com sucesso.
				#    1: erro ao tentar remover endereço.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 inexistent drop recipient\n"
				else
					recipient=$3

					response=$(echo "INEXISTENT DROP $recipient" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "DROPPED" ]]; then
						exit 0
					else
						exit 1
					fi
				fi
			;;
			'show')
				# Parâmetros de entrada: nenhum.
				#
				# Códigos de saída:
				#
				#    0: visualizado com sucesso.
				#    1: erro ao tentar visualizar inexistentes.
				#    2: timeout de conexão.
				#    3: out of service.
				#   26: serviço em manutenção programada (status.spfbl.net).

				if [ $# -lt "2" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 inexistent show\n"
				else
					response=$(echo "INEXISTENT SHOW" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					else
						exit 0
					fi
				fi
			;;
			*)
				head
				printf "Syntax:\n    $0 inexistent add recipient\n    $0 inexistent drop recipient\n    $0 inexistent show\n"
			;;
		esac
	;;
	'suppression'|'supression')
		# Códigos de saída de todos os subcomandos:
		#
		#    0: sucesso.
		#    1: já existe, não encontrado, vazio ou parâmetro inválido.
		#    2: timeout de conexão.
		#    3: out of service.
		#   26: serviço em manutenção programada (status.spfbl.net).
		case $2 in
			'inexistent'|'rejected'|'unsubscribed'|'complaint'|'malware'|'abuse'|'quota'|'hold'|'spammer'|'noncompliant'|\
			'INEXISTENT'|'REJECTED'|'UNSUBSCRIBED'|'COMPLAINT'|'MALWARE'|'ABUSE'|'QUOTA'|'HOLD'|'SPAMMER'|'NONCOMPLIANT')
				# suppression <TIPO> <chave>: adiciona com origem ADMIN.
				if [ $# -ne "3" ]; then
					head
					suppression_manual
					exit 1
				else
					type=$(echo "$2" | tr '[:lower:]' '[:upper:]')
					key=$3

					response=$(echo "SUPPRESSION ADD $type $key" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "ADDED" ]]; then
						exit 0
					else
						exit 1
					fi
				fi
			;;
			'drop')
				# suppression drop <chave> [TIPO]
				if [ $# -lt "3" ] || [ $# -gt "4" ]; then
					head
					suppression_manual
					exit 1
				else
					key=$3
					type=$(echo "$4" | tr '[:lower:]' '[:upper:]')

					response=$(echo "SUPPRESSION DROP $key $type" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "DROPPED" ]]; then
						exit 0
					else
						exit 1
					fi
				fi
			;;
			'show')
				# suppression show <chave>
				if [ $# -ne "3" ]; then
					head
					suppression_manual
					exit 1
				else
					key=$3

					response=$(echo "SUPPRESSION SHOW $key" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response != "EMPTY" ]] && [[ $response != "INVALID COMMAND" ]]; then
						exit 0
					else
						exit 1
					fi
				fi
			;;
			'list')
				# suppression list <TIPO>
				if [ $# -ne "3" ]; then
					head
					suppression_manual
					exit 1
				else
					type=$(echo "$3" | tr '[:lower:]' '[:upper:]')

					response=$(echo "SUPPRESSION LIST $type" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						response=$(emptyResponse)
						maintenanceExit "$response"
					else
						resetTimeout
					fi

					echo "$response"

					if [[ $response == "OUT OF SERVICE" ]]; then
						exit 3
					elif [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response != "EMPTY" ]] && [[ $response != "INVALID COMMAND" ]]; then
						exit 0
					else
						exit 1
					fi
				fi
			;;
			*)
				head
				suppression_manual
			;;
		esac
	;;
	'listing')
		# Listagens DNS dos usuários pela porta administrativa. Códigos de saída:
		#
		#    0: sucesso.
		#    1: não encontrado, vazio ou parâmetro inválido.
		#    2: timeout de conexão.
		#    3: out of service.
		#   26: serviço em manutenção programada (status.spfbl.net).
		case $2 in
			'show')
				if [ $# -ne "3" ]; then
					head
					listing_manual
					exit 1
				fi
				command="LISTING SHOW $3"
				success='^(DNSWL|DNSAL) '
			;;
			'list')
				if [ $# -ne "3" ] || { [ "$3" != "dnswl" ] && [ "$3" != "dnsal" ]; }; then
					head
					listing_manual
					exit 1
				fi
				command="LISTING LIST $(echo "$3" | tr '[:lower:]' '[:upper:]')"
				success='^(DNSWL|DNSAL) '
			;;
			'drop')
				if [ $# -ne "5" ] || { [ "$3" != "dnswl" ] && [ "$3" != "dnsal" ]; }; then
					head
					listing_manual
					exit 1
				fi
				command="LISTING DROP $(echo "$3" | tr '[:lower:]' '[:upper:]') $4 $5"
				success='^DROPPED'
			;;
			*)
				head
				listing_manual
				exit 1
			;;
		esac

		response=$(echo "$command" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

		if [[ $response == "" ]]; then
			response=$(emptyResponse)
			maintenanceExit "$response"
		else
			resetTimeout
		fi

		echo "$response"

		if [[ $response == "OUT OF SERVICE" ]]; then
			exit 3
		elif [[ $response == "TIMEOUT" ]]; then
			exit 2
		elif [[ $response =~ $success ]]; then
			exit 0
		else
			exit 1
		fi
	;;
	'billing')
		# Faturamento pela porta administrativa. Códigos de saída:
		#
		#    0: sucesso.
		#    1: não encontrado, já existe, vazio ou parâmetro inválido.
		#    2: timeout de conexão.
		#    3: out of service.
		#   26: serviço em manutenção programada (status.spfbl.net).
		case $2 in
			'create'|'show'|'close'|'drop')
				if [ $# -ne "3" ]; then
					head
					billing_manual
					exit 1
				fi
				command="BILLING $(echo "$2" | tr '[:lower:]' '[:upper:]') $3"
				success='^(CREATED|CLOSED|DROPPED|[^ ]+@[^ ]+ created=)'
			;;
			'pix')
				if [ $# -ne "3" ]; then
					head
					billing_manual
					exit 1
				fi
				command="BILLING PIX $3"
				success='^(ENABLED|ALREADY ENABLED)'
			;;
			'credit')
				if [ $# -ne "5" ] || { [ "$3" != "add" ] && [ "$3" != "drop" ]; }; then
					head
					billing_manual
					exit 1
				fi
				command="BILLING CREDIT $(echo "$3" | tr '[:lower:]' '[:upper:]') $4 $5"
				success='^CREDIT USD'
			;;
			'element')
				if [ $# -ne "6" ] || { [ "$3" != "add" ] && [ "$3" != "drop" ]; }; then
					head
					billing_manual
					exit 1
				fi
				command="BILLING ELEMENT $(echo "$3" | tr '[:lower:]' '[:upper:]') $4 $5 $6"
				success='^(ADDED|DROPPED)'
			;;
			'invoice')
				# Correção de fatura não paga: preço de um item ou edição.
				case $3 in
					'price')
						if [ $# -ne "6" ]; then
							head
							billing_manual
							exit 1
						fi
						command="BILLING INVOICE PRICE $4 $5 $6"
						success='^PRICE'
					;;
					'edit'|'done')
						if [ $# -ne "4" ]; then
							head
							billing_manual
							exit 1
						fi
						command="BILLING INVOICE $(echo "$3" | tr '[:lower:]' '[:upper:]') $4"
						success='^(EDIT|DONE)'
					;;
					*)
						head
						billing_manual
						exit 1
					;;
				esac
			;;
			'paid')
				if [ $# -ne "5" ]; then
					head
					billing_manual
					exit 1
				fi
				command="BILLING PAID $3 $4 $5"
				success='^PAID'
			;;
			'list')
				if [ $# -ne "2" ]; then
					head
					billing_manual
					exit 1
				fi
				command="BILLING LIST"
				success='^[^ ]+@'
			;;
			'price')
				case $3 in
					'set')
						if [ $# -ne "5" ]; then
							head
							billing_manual
							exit 1
						fi
						command="BILLING PRICE SET $4 $5"
						success='^(SET|DROPPED)'
					;;
					'drop')
						if [ $# -ne "4" ]; then
							head
							billing_manual
							exit 1
						fi
						command="BILLING PRICE DROP $4"
						success='^DROPPED'
					;;
					'show')
						if [ $# -ne "3" ]; then
							head
							billing_manual
							exit 1
						fi
						command="BILLING PRICE SHOW"
						success='^spfbl_'
					;;
					'apply')
						if [ $# -ne "3" ] && [ $# -ne "4" ]; then
							head
							billing_manual
							exit 1
						fi
						command="BILLING PRICE APPLY $4"
						success='^APPLIED'
					;;
					*)
						head
						billing_manual
						exit 1
					;;
				esac
			;;
			*)
				head
				billing_manual
				exit 1
			;;
		esac

		response=$(echo "$command" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

		if [[ $response == "" ]]; then
			response=$(emptyResponse)
			maintenanceExit "$response"
		else
			resetTimeout
		fi

		echo "$response"

		if [[ $response == "OUT OF SERVICE" ]]; then
			exit 3
		elif [[ $response == "TIMEOUT" ]]; then
			exit 2
		elif [[ $response =~ $success ]]; then
			exit 0
		else
			exit 1
		fi
	;;
	'noreply')
		# Comando abolido: substituído por "suppression".
		head
		suppression_manual
		exit 1
	;;
	'dump')
		# Parâmetros de entrada: nenhum.
		#
		# Códigos de saída: nenhum.

		echo "DUMP" | $NCAT $IP_ADMIN $PORTA_ADMIN > $DUMP_PATH/spfbl.dump.$(date "+%Y-%m-%d_%H-%M")
		if [ -f $DUMP_PATH/spfbl.dump.$(date "+%Y-%m-%d_%H-%M") ]; then
			echo "Dump saved as $DUMP_PATH/spfbl.dump.$(date "+%Y-%m-%d_%H-%M")"
		else
			echo "File $DUMP_PATH/spfbl.dump.$(date "+%Y-%m-%d_%H-%M") not found."
		fi
	;;
	'load')
		# Parâmetros de entrada: nenhum.
		#
		# Códigos de saída: nenhum.

		if [ $# -lt "2" ]; then
			head
			printf "Invalid Parameters. Syntax: $0 load path\n"
		else
			file=$2
			if [ -f $file ]; then
				while read line; do
					echo -n "Adding $line ... "
					echo "$line" | $NCAT $IP_ADMIN $PORTA_ADMIN
				done < $file
			else
				echo "File not found."
			fi
		fi
	;;
	'backup')
		# Parâmetros de entrada: dias p/ reter o backup.
		#
		# Códigos de saída: nenhum.

		fazBackup(){

			PASTABKP=/opt/spfbl/backup
			NOW=$(date +"%d-%m-%Y-%H-%S")
			if [ ! -d $PASTABKP ]; then
				mkdir $PASTABKP
			fi

			echo "STORE" | $NCAT 127.0.0.1 9875
			echo "DUMP" | $NCAT 127.0.0.1 9875 > "$PASTABKP"/dump-"$NOW".txt
			tar -zcf "$PASTABKP"/spfbl-folder-"$NOW".tar /opt/spfbl --exclude "$PASTABKP" &> /dev/null
			find $PASTABKP -mtime +"$DAYSTORETAIN" -exec rm {} \;
		}

		if [ $# -lt "2" ]; then
			DAYSTORETAIN=60
			fazBackup
		else
			DAYSTORETAIN=$2
			fazBackup
		fi
	;;
	'stats')
	#
	# gera estatistica diaria
	# saida em linha de comando
	#
	# Formato: spfbl.sh stats AAAA-MM-DD
	# Exemplo: spfbl.sh stats 2017-01-31
	#
	# apenas "spfbl.sh stats" mostra o resultado do dia
	#

	if [[ $2 =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
		TODAY=$2
	else
		TODAY=`date +%Y-%m-%d`
	fi

	LOGFILE=/var/log/spfbl/spfbl."$TODAY".log
	LOGTEMP=/tmp/spfblstats
	LOGTEMPDNS=/tmp/spfblstatsdns

	verificaLogFile(){
		if [[ ! -f "$LOGFILE" ]]; then
			echo "";
			echo -e "\e[41m The file $LOGFILE was not found in your system! \e[0m";
			echo "";
			exit 1
		fi
	}

	verificaLogTemp(){
		if [[ -f "$LOGTEMP" ]]; then
			rm "$LOGTEMP"
		fi
	}

	verificaLogTempDns(){
		if [[ -f "$LOGTEMPDNS" ]]; then
			rm "$LOGTEMPDNS"
		fi
	}

	criaLogTemp(){
		egrep " SPFTCP[0-9]+ SPFBL " $LOGFILE > $LOGTEMP
		egrep " DNSUDP[0-9]+ DNSBL " $LOGFILE > $LOGTEMPDNS
	}

	executaStats(){
		#Calcula a quantidade de mensagens por resposta - Ações permanentes
		BLOCKED=$(grep -c BLOCKED "$LOGTEMP")
		FAIL=$(grep -c ' FAIL' "$LOGTEMP")
		FLAG=$(grep -c FLAG "$LOGTEMP")
		HOLD=$(grep -c HOLD "$LOGTEMP")
		INTERRUPTED=$(grep -c INTERRUPTED "$LOGTEMP")
		INVALID=$(grep -c INVALID "$LOGTEMP")
		NEUTRAL=$(grep -c NEUTRAL "$LOGTEMP")
		NONE=$(grep -c NONE "$LOGTEMP")
		NXDOMAIN=$(grep -c NXDOMAIN "$LOGTEMP")
		NXSENDER=$(grep -c NXSENDER "$LOGTEMP")
		PASS=$(grep -c PASS "$LOGTEMP")
		WHITE=$(grep -c WHITE "$LOGTEMP")
		SOFTFAIL=$(grep -c SOFTFAIL "$LOGTEMP")
		SPAMTRAP=$(grep -c SPAMTRAP "$LOGTEMP")
		INEXISTENT=$(grep -c INEXISTENT "$LOGTEMP")
		TIMEOUT=$(grep -c TIMEOUT "$LOGTEMP")
		
		#Calcula os totais da sessão permanente
		TOTALES=$(echo $WHITE + $BLOCKED + $FLAG + $HOLD + $NXDOMAIN + $NXSENDER + $PASS + $TIMEOUT + $NONE + $SOFTFAIL + $NEUTRAL + $INTERRUPTED + $SPAMTRAP + $INEXISTENT + $INVALID + $FAIL | bc)
		BLOCKTOTAL=$( echo $BLOCKED + $HOLD + $NXDOMAIN + $NXSENDER + $TIMEOUT + $NONE + $SOFTFAIL + $NEUTRAL + $INTERRUPTED + $SPAMTRAP + $INEXISTENT + $INVALID + $FAIL | bc)
		PASSTOTAL=$( echo $WHITE + $PASS | bc)

		clear

		echo '=========================='
		echo '= SPFBL Daily Statistics ='
		echo '=      '"$TODAY"'        ='
		echo '=========================='
		echo '=    Permanent actions   ='
		echo '=========================='

		if [[ $WHITE != 0 ]]; then
			echo '     WHITE:' $(echo "scale=0;($WHITE*100) / $TOTALES" | bc)'% - '"$WHITE"
		fi

		if [[ $PASS != 0 ]]; then
			echo '      PASS:' $(echo "scale=0;($PASS*100) / $TOTALES" | bc)'% - '"$PASS"
		fi

		if [[ $BLOCKED != 0 ]]; then
			echo '   BLOCKED:' $(echo "scale=0;($BLOCKED*100) / $TOTALES" | bc)'% - '"$BLOCKED"
		fi

		if [[ $FAIL != 0 ]]; then
			echo '      FAIL:' $(echo "scale=0;($FAIL*100) / $TOTALES" | bc)'% - '"$FAIL"
		fi

		if [[ $FLAG != 0 ]]; then
			echo '      FLAG:' $(echo "scale=0;($FLAG*100) / $TOTALES" | bc)'% - '"$FLAG"
		fi

		if [[ $HOLD != 0 ]]; then
			echo '      HOLD:' $(echo "scale=0;($HOLD*100) / $TOTALES" | bc)'% - '"$HOLD"
		fi

		if [[ $INTERRUPTED != 0 ]]; then
			echo '  INTRRPTD:' $(echo "scale=0;($INTERRUPTED*100) / $TOTALES" | bc)'% - '"$INTERRUPTED"
		fi

		if [[ $INVALID != 0 ]]; then
			echo '   INVALID:' $(echo "scale=0;($INVALID*100) / $TOTALES" | bc)'% - '"$INVALID"
		fi

		if [[ $NEUTRAL != 0 ]]; then
			echo '   NEUTRAL:' $(echo "scale=0;($NEUTRAL*100) / $TOTALES" | bc)'% - '"$NEUTRAL"
		fi

		if [[ $NONE != 0 ]]; then
			echo '      NONE:' $(echo "scale=0;($NONE*100) / $TOTALES" | bc)'% - '"$NONE"
		fi

		if [[ $NXDOMAIN != 0 ]]; then
			echo '  NXDOMAIN:' $(echo "scale=0;($NXDOMAIN*100) / $TOTALES" | bc)'% - '"$NXDOMAIN"
		fi

		if [[ $NXSENDER != 0 ]]; then
			echo '  NXSENDER:' $(echo "scale=0;($NXSENDER*100) / $TOTALES" | bc)'% - '"$NXSENDER"
		fi

		if [[ $SOFTFAIL != 0 ]]; then
			echo '  SOFTFAIL:' $(echo "scale=0;($SOFTFAIL*100) / $TOTALES" | bc)'% - '"$SOFTFAIL"
		fi

		if [[ $SPAMTRAP != 0 ]]; then
			echo '  SPAMTRAP:' $(echo "scale=0;($SPAMTRAP*100) / $TOTALES" | bc)'% - '"$SPAMTRAP"
		fi

		if [[ $INEXISTENT != 0 ]]; then
			echo 'INEXISTENT:' $(echo "scale=0;($INEXISTENT*100) / $TOTALES" | bc)'% - '"$INEXISTENT"
		fi

		if [[ $TIMEOUT != 0 ]]; then
			echo '   TIMEOUT:' $(echo "scale=0;($TIMEOUT*100) / $TOTALES" | bc)'% - '"$TIMEOUT"
		fi

		echo ' -----------------------'
		echo ' ALL BLOCKED :' $(echo "scale=0;($BLOCKTOTAL*100) / $TOTALES" | bc)'% - '"$BLOCKTOTAL"
		echo ' ALL ACCEPTED:' $(echo "scale=0;($PASSTOTAL*100) / $TOTALES" | bc)'% - '"$PASSTOTAL"
		echo '   SUSPICIOUS: ' $(echo "scale=0;($FLAG*100) / $TOTALES" | bc)'% - '"$FLAG"
		echo '    TOTAL   :' $(echo "scale=0;($TOTALES*100) / $TOTALES" | bc)'% - '"$TOTALES"
		echo '=========================='
	}

	executaStatsTemp(){
		#Calcula a quantidade e total de mensagens para resultados de checagem com ações temporarias
		GREYLIST=$(grep -c GREYLIST "$LOGTEMP")		
		LISTED=$(grep -c LISTED "$LOGTEMP")
		TOTALEST=$(echo $LISTED + $GREYLIST | bc)

		if [[ $TOTALEST != 0 ]]; then
			echo ''
			echo '=========================='
			echo '=   Temporary actions    ='
			echo '=========================='
			echo '  GREYLIST: ' $(echo "scale=0;($GREYLIST*100) / $TOTALEST" | bc)'% - '"$GREYLIST"
			echo '    LISTED: ' $(echo "scale=0;($LISTED*100) / $TOTALEST" | bc)'% - '"$LISTED"
			echo '  ----------------------'
			echo '     TOTAL: ' $(echo "scale=0;($TOTALEST*100) / $TOTALEST" | bc)'% - '"$TOTALEST"
			echo '=========================='
		fi
	}

	executaStatsDNSBL(){
		#Calcula a quantidade de consultas DNSBL por tipo de resposta
		#127.0.0.2 - Rejeitada por má reputação
		#127.0.0.3 - Rejeitada por suspeita/problemas na identificação
		#NXDOMAIN - Aceita por não estar listada
		DNSBLBLOCK=$(egrep -c "A .* => [0-9]+ 127.0.0.2" "$LOGFILE")
		DNSBLSPAM=$(egrep -c "A .* => [0-9]+ 127.0.0.3" "$LOGFILE")
		DNSBLOK=$(egrep -c "A .* => [0-9]+ NXDOMAIN" "$LOGFILE")
		TOTALESDNSBL=$(echo $DNSBLBLOCK + $DNSBLSPAM + $DNSBLOK | bc)

		if [[ $TOTALESDNSBL != 0 ]]; then
			echo ''
			echo '=========================='
			echo ' Permanent: ' $(echo "scale=0; ($TOTALES*100) / ($TOTALES + $TOTALEST)" | bc)'% - '"$TOTALES"
			echo ' Temporary: ' $(echo "scale=0; ($TOTALEST*100) / ($TOTALES + $TOTALEST)" | bc)'% - '"$TOTALEST"
			echo '   TOTAL  : ' $(echo "scale=0;(($TOTALEST + $TOTALES)*100) / ($TOTALEST + $TOTALES)" | bc)'% - ' $( echo "$TOTALEST + $TOTALES" | bc)
			echo '=========================='
			echo ''
			echo '=========================='
			echo '=      DNSBL BLOCKs      ='
			echo '=========================='
			echo '        OK: ' $(echo "scale=0; ($DNSBLOK*100) / $TOTALESDNSBL" | bc)'% - '"$DNSBLOK"
			echo 'SUSPICIOUS: ' $(echo "scale=0; ($DNSBLSPAM*100) / $TOTALESDNSBL" | bc)'% - '"$DNSBLSPAM"
			echo '     BLOCK: ' $(echo "scale=0; ($DNSBLBLOCK*100) / $TOTALESDNSBL" | bc)'% - '"$DNSBLBLOCK"
			echo '     TOTAL: ' $(echo "scale=0;($TOTALESDNSBL*100) / $TOTALESDNSBL" | bc)'% - '"$TOTALESDNSBL"
			echo '=========================='
		fi
	}

	# Executa processos

	verificaLogFile
	verificaLogTemp      # apaga temporarios
	verificaLogTempDns   # apaga temporarios
	criaLogTemp
	executaStats
	executaStatsTemp
	executaStatsDNSBL
	verificaLogTemp      # apaga temporarios
	verificaLogTempDns   # apaga temporarios
	exit 0

	# Fim processos

	;;
	'thread'|'memory'|'service'|'log'|'owner'|'locale'|'icann'|'private'|'dnsbl'|'uribl'|'dnswl'|'score'|'dnsal'|'since'|'fqdn'|'gateway'|'recipient'|'guess'|'dictionary'|'certificate'|'stack'|'reload'|'queue'|'split'|'suspect'|'licence'|'invitation'|'transport')
		# Comandos administrativos repassados à porta administrativa:
		# spfbl <familia> <subcomando> [argumentos...] envia
		# FAMILIA SUBCOMANDO argumentos... Só a família e as palavras-chave
		# conhecidas vão em maiúsculas; os valores seguem como digitados.
		#
		# Códigos de saída:
		#
		#    0: sucesso.
		#    1: parâmetro inválido, não encontrado ou erro.
		#    2: timeout de conexão.
		#    3: out of service.
		#   26: serviço em manutenção programada (status.spfbl.net).
		family=$1
		FAMILY=$(echo "$family" | tr '[:lower:]' '[:upper:]')
		shift
		args=("$@")
		case $family in
			'certificate'|'stack'|'reload'|'queue')
				# Sem argumentos.
				if [ ${#args[@]} -ne 0 ]; then
					head
					admin_manual "$family"
					exit 1
				fi
			;;
			'split'|'suspect'|'licence'|'invitation'|'transport')
				# O primeiro argumento é um valor, não um subcomando.
				case $family in
					'split'|'suspect') minimum=1 ;;
					'licence') minimum=2 ;;
					'invitation') minimum=1 ;;
					'transport') minimum=2 ;;
				esac
				if [ ${#args[@]} -lt $minimum ]; then
					head
					admin_manual "$family"
					exit 1
				fi
				if [[ $family == "transport" ]]; then
					# TRANSPORT <usuario> <ACAO> ...; no ADD, o protocolo é o 4º.
					args[1]=$(upperKeyword "${args[1]}" ADD SET PUT DROP SHOW)
					if [[ ${args[1]} == "ADD" && ${#args[@]} -ge 4 ]]; then
						args[3]=$(upperKeyword "${args[3]}" SMTP)
					fi
				fi
			;;
			*)
				# O primeiro argumento é o subcomando.
				case $family in
					'thread'|'memory') subcommands="SHOW" ;;
					'service') subcommands="START" ;;
					'log') subcommands="LEVEL DNS P2P" ;;
					'owner') subcommands="GET SET" ;;
					'locale') subcommands="SET GET" ;;
					'icann'|'private') subcommands="ADD DROP SHOW" ;;
					'dnsbl'|'uribl'|'dnswl'|'score'|'dnsal'|'since') subcommands="ADD SET DROP SHOW" ;;
					'fqdn') subcommands="ADD WHITE DROP SHOW" ;;
					'gateway') subcommands="KEY SHOW ADD SET DROP IMPORT" ;;
					'recipient') subcommands="ADD SET DROP SHOW" ;;
					'guess') subcommands="ADD DROP SHOW" ;;
					'dictionary') subcommands="ADD PUT COMPILE FLAG DROP REP SHOW" ;;
				esac
				if [ ${#args[@]} -eq 0 ]; then
					head
					admin_manual "$family"
					exit 1
				fi
				if ! args[0]=$(upperKeyword "${args[0]}" $subcommands); then
					head
					admin_manual "$family"
					exit 1
				fi
				# Palavras-chave na segunda posição, conforme o subcomando.
				keywords=""
				case "$FAMILY ${args[0]}" in
					'LOG LEVEL') keywords="ERROR WARN INFO DEBUG TRACE" ;;
					'LOG DNS'|'LOG P2P') keywords="TRUE FALSE" ;;
					'DNSBL DROP'|'URIBL DROP'|'DNSWL DROP'|'SCORE DROP'|'DNSAL DROP'|'SINCE DROP'|'GUESS DROP') keywords="ALL" ;;
					'GATEWAY KEY') keywords="ADD SHOW DROP" ;;
					'DICTIONARY DROP') keywords="KEY WORD REGEX FLAG REP" ;;
					'DICTIONARY SHOW') keywords="SET MAP REGEX FLAG" ;;
					'RECIPIENT SHOW') keywords="ATTACK CATCHALL NODE" ;;
					'RECIPIENT DROP') keywords="USER" ;;
				esac
				if [[ -n $keywords && ${#args[@]} -ge 2 ]]; then
					args[1]=$(upperKeyword "${args[1]}" $keywords)
				fi
			;;
		esac

		command="$FAMILY"
		if [ ${#args[@]} -gt 0 ]; then
			command="$FAMILY ${args[*]}"
		fi

		response=$(echo "$command" | $NCAT $IP_ADMIN $PORTA_ADMIN 2> /dev/null)

		if [[ $response == "" ]]; then
			response=$(emptyResponse)
			maintenanceExit "$response"
		else
			resetTimeout
		fi

		echo "$response"

		if [[ $response == "OUT OF SERVICE" ]]; then
			exit 3
		elif [[ $response == "TIMEOUT" ]]; then
			exit 2
		elif [[ $response =~ ^(INVALID|NOT\ FOUND|ERROR|NULL|NOT\ CHANGED|[A-Z]+\ NOT\ (FOUND|RESOLVED)|COULD\ NOT|KEY\ LIMIT) ]]; then
			exit 1
		else
			exit 0
		fi
	;;
	*)
		head
		printf "Help\n\n"
		printf "User Commands:\n"
		printf "    $0 version\n"
		printf "    $0 diagnose                   connection of this server to SPFBL (changes nothing)\n"
		printf "    $0 monitor                    hourly check: e-mail to the local postmaster when SPFBL is unreachable\n"
		printf "    $0 start|stop|restart|shutdown\n"
		printf "    $0 block { add sender | drop sender | show [all] | find }\n"
		printf "    $0 white { add sender | drop sender | show | sender }\n"
		printf "    $0 reputation\n"
		printf "    $0 clear hostname\n"
		printf "    $0 refresh hostname\n"
		printf "    $0 check ip email helo\n"
		printf "    $0 supercheck ip email helo [recipient]   (administration port)\n"
		printf "    $0 spam ticketid/file\n"
		printf "    $0 ham ticketid/file\n"
		printf "    $0 query ip email helo recipient\n"
		printf "    $0 trap { add recipient | drop recipient | show }\n"
		printf "    $0 suppression { TYPE key | drop key [TYPE] | show key | list TYPE }\n"
		printf "    $0 listing { show user | list TYPE | drop TYPE user VALUE }\n"
		printf "    $0 billing { create user | show user | close user | drop user | list | paid INVOICE CUR VALUE | pix user | credit { add | drop } user USD | element { add | drop } INVOICE ITEM ELEMENT | invoice { price INVOICE ITEM VALUE | edit INVOICE | done INVOICE } | price { set ITEM VALUE | drop ITEM | show | apply [ITEM] } }\n"
		printf "    $0 abuse In-Reply-To:<messageID> From:<from>\n"
		printf "\n"
		printf "Admin Commands:\n"
		printf "    $0 shutdown\n"
		printf "    $0 store\n"
		printf "    $0 stats\n"
		printf "    $0 stats AAAA-MM-DD\n"
		printf "    $0 clear hostname\n"
		printf "    $0 tld { add tld | drop tld | show }\n"
		printf "    $0 peer { add host [email] | drop { host | all } | show [host] | set host send receive | ping host | send host }\n"
		printf "    $0 provider { add sender | drop sender | show }\n"
		printf "    $0 ignore { add sender | drop sender | show }\n"
		printf "    $0 client { add/set cidr domain option [email] | drop cidr | show }\n"
		printf "    $0 user { add email nome | drop email | copy origem destino | move origem destino | send-totp email | show }\n"
		printf "    $0 superblock { add sender | drop sender | show [all] | split | overlap }\n"
		printf "    $0 superwhite { add sender | drop sender | show [all] }\n"
		printf "    $0 analise <ip> or { show | dump | drop }\n"
		printf "    $0 dynamic { add host | find token | drop host | show }\n"
		printf "    $0 dump\n"
		printf "    $0 load path\n"
		printf "    $0 backup days [days to retain backup, default 60]\n"
		printf "    $0 { thread | memory | service | log | owner | locale | icann | private | dnsbl | uribl | dnswl | score | dnsal | since | fqdn | gateway | recipient | guess | dictionary } subcommand [args...]\n"
		printf "    $0 { certificate | stack | reload | queue }\n"
		printf "    $0 { split cidr | suspect token | licence email mx | invitation recipient | transport user action ... }\n"
		printf "    $0 <family>                   help of the family\n"
		printf "\n"
	;;
esac
