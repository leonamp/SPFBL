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
#   sudo apt-get install nmap
#

### CONFIGURACOES ###
IP_SERVIDOR="matrix.spfbl.net"
PORTA_SERVIDOR="9877"
PORTA_ADMIN="9875"
SECURED="false"
DUMP_PATH="/tmp"
QUERY_TIMEOUT="10"
MAX_TIMEOUT="256"
LOGPATH=/var/log/spfbl/

export PATH=/sbin:/usr/sbin:/bin:/usr/bin:/usr/local/sbin:/usr/local/bin
version="2.14"

if [ ! -f "/tmp/SPFBL_TIMEOUT_COUNT" ]; then
    touch /tmp/SPFBL_TIMEOUT_COUNT
    chmod 777 /tmp/SPFBL_TIMEOUT_COUNT
fi

function head(){

	echo "SPFBL v$version - by Leandro Rodrigues - leandro@spfbl.net"
}

function incrementTimeout() {

	if [ ! -f "/tmp/SPFBL_TIMEOUT_COUNT" ] ; then
		local COUNT=0
	else
		local COUNT=`cat /tmp/SPFBL_TIMEOUT_COUNT`
	fi
	local COUNT=`expr ${COUNT} + 1`
	echo "${COUNT}" > /tmp/SPFBL_TIMEOUT_COUNT

	return ${COUNT}

}

function resetTimeout() {

	echo "0" > /tmp/SPFBL_TIMEOUT_COUNT

}

if [[ $SECURED == "true" ]]; then
	NCAT="ncat -w $QUERY_TIMEOUT --ssl-verify"
else
	NCAT="ncat -w $QUERY_TIMEOUT"
fi

case $1 in
	'start')
		echo "Iniciando serviço do SPFBL"
        	cd /opt/spfbl/
        	/usr/bin/java -jar /opt/spfbl/SPFBL.jar &
		echo "OK"
	;;
	'stop')
		echo "Parando o serviço do SPFBL"
		echo "STORE" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null
		echo "SHUTDOWN" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null
		echo "OK"
	;;
	'restart')
		echo "Reiniciando serviço do SPFBL"
		cd /opt/spfbl/
		echo "STORE" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null
		echo "SHUTDOWN" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null
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


		response=$(echo "VERSION" | $NCAT $IP_SERVIDOR $PORTA_SERVIDOR 2> /dev/null)

		if [[ $response == "" ]]; then
			$(incrementTimeout)
			if [ "$?" -le "$MAX_TIMEOUT" ]; then
				response="TIMEOUT"
			else
				response="OUT OF SERVICE"
			fi
		else
			$(resetTimeout)
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
	'firewall')
		# Constroi um firewall pelo SPPFBL.
		#
		# Códigos de saída:
		#
		#    0: firwall adquirido com sucesso.
		#    1: erro ao tentar adiquirir firewall.
		#    2: timeout de conexão.
		#    3: out of service.


		response=$(echo "FIREWALL" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)

		if [[ $response == "" ]]; then
			$(incrementTimeout)
			if [ "$?" -le "$MAX_TIMEOUT" ]; then
				response="TIMEOUT"
			else
				response="OUT OF SERVICE"
			fi
		else
			$(resetTimeout)
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


		response=$(echo "SHUTDOWN" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)

		if [[ $response == "" ]]; then
			$(incrementTimeout)
			if [ "$?" -le "$MAX_TIMEOUT" ]; then
				response="TIMEOUT"
			else
				response="OUT OF SERVICE"
			fi
		else
			$(resetTimeout)
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


		response=$(echo "STORE" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)

		if [[ $response == "" ]]; then
			$(incrementTimeout)
			if [ "$?" -le "$MAX_TIMEOUT" ]; then
				response="TIMEOUT"
			else
				response="OUT OF SERVICE"
			fi
		else
			$(resetTimeout)
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

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 tld add tld\n"
				else
					tld=$3

					response=$(echo "TLD ADD $tld" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 tld drop tld\n"
				else
					tld=$3

					response=$(echo "TLD DROP $tld" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "2" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 tld show\n"
				else

					response=$(echo "TLD SHOW" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 provider add sender\n"
				else
					provider=$3

					response=$(echo "PROVIDER ADD $provider" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 provider drop sender\n"
				else
					provider=$3

					response=$(echo "PROVIDER DROP $provider" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "2" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 provider show\n"
				else

					response=$(echo "PROVIDER SHOW" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 ignore add sender\n"
				else
					ignore=$3

					response=$(echo "IGNORE ADD $ignore" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 ignore drop sender\n"
				else
					ignore=$3

					response=$(echo "IGNORE DROP $ignore" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "2" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 ignore show\n"
				else

					response=$(echo "IGNORE SHOW" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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
				#    2: timeout de conexão.
				#    3: out of service.

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 block add sender\n"
				else
					sender=$3

					response=$(echo "BLOCK ADD $sender" | $NCAT $IP_SERVIDOR $PORTA_SERVIDOR 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 block drop sender\n"
				else
					sender=$3

					response=$(echo "BLOCK DROP $sender" | $NCAT $IP_SERVIDOR $PORTA_SERVIDOR 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "2" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 block show [all]\n"
				else
					if [ "$3" == "all" ]; then
						response=$(echo "BLOCK SHOW ALL" | $NCAT $IP_SERVIDOR $PORTA_SERVIDOR 2> /dev/null)
					else
						response=$(echo "BLOCK SHOW" | $NCAT $IP_SERVIDOR $PORTA_SERVIDOR 2> /dev/null)
					fi

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 block find token\n"
				else
					token=$3
					response=$(echo "BLOCK FIND $token" | $NCAT $IP_SERVIDOR $PORTA_SERVIDOR 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 superblock add sender\n"
				else
					sender=$3

					response=$(echo "BLOCK ADD $sender" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 superblock split CIDR\n"
				else
					sender=$3

					response=$(echo "BLOCK SPLIT $sender" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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


				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 superblock overlap CIDR\n"
				else
					sender=$3

					response=$(echo "BLOCK OVERLAP $sender" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 superblock extract IP\n"
				else
					sender=$3

					response=$(echo "BLOCK EXTRACT $sender" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 superblock drop sender\n"
				else
					sender=$3

					response=$(echo "BLOCK DROP $sender" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "2" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 superblock show [all]\n"
				else
					if [ "$3" == "all" ]; then
						response=$(echo "BLOCK SHOW ALL" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)
					else
						response=$(echo "BLOCK SHOW" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)
					fi

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "3" ]; then
					head
					printf "Faltando parametro(s).\nSintaxe: $0 generic add sender\n"
				else
					sender=$3

					response=$(echo "GENERIC ADD $sender" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "3" ]; then
					head
					printf "Faltando parametro(s).\nSintaxe: $0 generic find <token>\n"
				else
					token=$3

					response=$(echo "GENERIC FIND $token" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "3" ]; then
					head
					printf "Faltando parametro(s).\nSintaxe: $0 generic drop sender\n"
				else
					sender=$3

					response=$(echo "GENERIC DROP $sender" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "2" ]; then
					head
					printf "Faltando parametro(s).\nSintaxe: $0 generic show [all]\n"
				else
					if [ "$3" == "all" ]; then
						response=$(echo "GENERIC SHOW ALL" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)
					else
						response=$(echo "GENERIC SHOW" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)
					fi

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "3" ]; then
					head
					printf "Faltando parametro(s).\nSintaxe: $0 dynamic add host\n"
				else
					host=$3

					response=$(echo "DYNAMIC ADD $host" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "3" ]; then
					head
					printf "Faltando parametro(s).\nSintaxe: $0 dynamic find <token>\n"
				else
					token=$3

					response=$(echo "DYNAMIC FIND $token" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "3" ]; then
					head
					printf "Faltando parametro(s).\nSintaxe: $0 dynamic drop host\n"
				else
					host=$3

					response=$(echo "DYNAMIC DROP $host" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "2" ]; then
					head
					printf "Faltando parametro(s).\nSintaxe: $0 dynamic show\n"
				else
					response=$(echo "DYNAMIC SHOW" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 white add recipient\n"
				else
					recipient=$3

					response=$(echo "WHITE ADD $recipient" | $NCAT $IP_SERVIDOR $PORTA_SERVIDOR 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 white sender recipient\n"
				else
					sender=$3

					response=$(echo "WHITE SENDER $sender" | $NCAT $IP_SERVIDOR $PORTA_SERVIDOR 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 white drop recipient\n"
				else
					recipient=$3

					response=$(echo "WHITE DROP $recipient" | $NCAT $IP_SERVIDOR $PORTA_SERVIDOR 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "2" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 white show\n"
				else
					response=$(echo "WHITE SHOW" | $NCAT $IP_SERVIDOR $PORTA_SERVIDOR 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 superwhite add recipient\n"
				else
					recipient=$3

					response=$(echo "WHITE ADD $recipient" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 superwhite drop recipient\n"
				else
					recipient=$3

					response=$(echo "WHITE DROP $recipient" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "2" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 superwhite show [all]\n"
				else
					if [ "$3" == "all" ]; then
						response=$(echo "WHITE SHOW ALL" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)
					else
						response=$(echo "WHITE SHOW" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)
					fi

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

					response=$(echo "CLIENT ADD $cidr $domain $option $email" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

					response=$(echo "CLIENT SET $cidr $domain $option $email" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 client drop cidr\n"
				else
					cidr=$3

					response=$(echo "CLIENT DROP $cidr" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "2" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 client show\n"
				else

					response=$(echo "CLIENT SHOW" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "4" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 user add email nome\n"
				else
					email=$3
					nome="${@:4}"

					response=$(echo "USER ADD $email $nome" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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
				#    1. email: E-mail do usuário.
				#
				# Códigos de saída:
				#
				#    0: removido com sucesso.
				#    1: erro ao tentar remover.
				#    2: timeout de conexão.
				#    3: out of service.

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 user drop email\n"
				else
					email=$3

					response=$(echo "USER DROP $email" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "2" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 user show\n"
				else
					response=$(echo "USER SHOW" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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
					response=$(echo "USER SEND $3 TOTP" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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
			*)
				head
				printf "Syntax:\n    $0 user add email nome\n    $0 user drop email\n    $0 user show\n"
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

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 peer add host [email]\n"
				else
					host=$3

					if [ -f "$4" ]; then
						email=$4
						response=$(echo "PEER ADD $host $email" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)
					else
						response=$(echo "PEER ADD $host" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)
					fi

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 peer drop { host | all }\n"
				else
					host=$3

					if [ "$host" == "all" ]; then
						response=$(echo "PEER DROP ALL" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)
					else
						response=$(echo "PEER DROP $host" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)
					fi

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "2" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 peer show [host]\n"
				else

					if [ -f "$3" ]; then
						host=$3
						response=$(echo "PEER SHOW $host" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)
					else
						response=$(echo "PEER SHOW" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)
					fi

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "5" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 peer set host send receive\n"
				else
					host=$3
					send=$4
					receive=$5

					response=$(echo "PEER SET $host $send $receive" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 peer ping host\n"
				else
					host=$3

					response=$(echo "PEER PING $host" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 peer send host\n"
				else
					host=$3

					response=$(echo "PEER SEND $host" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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
	'retention')
		case $2 in
			'show')
				# Parâmetros de entrada:
				#
				#    1. host: Endereço do peer.
				#
				# Códigos de saída:
				#
				#    0: visualizado com sucesso.
				#    1: erro ao tentar visualizar.
				#    2: timeout de conexão.
				#    3: out of service.

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 retention show { host | all }\n"
				else
					host=$3

					if [ "$host" == "all" ]; then
						response=$(echo "PEER RETENTION SHOW ALL" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)
					else
						response=$(echo "PEER RETENTION SHOW $host" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)
					fi

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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
			'release')
				# Parâmetros de entrada:
				#
				#    1. sender: Bloqueio recebido do peer.
				#
				# Códigos de saída:
				#
				#    0: visualizado com sucesso.
				#    1: erro ao tentar visualizar.
				#    2: timeout de conexão.
				#    3: out of service.

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 retention release { sender | all }\n"
				else
					sender=$3

					if [ "$sender" == "all" ]; then
						response=$(echo "PEER RETENTION RELEASE ALL" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)
					else
						response=$(echo "PEER RETENTION RELEASE $sender" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)
					fi

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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
			'reject')
				# Parâmetros de entrada:
				#
				#    1. sender: Bloqueio recebido do peer.
				#
				# Códigos de saída:
				#
				#    0: visualizado com sucesso.
				#    1: erro ao tentar visualizar.
				#    2: timeout de conexão.
				#    3: out of service.

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 retention reject { sender | all }\n"
				else
					sender=$3

					if [ "$sender" == "all" ]; then
						response=$(echo "PEER RETENTION REJECT ALL" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)
					else
						response=$(echo "PEER RETENTION REJECT $sender" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)
					fi

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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
				printf "Syntax:\n    $0 retention show { host | all }\n    $0 retention release { sender | all }\n    $0 retention reject { sender | all }\n"
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

		if [[ $2 == "cidr" ]]; then
			response=$(echo "REPUTATION CIDR" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)
		else
			response=$(echo "REPUTATION" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)
		fi

		if [[ $response == "" ]]; then
			$(incrementTimeout)
			if [ "$?" -le "$MAX_TIMEOUT" ]; then
				response="TIMEOUT"
			else
				response="OUT OF SERVICE"
			fi
		else
			$(resetTimeout)
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

		if [ $# -lt "2" ]; then
			head
			printf "Invalid Parameters. Syntax: $0 abuse In-Reply-To:<messageID> From:<from>\n"
		else
			messageID=$2
			from=$3

			response=$(echo "ABUSE $messageID $from" | $NCAT $IP_SERVIDOR $PORTA_SERVIDOR 2> /dev/null)

			if [[ $response == "" ]]; then
				$(incrementTimeout)
				if [ "$?" -le "$MAX_TIMEOUT" ]; then
					response="TIMEOUT"
				else
					response="OUT OF SERVICE"
				fi
			else
				$(resetTimeout)
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

		if [ $# -lt "2" ]; then
			head
			printf "Invalid Parameters. Syntax: $0 clear hostname\n"
		else
			hostname=$2

			response=$(echo "CLEAR $hostname" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)

			if [[ $response == "" ]]; then
				$(incrementTimeout)
				if [ "$?" -le "$MAX_TIMEOUT" ]; then
					response="TIMEOUT"
				else
					response="OUT OF SERVICE"
				fi
			else
				$(resetTimeout)
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

		if [ $# -lt "2" ]; then
			head
			printf "Invalid Parameters. Syntax: $0 refresh hostname\n"
		else
			hostname=$2

			response=$(echo "REFRESH $hostname" | $NCAT $IP_SERVIDOR $PORTA_SERVIDOR 2> /dev/null)

			if [[ $response == "" ]]; then
				$(incrementTimeout)
				if [ "$?" -le "$MAX_TIMEOUT" ]; then
					response="TIMEOUT"
				else
					response="OUT OF SERVICE"
				fi
			else
				$(resetTimeout)
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

		case $2 in
			'show')
				response=$(echo "ANALISE SHOW" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)

				if [[ $response == "" ]]; then
					$(incrementTimeout)
					if [ "$?" -le "$MAX_TIMEOUT" ]; then
						response="TIMEOUT"
					else
						response="OUT OF SERVICE"
					fi
				else
					$(resetTimeout)
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
				response=$(echo "ANALISE DUMP $3" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)

				if [[ $response == "" ]]; then
					$(incrementTimeout)
					if [ "$?" -le "$MAX_TIMEOUT" ]; then
						response="TIMEOUT"
					else
						response="OUT OF SERVICE"
					fi
				else
					$(resetTimeout)
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

				response=$(echo "ANALISE DROP $3" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)

				if [[ $response == "" ]]; then
					$(incrementTimeout)
					if [ "$?" -le "$MAX_TIMEOUT" ]; then
						response="TIMEOUT"
					else
						response="OUT OF SERVICE"
					fi
				else
					$(resetTimeout)
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

				response=$(echo "ANALISE $ip $list" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)

				if [[ $response == "" ]]; then
					$(incrementTimeout)
					if [ "$?" -le "$MAX_TIMEOUT" ]; then
						response="TIMEOUT"
					else
						response="OUT OF SERVICE"
					fi
				else
					$(resetTimeout)
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
		#    13: remetente inexistente.

		if [ $# -lt "4" ]; then
			head
			printf "Invalid Parameters. Syntax: $0 check ip email helo\n"
		else
			ip=$2
			email=$3
			helo=$4
			recipient=$5

			qualifier=$(echo "CHECK '$ip' '$email' '$helo' '$recipient'" | $NCAT $IP_SERVIDOR $PORTA_SERVIDOR 2> /dev/null)

			if [[ $qualifier == "" ]]; then
				$(incrementTimeout)
				if [ "$?" -le "$MAX_TIMEOUT" ]; then
					qualifier="TIMEOUT"
				else
					qualifier="OUT OF SERVICE"
				fi
			else
				$(resetTimeout)
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
					resposta=$(echo "SPAM $ticket" | $NCAT $IP_SERVIDOR $PORTA_SERVIDOR 2> /dev/null)

					if [[ $resposta == "" ]]; then
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
				resposta=$(curl -X PUT -s -m 3 $url)
				if [[ $? == "28" ]]; then
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
		#    5: hold message.
		#    6: flag message.

		if [ $# -lt "2" ]; then
			head
			printf "Faltando parametro(s).\nSintaxe: $0 link <ticket> <links>\n"
		else
			ticket=$2
			links=$3

			response=$(echo "LINK $ticket $links" | $NCAT $IP_SERVIDOR $PORTA_SERVIDOR 2> /dev/null)

			if [[ $response == "" ]]; then
				$(incrementTimeout)
				if [ "$?" -le "$MAX_TIMEOUT" ]; then
					response="TIMEOUT"
				else
					response="OUT OF SERVICE"
				fi
			else
				$(resetTimeout)
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
			elif [[ $response == "BLOCKED"* ]]; then
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
			elif [[ $2 =~ ^[a-zA-Z0-9/+=_\;-]{44,}$ ]]; then
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
					resposta=$(echo "MALWARE $ticket $3" | $NCAT $IP_SERVIDOR $PORTA_SERVIDOR 2> /dev/null)

					if [[ $resposta == "" ]]; then
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
				resposta=$(curl -X PUT -s -m 3 $url)
				if [[ $? == "28" ]]; then
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
		#   17: remetente colocado em lista branca.

		if [ $# -lt "3" ]; then
			head
			printf "Faltando parametro(s).\nSintaxe: $0 from <ticket> From:<from> Reply-To:<replyto> List-Unsubscribe:<url>\n"
		else
			ticket=$2
			from=$3
			replyto=$4
			unsubscribe=$5

			response=$(echo "FROM $ticket $from $replyto $unsubscribe" | $NCAT $IP_SERVIDOR $PORTA_SERVIDOR 2> /dev/null)

			if [[ $response == "" ]]; then
				$(incrementTimeout)
				if [ "$?" -le "$MAX_TIMEOUT" ]; then
					response="TIMEOUT"
				else
					response="OUT OF SERVICE"
				fi
			else
				$(resetTimeout)
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
		#    5: mensagem rejeitada pelo conteudo.
		#    6: marcar como SPAM.
		#    7: congelar a entrega da mensagem.
		#   17: remetente colocado em lista branca.

		if [ $# -lt "3" ]; then
			head
			printf "Faltando parametro(s).\nSintaxe: $0 header <ticket> 'From:[<from>]' 'Reply-To:[<replyto>]' 'Date:[<date>]' 'Subject:[<subject>]' 'List-Unsubscribe:[<url>]'\n"
		else
			ticket=$2
			from=$3
			replyto=$4
			date=$5
			subject=$6
			unsubscribe=$7

			response=$(echo "HEADER $ticket $from $replyto $date $subject $unsubscribe" | $NCAT $IP_SERVIDOR $PORTA_SERVIDOR 2> /dev/null)

			if [[ $response == "" ]]; then
				$(incrementTimeout)
				if [ "$?" -le "$MAX_TIMEOUT" ]; then
					response="TIMEOUT"
				else
					response="OUT OF SERVICE"
				fi
			else
				$(resetTimeout)
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

				COMPRESSED=$(iconv -f $CHARSET -t utf-8 $FILE | gzip --no-name --quiet --to-stdout)
				LENGTH=$(echo "$COMPRESSED" | wc -c)

				if [ "$LENGTH" -gt "65535" ]; then
					response="TOO BIG"
				else
					ENCODED=$(iconv -f $CHARSET -t utf-8 $FILE | gzip --no-name --quiet --to-stdout | base64 --wrap=0)
					response=$(echo "BODY $TICKET $ENCODED" | $NCAT $IP_SERVIDOR $PORTA_SERVIDOR 2> /dev/null)
				fi
			else
				response="NOT A FILE"
			fi


			if [[ $response == "" ]]; then
				$(incrementTimeout)
				if [ "$?" -le "$MAX_TIMEOUT" ]; then
					response="TIMEOUT"
				else
					response="OUT OF SERVICE"
				fi
			else
				$(resetTimeout)
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
		which exigrep > /dev/null

		if [ $? -eq 0 ]; then

			list=$(exiqgrep -z | egrep -o "([0-9a-zA-Z]{6}-){2}[0-9a-zA-Z]{2}")

			if [ $? -eq 0 ]; then

				while read -r message; do

					# ticket=$(exim -Mvh $message | grep -Pom 1 "Received-SPFBL: [A-Z]+ (https?://.+/)?\K([0-9a-zA-Z_-]{44,})$")
					ticket=$(exim -Mvh $message | grep -Pom 1 "^(PASS|SOFTFAIL|NEUTRAL|NONE|WHITE|HOLD) (https?://.+/)?\K([0-9a-zA-Z_-]{44,})$")

					if [ $? -eq 0 ]; then

						response=$(echo "HOLDING $ticket" | $NCAT $IP_SERVIDOR $PORTA_SERVIDOR 2> /dev/null)

						if [[ $response == "" ]]; then

							# Manter a mensagem congelada.
							echo "Message $message keep frozen."

						elif [[ $response == "WHITE" ]]; then

							# Liberar a mensagem congelada 
							# e entregar imedatamente.
							exim -Mt $message
							exim -M $message

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
					resposta=$(echo "HAM $ticket" | $NCAT $IP_SERVIDOR $PORTA_SERVIDOR 2> /dev/null)

					if [[ $resposta == "" ]]; then
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
				resposta=$(curl -X PUT -s -m 3 $url)
				if [[ $? == "28" ]]; then
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
		#    21: remetente inexistente.

		if [ $# -lt "5" ]; then
			head
			printf "Invalid Parameters. Syntax: $0 query ip email helo recipient\n"
		else
			ip=$2
			email=$3
			helo=$4
			recipient=$5

			qualifier=$(echo "SPF '$ip' '$email' '$helo' '$recipient'" | $NCAT -w $QUERY_TIMEOUT $IP_SERVIDOR $PORTA_SERVIDOR 2> /dev/null)

			if [[ $qualifier == "" ]]; then
				$(incrementTimeout)
				if [ "$?" -le "$MAX_TIMEOUT" ]; then
					qualifier="TIMEOUT"
				else
					qualifier="OUT OF SERVICE"
				fi
			else
				$(resetTimeout)
			fi

			echo "$qualifier"

			if [[ $qualifier == "OUT OF SERVICE" ]]; then
				exit 20
			elif [[ $qualifier == "TIMEOUT" ]]; then
				exit 9
			elif [[ $qualifier == "NXDOMAIN" ]]; then
				exit 13
			elif [[ $qualifier == "NXSENDER" ]]; then
				exit 21
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

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 trap add recipient\n"
				else
					recipient=$3

					response=$(echo "TRAP ADD $recipient" | $NCAT $IP_SERVIDOR $PORTA_SERVIDOR 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 trap drop recipient\n"
				else
					recipient=$3

					response=$(echo "TRAP DROP $recipient" | $NCAT $IP_SERVIDOR $PORTA_SERVIDOR 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "2" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 trap show\n"
				else
					response=$(echo "TRAP SHOW" | $NCAT $IP_SERVIDOR $PORTA_SERVIDOR 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 inexistent add recipient\n"
				else
					recipient=$3

					response=$(echo "INEXISTENT ADD $recipient" | $NCAT $IP_SERVIDOR $PORTA_SERVIDOR 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 inexistent drop recipient\n"
				else
					recipient=$3

					response=$(echo "INEXISTENT DROP $recipient" | $NCAT $IP_SERVIDOR $PORTA_SERVIDOR 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "2" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 inexistent show\n"
				else
					response=$(echo "INEXISTENT SHOW" | $NCAT $IP_SERVIDOR $PORTA_SERVIDOR 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 inexistent is <recipient>\n"
				else
					recipient=$3
					response=$(echo "INEXISTENT IS $recipient" | $NCAT $IP_SERVIDOR $PORTA_SERVIDOR 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 inexistent add recipient\n"
				else
					recipient=$3

					response=$(echo "INEXISTENT ADD $recipient" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 inexistent drop recipient\n"
				else
					recipient=$3

					response=$(echo "INEXISTENT DROP $recipient" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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

				if [ $# -lt "2" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 inexistent show\n"
				else
					response=$(echo "INEXISTENT SHOW" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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
	'noreply')
		case $2 in
			'add')
				# Parâmetros de entrada:
				#
				#    1. recipient: o destinatário que o SPFBL não deve enviar mensagem de e-mail.
				#
				#
				# Códigos de saída:
				#
				#    0: adicionado com sucesso.
				#    1: erro ao tentar adicionar endereço.
				#    2: timeout de conexão.
				#    3: out of service.

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 noreply add recipient\n"
				else
					recipient=$3

					response=$(echo "NOREPLY ADD $recipient" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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
				#    1. recipient: o destinatário que o SPFBL não deve enviar mensagem de e-mail.
				#
				#
				# Códigos de saída:
				#
				#    0: desbloqueado com sucesso.
				#    1: erro ao tentar adicionar endereço.
				#    2: timeout de conexão.
				#    3: out of service.

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 noreply drop recipient\n"
				else
					recipient=$3

					response=$(echo "NOREPLY DROP $recipient" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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
				#    1: erro ao tentar visualizar endereços.
				#    2: timeout de conexão.
				#    3: out of service.

				if [ $# -lt "2" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 noreply show\n"
				else
					response=$(echo "NOREPLY SHOW" | $NCAT $IP_SERVIDOR $PORTA_ADMIN 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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
				# Parâmetros de entrada:
				#
				#    1. recipient: o destinatário que o SPFBL deve verificar se pode responder e-mail.
				#
				#
				# Códigos de saída:
				#
				#    0: pode reponder e-mail.
				#    1: não pode reponder e-mail.
				#    2: timeout de conexão.
				#    3: out of service.

				if [ $# -lt "3" ]; then
					head
					printf "Invalid Parameters. Syntax: $0 noreply is <recipient>\n"
				else
					recipient=$3

					response=$(echo "NOREPLY IS $recipient" | $NCAT $IP_SERVIDOR $PORTA_SERVIDOR 2> /dev/null)

					if [[ $response == "" ]]; then
						$(incrementTimeout)
						if [ "$?" -le "$MAX_TIMEOUT" ]; then
							response="TIMEOUT"
						else
							response="OUT OF SERVICE"
						fi
					else
						$(resetTimeout)
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
				printf "Syntax:\n    $0 noreply add recipient\n    $0 noreply drop recipient\n    $0 noreply show\n"
			;;
		esac
	;;
	'dump')
		# Parâmetros de entrada: nenhum.
		#
		# Códigos de saída: nenhum.

		echo "DUMP" | $NCAT $IP_SERVIDOR $PORTA_ADMIN > $DUMP_PATH/spfbl.dump.$(date "+%Y-%m-%d_%H-%M")
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
					echo "$line" | $NCAT $IP_SERVIDOR $PORTA_ADMIN
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
	*)
		head
		printf "Help\n\n"
		printf "User Commands:\n"
		printf "    $0 version\n"
		printf "    $0 start|stop|restart|shutdown\n"
		printf "    $0 block { add sender | drop sender | show [all] | find }\n"
		printf "    $0 white { add sender | drop sender | show | sender }\n"
		printf "    $0 reputation\n"
		printf "    $0 clear hostname\n"
		printf "    $0 refresh hostname\n"
		printf "    $0 check ip email helo\n"
		printf "    $0 spam ticketid/file\n"
		printf "    $0 ham ticketid/file\n"
		printf "    $0 query ip email helo recipient\n"
		printf "    $0 trap { add recipient | drop recipient | show }\n"
		printf "    $0 noreply { add recipient | drop recipient | show }\n"
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
		printf "    $0 retention { show [host] | release { sender | all } | reject { sender | all } }\n"
		printf "    $0 provider { add sender | drop sender | show }\n"
		printf "    $0 ignore { add sender | drop sender | show }\n"
		printf "    $0 client { add/set cidr domain option [email] | drop cidr | show }\n"
		printf "    $0 user { add email nome | drop email | send-totp email | show }\n"
		printf "    $0 superblock { add sender | drop sender | show [all] | split | overlap }\n"
		printf "    $0 superwhite { add sender | drop sender | show [all] }\n"
		printf "    $0 analise <ip> or { show | dump | drop }\n"
		printf "    $0 dynamic { add host | find token | drop host | show }\n"
		printf "    $0 dump\n"
		printf "    $0 load path\n"
		printf "    $0 backup days [days to retain backup, default 60]\n"
		printf "\n"
	;;
esac
