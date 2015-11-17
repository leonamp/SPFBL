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
# Última alteração: 17/11/2015 11:44

### CONFIGURACOES ###
IP_SERVIDOR="matrix.spfbl.net"
PORTA_SERVIDOR="9877"
PORTA_ADMIN="9875"

export PATH=/sbin:/usr/sbin:/bin:/usr/bin:/usr/local/sbin:/usr/local/bin
version="0.5"

head()
{
	echo "SPFBL v$version - by Leandro Rodrigues - leandro@spfbl.net"
}

case $1 in
	'version')
		# Verifica a versão do servidor SPPFBL.
		#
		# Códigos de saída:
		#
		#    0: versão adquirida com sucesso.
		#    1: erro ao tentar adiquirir versão.
		#    2: timeout de conexão.
		

		response=$(echo "VERSION" | nc $IP_SERVIDOR $PORTA_SERVIDOR)

		if [[ $response == "" ]]; then
			response="TIMEOUT"
		fi

		echo "$response"

		if [[ $response == "TIMEOUT" ]]; then
			exit 2
		elif [[ $response == "SPFBL"* ]]; then
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
		

		response=$(echo "SHUTDOWN" | nc $IP_SERVIDOR $PORTA_ADMIN)

		if [[ $response == "" ]]; then
			response="TIMEOUT"
		fi

		echo "$response"

		if [[ $response == "TIMEOUT" ]]; then
			exit 2
		elif [[ $response == "OK" ]]; then
			exit 0
		elif [[ $response == "ERROR: SHUTDOWN" ]]; then
			exit 1
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
		

		response=$(echo "STORE" | nc $IP_SERVIDOR $PORTA_ADMIN)

		if [[ $response == "" ]]; then
			response="TIMEOUT"
		fi

		echo "$response"

		if [[ $response == "TIMEOUT" ]]; then
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
				
				if [ $# -lt "3" ]; then
					head
					printf "Faltando parametro(s).\nSintaxe: $0 tld add tld\n"
				else
					tld=$3

					response=$(echo "TLD ADD $tld" | nc $IP_SERVIDOR $PORTA_ADMIN)

					if [[ $response == "" ]]; then
						response="TIMEOUT"
					fi

					echo "$response"

					if [[ $response == "TIMEOUT" ]]; then
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
				
				if [ $# -lt "3" ]; then
					head
					printf "Faltando parametro(s).\nSintaxe: $0 tld drop tld\n"
				else
					tld=$3

					response=$(echo "TLD DROP $tld" | nc $IP_SERVIDOR $PORTA_ADMIN)

					if [[ $response == "" ]]; then
						response="TIMEOUT"
					fi

					echo "$response"

					if [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "DROPED" ]]; then
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
				
				if [ $# -lt "2" ]; then
					head
					printf "Faltando parametro(s).\nSintaxe: $0 tld show\n"
				else

					response=$(echo "TLD SHOW" | nc $IP_SERVIDOR $PORTA_ADMIN)

					if [[ $response == "" ]]; then
						response="TIMEOUT"
					fi

					echo "$response"

					if [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "ERROR"* ]]; then
						exit 1
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
##########
### DNSBL?
##########
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
				
				if [ $# -lt "3" ]; then
					head
					printf "Faltando parametro(s).\nSintaxe: $0 provider add sender\n"
				else
					provider=$3

					response=$(echo "PROVIDER ADD $provider" | nc $IP_SERVIDOR $PORTA_ADMIN)

					if [[ $response == "" ]]; then
						response="TIMEOUT"
					fi

					echo "$response"

					if [[ $response == "TIMEOUT" ]]; then
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
				
				if [ $# -lt "3" ]; then
					head
					printf "Faltando parametro(s).\nSintaxe: $0 provider drop sender\n"
				else
					provider=$3

					response=$(echo "PROVIDER DROP $provider" | nc $IP_SERVIDOR $PORTA_ADMIN)

					if [[ $response == "" ]]; then
						response="TIMEOUT"
					fi

					echo "$response"

					if [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "DROPED" ]]; then
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
				
				if [ $# -lt "2" ]; then
					head
					printf "Faltando parametro(s).\nSintaxe: $0 provider show\n"
				else

					response=$(echo "PROVIDER SHOW" | nc $IP_SERVIDOR $PORTA_ADMIN)

					if [[ $response == "" ]]; then
						response="TIMEOUT"
					fi

					echo "$response"

					if [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "ERROR"* ]]; then
						exit 1
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
				
				if [ $# -lt "3" ]; then
					head
					printf "Faltando parametro(s).\nSintaxe: $0 ignore add sender\n"
				else
					ignore=$3

					response=$(echo "IGNORE ADD $ignore" | nc $IP_SERVIDOR $PORTA_ADMIN)

					if [[ $response == "" ]]; then
						response="TIMEOUT"
					fi

					echo "$response"

					if [[ $response == "TIMEOUT" ]]; then
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
				
				if [ $# -lt "3" ]; then
					head
					printf "Faltando parametro(s).\nSintaxe: $0 ignore drop sender\n"
				else
					ignore=$3

					response=$(echo "IGNORE DROP $ignore" | nc $IP_SERVIDOR $PORTA_ADMIN)

					if [[ $response == "" ]]; then
						response="TIMEOUT"
					fi

					echo "$response"

					if [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "DROPED" ]]; then
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
				
				if [ $# -lt "2" ]; then
					head
					printf "Faltando parametro(s).\nSintaxe: $0 ignore show\n"
				else

					response=$(echo "IGNORE SHOW" | nc $IP_SERVIDOR $PORTA_ADMIN)

					if [[ $response == "" ]]; then
						response="TIMEOUT"
					fi

					echo "$response"

					if [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "ERROR"* ]]; then
						exit 1
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
				#    1. domínio: o domínio que deve ser bloqueado, com arroba (ex: @dominio.com.br)
				#    1. caixa postal: a caixa postal que deve ser bloqueada, com arroba (ex: www-data@)
				#
				#
				# Códigos de saída:
				#
				#    0: adicionado com sucesso.
				#    1: erro ao tentar adicionar bloqueio.
				#    2: timeout de conexão.
				
				if [ $# -lt "3" ]; then
					head
					printf "Faltando parametro(s).\nSintaxe: $0 block add sender\n"
				else
					sender=$3

					response=$(echo "BLOCK ADD $sender" | nc $IP_SERVIDOR $PORTA_SERVIDOR)

					if [[ $response == "" ]]; then
						response="TIMEOUT"
					fi

					echo "$response"

					if [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "OK" ]]; then
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
				
				if [ $# -lt "3" ]; then
					head
					printf "Faltando parametro(s).\nSintaxe: $0 block drop sender\n"
				else
					sender=$3

					response=$(echo "BLOCK DROP $sender" | nc $IP_SERVIDOR $PORTA_SERVIDOR)

					if [[ $response == "" ]]; then
						response="TIMEOUT"
					fi

					echo "$response"

					if [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "OK" ]]; then
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
				
				if [ $# -lt "2" ]; then
					head
					printf "Faltando parametro(s).\nSintaxe: $0 block show [all]\n"
				else
					if [ "$3" == "all" ]; then
						response=$(echo "BLOCK SHOW ALL" | nc $IP_SERVIDOR $PORTA_SERVIDOR)
					else
						response=$(echo "BLOCK SHOW" | nc $IP_SERVIDOR $PORTA_SERVIDOR)
					fi

					if [[ $response == "" ]]; then
						response="TIMEOUT"
					fi

					echo "$response"

					if [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "OK" ]]; then
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
				
				if [ $# -lt "3" ]; then
					head
					printf "Faltando parametro(s).\nSintaxe: $0 superblock add sender\n"
				else
					sender=$3

					response=$(echo "BLOCK ADD $sender" | nc $IP_SERVIDOR $PORTA_ADMIN)

					if [[ $response == "" ]]; then
						response="TIMEOUT"
					fi

					echo "$response"

					if [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "OK" ]]; then
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
				
				if [ $# -lt "3" ]; then
					head
					printf "Faltando parametro(s).\nSintaxe: $0 superblock drop sender\n"
				else
					sender=$3

					response=$(echo "BLOCK DROP $sender" | nc $IP_SERVIDOR $PORTA_ADMIN)

					if [[ $response == "" ]]; then
						response="TIMEOUT"
					fi

					echo "$response"

					if [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "OK" ]]; then
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
				
				if [ $# -lt "2" ]; then
					head
					printf "Faltando parametro(s).\nSintaxe: $0 superblock show [all]\n"
				else
					if [ "$3" == "all" ]; then
						response=$(echo "BLOCK SHOW ALL" | nc $IP_SERVIDOR $PORTA_ADMIN)
					else
						response=$(echo "BLOCK SHOW" | nc $IP_SERVIDOR $PORTA_ADMIN)
					fi

					if [[ $response == "" ]]; then
						response="TIMEOUT"
					fi

					echo "$response"

					if [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "OK" ]]; then
						exit 0
					else
						exit 1
					fi
				fi
			;;
			*)
				head
				printf "Syntax:\n    $0 superblock add recipient\n    $0 superblock drop recipient\n    $0 superblock show\n"
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
				
				if [ $# -lt "3" ]; then
					head
					printf "Faltando parametro(s).\nSintaxe: $0 white add recipient\n"
				else
					recipient=$3

					response=$(echo "WHITE ADD $recipient" | nc $IP_SERVIDOR $PORTA_SERVIDOR)

					if [[ $response == "" ]]; then
						response="TIMEOUT"
					fi

					echo "$response"

					if [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "OK" ]]; then
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
				
				if [ $# -lt "3" ]; then
					head
					printf "Faltando parametro(s).\nSintaxe: $0 white drop recipient\n"
				else
					recipient=$3

					response=$(echo "WHITE DROP $recipient" | nc $IP_SERVIDOR $PORTA_SERVIDOR)

					if [[ $response == "" ]]; then
						response="TIMEOUT"
					fi

					echo "$response"

					if [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "OK" ]]; then
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
				
				if [ $# -lt "2" ]; then
					head
					printf "Faltando parametro(s).\nSintaxe: $0 white show\n"
				else
					response=$(echo "WHITE SHOW" | nc $IP_SERVIDOR $PORTA_SERVIDOR)

					if [[ $response == "" ]]; then
						response="TIMEOUT"
					fi

					echo "$response"

					if [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "OK" ]]; then
						exit 0
					else
						exit 1
					fi
				fi
			;;
			*)
				head
				printf "Syntax:\n    $0 white add recipient\n    $0 white drop recipient\n    $0 white show\n"
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
				
				if [ $# -lt "3" ]; then
					head
					printf "Faltando parametro(s).\nSintaxe: $0 superwhite add recipient\n"
				else
					recipient=$3

					response=$(echo "WHITE ADD $recipient" | nc $IP_SERVIDOR $PORTA_ADMIN)

					if [[ $response == "" ]]; then
						response="TIMEOUT"
					fi

					echo "$response"

					if [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "OK" ]]; then
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
				
				if [ $# -lt "3" ]; then
					head
					printf "Faltando parametro(s).\nSintaxe: $0 superwhite drop recipient\n"
				else
					recipient=$3

					response=$(echo "WHITE DROP $recipient" | nc $IP_SERVIDOR $PORTA_ADMIN)

					if [[ $response == "" ]]; then
						response="TIMEOUT"
					fi

					echo "$response"

					if [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "OK" ]]; then
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
				
				if [ $# -lt "2" ]; then
					head
					printf "Faltando parametro(s).\nSintaxe: $0 superwhite show\n"
				else
					response=$(echo "WHITE SHOW" | nc $IP_SERVIDOR $PORTA_ADMIN)

					if [[ $response == "" ]]; then
						response="TIMEOUT"
					fi

					echo "$response"

					if [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "OK" ]]; then
						exit 0
					else
						exit 1
					fi
				fi
			;;
			*)
				head
				printf "Syntax:\n    $0 superwhite add recipient\n    $0 superwhite drop recipient\n    $0 superwhite show\n"
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
				#    3. email: [opcional] e-mail do cliente
				#
				# Códigos de saída:
				#
				#    0: adicionado com sucesso.
				#    1: erro ao tentar adiciona.
				#    2: timeout de conexão.
				
				if [ $# -lt "4" ]; then
					head
					printf "Faltando parametro(s).\nSintaxe: $0 client add cidr domain [email]\n"
				else
					cidr=$3
					domain=$4
					
					if [ -z "$5" ]; then
						response=$(echo "CLIENT ADD $cidr $domain" | nc $IP_SERVIDOR $PORTA_ADMIN)
					else
						email=$5
						response=$(echo "CLIENT ADD $cidr $domain $email" | nc $IP_SERVIDOR $PORTA_ADMIN)
					fi

					if [[ $response == "" ]]; then
						response="TIMEOUT"
					fi

					echo "$response"

					if [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "ADDED"* ]]; then
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
				#    3. email: [opcional] e-mail do cliente
				#
				# Códigos de saída:
				#
				#    0: adicionado com sucesso.
				#    1: erro ao tentar adiciona.
				#    2: timeout de conexão.
				
				if [ $# -lt "4" ]; then
					head
					printf "Faltando parametro(s).\nSintaxe: $0 client set cidr domain [email]\n"
				else
					cidr=$3
					domain=$4
					
					if [ -z "$5" ]; then
						response=$(echo "CLIENT SET $cidr $domain" | nc $IP_SERVIDOR $PORTA_ADMIN)
					else
						email=$5
						response=$(echo "CLIENT SET $cidr $domain $email" | nc $IP_SERVIDOR $PORTA_ADMIN)
					fi

					if [[ $response == "" ]]; then
						response="TIMEOUT"
					fi

					echo "$response"

					if [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "UPDATED"* ]]; then
						exit 0
					else
						exit 1
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
				
				if [ $# -lt "3" ]; then
					head
					printf "Faltando parametro(s).\nSintaxe: $0 client drop cidr\n"
				else
					cidr=$3

					response=$(echo "CLIENT DROP $cidr" | nc $IP_SERVIDOR $PORTA_ADMIN)

					if [[ $response == "" ]]; then
						response="TIMEOUT"
					fi

					echo "$response"

					if [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "DROPED"* ]]; then
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
				
				if [ $# -lt "2" ]; then
					head
					printf "Faltando parametro(s).\nSintaxe: $0 client show\n"
				else

					response=$(echo "CLIENT SHOW" | nc $IP_SERVIDOR $PORTA_ADMIN)

					if [[ $response == "" ]]; then
						response="TIMEOUT"
					fi

					echo "$response"

					if [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "ERROR"* ]]; then
						exit 1
					else
						exit 0
					fi
				fi
			;;
			*)
				head
				printf "Syntax:\n    $0 client add cidr domain [email] \n    $0 client set cidr domain [email] \n    $0 client drop cidr\n    $0 client show\n"
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
				
				if [ $# -lt "4" ]; then
					head
					printf "Faltando parametro(s).\nSintaxe: $0 user add email nome\n"
				else
					email=$3
					nome="${@:4}"

					response=$(echo "USER ADD $email $nome" | nc $IP_SERVIDOR $PORTA_ADMIN)

					if [[ $response == "" ]]; then
						response="TIMEOUT"
					fi

					echo "$response"

					if [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "ADDED"* ]]; then
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
				
				if [ $# -lt "3" ]; then
					head
					printf "Faltando parametro(s).\nSintaxe: $0 user drop email\n"
				else
					email=$3

					response=$(echo "USER DROP $email" | nc $IP_SERVIDOR $PORTA_ADMIN)

					if [[ $response == "" ]]; then
						response="TIMEOUT"
					fi

					echo "$response"

					if [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "DROPED"* ]]; then
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
				
				if [ $# -lt "2" ]; then
					head
					printf "Faltando parametro(s).\nSintaxe: $0 user show\n"
				else

					response=$(echo "USER SHOW" | nc $IP_SERVIDOR $PORTA_ADMIN)

					if [[ $response == "" ]]; then
						response="TIMEOUT"
					fi

					echo "$response"

					if [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "ERROR"* ]]; then
						exit 1
					else
						exit 0
					fi
				fi
			;;
			*)
				head
				printf "Syntax:\n    $0 user add email nome\n    $0 user drop email\n    $0 user show\n"
			;;
		esac
	;;
########
## PEER
########
## GUESS
########
	'reputation')
		# Parâmetros de entrada: nenhum
		#
		# Códigos de saída:
		#
		#    0: listado com sucesso.
		#    1: lista vazia.
		#    2: timeout de conexão.
		
		response=$(echo "REPUTATION" | nc $IP_SERVIDOR $PORTA_SERVIDOR)
			
		if [[ $response == "" ]]; then
			response="TIMEOUT"
		fi
			
		echo "$response"

		if [[ $response == "TIMEOUT" ]]; then
			exit 2
		elif [[ $response == "EMPTY" ]]; then
			exit 1
		else
			exit 0
		fi
	;;
	'clear')
		# Parâmetros de entrada:
		#
		#    1. hostname: o nome do host cujo registro SPF que deve ser limpado.
		#
		#
		# Códigos de saída:
		#
		#    0: limpado com sucesso.
		#    1: registro não encontrado em cache.
		#    2: erro ao processar atualização.
		#    3: timeout de conexão.
		
		if [ $# -lt "2" ]; then
			head
			printf "Faltando parametro(s).\nSintaxe: $0 clear hostname\n"
		else
			hostname=$2

			response=$(echo "CLEAR $hostname" | nc $IP_SERVIDOR $PORTA_SERVIDOR)

			if [[ $response == "" ]]; then
				response="TIMEOUT"
			fi

			echo "$response"

			if [[ $response == "TIMEOUT" ]]; then
				exit 3
			elif [[ $response == "UPDATED" ]]; then
				exit 0
			elif [[ $response == "NOT LOADED" ]]; then
				exit 1
			else
				exit 2
			fi
		fi
	;;
########
## DROP
########
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
		
		if [ $# -lt "2" ]; then
			head
			printf "Faltando parametro(s).\nSintaxe: $0 refresh hostname\n"
		else
			hostname=$2

			response=$(echo "REFRESH $hostname" | nc $IP_SERVIDOR $PORTA_SERVIDOR)

			if [[ $response == "" ]]; then
				response="TIMEOUT"
			fi

			echo "$response"

			if [[ $response == "TIMEOUT" ]]; then
				exit 3
			elif [[ $response == "UPDATED" ]]; then
				exit 0
			elif [[ $response == "NOT LOADED" ]]; then
				exit 1
			else
				exit 2
			fi
		fi
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
		
		if [ $# -lt "4" ]; then
			head
			printf "Faltando parametro(s).\nSintaxe: $0 check ip email helo\n"
		else
			ip=$2
			email=$3
			helo=$4

			qualifier=$(echo "CHECK '$ip' '$email' '$helo'" | nc $IP_SERVIDOR $PORTA_SERVIDOR)

			if [[ $qualifier == "" ]]; then
				qualifier="TIMEOUT"
			fi

			echo "$qualifier"

			if [[ $qualifier == "TIMEOUT" ]]; then
				exit 9
			elif [[ $qualifier == "NXDOMAIN" ]]; then
				exit 10
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
			printf "Faltando parametro(s).\nSintaxe: $0 spam ticketid/file\n"
		else
                        if [[ $2 =~ ^http://.+/spam/[a-zA-Z0-9/+=]{44,512}$ ]]; then
                                # O parâmentro é uma URL de denúncia SPFBL.
                                url=$2
			elif [[ $2 =~ ^[a-zA-Z0-9/+=]{44,512}$ ]]; then
				# O parâmentro é um ticket SPFBL.
				ticket=$2
			elif [ -f "$1" ]; then
				# O parâmetro é um arquivo.
				file=$2
				
				if [ -e "$file" ]; then
					# Extrai o ticket incorporado no arquivo.
					ticket=$(grep -Pom 1 "^Received-SPFBL: (PASS|SOFTFAIL|NEUTRAL|NONE) \K([0-9a-zA-Z\+/=]+)$" $file)
					
					if [ $? -gt 0 ]; then
						echo "Nenhum ticket SPFBL foi encontrado na mensagem."
						exit 2
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
					resposta=$(echo "SPAM $ticket" | nc $IP_SERVIDOR $PORTA_SERVIDOR)

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
                                resposta=$(curl -s -m 3 $url)
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
			printf "Faltando parametro(s).\nSintaxe: $0 ham ticketid/file\n"
		else
			if [[ $2 =~ ^http://.+/spam/[a-zA-Z0-9/+=]{44,512}$ ]]; then
                                # O parâmentro é uma URL de denúncia SPFBL.
                                spamURL=/spam/
                                hamURL=/ham/
                                url=${2/$spamURL/$hamURL}
			elif [[ $2 =~ ^[a-zA-Z0-9/+]{44,512}$ ]]; then
				# O parâmentro é um ticket SPFBL.
				ticket=$2
			elif [ -f "$1" ]; then
				# O parâmetro é um arquivo.
				file=$2
				
				if [ -e "$file" ]; then
					# Extrai o ticket incorporado no arquivo.
					ticket=$(grep -Pom 1 "^Received-SPFBL: (PASS|SOFTFAIL|NEUTRAL|NONE) \K([0-9a-zA-Z\+/=]+)$" $file)
					
					if [ $? -gt 0 ]; then
						echo "Nenhum ticket SPFBL foi encontrado na mensagem."
						exit 2
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
					resposta=$(echo "HAM $ticket" | nc $IP_SERVIDOR $PORTA_SERVIDOR)

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
                                resposta=$(curl -s -m 3 $url)
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
		# O ticket da consulta só é gerado nas saídas cujos qualificadores sejam: PASS, SOFTFAIL, NEUTRAL e NONE.
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
		#    SPAMTRAP: discaratar silenciosamente a mensagem e informar à origem que a mensagem foi recebida com sucesso.
		#    GREYLIST: atrasar a mensagem informando à origem ele está em greylisting.
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
		
		if [ $# -lt "5" ]; then
			head
			printf "Faltando parametro(s).\nSintaxe: $0 query ip email helo recipient\n"
		else
			ip=$2
			email=$3
			helo=$4
			recipient=$5

			qualifier=$(echo "SPF '$ip' '$email' '$helo' '$recipient'" | nc -w 10 $IP_SERVIDOR $PORTA_SERVIDOR)

			if [[ $qualifier == "" ]]; then
				qualifier="TIMEOUT"
			fi

			echo "$qualifier"

			if [[ $qualifier == "TIMEOUT" ]]; then
				exit 9
			elif [[ $qualifier == "NXDOMAIN" ]]; then
				exit 13
			elif [[ $qualifier == "GREYLIST" ]]; then
				exit 12
			elif [[ $qualifier == "INVALID" ]]; then
				exit 14
			elif [[ $qualifier == "SPAMTRAP" ]]; then
				exit 11
			elif [[ $qualifier == "BLOCKED" ]]; then
				exit 10
			elif [[ $qualifier == "LISTED" ]]; then
				exit 8
			elif [[ $qualifier == "ERROR: HOST NOT FOUND" ]]; then
				exit 6
			elif [[ $qualifier == "ERROR: "* ]]; then
				exit 7
			elif [[ $qualifier == "NONE "* ]]; then
				exit 5
			elif [[ $qualifier == "PASS "* ]]; then
				exit 2
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
				#    1. recipient: o destinatário que deve ser bloqueado, com endereço completo.
				#
				#
				# Códigos de saída:
				#
				#    0: adicionado com sucesso.
				#    1: erro ao tentar adicionar bloqueio.
				#    2: timeout de conexão.

				if [ $# -lt "3" ]; then
					head
					printf "Faltando parametro(s).\nSintaxe: $0 trap add recipient\n"
				else
					recipient=$3

					response=$(echo "TRAP ADD $recipient" | nc $IP_SERVIDOR $PORTA_SERVIDOR)

					if [[ $response == "" ]]; then
						response="TIMEOUT"
					fi

					echo "$response"

					if [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "OK" ]]; then
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
				
				if [ $# -lt "3" ]; then
					head
					printf "Faltando parametro(s).\nSintaxe: $0 trap drop recipient\n"
				else
					recipient=$3

					response=$(echo "TRAP DROP $recipient" | nc $IP_SERVIDOR $PORTA_SERVIDOR)

					if [[ $response == "" ]]; then
						response="TIMEOUT"
					fi

					echo "$response"

					if [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "OK" ]]; then
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
				
				if [ $# -lt "2" ]; then
					head
					printf "Faltando parametro(s).\nSintaxe: $0 trap show\n"
				else
					response=$(echo "TRAP SHOW" | nc $IP_SERVIDOR $PORTA_SERVIDOR)

					if [[ $response == "" ]]; then
						response="TIMEOUT"
					fi

					echo "$response"

					if [[ $response == "TIMEOUT" ]]; then
						exit 2
					elif [[ $response == "OK" ]]; then
						exit 0
					else
						exit 1
					fi
				fi
			;;
			*)
				head
				printf "Syntax:\n    $0 trap add recipient\n    $0 trap drop recipient\n    $0 trap show\n"
			;;
		esac
	;;
	*)
		head
		printf "Help:\n"
		printf "    $0 version\n"
		printf "    $0 block { add sender | drop sender | show [all] }\n"
		printf "    $0 white { add sender | drop sender | show }\n"
		printf "    $0 reputation\n"
		printf "    $0 clear hostname\n"
		printf "    $0 refresh hostname\n"
		printf "    $0 check ip email helo\n"
		printf "    $0 spam ticketid/file\n"
		printf "    $0 ham ticketid/file\n"
		printf "    $0 query ip email helo recipient\n"
		printf "    $0 trap { add recipient | drop recipient | show }\n"
		printf "\n"
		printf "Admin Commands:\n"
		printf "    $0 shutdown\n"
		printf "    $0 store\n"
		printf "    $0 tld { add tld | drop tld | show }\n"
		printf "    $0 provider { add sender | drop sender | show }\n"
		printf "    $0 ignore { add sender | drop sender | show }\n"
		printf "    $0 client { add cidr domain [email] | drop cidr | show }\n"
		printf "    $0 user { add email nome | drop email | show }\n"
		printf "\n"
	;;
esac
