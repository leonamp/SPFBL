#!/bin/bash
#
# Projeto SPFBL - Copyright Leandro Carlos Rodrigues - leandro@allchemistry.com.br
# https://github.com/leonamp/SPFBL
#
# Atenção! Para utilizar este serviço, solicite a liberação das consultas 
# no servidor 54.94.137.168 através do endereço leandro@allchemistry.com.br 
# ou altere o IP 54.94.137.168 deste script para seu servidor SPFBL próprio.
IP_SERVIDOR="54.94.137.168"
PORTA_SERVIDOR="9877"

export PATH=/sbin:/usr/sbin:/bin:/usr/bin:/usr/local/sbin:/usr/local/bin

# Opcoes:
# block add
# block drop
# block show
# check
# spam
# ham
# query
# trap add
# trap drop
# trap show

case $1 in
	'block')
		case $2 in
			'add')
				if [ $# -lt "3" ]; then
					printf "Faltando parametro(s).\nSintaxe: $0 block add sender\n"
				else
					sender=$3

					response=$(echo "BLOCK ADD $sender" | nc -w 5 $IP_SERVIDOR $PORTA_SERVIDOR)

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
				if [ $# -lt "3" ]; then
					printf "Faltando parametro(s).\nSintaxe: $0 block drop sender\n"
				else
					sender=$3

					response=$(echo "BLOCK DROP $sender" | nc -w 5 $IP_SERVIDOR $PORTA_SERVIDOR)

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
				if [ $# -lt "2" ]; then
					printf "Faltando parametro(s).\nSintaxe: $0 block show\n"
				else
					response=$(echo "BLOCK SHOW" | nc -w 5 $IP_SERVIDOR $PORTA_SERVIDOR)

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
		esac
	;;
	'check')
		if [ $# -lt "4" ]; then
			printf "Faltando parametro(s).\nSintaxe: $0 check ip email helo\n"
		else
			ip=$2
			email=$3
			helo=$4

			qualifier=$(echo "CHECK $ip $email $helo" | nc -w 5 $IP_SERVIDOR $PORTA_SERVIDOR)

			if [[ $qualifier == "" ]]; then
				qualifier="TIMEOUT"
			fi

			echo "$qualifier"

			if [[ $qualifier == "TIMEOUT" ]]; then
					exit 9
			elif [[ $qualifier == "LISTED"* ]]; then
				exit 8
			elif [[ $qualifier == "ERROR: HOST NOT FOUND" ]]; then
				exit 6
			elif [[ $qualifier == "ERROR: QUERY" ]]; then
				exit 10
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
		if [ $# -lt "2" ]; then
			printf "Faltando parametro(s).\nSintaxe: $0 spam ticketid/file\n"
		else
			if [[ $2 =~ ^[a-zA-Z0-9/+=]+$ ]]; then
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

			if [[ -z $ticket ]]; then
				echo "Ticket SPFBL inválido."
				exit 6
			else
				# Registra reclamação SPFBL.
				resposta=$(echo "SPAM $ticket" | nc -w 5 $IP_SERVIDOR $PORTA_SERVIDOR)

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
		fi
	;;
	'ham')
		if [ $# -lt "2" ]; then
			printf "Faltando parametro(s).\nSintaxe: $0 ham ticketid/file\n"
		else
			if [[ $2 =~ ^[a-zA-Z0-9/+]+$ ]]; then
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

			if [[ -z $ticket ]]; then
				echo "Ticket SPFBL inválido."
				exit 6
			else
				# Registra reclamação SPFBL.
				resposta=$(echo "HAM $ticket" | nc -w 5 $IP_SERVIDOR $PORTA_SERVIDOR)

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
		fi
	;;
	'query')
		if [ $# -lt "5" ]; then
			printf "Faltando parametro(s).\nSintaxe: $0 query ip email helo recipient\n"
		else
			ip=$2
			email=$3
			helo=$4
			recipient=$5

			qualifier=$(echo "SPF '$ip' '$email' '$helo' '$recipient'" | nc -w 5 $IP_SERVIDOR $PORTA_SERVIDOR)

			if [[ $qualifier == "" ]]; then
				qualifier="TIMEOUT"
			fi

			echo "$qualifier"

			if [[ $qualifier == "TIMEOUT" ]]; then
				exit 9
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
				if [ $# -lt "3" ]; then
					printf "Faltando parametro(s).\nSintaxe: $0 trap add recipient\n"
				else
					recipient=$3

					response=$(echo "TRAP ADD $recipient" | nc -w 5 $IP_SERVIDOR $PORTA_SERVIDOR)

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
				if [ $# -lt "3" ]; then
					printf "Faltando parametro(s).\nSintaxe: $0 trap drop recipient\n"
				else
					recipient=$3

					response=$(echo "TRAP DROP $recipient" | nc -w 5 $IP_SERVIDOR $PORTA_SERVIDOR)

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
				if [ $# -lt "2" ]; then
					printf "Faltando parametro(s).\nSintaxe: $0 trap show\n"
				else
					response=$(echo "TRAP SHOW" | nc -w 5 $IP_SERVIDOR $PORTA_SERVIDOR)

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
		esac
	;;
esac
