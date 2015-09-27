#!/bin/bash
#
# Projeto SPFBL - Copyright Leandro Carlos Rodrigues - leandro@allchemistry.com.br
# https://github.com/leonamp/SPFBL
#
# Atenção! Para utilizar este serviço, solicite a liberação das consultas 
# no servidor 54.94.137.168 através do endereço leandro@allchemistry.com.br 
# ou altere o IP 54.94.137.168 deste script para seu servidor SPFBL próprio.

### CONFIGURACOES ###
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
# white add
# white drop
# white show
# refresh

case $1 in
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
				# Parâmetros de entrada: nenhum.
				#
				# Códigos de saída:
				#
				#    0: visualizado com sucesso.
				#    1: erro ao tentar visualizar bloqueio.
				#    2: timeout de conexão.
				
				if [ $# -lt "2" ]; then
					printf "Faltando parametro(s).\nSintaxe: $0 block show\n"
				else
					response=$(echo "BLOCK SHOW" | nc $IP_SERVIDOR $PORTA_SERVIDOR)

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
		#    10: parâmetros inválidos.
		
		if [ $# -lt "4" ]; then
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
			printf "Faltando parametro(s).\nSintaxe: $0 spam ticketid/file\n"
		else
			if [[ $2 =~ ^[a-zA-Z0-9/+=]{44,512}$ ]]; then
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
			printf "Faltando parametro(s).\nSintaxe: $0 ham ticketid/file\n"
		else
			if [[ $2 =~ ^[a-zA-Z0-9/+]{44,512}$ ]]; then
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
			elif [[ $qualifier == "GREYLIST" ]]; then
				exit 12
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
		esac
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
		
		if [ $# -lt "2" ]; then
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
esac
