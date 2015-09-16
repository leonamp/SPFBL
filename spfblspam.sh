#!/bin/bash
#
# Este é um script que faz a reclação de SPAM ao serviço SPFBL.
#
# Atenção! Para utilizar este serviço, solicite a liberação das consultas 
# no servidor 54.94.137.168 através do endereço leandro@allchemistry.com.br 
# ou altere o IP 54.94.137.168 deste script para seu servidor SPFBL próprio.
#
# Este programa procura e extrai o ticket de consulta SPFBL de uma mensagem de e-mail se o parâmetro for um arquivo.
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
#

if [[ $1 =~ ^[a-zA-Z0-9/+=]{44,512}$ ]]; then

	# O parâmentro é um ticket SPFBL.
	ticket=$1

elif [ -f "$1" ]; then

	# O parâmetro é um arquivo.
	file=$1
	
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
	resposta=$(echo "SPAM $ticket" | nc -w 5 54.94.137.168 9877)

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
