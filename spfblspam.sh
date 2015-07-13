#!/bin/bash
#
# Este é um script que faz a reclação de SPAM ao serviço SPFBL.
#
# Este programa procura e extrai o ticket de consulta SPFBL de uma mensagem de e-mail.
# Com posse do ticket, ele envia a reclamação ao serviço SPFBL para contabilização de reclamação.
#
# Parâmetros de entrada:
#  1. file: o arquivo de e-mail.
#

file=$1

# Extrai o ticket incorporado à mensagem.
ticket=$(grep -Pom 1 "^Received-SPFBL: (PASS|SOFTFAIL|NEUTRAL|NONE) \K([0-9a-zA-Z\+/=]+)$" $file)

if [ $? -eq 0 ]; then

        # Registra reclamação SPFBL.
	resposta=$(echo "SPAM $ticket" | nc -w 3 54.94.137.168 9877)
	
	if [[ $resposta == "" ]]; then
	
		echo "A reclamação SPFBL não foi enviada por timeout."
		
	elif [[ $resposta == "OK"* ]]; then
	
		echo "Reclamação SPFBL enviada com sucesso."
	
	else
	
		echo "A reclamação SPFBL não foi enviada: $resposta"
	
	fi
	
else

	echo "Nenhum ticket SPFBL foi encontrado na mensagem."

fi
