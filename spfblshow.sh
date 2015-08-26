#!/bin/bash
#
# Este é um script em BASH que visualiza a lista arbitrária do SPFBL.
#
# Atenção! Para utilizar este serviço, solicite a liberação das consultas 
# no servidor 54.94.137.168 através do endereço leandro@allchemistry.com.br 
# ou altere o IP 54.94.137.168 deste script para seu servidor SPFBL próprio.
#
# Parâmetros de entrada: nenhum.
#
# Códigos de saída:
#
#    0: visualizado com sucesso.
#    1: erro ao tentar visualizar bloqueio.
#    2: timeout de conexão.
#

sender=$1

response=$(echo "BLOCK SHOW" | nc -w 3 54.94.137.168 9877)

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
