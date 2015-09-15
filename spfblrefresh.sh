#!/bin/bash
#
# Este é um script em BASH que atualiza um registro SPF no cache do SPFBL.
#
# Atenção! Para utilizar este serviço, solicite a liberação das consultas 
# no servidor 54.94.137.168 através do endereço leandro@allchemistry.com.br 
# ou altere o IP 54.94.137.168 deste script para seu servidor SPFBL próprio.
#
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
#

hostname=$1

response=$(echo "REFRESH $hostname" | nc 54.94.137.168 9877)

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
