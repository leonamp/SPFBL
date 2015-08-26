#!/bin/bash
#
# Este é um script em BASH que remove um bloqueio de remetente na lista arbitrária do SPFBL.
#
# Atenção! Para utilizar este serviço, solicite a liberação das consultas 
# no servidor 54.94.137.168 através do endereço leandro@allchemistry.com.br 
# ou altere o IP 54.94.137.168 deste script para seu servidor SPFBL próprio.
#
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
#

sender=$1

response=$(echo "BLOCK DROP $sender" | nc -w 3 54.94.137.168 9877)

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
