#!/bin/bash
#
# Este é um script que detalha o resultado de uma consulta SPFBL sem gerar ticket.
#
# Atenção! Para utilizar este serviço, solicite a liberação das consultas 
# no servidor 54.94.137.168 através do endereço leandro@allchemistry.com.br 
# ou altere o IP 54.94.137.168 deste script para seu servidor SPFBL próprio.
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
#    10: parâmetros inválidos.
#

ip=$1
email=$2
helo=$3

qualifier=$(echo "CHECK $ip $email $helo" | nc -w 3 54.94.137.168 9877)

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
