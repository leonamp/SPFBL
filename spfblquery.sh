#!/bin/bash
#
# Este é um script em BASH que retorna o resultado SPFBL
# através de uma implementação em servidor externo.
#
# Atenção! Para utilizar este serviço, solicite a liberação das consultas 
# no servidor 54.94.137.168 através do endereço leandro@allchemistry.com.br 
# ou altere o IP 54.94.137.168 deste script para seu servidor SPFBL próprio.
#
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
#

ip=$1
email=$2
helo=$3
recipient=$4

qualifier=$(echo "SPF '$ip' '$email' '$helo' '$recipient'" | nc -w 5 54.94.137.168 9877)

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
	
elif [[ $qualifier == "FAIL" ]]; then

	exit 3
	
elif [[ $qualifier == "SOFTFAIL "* ]]; then

	exit 4
	
elif [[ $qualifier == "NEUTRAL "* ]]; then

	exit 1
	
else

	exit 0
	
fi
