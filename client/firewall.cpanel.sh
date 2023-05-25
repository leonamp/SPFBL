#!/bin/bash
#
# Firewall for SPFBL client.
# Author: Leandro Carlos Rodrigues <leandro@spfbl.net>
# Contribuição de Luciano Zanita <lucianozanita@advenhost.com.br>

# Gerando lista de Firewall
echo "FIREWALL" | nc -w 60 54.233.253.229 9877 > /usr/local/bin/spfbl-firewall
# Aplicando permissão
chmod +x /usr/local/bin/spfbl-firewall
# Verifica se já existe o atalho pra o cron de 1H
if [ -e "/etc/cron.hourly/spfbl-firewall-update" ]; then
    # Caso já exista o arquivo de cron, ignoramos
    :
else
    # Aplicando permissão
    chmod +x /usr/local/bin/spfbl-firewall-update
    # Caso não exista, vamos adicionar agora o atalho para o cron
    ln -s /usr/local/bin/spfbl-firewall-update /etc/cron.hourly/spfbl-firewall-update
fi
# Verificando se o cliente possui CSF
if [ -d "/etc/csf/" ]; then
    # Verificando se o cliente ja possui o csfpost
    if [ -e "/etc/csf/csfpost.sh" ]; then
        if grep -Fxq '/usr/local/bin/spfbl-firewall' "/etc/csf/csfpost.sh"; then
            # Caso a linha ja existe, vamos ignorar
            :
	else
            # Adicionando a linha ao arquivo csfpost.sh
            echo '/usr/local/bin/spfbl-firewall' >> "/etc/csf/csfpost.sh"
        fi
    else
        # Caso não existir, vamos cria-lo
        # Adicionando cabeçario de shell
        echo '#!/bin/bash' > "/etc/csf/csfpost.sh"
        # Adicionando código executavel
        echo '/usr/local/bin/spfbl-firewall' >> "/etc/csf/csfpost.sh"
    fi
    # Vamos agora aplicar a permissão
    chmod +x /etc/csf/csfpost.sh
else
    # Caso o CSF não esteja instalado, apenas ignoramos
    :
fi
# Executa o Firewall para atualização
/usr/local/bin/spfbl-firewall
