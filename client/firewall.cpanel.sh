#!/bin/bash
#
# Firewall for SPFBL client.
# Author: Leandro Carlos Rodrigues <leandro@spfbl.net>
# Contribuição de Luciano Zanita <lucianozanita@advenhost.com.br>
#
# Instala o atualizador /usr/local/bin/spfbl-firewall-update,
# agenda ele de hora em hora, integra com o CSF e roda a primeira vez.

export PATH=/sbin:/usr/sbin:/bin:/usr/bin:/usr/local/sbin:/usr/local/bin

FIREWALL="/usr/local/bin/spfbl-firewall"
UPDATE="/usr/local/bin/spfbl-firewall-update"

if ! command -v curl > /dev/null 2>&1; then
    echo "curl não encontrado." >&2
    exit 1
fi

# Atualizador: baixa o firewall, valida e só então substitui e executa.
cat > "${UPDATE}.tmp" << 'EOF'
#!/bin/bash
#
# Atualização do firewall do SPFBL (instalado pelo firewall.cpanel.sh).

export PATH=/sbin:/usr/sbin:/bin:/usr/bin:/usr/local/sbin:/usr/local/bin

FIREWALL="/usr/local/bin/spfbl-firewall"
URL="https://matrix.spfbl.net/spfbl/"

TEMP=$(mktemp "${FIREWALL}.XXXXXX") || exit 1
trap 'rm -f "$TEMP"' EXIT

# -4: a liberação do cliente no SPFBL é pelo IPv4.
# -f: erro HTTP (403 cliente não liberado, 503 etc.) não gera arquivo.
if ! echo "FIREWALL" | curl -4 -s -f --connect-timeout 10 -m 300 \
        --data-binary @- "$URL" > "$TEMP"; then
    echo "Não foi possível obter o firewall do SPFBL." >&2
    exit 2
fi

# Só aceita um script bash: qualquer outra resposta não pode ser executada.
if [ "$(head -n 1 "$TEMP")" != "#!/bin/bash" ]; then
    echo "Resposta inválida do SPFBL." >&2
    exit 3
fi

chmod 755 "$TEMP"
mv -f "$TEMP" "$FIREWALL"
trap - EXIT

"$FIREWALL" > /dev/null 2>&1
EOF
chmod 755 "${UPDATE}.tmp"
mv -f "${UPDATE}.tmp" "$UPDATE"

# Agenda de hora em hora. Recria o atalho se ele não existir
# ou se estiver quebrado (apontando para arquivo inexistente).
if [ ! -e "/etc/cron.hourly/spfbl-firewall-update" ]; then
    ln -sf "$UPDATE" /etc/cron.hourly/spfbl-firewall-update
fi

# Verificando se o cliente possui CSF
if [ -d "/etc/csf/" ]; then
    if [ -e "/etc/csf/csfpost.sh" ]; then
        # Adicionando a linha ao arquivo csfpost.sh, se ainda não existir
        if ! grep -Fxq "$FIREWALL" "/etc/csf/csfpost.sh"; then
            sed -i -e '$a\'"$FIREWALL" "/etc/csf/csfpost.sh"
        fi
    else
        # Caso não exista, vamos criá-lo
        echo '#!/bin/bash' > "/etc/csf/csfpost.sh"
        echo "$FIREWALL" >> "/etc/csf/csfpost.sh"
    fi
    chmod +x /etc/csf/csfpost.sh
fi

# Primeira atualização
"$UPDATE"
