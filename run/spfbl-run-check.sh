#!/bin/bash
#
# Verifica se o serviço esta ativo
#
# Salve este arquivo em: /opt/spfbl/client
#
# adicione em: /etc/crontab
#
# 00-59/15 *	* * *	root	/opt/spfbl/client/spfbl-run-check.sh
#
# Execute os comandos:
#
# chmod a+x /opt/spfbl/client/spfbl-run-check.sh
#
# service cron restart
#
# atualizado em 03/09/2016 23:45
#
if [ "$(ps auxwf | grep java | grep SPFBL | grep -v grep | wc -l)" -eq "0" ]; then
cd /opt/spfbl/
java -jar SPFBL.jar &
else
echo
echo -n "The service SPFBL is already running... "
echo
fi
