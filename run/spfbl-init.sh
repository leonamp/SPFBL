#!/bin/sh
####
# SPFBL Script de Controle do SPFBL
# Author: Roberto Almeida <falecom@robertoalmeida.com>
####

start() {
    cd /opt/spfbl/
    /usr/bin/java -jar -Xms512m -Xmx1536m /opt/spfbl/SPFBL.jar 2>&1 &
}

stop() {
    echo "STORE" | nc 127.0.0.1 9875
    echo "SHUTDOWN" | nc 127.0.0.1 9875
}

case "$1" in
    start)
        echo "[start] Iniciando serviço do SPFBL"
        start
    ;;
    stop)
        echo "[stop] Parando o serviço do SPFBL"
        stop
    ;;
    restart)
        echo "[restart] Reiniciando serviço do SPFBL"
        stop
        start
    ;;
    *)
        echo "*** Usage: $0 {start|stop|restart}"
        exit 1
esac

exit 0
