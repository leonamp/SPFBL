#!/bin/bash

### BEGIN INIT INFO
# Provides:          spfbl
# Required-Start:    $remote_fs $syslog
# Required-Stop:     $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: SPFBL - p2p anti-spam service
# Description:       SPFBL - p2p anti-spam service
### END INIT INFO

##########################################
#       Gerenciador de start / stop      #                  
#               SPFBL                    #
##########################################

PATH=/bin:/usr/bin:/sbin:/usr/sbin

if [ -f /etc/lsb-release ]; then
  . /etc/lsb-release
else
  . /etc/init.d/functions
fi

start() {
    ret=0
    echo -n "[SPFBL] Starting... "

    if [ "$(ps auxwf | grep java | grep SPFBL | grep -v grep | wc -l)" -eq "0" ]; then
	cd /opt/spfbl/
        # Log personalizado caso nao deseja utilizar logrotate.d/spfbl
        if [ ! -f /etc/logrotate.d/spfbl ]; then
            /usr/bin/java -jar -Xms512m -Xmx1536m /opt/spfbl/SPFBL.jar &
        else
            /usr/bin/java -jar -Xms512m -Xmx1536m /opt/spfbl/SPFBL.jar &
        fi
        sleep 5
        ret=$(ps auxwf | grep java | grep SPFBL | grep -v grep | wc -l)
        if [ "$ret" -eq "0" ]; then
            echo -n "Error"
        fi
    else
       echo -n "Already started. "
       ret=1
    fi
    [ "$ret" -eq "1" ] && success || failure
    echo
}

stop() {
    ret=0
    echo -n "[SPFBL] Stopping... "
    if [ "$(ps auxwf | grep java | grep SPFBL | grep -v grep | wc -l)" -eq "1" ]; then
        response=$(echo "SHUTDOWN" | nc 127.0.0.1 9875)
        sleep 5
        if [[ $response == "" ]]; then
            # Encerro o processo via kill pois certamente esta trancado
            kill $(ps aux | grep SPFBL | grep java | grep -v grep | awk '{print $2}')
            ret=0
        elif [[ $response == "OK" ]]; then
            ret=0
        fi
    else
       echo -n "Already stopped. "
       ret=1
    fi
    [ "$ret" -eq "0" ] && success || failure
    echo
}

restart() {
    stop
    start
}

status() {
    if [ "$(ps auxwf | grep java | grep SPFBL | grep -v grep | wc -l)" -eq "1" ]; then
        echo -n "[SPFBL] Server is running"
        echo
        ps axwuf | grep -E "PID|SPFBL" | grep -v grep
    else
        echo -n "[SPFBL] Server is not running"
        echo
    fi
}

case "$1" in
    start)
        start
    ;;
    stop)
        stop
    ;;
    restart)
        restart
    ;;
    status)
        status
    ;;
    *)
        echo "Usage: /etc/init.d/spfbl {start|stop|restart|status}"
        exit 1
    ;;
esac

exit 0
