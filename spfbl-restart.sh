#!/bin/bash
export PATH=/sbin:/usr/sbin:/bin:/usr/bin:/usr/local/sbin:/usr/local/bin

if [ "$(ps auxwf | grep SPFBL | wc -l)" -eq "1" ]; then
    echo $(echo "SHUTDOWN" | nc 127.0.0.1 9875)
    java -jar /opt/spfbl/dist/SPFBL.jar 9875 512 >> /var/log/spfbl/activity.log &
fi
