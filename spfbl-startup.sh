#!/bin/bash
export PATH=/sbin:/usr/sbin:/bin:/usr/bin:/usr/local/sbin:/usr/local/bin

if [ "$(ps auxwf | grep SPFBL | wc -l)" -lt "1" ]; then
    cd /var/lib/spfbl
    java -jar /opt/spfb/dist/SPFBL.jar 9875 512 >> /var/log/spfbl/activity.log &
fi
