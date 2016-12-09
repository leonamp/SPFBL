#!/bin/bash

TODAY=`date +%Y-%m-%d`
LOGPATH=/var/log/spfbl/

BLOCKED=$(grep -c BLOCKED "$LOGPATH"spfbl."$TODAY".log)
FAIL=$(grep -c ' FAIL' "$LOGPATH"spfbl."$TODAY".log)
FLAG=$(grep -c FLAG "$LOGPATH"spfbl."$TODAY".log)
GREYLIST=$(grep -c GREYLIST "$LOGPATH"spfbl."$TODAY".log)
HOLD=$(grep -c HOLD "$LOGPATH"spfbl."$TODAY".log)
INTERRUPTED=$(grep -c INTERRUPTED "$LOGPATH"spfbl."$TODAY".log)
INVALID=$(grep -c INVALID "$LOGPATH"spfbl."$TODAY".log)
LISTED=$(grep -c LISTED "$LOGPATH"spfbl."$TODAY".log)
NEUTRAL=$(grep -c NEUTRAL "$LOGPATH"spfbl."$TODAY".log)
NONE=$(grep -c NONE "$LOGPATH"spfbl."$TODAY".log)
NXDOMAIN=$(grep -c NXDOMAIN "$LOGPATH"spfbl."$TODAY".log)
PASS=$(grep -c PASS "$LOGPATH"spfbl."$TODAY".log)
SOFTFAIL=$(grep -c SOFTFAIL "$LOGPATH"spfbl."$TODAY".log)
SPAMTRAP=$(grep -c SPAMTRAP "$LOGPATH"spfbl."$TODAY".log)
TIMEOUT=$(grep -c TIMEOUT "$LOGPATH"spfbl."$TODAY".log)

TOTALES=$(echo $BLOCKED + $FLAG + $GREYLIST + $HOLD + $LISTED + $NXDOMAIN + $PASS + $TIMEOUT + $NONE + $SOFTFAIL + $NEUTRAL + $INTERRUPTED + $SPAMTRAP + $INVALID + $FAIL | bc)

echo '=========================='
echo '= SPFBL Daily Statistics ='
echo '=========================='
echo '     PASS:' $(echo "scale=0;($PASS*100) / $TOTALES" | bc)'% - '"$PASS"
echo '  BLOCKED:' $(echo "scale=0;($BLOCKED*100) / $TOTALES" | bc)'% - '"$BLOCKED"
echo '     FAIL:' $(echo "scale=0;($FAIL*100) / $TOTALES" | bc)'% - '"$FAIL"
echo '     FLAG:' $(echo "scale=0;($FLAG*100) / $TOTALES" | bc)'% - '"$FLAG"
echo ' GREYLIST:' $(echo "scale=0;($GREYLIST*100) / $TOTALES" | bc)'% - '"$GREYLIST"
echo '     HOLD:' $(echo "scale=0;($HOLD*100) / $TOTALES" | bc)'% - '"$HOLD"
echo ' INTRRPTD:' $(echo "scale=0;($INTERRUPTED*100) / $TOTALES" | bc)'% - '"$INTERRUPTED"
echo '  INVALID:' $(echo "scale=0;($INVALID*100) / $TOTALES" | bc)'% - '"$INVALID"
echo '   LISTED:' $(echo "scale=0;($LISTED*100) / $TOTALES" | bc)'% - '"$LISTED"
echo '  NEUTRAL:' $(echo "scale=0;($NEUTRAL*100) / $TOTALES" | bc)'% - '"$NEUTRAL"
echo '     NONE:' $(echo "scale=0;($NONE*100) / $TOTALES" | bc)'% - '"$NONE"
echo ' NXDOMAIN:' $(echo "scale=0;($NXDOMAIN*100) / $TOTALES" | bc)'% - '"$NXDOMAIN"
echo ' SOFTFAIL:' $(echo "scale=0;($SOFTFAIL*100) / $TOTALES" | bc)'% - '"$SOFTFAIL"
echo ' SPAMTRAP:' $(echo "scale=0;($SPAMTRAP*100) / $TOTALES" | bc)'% - '"$SPAMTRAP"
echo '  TIMEOUT:' $(echo "scale=0;($TIMEOUT*100) / $TOTALES" | bc)'% - '"$TIMEOUT"
echo '  ----------------------'
echo '    TOTAL:' $(echo "scale=0;($TOTALES*100) / $TOTALES" | bc)'% - '"$TOTALES"
echo '=========================='
