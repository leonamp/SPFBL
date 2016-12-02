#!/bin/sh

V='\033[01;31m'
D='\033[01;32m'
R='\033[0m'

echo "\n${V}SPFBL Updater v0.1 release 06/11/2016 ${R}"

BACKUP_DIR=/opt/spfbl/backup
TMP_DIR=/tmp/spfbl-update
AGORA=`date +%y-%m-%d-%H-%M`
URLBETA=https://github.com/SPFBL/beta-test/raw/master/SPFBL.jar
URLSTABLE=https://github.com/SPFBL/stable/raw/master/SPFBL.jar
URLMASTER=https://github.com/SPFBL/stable/archive/master.zip

if [ -f /etc/lsb-release ]; then
    . /etc/lsb-release
    else
    . /etc/init.d/functions
fi 

if [ ! -d "$TMP_DIR" ]; then
    mkdir -p "$TMP_DIR"
    else
    rm -Rf "$TMP_DIR"/*
fi

atualizaSistema(){

        if [ ! -d "$BACKUP_DIR" ]; then
            mkdir -p "$BACKUP_DIR"
        fi

        #Compara Arquivos
        var1=$(stat -c%s /tmp/spfbl-update/SPFBL.jar)
        var2=$(stat -c%s /opt/spfbl/SPFBL.jar)

    if [ "$var1" != "$var2" ]; then
        #Necessario atualizar
        echo "${D}\n Os arquivos são diferentes, o SPFBL será atualizado${R}"
        fazBackup
        
        echo "${D}\n Verificando LIBs necessárias...${R}"
        cd "$TMP_DIR"
        wget "$URLMASTER" -O /tmp/spfbl-update/master.zip > /dev/null
        unzip master.zip > /dev/null
        cp -n /tmp/spfbl-update/stable-master/lib/* /opt/spfbl/lib

        #Atualiza SPFBL.jar
        echo "Movendo o arquivo SPFBL.jar"
        echo
            if [ ! -f "/tmp/spfbl-update/SPFBL.jar" ]; then
                echo "Can't download URL/file, please check initial config."
                exit
            fi 

        echo "****   Current Version   ****"
        mostraVersao

        echo "**** SPFBL - Shutdown    ****"
        echo "SHUTDOWN" | nc 127.0.0.1 9875

        echo "**** SPFBL - Copy new v. ****"
        mv /opt/spfbl/SPFBL.jar $BACKUP_DIR/SPFBL.jar-"$AGORA"
        mv /tmp/spfbl-update/SPFBL.jar /opt/spfbl/SPFBL.jar
        echo "OK"

        echo "**** SPFBL - Starting    ****"
        iniciaSPFBL
        sleep 30

        if [ "$(ps auxwf | grep java | grep SPFBL | grep -v grep | wc -l)" -eq "1" ]; then
            echo "OK - SERVICE ONLINE"
        else
            echo "FALHA - Verifique os logs e se necessario reverta o backup"
        fi

        echo "**** SPFBL - New Version ****"
        mostraVersao

        echo "****  F I N I S H E D !  ****"
        echo "Done."
        
    else
        
        echo "Os arquivos são iguais, nenhum procedimento foi efetuado."

    fi

} 

iniciaSPFBL(){

    if [ -f /etc/init.d/spfbl ]; then
    /etc/init.d/spfbl start
    else
    cd /opt/spfbl
    java -jar SPFBL.jar &
    fi
}

iniciaMta(){

        echo "**** !  Starting MTA   ! ****"
        service "$2" start
        echo "OK"

}

paraMta(){

        echo "**** !!  Stoping MTA  !! ****"
        service "$2" stop
        echo "OK"

}

fazBackup(){

    echo "${V} **** SPFBL - Store cache ****${R}" 
    echo "STORE" | nc 127.0.0.1 9875

    echo "${V} **** SPFBL - Backup      ****${R}"
    echo "DUMP" | nc 127.0.01 9875 > "$BACKUP_DIR"/spfbl-dump-"$AGORA".txt
    tar -zcf "$BACKUP_DIR"/spfbl-backup-"$AGORA".tar /opt/spfbl --exclude "$BACKUP_DIR" &> /dev/null
    echo "BACKUP OK"

}

mostraVersao(){

    echo "VERSION" | nc 127.0.0.1 9875

}

downloadBeta(){

    cd /tmp/spfbl-update/
    wget "$URLBETA" -O /tmp/spfbl-update/SPFBL.jar > /dev/null

}

downloadStable(){

    cd /tmp/spfbl-update/
    wget "$URLSTABLE" -O /tmp/spfbl-update/SPFBL.jar > /dev/null

}


############

mostraHelp(){
    echo "${D}\nParametros necessarios: ${R}"
    echo "${D}\n Selecione o canal: stable ou beta ${R}" 
    echo "${D}   stable: versao estavel (opcao recomendada) ${R}" 
    echo "${D}   beta: versao de teste ${R}"
    echo "${D}\n Selecione o serviço MTA: nenhum ou exim ou postix ${R}" 
    echo "${D}\n Exemplo: ${R}"
    echo "${D}\n ./spfbl-update.sh stable nenhum \n ${R}"
    exit
}

case $2 in
  'exim'|'postfix')
    paraMTA;;
  nenhum)
     echo "Nenhum MTA selecionado.";;
  *)
    mostraHelp
    exit;;
esac


case $1 in
  beta)
    downloadBeta;;
  stable)
    downloadStable;;
  *)
    mostraHelp
    exit;;
esac

atualizaSistema

case $2 in
  'exim'|'postfix')
    iniciaMTA;;
  *)
    exit;;
esac
