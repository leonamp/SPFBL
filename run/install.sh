#!/bin/bash

##########################################
# Gerenciador de instalação e remoção    #                  
#               SPFBL                    #
##########################################

################################ desinstalação

V='\033[01;31m'
D='\033[01;32m'
R='\033[0m'

if [ "$1" == "--uninstall" ]; then
    echo -e "${D}Iniciando processo de remocao do SPFBL!${R}"
    echo "Desligando servidor SPFBL..."
    echo "SHUTDOWN" | nc 127.0.0.1 9875
    echo -n "Removendo /opt/spfbl"
    rm -rf /opt/spfbl
    [ ! -d /opt/spfbl ] && success || failure
    echo -n "Removendo /etc/spfbl"
    rm -rf /etc/spfbl
    [ ! -d /etc/spfbl ] && success || failure
    echo -n "Removendo /usr/src/SPFBL"
    rm -rf /usr/src/SPFBL
    [ ! -d /usr/src/SPFBL ] && success || failure
    echo -n "Removendo /etc/logrotate.d/spfbl"
    rm -rf /etc/logrotate.d/spfbl
    [ ! -f /etc/logrotate.d/spfbl ] && success || failure
    echo -n "Removendo /var/log/spfbl"
    rm -rf /var/log/spfbl
    [ ! -d /var/log/spfbl ] && success || failure
    echo -n "Removendo /etc/init.d/spfbl"
    rm -rf /etc/init.d/spfbl
    [ ! -f /etc/init.d/spfbl ] && success || failure

    #########################################################################################
    # ABAIXO, SCRIPT DE INSTALAÇÃO EM PLATAFORMA BASEADA EM DEBIAN
    #########################################################################################

    elif [ "$1" == "--install" ]; then
    echo -e "${D}Iniciando processo de instalacao do SPFBL!${R}"
    cd /usr/src

    echo "Acessando pasta $PWD"
    echo -n "Precisamos detectar a plataforma e instalar o \n git, nc, wget, unzip e pacotes java"
    if [ -f /etc/lsb-release ]; then
    . /etc/lsb-release
    OS=$DISTRIB_ID
    VER=$DISTRIB_RELEASE
    echo -e "${V}Plataforma baseada em Debian: $OS ${R}"
    . /lib/lsb/init-functions
    apt-get update >/dev/null && apt-get install -y unzip wget git logrotate default-jre >/dev/null

    # Verifica se há instalação e instala
    if [ -d /opt/spfbl ]; then
        data=`date +"%Y%m%d%H%M%S"`
        echo -e "${V}Localizei arquivos antigos. \nRenomeando para $PWD/SPFBL-$data$ \nRenomeando /opt/spfbl-$data\nRenomeando /etc/spfbl-$data\nRemovendo /etc/logrotate.d/spfbl\nRemovendo /var/log/spfbl\nRemovendo /etc/init.d/spfbl{R}"
        mv /usr/src/SPFBL /usr/src/SPFBL-$data
        mv /opt/spfbl /opt/spfbl-$data
        mv /etc/spfbl /etc/spfbl-$data
        rm -rf /etc/logrotate.d/spfbl
        rm -rf /var/log/spfbl
        [ -d /usr/src/SPFBL-$data ] && success || failure echo
    fi

    cd /usr/src && git clone https://github.com/leonamp/SPFBL.git
    echo -n "Clonando SPFBL a partir do Github... "
    [ -d /usr/src/SPFBL ] && success || failure echo
    
    if [ -d /usr/src/SPFBL ]; then
        chmod a+x SPFBL/client/*.sh
        chmod a+x SPFBL/run/*
    fi
    
    # Movendo arquivos
    if [ ! -d /etc/spfbl ]; then
        echo -n "Criando /etc/spfbl .. "
        mkdir -p /etc/spfbl
        mv SPFBL/client/spfbl.sh /opt/spfbl/bin/
        ln -sf /opt/spfbl/bin/spfbl.sh /usr/local/bin/spfbl
        [ -d /etc/spfbl ] && success || failure echo
    fi
    
    # Create spfbl folder
    if [ ! -d /opt/spfbl ]; then
        echo -n "Criando /opt/spfbl .. "
        mkdir -p /opt/spfbl/bin
        mv SPFBL/run/spfbl-init.sh /opt/spfbl/bin/
        # Store SPFBL core to /opt
        mv SPFBL/dist/* /opt/spfbl/
        mv SPFBL/run/spfbl.conf /opt/spfbl/
        ln -sf /opt/spfbl/spfbl.conf /etc/spfbl/spfbl.conf
        mv -Rf SPFBL/lib/* /opt/spfbl/
        mv -Rf SPFBL/data/* /opt/spfbl/
        mv  SPFBL/doc/* /opt/spfbl/
        mv SPFBL/README.md /opt/spfbl/doc/
        [ -d /opt/spfbl ] && success || failure echo
    fi
    
    # Criando pasta de logs
    if [ ! -d /var/log/spfbl ]; then
        echo -n "Criando /var/log/spfbl .. "
        mkdir -p /var/log/spfbl
        [ -d /var/log/spfbl ] && success || failure echo
    fi    

    # Configurando auto-boot
    echo -n "Configurando auto-boot"
    mv SPFBL/run/spfbl-init-noarch.sh /etc/init.d/spfbl
    chmod a+x /etc/init.d/spfbl
    update-rc.d spfbl defaults 100
    [ -f /etc/init.d/spfbl ] && success || failure echo
    
    # Configurar log rotation
    echo -n "Configurando rotacao de logs"
    mv SPFBL/run/spfbl-rotate /etc/logrotate.d/spfbl
    [ -f /etc/logrotate.d/spfbl ] && success || failure echo
    
    # Setando variáveis do ambiente para o auto-updater

    touch /root/.spfbl-install
    echo -en "** NAO REMOVA ESTE ARQUIVO! \nELE SERA UTILIZADO PELO SPFBL \nPARA ATUALIZACAO AUTOMATICA**\n" >> /root/.spfbl-install 
    echo -en $"\nBASE_FOLDER=/opt/spfbl\nCONF_FILE=/etc/spfbl/spfbl.conf\nSTART_FILE=/etc/init.d/spfbl\nLR_FILE=/etc/logrotate.d/spfbl\nLOG_FOLDER=/var/log/spfbl\n" >> /root/.spfbl-install 

    # Limpando pasta temporária
    rm -rf /usr/src/SPFBL

    # Iniciando
    
    /etc/init.d/spfbl start
    
    if [ "$(ps auxwf | grep SPFBL | grep -v grep | wc -l)" -eq "1" ]; then
        echo "-------------------------------------------"
        echo " Feito, seu servidor SPFBL esta iniciando! "
        echo "-------------------------------------------"
    else
        echo "Oops, algum erro ocorreu!"
    fi 
    
    #########################################################################################
    # ABAIXO, SCRIPT DE INSTALAÇÃO EM PLATAFORMA BASEADA EM RHEL
    #########################################################################################

    elif [ -f /etc/redhat-release ] && [ "$1" == "--install" ]; then
    OS(){
        cat '/etc/redhat-release'
    }
    . /etc/init.d/functions
    # Iniciando processo de instalação em plataforma rhel based
    echo -e "${V}Plataforma baseada em RHEL: $(OS) ${R}"

    echo "Acessando pasta $PWD"
    echo
    echo -n "Instalando git, nc, wget, unzip e pacotes java"
            yum -y upgrade >/dev/null && yum -y install git nc unzip logrotate wget java-1.8.0-openjdk >/dev/null
        [ "$(rpm -q git java-1.8.0-openjdk wget unzip nc | wc -l)" -eq "5" ] && success || failure echo    

    # Verifica se há instalação e instala
    if [ -d /opt/spfbl ]; then
        data=`date +"%Y%m%d%H%M%S"`
        echo -e "${V}Localizei arquivos antigos. \nRenomeando /opt/spfbl-$data\nRenomeando /etc/spfbl-$data{R}"
        mv /usr/src/SPFBL /usr/src/SPFBL-$data
        mv /opt/spfbl /opt/spfbl-$data
        mv /etc/spfbl /etc/spfbl-$data
        [ -d /opt/spfbl-$data ] && success || failure echo
    fi

    cd /usr/src && git clone https://github.com/leonamp/SPFBL.git
    echo -n "Clonando SPFBL a partir do Github... "
    [ -d /usr/src/SPFBL ] && success || failure echo
    
    if [ -d /usr/src/SPFBL ]; then
        chmod a+x SPFBL/client/*.sh
        chmod a+x SPFBL/run/*
    fi
    
    # Movendo arquivos
    if [ ! -d /etc/spfbl ]; then
        echo -n "Criando /etc/spfbl .. "
        mkdir -p /etc/spfbl
        mv SPFBL/client/spfbl.sh /opt/spfbl/bin/
        ln -sf /opt/spfbl/bin/spfbl.sh /usr/local/bin/spfbl
        [ -d /etc/spfbl ] && success || failure echo
    fi
    
    # Create spfbl folder
    if [ ! -d /opt/spfbl ]; then
        echo -n "Criando /opt/spfbl .. "
        mkdir -p /opt/spfbl/bin
        mv SPFBL/run/spfbl-init.sh /opt/spfbl/bin/
        # Store SPFBL core to /opt
        mv SPFBL/dist/* /opt/spfbl/
        mv SPFBL/run/spfbl.conf /opt/spfbl/
        ln -sf /opt/spfbl/spfbl.conf /etc/spfbl/spfbl.conf
        mv -Rf SPFBL/lib/* /opt/spfbl/
        mv -Rf SPFBL/data/* /opt/spfbl/
        mv  SPFBL/doc/* /opt/spfbl/
        mv SPFBL/README.md /opt/spfbl/doc/
        [ -d /opt/spfbl ] && success || failure echo
    fi
    
    # Criando pasta de logs
    if [ ! -d /var/log/spfbl ]; then
        echo -n "Criando /var/log/spfbl .. "
        mkdir -p /var/log/spfbl
        [ -d /var/log/spfbl ] && success || failure echo
    fi      
      
    # Configurando auto-boot
    echo -n "Configurando auto-boot"
    mv SPFBL/run/spfbl-init-noarch /etc/init.d/spfbl
    chmod a+x /etc/init.d/spfbl    
    chkconfig --add spfbl
    chkconfig spfbl on
    [ -f /etc/init.d/spfbl ] && success || failure echo

    
    # Configurar log rotation
    echo -n "Configurando rotacao de logs"
    mv SPFBL/run/spfbl-rotate /etc/logrotate.d/spfbl
    [ -f /etc/logrotate.d/spfbl ] && success || failure echo

    # Setando variáveis do ambiente para o auto-updater

    touch /root/.spfbl-install
    echo -en "** NAO REMOVA ESTE ARQUIVO! \nELE SERA UTILIZADO PELO SPFBL \nPARA ATUALIZACAO AUTOMATICA**\n" >> /root/.spfbl-install 
    echo -en $"\nBASE_FOLDER=/opt/spfbl\nCONF_FILE=/etc/spfbl/spfbl.conf\nSTART_FILE=/etc/init.d/spfbl\nLR_FILE=/etc/logrotate.d/spfbl\nLOG_FOLDER=/var/log/spfbl\n" >> /root/.spfbl-install 

    # Limpando pasta temporária
    rm -rf /usr/src/SPFBL
    
    # Iniciando
    /etc/init.d/spfbl start
    
    if [ "$(ps auxwf | grep SPFBL | grep -v grep | wc -l)" -eq "1" ]; then
        echo "-------------------------------------------"
        echo " Feito, seu servidor SPFBL esta iniciando! "
        echo "-------------------------------------------"
    else
        echo "Oops, algum erro ocorreu!"
    fi
fi


    #########################################################################################
    # Abaixo estão instruções que podem ser usadas em necessidade futura para
    # reconhecimento de arquitetura e de sistema debian específico
    #########################################################################################

    # Identifica se eh 32 ou 64 bits. Nao eh necessario pro spfbl ainda.. 
    # mas se um dia for
    #
    # ARQ=$(uname -m | sed 's/x86_//;s/i[3-6]86/32/')

    # Não é necessário uma instalação específica para Debain..
    # mas se um dia for
    #
    # elif [ -f /etc/debian_version ]; then
    # OS=Debian
    # VER=$(cat /etc/debian_version)
