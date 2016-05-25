#!/bin/bash

##########################################
# Gerenciador de instalação e remoção    #                  
#               SPFBL                    #
##########################################

V='\033[01;31m'
D='\033[01;32m'
R='\033[0m'
echo -e "${D}Versao do instalador: 0.1 ${R}"

if [ "$1" == "--uninstall" ]; then
    
    if [ -f /etc/lsb-release ]; then
    . /etc/lsb-release
    else
    . /etc/init.d/functions
    fi    
    
    echo -e "${D}Iniciando processo de remocao do SPFBL!${R}"
    echo "Desligando servidor SPFBL..."
    echo "SHUTDOWN" | nc 127.0.0.1 9875
    echo "Removendo /opt/spfbl"
    rm -rf /opt/spfbl
    [ ! -d /opt/spfbl ] && success || failure
    echo "Removendo /etc/spfbl"
    rm -rf /etc/spfbl
    [ ! -d /etc/spfbl ] && success || failure
    echo "Removendo /usr/src/SPFBL"
    rm -rf /usr/src/SPFBL
    [ ! -d /usr/src/SPFBL ] && success || failure
    echo "Removendo /etc/logrotate.d/spfbl"
    rm -rf /etc/logrotate.d/spfbl
    [ ! -f /etc/logrotate.d/spfbl ] && success || failure
    echo "Removendo /var/log/spfbl"
    rm -rf /var/log/spfbl
    [ ! -d /var/log/spfbl ] && success || failure
    echo "Removendo /etc/init.d/spfbl"
    rm -rf /etc/init.d/spfbl
    [ ! -f /etc/init.d/spfbl ] && success || failure
    echo
    echo
fi

instalaDebian(){ 

    apt-get update >/dev/null && apt-get install -y unzip wget git logrotate default-jre >/dev/null
}

instalaRedhat(){ 

    yum -y upgrade >/dev/null && yum -y install git nc unzip logrotate wget java-1.8.0-openjdk >/dev/null
        [ "$(rpm -q git java-1.8.0-openjdk wget unzip nc | wc -l)" -eq "5" ] && success || failure echo   
}

preInstall(){

    # Verifica se há instalação e instala
    if [ -d /opt/spfbl ]; then
        data=`date +"%Y%m%d%H%M%S"`
        echo -e "${V}Localizei arquivos antigos. \nRenomeando para $PWD/SPFBL-$data$ \nRenomeando /opt/spfbl-$data\nRenomeando /etc/spfbl-$data\nRemovendo /etc/logrotate.d/spfbl\nRemovendo /var/log/spfbl\nRemovendo /etc/init.d/spfbl{R}"
            if [ -d /usr/src/SPFBL ]; then
            mv /usr/src/SPFBL /usr/src/SPFBL-$data
            fi
        mv /opt/spfbl /opt/spfbl-$data
        mv /etc/spfbl /etc/spfbl-$data
        rm -rf /etc/logrotate.d/spfbl
        rm -rf /var/log/spfbl
        rm -f /root/.spfbl-install
        [ -d /usr/src/SPFBL-$data ] && success || failure echo
    fi
}    

baixaGit(){

    cd /usr/src && git clone https://github.com/leonamp/SPFBL.git
    echo -n "Clonando SPFBL a partir do Github... "
    [ -d /usr/src/SPFBL ] && success || failure echo
    
    if [ -d /usr/src/SPFBL ]; then
        chmod a+x SPFBL/client/*.sh
        chmod a+x SPFBL/run/*
    fi
}     

moveArquivos(){

    # Movendo arquivos
    if [ ! -d /opt/spfbl ]; then
        echo -n "Criando diretorios e movendo arquivos .. "
        mkdir -p /opt/spfbl/
        mkdir -p /opt/spfbl/doc
        mkdir -p /opt/spfbl/lib
        mkdir -p /opt/spfbl/data
        mkdir -p /etc/spfbl/
        mv SPFBL/dist/* /opt/spfbl/
        mv SPFBL/run/spfbl.conf /opt/spfbl/
        ln -sf /opt/spfbl/spfbl.conf /etc/spfbl/spfbl.conf
        mv SPFBL/lib/* /opt/spfbl/lib/
        mv SPFBL/data/* /opt/spfbl/data/
        mv SPFBL/doc/* /opt/spfbl/doc/
        mv SPFBL/README.md /opt/spfbl/doc/
        [ -d /opt/spfbl ] && success || failure echo
    fi
} 

criaVarLog(){    

    # Criando pasta de logs
    if [ ! -d /var/log/spfbl ]; then
        echo -n "Criando /var/log/spfbl .. "
        mkdir -p /var/log/spfbl
        [ -d /var/log/spfbl ] && success || failure echo
    fi    
}

autoBootDebian(){ 

    # Configurando auto-boot
    echo -n "Configurando auto-boot"
    mv SPFBL/run/spfbl-init-noarch.sh /etc/init.d/spfbl
    chmod a+x /etc/init.d/spfbl
    update-rc.d spfbl defaults 100
    [ -f /etc/init.d/spfbl ] && success || failure echo
}    

autoBootRedhat(){

    # Configurando auto-boot
    echo -n "Configurando auto-boot"
    mv SPFBL/run/spfbl-init-noarch.sh /etc/init.d/spfbl
    chmod a+x /etc/init.d/spfbl    
    chkconfig --add spfbl
    chkconfig spfbl on
    [ -f /etc/init.d/spfbl ] && success || failure echo
}    

configRotate(){ 

    # Configurar log rotation
    echo -n "Configurando rotacao de logs"
    mv SPFBL/run/spfbl-rotate /etc/logrotate.d/spfbl
    [ -f /etc/logrotate.d/spfbl ] && success || failure echo
}    
 
setaVariaveis(){

    # Setando variáveis do ambiente para o auto-updater
    touch /root/.spfbl-install
    echo -en "** NAO REMOVA ESTE ARQUIVO! \nELE SERA UTILIZADO PELO SPFBL \nPARA ATUALIZACAO AUTOMATICA**\n" >> /root/.spfbl-install 
    echo -en $"\nBASE_FOLDER=/opt/spfbl\nCONF_FILE=/etc/spfbl/spfbl.conf\nSTART_FILE=/etc/init.d/spfbl\nLR_FILE=/etc/logrotate.d/spfbl\nLOG_FOLDER=/var/log/spfbl\n" >> /root/.spfbl-install 
}

finaliza(){ 

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
}    

if [ "$1" == "--install" ]; then
    echo -e "${D}Iniciando processo de instalacao do SPFBL!${R}"
    cd /usr/src

    echo "Acessando pasta $PWD"
    echo -en "Precisamos detectar a plataforma e instalar o git, nc, wget, unzip e pacotes java"
    
    if [ -f /etc/lsb-release ]; then
    . /etc/lsb-release 
    OS=$DISTRIB_ID
    VER=$DISTRIB_RELEASE
    # Chama instalação em plataforma DEBIAN
    echo -e "${V}\nPlataforma baseada em Debian: $OS ${R}"
    . /lib/lsb/init-functions
    instalaDebian
    preInstall
    baixaGit
    moveArquivos
    criaVarLog
    autoBootDebian
    configRotate
    setaVariaveis
    finaliza

    elif [ -f /etc/redhat-release ] && [ "$1" == "--install" ]; then
    OS(){
        cat '/etc/redhat-release'
    }
    # Chama instalação em plataforma RHEL
    echo -e "${V}\nPlataforma baseada em RHEL: $(OS) ${R}"
    . /etc/init.d/functions
    instalaRedhat
    preInstall
    baixaGit
    moveArquivos
    criaVarLog
    autoBootRedhat
    configRotate
    setaVariaveis
    finaliza

    else 
        echo -e "{V}\nSua plataforma nao eh suportada ${R}"
    fi 
fi

if [ "$1" != "--install" ] && [ "$1" != "--uninstall" ]; then
    echo -e "${V}\nScript de instalacao do SPFBL${R}"
    echo -e "${D}\nParametros aceitos: ${R}"
    echo -e "${D}   --install   /  efetua a instalacao${R}" 
    echo -e "${D}   --uninstall /  remocao completa do sistema${R}" 
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
