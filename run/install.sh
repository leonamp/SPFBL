#!/bin/bash

##########################################
# Gerenciador de instalacao e remocao    #                  
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
        if [ -e /etc/init.d/functions ]
        then
                source /etc/init.d/functions
        fi
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
    #echo "Removendo /usr/src/SPFBL"
    #rm -rf /usr/src/SPFBL
    #[ ! -d /usr/src/SPFBL ] && success || failure
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
#
#	FUNCAO DE INSTALACAO DE PACOTES DEBIAN
#
instalaDebian(){ 
_dpkg=( "unzip" "wget" "git" "bc" "netcat" "logrotate" "default-jre" )
apt-get update >/dev/null 2>&1
#
#	INSTALA PACOTES
#
for j in "${_dpkg[@]}"
do
        if ! dpkg -s "$j" >/dev/null 2>&1
        then
                apt-get -y install "$j" >/dev/null 2>&1
                _key="$?"
                if [ "$_key" == "0" ]
                then
                        echo "$j Instalado com sucesso"
                else
                        echo "Nao foi possivel instalar $j :"
                        echo "* Verifique sua lista de repositorios cadastrados /etc/apt/sources.list"
                        echo "* Para maiores informacoes, utilize o comando apt-get --help"
                        exit 1
                fi

        fi
done

}
#
#	FUNCAO DE INSTALACAO DOS PACOTES NECESSARIOS VIA YUM
#
instalaRedhat(){ 
#
#	DEFINICAO DE PACOTES
#
_pacotes=( "git" "nc" "unzip" "logrotate" "wget" "java-1.8.0-openjdk" "bc" )
#
#	CHECK POR VERSAO
#
if [ -e /etc/os-release ]
then
	source /etc/os-release
fi
#
#	INSTALA PACOTES
#
for i in "${_pacotes[@]}"
do
        if [ "$i" == "nc" ] && [ ! -z $VERSION_ID ] && [ $VERSION_ID == "7" ]
        then
 		i="nmap-ncat"
        fi

	if ! yum list installed "$i" >/dev/null 2>&1
	then
		yum -y install "$i" >/dev/null 2>&1
		if rpm -q "$i" >/dev/null 2>&1
		then
			echo "$i Instalado com sucesso"
		else
			echo "Nao foi possivel instalar $i :"
			echo "* Verifique sua lista de repositorios cadastrados /etc/yum.repos.d/"
			echo "* Para maiores informacoes, utilize o comando yum --help"
			exit 1
		fi		
	fi
done
}

preInstall(){

    # Verifica se existe pre instalacao e ou instala
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
	if [ ! -d /usr/src/SPFBL ]
	then 
   		echo "/usr/src/SPFBL nao encontrado"
		exit 1
	else 
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
	mkdir -p /opt/spfbl/web
        mkdir -p /etc/spfbl/
        mv SPFBL/client/spfbl.sh /etc/spfbl/
        ln -sf /etc/spfbl/spfbl.sh /usr/local/bin/spfbl
        mv SPFBL/dist/* /opt/spfbl/
        mv SPFBL/run/spfbl-cron /etc/cron.d/
        mv SPFBL/run/spfbl.conf /opt/spfbl/
        ln -sf /opt/spfbl/spfbl.conf /etc/spfbl/spfbl.conf
        mv SPFBL/lib/* /opt/spfbl/lib/
        mv SPFBL/data/* /opt/spfbl/data/
        mv SPFBL/doc/* /opt/spfbl/doc/
        mv SPFBL/README.md /opt/spfbl/doc/
	mv SPFBL/web/* /opt/spfbl/web/
	if [ ! -d /opt/spfbl ]
	then
		echo "/opt/spfbl nao encontrado"
		exit 1
	fi
    fi
} 

criaVarLog(){    

    # Criando pasta de logs
    if [ ! -d /var/log/spfbl ]; then
        echo -n "Criando /var/log/spfbl .. "
        mkdir -p /var/log/spfbl
        if [ ! -d /var/log/spfbl ]
	then
		echo "/var/log/spfbl nao encontrado"
		exit 1
	fi
    fi    
}

autoBootDebian(){ 

    # Configurando auto-boot
    echo -n "Configurando auto-boot"
    mv SPFBL/run/spfbl-init-noarch.sh /etc/init.d/spfbl
    chmod a+x /etc/init.d/spfbl
    update-rc.d spfbl defaults 100
    	if [ ! -e /etc/init.d/spfbl ]
	then
		echo "/etc/init.d/spfbl nao encontrado"
		exit 1
	fi
}    

autoBootRedhat(){

    # Configurando auto-boot
    echo -n "Configurando auto-boot"
    mv SPFBL/run/spfbl-init-noarch.sh /etc/init.d/spfbl
    chmod a+x /etc/init.d/spfbl    
    chkconfig --add spfbl
    chkconfig spfbl on
        if [ ! -e /etc/init.d/spfbl ] 
	then
		echo "/etc/init.d/spfbl nao encontrado"
		exit 1
	fi
}    

configRotate(){ 

    # Configurar log rotation
    echo -n "Configurando rotacao de logs"
    mv SPFBL/run/spfbl-rotate /etc/logrotate.d/spfbl
    chmod a-x /etc/logrotate.d/spfbl
    	if [ ! -e /etc/logrotate.d/spfbl ] 
	then
		echo "/etc/logrotate.d/spfbl nao encontrado"
		exit 1
	fi
}    
 
setaVariaveis(){

    # Setando variaveis do ambiente para o auto-updater
    touch /root/.spfbl-install
    echo -en "** NAO REMOVA ESTE ARQUIVO! \nELE SERA UTILIZADO PELO SPFBL \nPARA ATUALIZACAO AUTOMATICA**\n" >> /root/.spfbl-install 
    echo -en $"\nBASE_FOLDER=/opt/spfbl\nCONF_FILE=/etc/spfbl/spfbl.conf\nSTART_FILE=/etc/init.d/spfbl\nLR_FILE=/etc/logrotate.d/spfbl\nLOG_FOLDER=/var/log/spfbl\n" >> /root/.spfbl-install 
}

finaliza(){ 

    # Limpando pasta temporaria
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
    
#
# DETECTANDO DEBIAN E UBUNTU
#    
        if [ -f /etc/debian_version ] && [ "$1" == "--install" ]
    	then
    	# Chama instalacao em plataforma DEBIAN
    	echo -e "${V}\nPlataforma baseada em Debian: $OS ${R}"
    	echo -e "${V}\nO processo a seguir ira levar varios minutos ${R}"
        if [ -e /etc/init.d/functions ]
        then
                source /etc/init.d/functions
        fi
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
    # Chama instalacao em plataforma RHEL
    echo -e "${V}\nPlataforma baseada em RHEL: $(OS) ${R}"
    echo -e "${V}\nO processo a seguir ira levar varios minutos ${R}"
	if [ -e /etc/init.d/functions ]
	then
    		source /etc/init.d/functions
	fi
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
    # Abaixo estao instrucoes que podem ser usadas em necessidade futura para
    # reconhecimento de arquitetura e de sistema debian especifico
    #########################################################################################

    # Identifica se eh 32 ou 64 bits. Nao eh necessario pro spfbl ainda.. 
    # mas se um dia for
    #
    # ARQ=$(uname -m | sed 's/x86_//;s/i[3-6]86/32/')

    # Nao eh necessario uma instalacao especifica para Debain..
    # mas se um dia for
    #
    # elif [ -f /etc/debian_version ]; then
    # OS=Debian
    # VER=$(cat /etc/debian_version)

