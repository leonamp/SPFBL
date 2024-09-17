#!/bin/bash
#
# The SPFBL Cheker installer for DirectAdmin.
#
# Usage as root:
#    ./spfbl.directadmin.sh [install|update|uninstall|firewall] 
#    
# SPFBL is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# SPFBL is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with SPFBL. If not, see <http://www.gnu.org/licenses/>.
#
# Project SPFBL - Copyright Leandro Carlos Rodrigues - leandro@spfbl.net
# https://github.com/leonamp/SPFBL
#
# Version: 1.0

function install() {

    # Check if DirectAdmin is installed.
    /usr/local/directadmin/directadmin c > /dev/null
    if [ $? -ne 0 ]; then
        echo "DirectAdmin is not installed in this host yet."
        exit 1
    fi
    
    # Install netcat.
    if command -v apt-get >/dev/null; then
        apt-get install nmap ncat
    elif command -v yum >/dev/null; then
        yum install -y nmap nc
    else
        echo "Linux installation tool not identified."
        echo "Please contact us to update this installation script to it works for your distro."
        echo "https://spfbl.net/en/contact"
        exit 1
    fi
    
    # Install SPFBL client script.
    wget https://raw.githubusercontent.com/leonamp/SPFBL/master/client/spfbl.sh -O /usr/local/bin/spfbl
    chmod +x /usr/local/bin/spfbl
    /usr/local/bin/spfbl version
    if [ $? -eq 0 ]; then
    	# Install Clamav
        if command -v apt-get >/dev/null; then
            apt-get install clamav clamav-daemon
        elif command -v yum >/dev/null; then
            yum install clamav clamav-update
        fi
	
        # Enable Clamav.
	/usr/local/directadmin/custombuild/build update
	/usr/local/directadmin/custombuild/build set clamav yes
	/usr/local/directadmin/custombuild/build set easy_spam_fighter no
        /usr/local/directadmin/custombuild/build clamav
	usermod -aG mail clamscan
        usermod -aG virusgroup mail
        
        # Install clamav-unofficial-sigs.
        mkdir -p /etc/clamav-unofficial-sigs/
        wget https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/config/master.conf -O /etc/clamav-unofficial-sigs/master.conf
        sed -i 's/^#clamd_restart_opt="service clamd restart"/clamd_restart_opt="service clamd@scan restart"/' /etc/clamav-unofficial-sigs/master.conf
        wget https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/config/user.conf -O /etc/clamav-unofficial-sigs/user.conf
        printf "\ndeclare -a additional_dbs=(\n\thttps://matrix.spfbl.net/spfbl.hsb\n\thttps://matrix.spfbl.net/spfbl.ign2\n) #END ADDITIONAL DATABASES\n\n" >> /etc/clamav-unofficial-sigs/user.conf
        DISTRO=$(cat /etc/*-release | tr [:upper:] [:lower:] | grep -Poi '(centos-8|centos stream 8|centos-7|centos-6|ubuntu|cloudlinux 7|cloudlinux 8|cloudlinux 9|almalinux-8|almalinux-9|cloudlinux server release 6|centos release 6|debian gnu/linux 7|debian gnu/linux 8|debian gnu/linux 10|debian gnu/linux 11|debian gnu/linux 12|rocky linux 9)' | sort | uniq)
        if [ "$DISTRO" = "centos-7" ]; then
            wget "https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/config/os/os.centos7-cpanel.conf" -O /etc/clamav-unofficial-sigs/os.conf
        elif [ "$DISTRO" = "centos-8" ]; then
            wget "https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/config/os/os.centos7-cpanel.conf" -O /etc/clamav-unofficial-sigs/os.conf
        elif [ "$DISTRO" = "centos stream 8" ]; then
            wget "https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/config/os/os.centos7-cpanel.conf" -O /etc/clamav-unofficial-sigs/os.conf
        elif [ "$DISTRO" = "centos-6" ]; then
            wget "https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/config/os/os.centos6.conf" -O /etc/clamav-unofficial-sigs/os.conf
        elif [ "$DISTRO" = "cloudlinux server release 6" ]; then
            wget "https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/config/os/os.centos6.conf" -O /etc/clamav-unofficial-sigs/os.conf
        elif [ "$DISTRO" = "centos release 6" ]; then
            wget "https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/config/os/os.centos6.conf" -O /etc/clamav-unofficial-sigs/os.conf
        elif [ "$DISTRO" = "ubuntu" ]; then
            wget "https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/config/os/os.ubuntu.conf" -O /etc/clamav-unofficial-sigs/os.conf
        elif [ "$DISTRO" = "debian gnu/linux 7" ]; then
            wget "https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/config/os/os.debian7.conf" -O /etc/clamav-unofficial-sigs/os.conf
        elif [ "$DISTRO" = "debian gnu/linux 8" ]; then
            wget "https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/config/os/os.debian8.conf" -O /etc/clamav-unofficial-sigs/os.conf
        elif [ "$DISTRO" = "debian gnu/linux 10" ]; then
            wget "https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/config/os/os.debian.conf" -O /etc/clamav-unofficial-sigs/os.conf
        elif [ "$DISTRO" = "debian gnu/linux 11" ]; then
            wget "https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/config/os/os.debian.conf" -O /etc/clamav-unofficial-sigs/os.conf
        elif [ "$DISTRO" = "debian gnu/linux 12" ]; then
            wget "https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/config/os/os.debian.conf" -O /etc/clamav-unofficial-sigs/os.conf
        elif [ "$DISTRO" = "cloudlinux 7" ]; then
            wget "https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/config/os/os.centos6.conf" -O /etc/clamav-unofficial-sigs/os.conf
        elif [ "$DISTRO" = "cloudlinux 8" ]; then
            wget "https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/config/os/os.centos6.conf" -O /etc/clamav-unofficial-sigs/os.conf
        elif [ "$DISTRO" = "cloudlinux 9" ]; then
            wget "https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/config/os/os.centos6.conf" -O /etc/clamav-unofficial-sigs/os.conf
        elif [ "$DISTRO" = "almalinux-8" ]; then
            wget "https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/config/os/os.centos6.conf" -O /etc/clamav-unofficial-sigs/os.conf
        elif [ "$DISTRO" = "almalinux-9" ]; then
            wget "https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/config/os/os.centos6.conf" -O /etc/clamav-unofficial-sigs/os.conf
        elif [ "$DISTRO" = "rocky linux 9" ]; then
            wget "https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/config/os/os.centos6.conf" -O /etc/clamav-unofficial-sigs/os.conf
        else
            echo "Linux distro not identified."
            echo "Please contact us to update this installation script to it works for your distro and send the information bellow."
            echo "https://spfbl.net/en/contact"
            echo ""
	    cat /etc/*-release
            exit 1;
        fi
        sed -i 's/^clam_user="clam"/clam_user="clamupdate"/' /etc/clamav-unofficial-sigs/os.conf
	sed -i 's/^clam_group="clam"/clam_group="clamupdate"/' /etc/clamav-unofficial-sigs/os.conf
	sed -i 's/^clamd_restart_opt="\/sbin\/service clamd reload"/clamd_restart_opt="\/sbin\/service clamd@scan reload"/' /etc/clamav-unofficial-sigs/os.conf
        wget https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/clamav-unofficial-sigs.sh -O /usr/local/bin/clamav-unofficial-sigs.sh
        chmod 755 /usr/local/bin/clamav-unofficial-sigs.sh
        /usr/local/bin/clamav-unofficial-sigs.sh --force
        /usr/local/bin/clamav-unofficial-sigs.sh --install-cron --install-logrotate
        
        # Install SPFBL configuration files.
        mkdir -p /etc/exim.easy_spam_fighter/
        wget https://raw.githubusercontent.com/leonamp/SPFBL/master/client/directadmin.acl_check_recipient.pre.conf -O /etc/exim.acl_check_recipient.pre.conf
        wget https://raw.githubusercontent.com/leonamp/SPFBL/master/client/directadmin.acl_check_dkim.conf -O /etc/exim.easy_spam_fighter/check_dkim.conf
        wget https://raw.githubusercontent.com/leonamp/SPFBL/master/client/directadmin.acl_check_message.pre.conf -O /etc/exim.acl_check_message.pre.conf
        echo "av_scanner = clamd:/run/clamd.scan/clamd.sock" > /etc/exim.variables.conf.custom
	echo "spamd_address = 54.233.253.229 9877" >> /etc/exim.variables.conf.custom
	echo "RBL_DNS_LIST==" > /etc/exim.strings.conf.custom
        
        # Restart DirectAdmin service.
        service exim restart
        
        # Creating holding routine.
	echo -e '#!/bin/bash\n/usr/local/bin/spfbl holding' > /etc/cron.hourly/spfbl-holding-check
        chmod +x /etc/cron.hourly/spfbl-holding-check
        
        echo "SPFBL Checker was successfully installed!"
        echo ""
        echo "Installing SPFBL Firewall solution..."
        
        # Install firewall solution
	firewall
    else
        myIP=$(curl -s http://checkip.amazonaws.com/)
        myHOST=$(hostname)
        echo "Your DirectAdmin doesn't have permission to access matrix.spfbl.net server yet."
        echo "Please contact us to get your permission for the host $myHOST [$myIP]."
        echo "https://spfbl.net/en/contact"
        echo "If this host has already it, open the port 9877 TCP OUT in your firewall"
        echo "and add the IP 54.233.253.229 in its whitelist."
        exit 1;
    fi
}

function update() {
    if [ -f "/etc/exim.acl_check_recipient.pre.conf" ]; then
        # Replace SPFBL client script.
        wget https://raw.githubusercontent.com/leonamp/SPFBL/master/client/spfbl.sh -O /usr/local/bin/spfbl
        
        # Replace SPFBL configuration files
        mkdir -p /etc/exim.easy_spam_fighter/
        wget https://raw.githubusercontent.com/leonamp/SPFBL/master/client/directadmin.acl_check_recipient.pre.conf -O /etc/exim.acl_check_recipient.pre.conf
        wget https://raw.githubusercontent.com/leonamp/SPFBL/master/client/directadmin.acl_check_dkim.conf -O /etc/exim.easy_spam_fighter/check_dkim.conf
        wget https://raw.githubusercontent.com/leonamp/SPFBL/master/client/directadmin.acl_check_message.pre.conf -O /etc/exim.acl_check_message.pre.conf
        echo "av_scanner = clamd:/run/clamd.scan/clamd.sock" > /etc/exim.variables.conf.custom
	echo "spamd_address = 54.233.253.229 9877" >> /etc/exim.variables.conf.custom
	echo "RBL_DNS_LIST==" > /etc/exim.strings.conf.custom
        
        # Restart cPanel service.
        service exim restart
        
 	# Reinstall holding routine
        echo -e '#!/bin/bash\n/usr/local/bin/spfbl holding' > /etc/cron.hourly/spfbl-holding-check
        chmod +x /etc/cron.hourly/spfbl-holding-check
        
        # Reinstall firewall solution
        rm -f /etc/cron.hourly/spfbl-firewall-update
	firewall
	
    else
        echo "The SPFBL Checker was not installed yet."
        exit 1;
    fi
}

function uninstall() {

    # Disable Clamav.
    /usr/local/directadmin/custombuild/build set clamav no
    /usr/local/directadmin/custombuild/build set clamav_exim no
    /usr/local/directadmin/custombuild/build set proftpd_uploadscan no
    /usr/local/directadmin/custombuild/build set pureftpd_uploadscan no
    /usr/local/directadmin/custombuild/build set suhosin_php_uploadscan no
    /usr/local/directadmin/custombuild/build set modsecurity_uploadscan no
    /usr/local/directadmin/custombuild/build set easy_spam_fighter yes
    /usr/local/directadmin/custombuild/build remove_clamav
    /usr/local/directadmin/custombuild/build exim_conf
    /usr/local/directadmin/custombuild/build proftpd
    /usr/local/directadmin/custombuild/build clean
    /usr/local/directadmin/custombuild/build php_ini
    /usr/local/directadmin/custombuild/build rewrite_confs

    # Remove SPFBL configuration files
    rm /etc/exim.acl_check_recipient.pre.conf
    rm -r /etc/exim.easy_spam_fighter/
    rm /etc/exim.acl_check_message.pre.conf
    rm /etc/exim.strings.conf.custom
    rm /etc/exim.variables.conf.custom
    
    # Restart DirectAdmin service.
    service exim restart

    # Remove holding rountine
    rm -f /etc/cron.hourly/spfbl-holding-check
    
    # Remove firewall files
    if grep -q "/usr/local/bin/spfbl-firewall" /etc/csf/csfpost.sh; then
        sed -i '/\/usr\/local\/bin\/spfbl-firewall/d' /etc/csf/csfpost.sh
    fi
    rm -f /usr/local/bin/spfbl-firewall-update
    rm -f /etc/cron.hourly/spfbl-firewall-update
    iptables -w -D INPUT -p tcp -m tcp --dport 25 --tcp-flags FIN,SYN,RST,ACK SYN -m state --state NEW -j SPFBL
    iptables -w -F SPFBL
    iptables -w -X SPFBL
}

function firewall() {
    rm -f /etc/cron.hourly/spfbl-firewall-update
    
    curl -s https://raw.githubusercontent.com/leonamp/SPFBL/master/client/firewall.cpanel.sh > /usr/local/bin/spfbl-firewall-update
    chmod +x /usr/local/bin/spfbl-firewall-update
    /usr/local/bin/spfbl-firewall-update
    
    echo "SPFBL Firewall was successfully installed!"
}

case "$1" in
    install)
        echo "[install] Installing SPFBL Checker powered by SPFBL.net"
        install
    ;;
    update)
        echo "[update] Updating SPFBL Checker powered by SPFBL.net"
        update
    ;;
    uninstall)
        echo "[uninstall] Uninstalling SPFBL Checker powered by SPFBL.net"
        uninstall
    ;;
    firewall)
        echo "[firewall] Installing SPFBL Firewall powered by SPFBL.net"
        firewall
    ;;
    *)
        echo "*** Usage: $0 [install|update|uninstall|firewall]"
        exit 1
esac
