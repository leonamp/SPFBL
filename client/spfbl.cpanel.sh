#!/usr/bin/bash
#
# An SPFBL Cheker installer for cPanel.
#
# Usage as root:
#    ./spfbl.cpanel.sh [install|update|uninstall|firewall] 
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
# Version: 1.4

function exim_configuration() {
    # Change parameters in Exim Configuration Manager interface.
    option_name=$1
    option_value=$2
    if grep -q "^${option_name}=" /etc/exim.conf.localopts; then
        sed -i "s/^${option_name}=.*/${option_name}=${option_value}/" /etc/exim.conf.localopts
    else
        echo "${option_name}=${option_value}" >> /etc/exim.conf.localopts
    fi
}

function install() {

    # Check if cPanel is installed.
    /usr/local/cpanel/cpanel -V > /dev/null
    if [ $? -ne 0 ]; then
        echo "cPanel is not installed in this host yet."
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
        # Enable Clamav.
        /usr/local/cpanel/scripts/update_local_rpm_versions --edit target_settings.clamav installed
        /usr/local/cpanel/scripts/check_cpanel_rpms --fix --targets=clamav
        
        # Install clamav-unofficial-sigs.
        mkdir -p /etc/clamav-unofficial-sigs/
        wget https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/config/master.conf -O /etc/clamav-unofficial-sigs/master.conf
        wget https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/config/user.conf -O /etc/clamav-unofficial-sigs/user.conf
        printf "\ndeclare -a additional_dbs=(\n\thttps://matrix.spfbl.net/spfbl.hsb\n\thttps://matrix.spfbl.net/spfbl.ign2\n\thttps://matrix.spfbl.net/cpanel.ign2\n) #END ADDITIONAL DATABASES\n\n" >> /etc/clamav-unofficial-sigs/user.conf
        DISTRO=$(cat /etc/*-release | tr [:upper:] [:lower:] | grep -Poi '(centos-8|centos stream 8|centos-7|centos-6|ubuntu|cloudlinux 7|cloudlinux 8|cloudlinux 9|almalinux-8|almalinux-9|cloudlinux server release 6|centos release 6|debian gnu/linux 7|debian gnu/linux 8|debian gnu/linux 10|debian gnu/linux 11|rocky linux 9)' | sort | uniq)
        if [ "$DISTRO" = "centos-7" ]; then
            wget "https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/config/os/os.centos7-cpanel.conf" -O /etc/clamav-unofficial-sigs/os.conf
            echo 'clamscan_bin="/usr/local/cpanel/3rdparty/bin/clamscan"' >> /etc/clamav-unofficial-sigs/os.conf
        elif [ "$DISTRO" = "centos-8" ]; then
            wget "https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/config/os/os.centos7-cpanel.conf" -O /etc/clamav-unofficial-sigs/os.conf
            echo 'clamscan_bin="/usr/local/cpanel/3rdparty/bin/clamscan"' >> /etc/clamav-unofficial-sigs/os.conf
        elif [ "$DISTRO" = "centos stream 8" ]; then
            wget "https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/config/os/os.centos7-cpanel.conf" -O /etc/clamav-unofficial-sigs/os.conf
            echo 'clamscan_bin="/usr/local/cpanel/3rdparty/bin/clamscan"' >> /etc/clamav-unofficial-sigs/os.conf
        elif [ "$DISTRO" = "centos-6" ]; then
            wget "https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/config/os/os.centos6-cpanel.conf" -O /etc/clamav-unofficial-sigs/os.conf
        elif [ "$DISTRO" = "cloudlinux server release 6" ]; then
            wget "https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/config/os/os.centos6-cpanel.conf" -O /etc/clamav-unofficial-sigs/os.conf
        elif [ "$DISTRO" = "centos release 6" ]; then
            wget "https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/config/os/os.centos6-cpanel.conf" -O /etc/clamav-unofficial-sigs/os.conf
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
        elif [ "$DISTRO" = "cloudlinux 7" ]; then
            wget "https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/config/os/os.centos7-cpanel.conf" -O /etc/clamav-unofficial-sigs/os.conf
            echo 'clamscan_bin="/usr/local/cpanel/3rdparty/bin/clamscan"' >> /etc/clamav-unofficial-sigs/os.conf
        elif [ "$DISTRO" = "cloudlinux 8" ]; then
            wget "https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/config/os/os.centos7-cpanel.conf" -O /etc/clamav-unofficial-sigs/os.conf
            echo 'clamscan_bin="/usr/local/cpanel/3rdparty/bin/clamscan"' >> /etc/clamav-unofficial-sigs/os.conf
        elif [ "$DISTRO" = "cloudlinux 9" ]; then
            wget "https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/config/os/os.centos7-cpanel.conf" -O /etc/clamav-unofficial-sigs/os.conf
            echo 'clamscan_bin="/usr/local/cpanel/3rdparty/bin/clamscan"' >> /etc/clamav-unofficial-sigs/os.conf
        elif [ "$DISTRO" = "almalinux-8" ]; then
            wget "https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/config/os/os.centos7-cpanel.conf" -O /etc/clamav-unofficial-sigs/os.conf
            echo 'clamscan_bin="/usr/local/cpanel/3rdparty/bin/clamscan"' >> /etc/clamav-unofficial-sigs/os.conf
        elif [ "$DISTRO" = "almalinux-9" ]; then
            wget "https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/config/os/os.centos7-cpanel.conf" -O /etc/clamav-unofficial-sigs/os.conf
            echo 'clamscan_bin="/usr/local/cpanel/3rdparty/bin/clamscan"' >> /etc/clamav-unofficial-sigs/os.conf
        elif [ "$DISTRO" = "rocky linux 9" ]; then
            wget "https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/config/os/os.centos7-cpanel.conf" -O /etc/clamav-unofficial-sigs/os.conf
            echo 'clamscan_bin="/usr/local/cpanel/3rdparty/bin/clamscan"' >> /etc/clamav-unofficial-sigs/os.conf
        else
            echo "Linux distro not identified."
            echo "Please contact us to update this installation script to it works for your distro and send the information bellow."
            echo "https://spfbl.net/en/contact"
            echo ""
	    cat /etc/*-release
            exit 1;
        fi
        wget https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/clamav-unofficial-sigs.sh -O /usr/local/bin/clamav-unofficial-sigs.sh
        chmod 755 /usr/local/bin/clamav-unofficial-sigs.sh
        /usr/local/bin/clamav-unofficial-sigs.sh --force
        /usr/local/bin/clamav-unofficial-sigs.sh --install-cron --install-logrotate
        
        # Install SPFBL configuration files.
        wget https://raw.githubusercontent.com/leonamp/SPFBL/master/client/spfbl_end_recipient -O /usr/local/cpanel/etc/exim/acls/ACL_RECIPIENT_BLOCK/spfbl_end_recipient
        wget https://raw.githubusercontent.com/leonamp/SPFBL/master/client/spfbl_begin_smtp_dkim -O /usr/local/cpanel/etc/exim/acls/ACL_SMTP_DKIM_BLOCK/spfbl_begin_smtp_dkim
        wget https://raw.githubusercontent.com/leonamp/SPFBL/master/client/spfbl_begin_check_message_pre -O /usr/local/cpanel/etc/exim/acls/ACL_CHECK_MESSAGE_PRE_BLOCK/spfbl_begin_check_message_pre
        
        # Config Exim Configuration Manager interface.
        exim_configuration "spfbl_end_recipient" "1"
        exim_configuration "spfbl_begin_smtp_dkim" "1"
        exim_configuration "spfbl_begin_check_message_pre" "1"
        exim_configuration "acl_delay_unknown_hosts" "0"
        exim_configuration "acl_dkim_disable" "0"
        exim_configuration "acl_dkim_bl" "0"
        exim_configuration "acl_spam_scan_secondarymx" "0"
        exim_configuration "acl_outgoing_spam_scan" "0"
        exim_configuration "acl_outgoing_spam_scan_over_int" "0"
        exim_configuration "acl_default_exiscan" "0"
        exim_configuration "acl_default_spam_scan" "0"
        exim_configuration "acl_default_spam_scan_check" "0"
        exim_configuration "acl_slow_fail_block" "0"

 	if [ -f /etc/exim.conf.local ]; then
            if grep -q "timeout_frozen_after" /etc/exim.conf.local; then
                sed -i 's/timeout_frozen_after = .*/timeout_frozen_after = 7d/' /etc/exim.conf.local
            else
                sed '/@CONFIG@/a timeout_frozen_after = 7d' /etc/exim.conf.local > spfbltemp && mv -f spfbltemp /etc/exim.conf.local
            fi
            if grep -q "spamd_address" /etc/exim.conf.local; then
                sed -i 's/spamd_address = .*/spamd_address = 54.233.253.229 9877 retry=30s tmo=3m/' /etc/exim.conf.local
            else
                sed '/@CONFIG@/a spamd_address = 54.233.253.229 9877 retry=30s tmo=3m' /etc/exim.conf.local > spfbltemp && mv -f spfbltemp /etc/exim.conf.local
            fi
            if grep -q "smtp_accept_max" /etc/exim.conf.local; then
                sed -i 's/smtp_accept_max = .*/smtp_accept_max = 250/' /etc/exim.conf.local
            else
                sed '/@CONFIG@/a smtp_accept_max = 250' /etc/exim.conf.local > spfbltemp && mv -f spfbltemp /etc/exim.conf.local
            fi
        else
	    echo "timeout_frozen_after = 7d" > /etc/exim.conf.local
            echo "spamd_address = 54.233.253.229 9877 retry=30s tmo=3m" >> /etc/exim.conf.local
            echo "smtp_accept_max = 250" >> /etc/exim.conf.local
	fi
	
        # Restart cPanel service.
        /usr/local/cpanel/scripts/buildeximconf
        /usr/local/cpanel/scripts/restartsrv_exim

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
        echo "Your cPanel doesn't have permission to access matrix.spfbl.net server yet."
        echo "Please contact us to get your permission for the host $myHOST [$myIP]."
        echo "https://spfbl.net/en/contact"
        echo "If this host has already it, open the port 9877 TCP OUT in your firewall"
        echo "and add the IP 54.233.253.229 in its whitelist."
        exit 1;
    fi
}

function update() {
    if [ -f "/usr/local/cpanel/etc/exim/acls/ACL_RECIPIENT_BLOCK/spfbl_end_recipient" ]; then
        # Replace SPFBL client script.
        wget https://raw.githubusercontent.com/leonamp/SPFBL/master/client/spfbl.sh -O /usr/local/bin/spfbl
        
        # Replace SPFBL configuration files
        wget https://raw.githubusercontent.com/leonamp/SPFBL/master/client/spfbl_end_recipient -O /usr/local/cpanel/etc/exim/acls/ACL_RECIPIENT_BLOCK/spfbl_end_recipient
        wget https://raw.githubusercontent.com/leonamp/SPFBL/master/client/spfbl_begin_smtp_dkim -O /usr/local/cpanel/etc/exim/acls/ACL_SMTP_DKIM_BLOCK/spfbl_begin_smtp_dkim
        wget https://raw.githubusercontent.com/leonamp/SPFBL/master/client/spfbl_begin_check_message_pre -O /usr/local/cpanel/etc/exim/acls/ACL_CHECK_MESSAGE_PRE_BLOCK/spfbl_begin_check_message_pre
        
        # Config Exim Configuration Manager interface.
        exim_configuration "spfbl_end_recipient" "1"
        exim_configuration "spfbl_begin_smtp_dkim" "1"
        exim_configuration "spfbl_begin_check_message_pre" "1"
        exim_configuration "acl_delay_unknown_hosts" "0"
        exim_configuration "acl_dkim_disable" "0"
        exim_configuration "acl_dkim_bl" "0"
        exim_configuration "acl_spam_scan_secondarymx" "0"
        exim_configuration "acl_outgoing_spam_scan" "0"
        exim_configuration "acl_outgoing_spam_scan_over_int" "0"
        exim_configuration "acl_default_exiscan" "0"
        exim_configuration "acl_default_spam_scan" "0"
        exim_configuration "acl_default_spam_scan_check" "0"
        exim_configuration "acl_slow_fail_block" "0"
	
        # Restart cPanel service.
        /usr/local/cpanel/scripts/buildeximconf
        /usr/local/cpanel/scripts/restartsrv_exim

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
    /usr/local/bin/clamav-unofficial-sigs.sh --remove-script

    # Remove SPFBL configuration files
    rm /usr/local/cpanel/etc/exim/acls/ACL_RECIPIENT_BLOCK/spfbl_end_recipient 2> /dev/null
    rm /usr/local/cpanel/etc/exim/acls/ACL_SMTP_DKIM_BLOCK/spfbl_begin_smtp_dkim 2> /dev/null
    rm /usr/local/cpanel/etc/exim/acls/ACL_CHECK_MESSAGE_PRE_BLOCK/spfbl_begin_check_message_pre 2> /dev/null
    
    # Config Exim Configuration Manager interface.
    exim_configuration "acl_delay_unknown_hosts" "1"
    exim_configuration "acl_dkim_disable" "1"
    exim_configuration "acl_dkim_bl" "0"
    exim_configuration "acl_spam_scan_secondarymx" "1"
    exim_configuration "acl_outgoing_spam_scan" "0"
    exim_configuration "acl_outgoing_spam_scan_over_int" "0"
    exim_configuration "acl_default_exiscan" "0"
    exim_configuration "acl_default_spam_scan" "1"
    exim_configuration "acl_default_spam_scan_check" "1"
    exim_configuration "acl_slow_fail_block" "1"
    if grep -q "timeout_frozen_after" /etc/exim.conf.local; then
        sed -i '/timeout_frozen_after/d' /etc/exim.conf.local
    fi
    if grep -q "spamd_address" /etc/exim.conf.local; then
        sed -i '/spamd_address/d' /etc/exim.conf.local
    fi
    if grep -q "smtp_accept_max" /etc/exim.conf.local; then
        sed -i '/smtp_accept_max/d' /etc/exim.conf.local
    fi
        
    /usr/local/cpanel/scripts/buildeximconf
    /usr/local/cpanel/scripts/restartsrv_exim
    
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
