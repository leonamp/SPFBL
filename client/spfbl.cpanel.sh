#!/usr/bin/bash
#
# An SPFBL Cheker installer for cPanel.
#
# Usage as root:
#    ./spfbl.cpanel.sh [install|uninstall] 
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
# Version: 1.2

install() {
    # Install netcat
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
    # Install SPFBL client script
    wget https://raw.githubusercontent.com/leonamp/SPFBL/master/client/spfbl.sh -O /usr/local/bin/spfbl
    chmod +x /usr/local/bin/spfbl
    /usr/local/bin/spfbl version
    if [ $? -eq 0 ]; then
        # Enable Clamav
        /usr/local/cpanel/scripts/update_local_rpm_versions --edit target_settings.clamav installed
        /usr/local/cpanel/scripts/check_cpanel_rpms --fix --targets=clamav
        # Install clamav-unofficial-sigs
        mkdir -p /etc/clamav-unofficial-sigs/
        wget https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/config/master.conf -O /etc/clamav-unofficial-sigs/master.conf
        wget https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/config/user.conf -O /etc/clamav-unofficial-sigs/user.conf
        DISTRO=$(cat /etc/*-release | tr [:upper:] [:lower:] | grep -Poi '(centos-8|centos-7|centos-6|ubuntu|cloudlinux 7|cloudlinux 8|almalinux-8|cloudlinux server release 6)' | uniq)
        if [ "$DISTRO" = "centos-7" ]; then
            wget "https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/config/os/os.centos7-cpanel.conf" -O /etc/clamav-unofficial-sigs/os.conf
            echo 'clamscan_bin="/usr/local/cpanel/3rdparty/bin/clamscan"' >> /etc/clamav-unofficial-sigs/os.conf
        elif [ "$DISTRO" = "centos-8" ]; then
            wget "https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/config/os/os.centos7-cpanel.conf" -O /etc/clamav-unofficial-sigs/os.conf
            echo 'clamscan_bin="/usr/local/cpanel/3rdparty/bin/clamscan"' >> /etc/clamav-unofficial-sigs/os.conf
        elif [ "$DISTRO" = "centos-6" ]; then
            wget "https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/config/os/os.centos6-cpanel.conf" -O /etc/clamav-unofficial-sigs/os.conf
        elif [ "$DISTRO" = "cloudlinux server release 6" ]; then
            wget "https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/config/os/os.centos6-cpanel.conf" -O /etc/clamav-unofficial-sigs/os.conf
        elif [ "$DISTRO" = "ubuntu" ]; then
            wget "https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/config/os/os.ubuntu.conf" -O /etc/clamav-unofficial-sigs/os.conf
        elif [ "$DISTRO" = "cloudlinux 7" ]; then
            wget "https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/config/os/os.centos7-cpanel.conf" -O /etc/clamav-unofficial-sigs/os.conf
            echo 'clamscan_bin="/usr/local/cpanel/3rdparty/bin/clamscan"' >> /etc/clamav-unofficial-sigs/os.conf
        elif [ "$DISTRO" = "cloudlinux 8" ]; then
            wget "https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/config/os/os.centos7-cpanel.conf" -O /etc/clamav-unofficial-sigs/os.conf
            echo 'clamscan_bin="/usr/local/cpanel/3rdparty/bin/clamscan"' >> /etc/clamav-unofficial-sigs/os.conf
        elif [ "$DISTRO" = "almalinux-8" ]; then
            wget "https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/config/os/os.centos7-cpanel.conf" -O /etc/clamav-unofficial-sigs/os.conf
            echo 'clamscan_bin="/usr/local/cpanel/3rdparty/bin/clamscan"' >> /etc/clamav-unofficial-sigs/os.conf
        else
            echo "Linux distro not identified."
            echo "Please contact us to update this installation script to it works for your distro."
            echo "https://spfbl.net/en/contact"
            exit 1;
        fi
        wget https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master/clamav-unofficial-sigs.sh -O /usr/local/bin/clamav-unofficial-sigs.sh
        chmod 755 /usr/local/bin/clamav-unofficial-sigs.sh
        /usr/local/bin/clamav-unofficial-sigs.sh --force
        /usr/local/bin/clamav-unofficial-sigs.sh --install-cron --install-logrotate
        # Remove old SPFBL configuration files
        rm /usr/local/cpanel/etc/exim/acls/ACL_RECIPIENT_BLOCK/custom_end_recipient_spfbl 2> /dev/null
        rm /usr/local/cpanel/etc/exim/acls/ACL_SMTP_DKIM_BLOCK/custom_begin_smtp_dkim_spfbl 2> /dev/null
        rm /usr/local/cpanel/etc/exim/acls/ACL_CHECK_MESSAGE_PRE_BLOCK/custom_end_check_message_pre_spfbl 2> /dev/null
        # Install SPFBL configuration files
        wget https://raw.githubusercontent.com/leonamp/SPFBL/master/client/spfbl_end_recipient -O /usr/local/cpanel/etc/exim/acls/ACL_RECIPIENT_BLOCK/spfbl_end_recipient
        wget https://raw.githubusercontent.com/leonamp/SPFBL/master/client/spfbl_begin_smtp_dkim -O /usr/local/cpanel/etc/exim/acls/ACL_SMTP_DKIM_BLOCK/spfbl_begin_smtp_dkim
        wget https://raw.githubusercontent.com/leonamp/SPFBL/master/client/spfbl_begin_check_message_pre -O /usr/local/cpanel/etc/exim/acls/ACL_CHECK_MESSAGE_PRE_BLOCK/spfbl_begin_check_message_pre
        # Restart cPanel service
        /usr/local/cpanel/scripts/buildeximconf
        /usr/local/cpanel/scripts/restartsrv_exim
    else
        myIP=$(curl -s http://checkip.amazonaws.com/)
        myHOST=$(hostname)
        echo "Your cPanel doesn't have permission to access matrix.spfbl.net server yet."
        echo "Please contact us to get your permission for the host $myHOST [$myIP]."
        echo "https://spfbl.net/en/contact"
        echo "If this host has already it, open the outgoing port 9877 TCP in your firewall."
        exit 1;
    fi
}

uninstall() {
    /usr/local/bin/clamav-unofficial-sigs.sh --remove-script

    rm /usr/local/cpanel/etc/exim/acls/ACL_RECIPIENT_BLOCK/custom_end_recipient_spfbl 2> /dev/null
    rm /usr/local/cpanel/etc/exim/acls/ACL_SMTP_DKIM_BLOCK/custom_begin_smtp_dkim_spfbl 2> /dev/null
    rm /usr/local/cpanel/etc/exim/acls/ACL_CHECK_MESSAGE_PRE_BLOCK/custom_end_check_message_pre_spfbl 2> /dev/null
    
    rm /usr/local/cpanel/etc/exim/acls/ACL_RECIPIENT_BLOCK/spfbl_end_recipient 2> /dev/null
    rm /usr/local/cpanel/etc/exim/acls/ACL_SMTP_DKIM_BLOCK/spfbl_begin_smtp_dkim 2> /dev/null
    rm /usr/local/cpanel/etc/exim/acls/ACL_CHECK_MESSAGE_PRE_BLOCK/spfbl_begin_check_message_pre 2> /dev/null
    
    /usr/local/cpanel/scripts/buildeximconf
    /usr/local/cpanel/scripts/restartsrv_exim
}

case "$1" in
    install)
        echo "[install] Installing SPFBL Checker powered by SPFBL.net"
        install
    ;;
    uninstall)
        echo "[uninstall] Uninstalling SPFBL Checker powered by SPFBL.net"
        uninstall
    ;;
    *)
        echo "*** Usage: $0 [install|uninstall]"
        exit 1
esac
