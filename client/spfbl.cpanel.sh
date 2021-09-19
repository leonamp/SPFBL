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
# Version: 1.1

install() {
    if command -v apt-get >/dev/null; then
      apt-get install nmap ncat
    elif command -v yum >/dev/null; then
      yum install -y nmap nc
    else
      exit 1
    fi
    wget https://raw.githubusercontent.com/leonamp/SPFBL/master/client/spfbl.sh -O /usr/local/bin/spfbl
    chmod +x /usr/local/bin/spfbl
    /usr/local/bin/spfbl version
    if [ $? -eq 0 ]; then
        /usr/local/cpanel/scripts/update_local_rpm_versions --edit target_settings.clamav installed
        /usr/local/cpanel/scripts/check_cpanel_rpms --fix --targets=clamav
        
        rm /usr/local/cpanel/etc/exim/acls/ACL_RECIPIENT_BLOCK/custom_end_recipient_spfbl 2> /dev/null
        rm /usr/local/cpanel/etc/exim/acls/ACL_SMTP_DKIM_BLOCK/custom_begin_smtp_dkim_spfbl 2> /dev/null
        rm /usr/local/cpanel/etc/exim/acls/ACL_CHECK_MESSAGE_PRE_BLOCK/custom_end_check_message_pre_spfbl 2> /dev/null

        wget https://raw.githubusercontent.com/leonamp/SPFBL/master/client/spfbl_end_recipient -O /usr/local/cpanel/etc/exim/acls/ACL_RECIPIENT_BLOCK/spfbl_end_recipient
        wget https://raw.githubusercontent.com/leonamp/SPFBL/master/client/spfbl_begin_smtp_dkim -O /usr/local/cpanel/etc/exim/acls/ACL_SMTP_DKIM_BLOCK/spfbl_begin_smtp_dkim
        wget https://raw.githubusercontent.com/leonamp/SPFBL/master/client/spfbl_begin_check_message_pre -O /usr/local/cpanel/etc/exim/acls/ACL_CHECK_MESSAGE_PRE_BLOCK/spfbl_begin_check_message_pre
        /usr/local/cpanel/scripts/buildeximconf
        /usr/local/cpanel/scripts/restartsrv_exim
    else
        myIP=$(curl -s http://checkip.amazonaws.com/)
        myHOST=$(hostname)
        echo "Your cPanel doesn't have permission to access matrix.spfbl.net server yet."
        echo "Please contact us to get your permission for the host $myHOST [$myIP]."
        echo "https://spfbl.net/en/contact"
        echo "If this host has already it, open the outgoing port 9877 TCP in your firewall."
    fi
}

uninstall() {
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
