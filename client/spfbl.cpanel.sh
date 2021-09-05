#!/usr/bin/bash
#
# An SPFBL Cheker installer for cPanel.
#
# Usage:
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
      sudo apt-get install nmap ncat
    elif command -v yum >/dev/null; then
      yum install -y nmap nc
    else
      exit 1
    fi
    wget https://raw.githubusercontent.com/leonamp/SPFBL/master/client/spfbl.sh -O /usr/local/bin/spfbl
    sudo chmod +x spfbl
    wget https://raw.githubusercontent.com/leonamp/SPFBL/master/client/custom_end_recipient_spfbl -O /usr/local/cpanel/etc/exim/acls/ACL_RECIPIENT_BLOCK/custom_end_recipient_spfbl
    wget https://raw.githubusercontent.com/leonamp/SPFBL/master/client/custom_end_check_message_pre_spfbl -O /usr/local/cpanel/etc/exim/acls/ACL_CHECK_MESSAGE_PRE_BLOCK/custom_end_check_message_pre_spfbl
    service exim restart
}

uninstall() {
    rm /usr/local/cpanel/etc/exim/acls/ACL_RECIPIENT_BLOCK/custom_end_recipient_spfbl
    rm /usr/local/cpanel/etc/exim/acls/ACL_CHECK_MESSAGE_PRE_BLOCK/custom_end_check_message_pre_spfbl
    service exim restart
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
