#!/usr/bin/bash
#
# An advanced SPF cheker installer for cPanel.
#
# Usage:
#    ./aspf.cpanel.sh [install|uninstall] 
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
    sudo cpan -i -f Config::Std Net::IP Net::DNS Mail::SPF URI::Encode
    sudo cpan -i -f LWP::UserAgent HTTP::Request HTTP::Cookies JSON::XS
    cd /usr/local/bin/
    wget https://raw.githubusercontent.com/leonamp/SPFBL/master/client/spfbl.pl
    sudo chmod +x spfbl.pl
    cd /usr/local/cpanel/etc/exim/acls/ACL_MAIL_BLOCK
    wget https://raw.githubusercontent.com/leonamp/SPFBL/master/client/custom_end_mail_spfbl
    service exim restart
}

uninstall() {
    rm /usr/local/cpanel/etc/exim/acls/ACL_MAIL_BLOCK/custom_end_mail_spfbl
    service exim restart
}

case "$1" in
    install)
        echo "[install] Installing Advanced SPF Checker powered by SPFBL.net"
        install
    ;;
    uninstall)
        echo "[uninstall] Uninstalling Advanced SPF Checker powered by SPFBL.net"
        uninstall
    ;;
    *)
        echo "*** Usage: $0 [install|uninstall]"
        exit 1
esac

