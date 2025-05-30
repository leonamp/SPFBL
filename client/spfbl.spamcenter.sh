#!/bin/bash
#
# The spamcenter databse installer for clamav-unofficial-sigs.
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

if [ ! -e /etc/clamav-unofficial-sigs/user.conf ]; then

    echo "The clamav-unofficial-sigs is not installed yet."

elif [ "$1" == "" ]; then

    IP=$(curl -s https://matrix.spfbl.net/whatsmyip/)

    if [ $? -eq 0 ]; then
        echo "Your host is using the address $IP"
    else
        echo "This script could not get your host IP."
    fi

elif [[ $1 =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then

    status_code1=$(curl -o /dev/null --silent --head --write-out '%{http_code}\n' "https://api.spam.center/download/clamav/$1/spamcenter.ndb")
    status_code2=$(curl -o /dev/null --silent --head --write-out '%{http_code}\n' "https://api.spam.center/download/clamav/$1/spamcenter.hsb")

    if [[ $status_code1 == 200 && $status_code2 == 200 ]]; then

        COUNT=$(grep -c "$1" /etc/clamav-unofficial-sigs/user.conf)

        if [[ $COUNT < 2 ]]; then
            sed -i "/^) #END ADDITIONAL DATABASES$/i \ \ \ https://api.spam.center/download/clamav/${1}/spamcenter.ndb\n\ \ \ https://api.spam.center/download/clamav/${1}/spamcenter.hsb" /etc/clamav-unofficial-sigs/user.conf
        else
            echo "This API key was already set."
        fi

        # Install rsync.
        if command -v apt-get >/dev/null; then
            apt-get install --yes rsync
        elif command -v yum >/dev/null; then
            yum install -y rsync
        else
            echo "Linux installation tool not identified."
            echo "Please contact us to update this installation script to it works for your distro."
            echo "https://spfbl.net/en/contact"
            exit 1
        fi
    
        /usr/local/bin/clamav-unofficial-sigs.sh --force
        if [ $? -eq 0 ]; then
            sed -i 's/^additional_update_hours="[0-9]\+"/additional_update_hours="1"/' /etc/clamav-unofficial-sigs/master.conf
            echo "Spamcenter data was successfully installed."
        else
            echo "Spamcenter data instalaton has failed."
        fi
    else
        IP=$(curl -s https://matrix.spfbl.net/whatsmyip/)
        echo "This API key has not permission to access Spamcenter data using IP $IP"
    fi
else
    echo "This is not a valid API key."
fi

