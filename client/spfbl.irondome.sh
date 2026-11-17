#!/bin/bash
#
# SPFBL Irondome installer for cPanel, DirectAdmin and pure Exim.
# The control panel is detected automatically. Pure Exim is supported
# on Debian and Ubuntu, with Exim 4.96 or newer.
#
# Usage as root:
#    ./spfbl.irondome.sh [install|update|uninstall|firewall]
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
# Version: 2.0

GITHUB_SPFBL="https://raw.githubusercontent.com/leonamp/SPFBL/master/client"
GITHUB_SIGS="https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master"
SPFBL_CLIENT="/usr/local/bin/spfbl"
SIGS_SCRIPT="/usr/local/bin/clamav-unofficial-sigs.sh"
SIGS_DIR="/etc/clamav-unofficial-sigs"
CONTACT_URL="https://spfbl.net/en/contact"

PANEL=""
PANEL_NAME=""
DISTRO_ID=""
DISTRO_VERSION=""
DISTRO_FAMILY=""

###########################################################################
# Common functions
###########################################################################

function fail() {
    echo "$@"
    echo "Please contact us to resolve this issue."
    echo "$CONTACT_URL"
    exit 1
}

function detect_other_panel() {
    # Panels with their own Exim configuration, not supported yet.
    if [ -d /usr/local/hestia ]; then
        echo "HestiaCP"
    elif [ -d /usr/local/vesta ]; then
        echo "VestaCP/myVesta"
    elif [ -d /usr/local/mgr5 ]; then
        echo "ISPmanager"
    elif [ -d /usr/local/webuzo ]; then
        echo "Webuzo"
    elif [ -d /usr/local/fastpanel2 ] || [ -d /usr/local/fastpanel ]; then
        echo "FASTPANEL"
    fi
}

function detect_panel() {
    local cpanel=false directadmin=false other
    [ -x /usr/local/cpanel/cpanel ] && cpanel=true
    [ -x /usr/local/directadmin/directadmin ] || [ -x /usr/local/directadmin/custombuild/build ] && directadmin=true
    other=$(detect_other_panel)
    if $cpanel && $directadmin; then
        fail "Both cPanel and DirectAdmin were found in this host. Installation aborted."
    elif $cpanel; then
        PANEL="cpanel"
        PANEL_NAME="cPanel"
    elif $directadmin; then
        PANEL="directadmin"
        PANEL_NAME="DirectAdmin"
    elif [ -n "$other" ]; then
        echo "Control panel detected: $other"
        echo "This control panel is not supported yet."
        echo "$CONTACT_URL"
        exit 1
    elif command -v exim4 >/dev/null 2>&1 || command -v exim >/dev/null 2>&1; then
        PANEL="exim"
        PANEL_NAME="Exim"
    else
        echo "Neither cPanel, DirectAdmin nor Exim is installed in this host."
        echo "$CONTACT_URL"
        exit 1
    fi
    echo "Control panel detected: $PANEL_NAME"
}

function detect_distro() {
    # Distribution from /etc/os-release, with the old release files
    # as fallback for CentOS/CloudLinux 6.
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO_ID=$(echo "$ID" | tr '[:upper:]' '[:lower:]')
        DISTRO_VERSION=${VERSION_ID%%.*}
        local like=" $(echo "$ID_LIKE" | tr '[:upper:]' '[:lower:]') "
    elif grep -qiE 'release 6' /etc/redhat-release 2>/dev/null; then
        DISTRO_ID=$(grep -qi cloudlinux /etc/redhat-release && echo cloudlinux || echo centos)
        DISTRO_VERSION="6"
        local like=" rhel "
    else
        DISTRO_ID="unknown"
    fi
    case "$DISTRO_ID" in
        almalinux|rocky|rhel|centos|cloudlinux|ol)
            DISTRO_FAMILY="rhel" ;;
        fedora)
            DISTRO_FAMILY="fedora" ;;
        debian)
            DISTRO_FAMILY="debian" ;;
        ubuntu)
            DISTRO_FAMILY="ubuntu" ;;
        *)
            if [[ $like == *" rhel "* || $like == *" centos "* ]]; then
                DISTRO_FAMILY="rhel"
            elif [[ $like == *" ubuntu "* ]]; then
                DISTRO_FAMILY="ubuntu"
            elif [[ $like == *" debian "* ]]; then
                DISTRO_FAMILY="debian"
            fi
            ;;
    esac
    if [ -z "$DISTRO_FAMILY" ]; then
        echo "Linux distro not identified."
        echo "Please contact us to update this installation script to it works for your distro and send the information bellow."
        echo "$CONTACT_URL"
        echo ""
        cat /etc/*-release
        exit 1
    fi
    # Versions tested by the clamav-unofficial-sigs project and by this script.
    local supported=false
    case "$DISTRO_ID:$DISTRO_VERSION" in
        almalinux:8|almalinux:9|almalinux:10) supported=true ;;
        rocky:8|rocky:9|rocky:10) supported=true ;;
        rhel:8|rhel:9|rhel:10) supported=true ;;
        ol:8|ol:9|ol:10) supported=true ;;
        centos:6|centos:7|centos:8|centos:9|centos:10) supported=true ;;
        cloudlinux:6|cloudlinux:7|cloudlinux:8|cloudlinux:9|cloudlinux:10) supported=true ;;
        debian:7|debian:8|debian:9|debian:10|debian:11|debian:12|debian:13) supported=true ;;
        ubuntu:18|ubuntu:20|ubuntu:22|ubuntu:24|ubuntu:26) supported=true ;;
        fedora:*) supported=true ;;
    esac
    echo "Linux distro detected: $DISTRO_ID $DISTRO_VERSION ($DISTRO_FAMILY family)"
    if ! $supported; then
        echo "WARNING: this version was not tested yet; using the $DISTRO_FAMILY family settings."
    fi
}

function pkg_install() {
    # Installs the given packages without asking anything.
    if command -v apt-get >/dev/null; then
        DEBIAN_FRONTEND=noninteractive apt-get install --yes "$@"
    elif command -v dnf >/dev/null; then
        dnf install -y "$@"
    elif command -v yum >/dev/null; then
        yum install -y "$@"
    else
        fail "Linux installation tool not identified."
    fi
}

function install_dependencies() {
    # nmap and ncat stay: the admin may need them to query a local SPFBL instance.
    if [ "$DISTRO_FAMILY" = "debian" ] || [ "$DISTRO_FAMILY" = "ubuntu" ]; then
        apt-get update
        pkg_install nmap curl wget gzip coreutils dnsutils rsync gnupg cron perl
        # ncat is a separate package since Debian 10 and Ubuntu 20.04.
        pkg_install ncat 2>/dev/null || true
    else
        pkg_install nmap nmap-ncat curl wget gzip coreutils bind-utils rsync gnupg2 cronie perl
    fi
    for tool in curl gzip timeout; do
        command -v $tool >/dev/null || fail "The $tool command was not correcly installed."
    done
}

function download() {
    # Downloads to a temporary file and only replaces the destination
    # when the download succeeds and is not empty.
    local url="$1" destination="$2"
    local temp
    temp=$(mktemp) || fail "Could not create a temporary file."
    if curl -fsSL --connect-timeout 10 -m 300 "$url" -o "$temp" && [ -s "$temp" ]; then
        mkdir -p "$(dirname "$destination")"
        cat "$temp" > "$destination"
        rm -f "$temp"
    else
        rm -f "$temp"
        fail "Download failed: $url"
    fi
}

function migrate_client_config() {
    # Copies the settings of the installed client into the new one:
    # every simple assignment of the configuration section (before
    # "export PATH") that also exists in the old file, plus the query
    # channel (HTTPS or ncat). Settings that only exist in the new
    # version keep their default value.
    local old="$1" new="$2"
    [ -f "$old" ] || return 0
    local name old_value new_value
    while IFS= read -r name; do
        old_value=$(awk -v n="$name" 'index($0, n "=") == 1 {print substr($0, length(n) + 2); exit}' "$old")
        new_value=$(awk -v n="$name" 'index($0, n "=") == 1 {print substr($0, length(n) + 2); exit}' "$new")
        if grep -q "^${name}=" "$old" && [ "$old_value" != "$new_value" ]; then
            V="$old_value" awk -v n="$name" '
                index($0, n "=") == 1 && !done { print n "=" ENVIRON["V"]; done = 1; next }
                { print }' "$new" > "$new.tmp" && cat "$new.tmp" > "$new" && rm -f "$new.tmp"
            echo "Preserved setting: ${name}=${old_value}"
        fi
    done < <(awk '/^export PATH=/ {exit} /^[A-Z_]+=/ {sub(/=.*/, ""); print}' "$new" | grep -vE '^(COMMAND|NCAT)$')
    # ncat only stays when it was a deliberate choice: the installed client
    # already offered curl (commented line) and the admin chose ncat.
    # Older clients, without the curl option, move to curl.
    if grep -qE '^COMMAND="\$NCAT' "$old" && grep -qE '^#[[:space:]]*COMMAND="curl' "$old"; then
        sed -i -E 's/^COMMAND="curl/# COMMAND="curl/; s/^# COMMAND="\$NCAT/COMMAND="$NCAT/' "$new"
        echo "Preserved setting: queries through ncat"
    elif grep -qE '^COMMAND="\$NCAT' "$old"; then
        echo "Changed setting: queries through HTTPS (curl) instead of ncat"
    fi
}

function install_client() {
    # Downloads the new client, applies the settings of the installed one
    # and only then replaces it.
    local new="$SPFBL_CLIENT.new"
    download "$GITHUB_SPFBL/spfbl.sh" "$new"
    migrate_client_config "$SPFBL_CLIENT" "$new"
    if ! bash -n "$new"; then
        rm -f "$new"
        fail "The new SPFBL client is invalid after applying the current settings."
    fi
    chmod +x "$new"
    mv -f "$new" "$SPFBL_CLIENT"
}

function client_value() {
    # Reads a configuration value from the installed SPFBL client.
    sed -n "s/^$1=\"\\(.*\\)\"/\\1/p" "$SPFBL_CLIENT" | head -1
}

function access_denied() {
    local myIP myHOST
    myIP=$(curl -s https://checkip.amazonaws.com/)
    myHOST=$(hostname)
    echo "Your $PANEL_NAME doesn't have permission to access the SPFBL server yet."
    echo "Please contact us to get your permission for the host $myHOST [$myIP]."
    echo "$CONTACT_URL"
    if grep -qE '^COMMAND="\$NCAT' "$SPFBL_CLIENT"; then
        # Client configured to query through ncat.
        local server port serverIP
        server=$(client_value IP_SERVIDOR)
        port=$(client_value PORTA_SERVIDOR)
        serverIP=$(dig +short A "$server" | grep -E '^[0-9.]+$' | head -1)
        echo "If this host has already it, open the port $port TCP OUT in your firewall"
        echo "and add the IP $serverIP in its whitelist."
    else
        # Client configured to query through HTTPS.
        local url host
        url=$(client_value URL_SERVIDOR)
        host=${url#*://}
        host=${host%%/*}
        echo "If this host has already it, allow outbound HTTPS (TCP 443)"
        echo "to $host in your firewall."
    fi
    exit 1
}

function find_clamd() {
    # Finds the clamd that is actually running: configuration, socket,
    # database directory and its owner. Waits up to 60 seconds for the
    # socket, because clamd only creates it after loading the databases.
    local candidates=(/etc/clamd.d/scan.conf /etc/clamav/clamd.conf /usr/local/etc/clamd.conf /etc/clamd.conf)
    if [ "$PANEL" = "cpanel" ]; then
        candidates=(/usr/local/cpanel/3rdparty/etc/clamd.conf "${candidates[@]}")
    fi
    CLAMD_CONF=""
    CLAMD_SOCKET=""
    CLAMD_DBS=""
    CLAMD_USER=""
    local wait conf socket
    for wait in $(seq 1 12); do
        for conf in "${candidates[@]}"; do
            [ -f "$conf" ] || continue
            socket=$(awk '$1 == "LocalSocket" {print $2}' "$conf" | tail -1)
            if [ -n "$socket" ] && [ -S "$socket" ]; then
                CLAMD_CONF="$conf"
                CLAMD_SOCKET="$socket"
                break 2
            fi
        done
        sleep 5
    done
    if [ -z "$CLAMD_CONF" ]; then
        # No socket yet: keeps the first configuration found.
        for conf in "${candidates[@]}"; do
            if [ -f "$conf" ]; then
                CLAMD_CONF="$conf"
                CLAMD_SOCKET=$(awk '$1 == "LocalSocket" {print $2}' "$conf" | tail -1)
                break
            fi
        done
    fi
    if [ -n "$CLAMD_CONF" ]; then
        CLAMD_DBS=$(awk '$1 == "DatabaseDirectory" {print $2}' "$CLAMD_CONF" | tail -1)
        CLAMD_USER=$(awk '$1 == "User" {print $2}' "$CLAMD_CONF" | tail -1)
    fi
    echo "ClamAV daemon: config=${CLAMD_CONF:-none} socket=${CLAMD_SOCKET:-none} dbs=${CLAMD_DBS:-default}"
}

function select_sigs_os_conf() {
    # Base OS configuration from the clamav-unofficial-sigs project.
    if [ "$PANEL" = "cpanel" ]; then
        # cPanel always uses its own ClamAV build under /usr/local/cpanel/3rdparty,
        # on every distro, Ubuntu included.
        if [ "$DISTRO_VERSION" = "6" ]; then
            echo "os.centos6-cpanel.conf"
        else
            echo "os.centos7-cpanel.conf"
        fi
    else
        case "$DISTRO_FAMILY:$DISTRO_VERSION" in
            rhel:6) echo "os.centos6.conf" ;;
            rhel:7) echo "os.centos.conf" ;;
            rhel:*) echo "os.rhel.conf" ;;
            fedora:*) echo "os.fedora.conf" ;;
            debian:7) echo "os.debian7.conf" ;;
            debian:8) echo "os.debian8.conf" ;;
            debian:*) echo "os.debian.conf" ;;
            ubuntu:*) echo "os.ubuntu.conf" ;;
        esac
    fi
}

function configure_sigs_databases() {
    # SPFBL databases, replacing any previous block (no duplicates on reinstall).
    local user_conf="$SIGS_DIR/user.conf"
    [ -f "$user_conf" ] || download "$GITHUB_SIGS/config/user.conf" "$user_conf"
    awk '/^declare -a additional_dbs=\(/{skip=1} !skip{print} /END ADDITIONAL DATABASES/{skip=0}' "$user_conf" > "$user_conf.tmp"
    cat "$user_conf.tmp" > "$user_conf" && rm -f "$user_conf.tmp"
    # Removes the blank lines left at the end, so reinstalls don't pile them up.
    sed -i -e :a -e '/^\n*$/{$d;N;ba' -e '}' "$user_conf"
    {
        printf "\ndeclare -a additional_dbs=(\n"
        printf "\thttps://matrix.spfbl.net/spfbl.hsb\n"
        printf "\thttps://matrix.spfbl.net/spfbl.ldb\n"
        printf "\thttps://matrix.spfbl.net/spfbl.ign2\n"
        if [ "$PANEL" = "cpanel" ]; then
            printf "\thttps://matrix.spfbl.net/cpanel.ign2\n"
        fi
        printf ") #END ADDITIONAL DATABASES\n\n"
    } >> "$user_conf"
    # Activation required by the script (already present in recent user.conf).
    grep -q '^user_configuration_complete="yes"' "$user_conf" || echo 'user_configuration_complete="yes"' >> "$user_conf"
}

function install_sigs() {
    # Conflicts with this script when installed as a distro package.
    if command -v dpkg >/dev/null && dpkg -s clamav-unofficial-sigs >/dev/null 2>&1; then
        apt-get purge -y clamav-unofficial-sigs
    fi
    mkdir -p "$SIGS_DIR"
    # The script and master.conf must always have the same version.
    download "$GITHUB_SIGS/clamav-unofficial-sigs.sh" "$SIGS_SCRIPT"
    chmod 755 "$SIGS_SCRIPT"
    download "$GITHUB_SIGS/config/master.conf" "$SIGS_DIR/master.conf"
    local os_conf
    os_conf=$(select_sigs_os_conf)
    download "$GITHUB_SIGS/config/os/$os_conf" "$SIGS_DIR/os.conf"
    # Adjusts the base configuration to the clamd actually installed.
    find_clamd
    {
        echo ""
        echo "# Detected by spfbl.irondome.sh from ${CLAMD_CONF:-defaults}."
        if [ -n "$CLAMD_DBS" ] && [ -d "$CLAMD_DBS" ]; then
            echo "clam_dbs=\"$CLAMD_DBS\""
            echo "clam_user=\"$(stat -c %U "$CLAMD_DBS")\""
            echo "clam_group=\"$(stat -c %G "$CLAMD_DBS")\""
        fi
        if [ -n "$CLAMD_SOCKET" ]; then
            echo "clamd_socket=\"$CLAMD_SOCKET\""
        fi
    } >> "$SIGS_DIR/os.conf"
    configure_sigs_databases
    "$SIGS_SCRIPT" --force
    "$SIGS_SCRIPT" --install-cron --install-logrotate
}

function install_holding() {
    echo -e '#!/bin/bash\n/usr/local/bin/spfbl holding' > /etc/cron.hourly/spfbl-holding-check
    chmod +x /etc/cron.hourly/spfbl-holding-check
}

function firewall() {
    rm -f /etc/cron.hourly/spfbl-firewall-update
    download "$GITHUB_SPFBL/firewall.cpanel.sh" /usr/local/bin/spfbl-firewall-update
    chmod +x /usr/local/bin/spfbl-firewall-update
    /usr/local/bin/spfbl-firewall-update
    echo "SPFBL Firewall was successfully installed!"
}

function uninstall_common() {
    # Holding routine.
    rm -f /etc/cron.hourly/spfbl-holding-check
    # Firewall.
    if [ -f /etc/csf/csfpost.sh ] && grep -q "/usr/local/bin/spfbl-firewall" /etc/csf/csfpost.sh; then
        sed -i '/\/usr\/local\/bin\/spfbl-firewall/d' /etc/csf/csfpost.sh
    fi
    rm -f /usr/local/bin/spfbl-firewall-update
    rm -f /etc/cron.hourly/spfbl-firewall-update
    iptables -w -D INPUT -p tcp -m tcp --dport 25 --tcp-flags FIN,SYN,RST,ACK SYN -m state --state NEW -j SPFBL 2>/dev/null
    iptables -w -F SPFBL 2>/dev/null
    iptables -w -X SPFBL 2>/dev/null
}

###########################################################################
# cPanel functions
###########################################################################

function cpanel_exim_option() {
    # Changes parameters in the Exim Configuration Manager interface.
    local option_name=$1 option_value=$2
    if grep -q "^${option_name}=" /etc/exim.conf.localopts; then
        sed -i "s/^${option_name}=.*/${option_name}=${option_value}/" /etc/exim.conf.localopts
    else
        echo "${option_name}=${option_value}" >> /etc/exim.conf.localopts
    fi
}

function cpanel_local_option() {
    # Sets "key = value" in the @CONFIG@ section of /etc/exim.conf.local.
    local key=$1 value=$2
    if grep -q "^${key} = " /etc/exim.conf.local; then
        sed -i "s/^${key} = .*/${key} = ${value}/" /etc/exim.conf.local
    elif grep -q "@CONFIG@" /etc/exim.conf.local; then
        sed -i "/@CONFIG@/a ${key} = ${value}" /etc/exim.conf.local
    else
        printf "@CONFIG@\n\n${key} = ${value}\n" >> /etc/exim.conf.local
    fi
}

function cpanel_install_clamav() {
    /usr/local/cpanel/scripts/update_local_rpm_versions --edit target_settings.clamav installed
    if [ -x /usr/local/cpanel/scripts/check_cpanel_pkgs ]; then
        /usr/local/cpanel/scripts/check_cpanel_pkgs --fix --targets=clamav
    else
        /usr/local/cpanel/scripts/check_cpanel_rpms --fix --targets=clamav
    fi
}

function cpanel_configure_exim() {
    download "$GITHUB_SPFBL/spfbl_end_recipient" /usr/local/cpanel/etc/exim/acls/ACL_RECIPIENT_BLOCK/spfbl_end_recipient
    download "$GITHUB_SPFBL/spfbl_begin_smtp_dkim" /usr/local/cpanel/etc/exim/acls/ACL_SMTP_DKIM_BLOCK/spfbl_begin_smtp_dkim
    download "$GITHUB_SPFBL/spfbl_begin_check_message_pre" /usr/local/cpanel/etc/exim/acls/ACL_CHECK_MESSAGE_PRE_BLOCK/spfbl_begin_check_message_pre
    cpanel_exim_option "spfbl_end_recipient" "1"
    cpanel_exim_option "spfbl_begin_smtp_dkim" "1"
    cpanel_exim_option "spfbl_begin_check_message_pre" "1"
    cpanel_exim_option "acl_delay_unknown_hosts" "0"
    cpanel_exim_option "acl_dkim_disable" "0"
    cpanel_exim_option "acl_dkim_bl" "0"
    cpanel_exim_option "acl_spam_scan_secondarymx" "0"
    cpanel_exim_option "acl_outgoing_spam_scan" "0"
    cpanel_exim_option "acl_outgoing_spam_scan_over_int" "0"
    cpanel_exim_option "acl_default_exiscan" "0"
    cpanel_exim_option "acl_default_spam_scan" "0"
    cpanel_exim_option "acl_default_spam_scan_check" "0"
    cpanel_exim_option "acl_slow_fail_block" "0"
    touch /etc/exim.conf.local
    # Legacy spamd interface: every query now goes through the SPFBL client.
    sed -i '/^spamd_address = /d' /etc/exim.conf.local
    cpanel_local_option "timeout_frozen_after" "7d"
    cpanel_local_option "smtp_accept_max" "250"
    /usr/local/cpanel/scripts/buildeximconf
    /usr/local/cpanel/scripts/restartsrv_exim
}

function cpanel_uninstall() {
    "$SIGS_SCRIPT" --remove-script
    rm -f /usr/local/cpanel/etc/exim/acls/ACL_RECIPIENT_BLOCK/spfbl_end_recipient
    rm -f /usr/local/cpanel/etc/exim/acls/ACL_SMTP_DKIM_BLOCK/spfbl_begin_smtp_dkim
    rm -f /usr/local/cpanel/etc/exim/acls/ACL_CHECK_MESSAGE_PRE_BLOCK/spfbl_begin_check_message_pre
    cpanel_exim_option "acl_delay_unknown_hosts" "1"
    cpanel_exim_option "acl_dkim_disable" "1"
    cpanel_exim_option "acl_dkim_bl" "0"
    cpanel_exim_option "acl_spam_scan_secondarymx" "1"
    cpanel_exim_option "acl_outgoing_spam_scan" "0"
    cpanel_exim_option "acl_outgoing_spam_scan_over_int" "0"
    cpanel_exim_option "acl_default_exiscan" "0"
    cpanel_exim_option "acl_default_spam_scan" "1"
    cpanel_exim_option "acl_default_spam_scan_check" "1"
    cpanel_exim_option "acl_slow_fail_block" "1"
    if [ -f /etc/exim.conf.local ]; then
        sed -i '/^timeout_frozen_after = /d;/^spamd_address = /d;/^smtp_accept_max = /d' /etc/exim.conf.local
    fi
    /usr/local/cpanel/scripts/buildeximconf
    /usr/local/cpanel/scripts/restartsrv_exim
}

###########################################################################
# DirectAdmin functions
###########################################################################

DA_BUILD="/usr/local/directadmin/custombuild/build"

function da_set_key() {
    local file="$1" key="$2" sep="$3" value="$4" keep="$5"
    touch "$file"
    if grep -qE "^[[:space:]]*${key}[[:space:]]*${sep}" "$file"; then
        if [ "$keep" != "keep" ]; then
            sed -i -E "s|^[[:space:]]*${key}[[:space:]]*${sep}.*|${key} ${sep} ${value}|" "$file"
        fi
    else
        echo "${key} ${sep} ${value}" >> "$file"
    fi
}

function da_unset_key() {
    local file="$1" key="$2" value="$3"
    [ -f "$file" ] || return 0
    awk -v k="$key" -v v="$value" '
        { line = $0; sub(/^[[:space:]]+/, "", line) }
        index(line, k) == 1 && substr(line, length(k) + 1) ~ /^[[:space:]]*=/ && (v == "" || index($0, v) > 0) { next }
        { print }' "$file" > "$file.tmp"
    cat "$file.tmp" > "$file" && rm -f "$file.tmp"
}

function da_restart_exim() {
    if command -v systemctl >/dev/null 2>&1 &&
       [ -d /run/systemd/system ] &&
       systemctl cat exim.service >/dev/null 2>&1; then
        systemctl restart exim.service
    elif [ -x /etc/init.d/exim ]; then
        /etc/init.d/exim restart
    elif command -v service >/dev/null 2>&1; then
        service exim restart
    else
        echo "ERROR: Exim service manager not found." >&2
        return 1
    fi
}

function da_install_clamav() {
    if [ "$DISTRO_FAMILY" = "debian" ] || [ "$DISTRO_FAMILY" = "ubuntu" ]; then
        pkg_install clamav clamav-daemon clamav-freshclam
    else
        # ClamAV comes from EPEL on the RHEL family.
        rpm -q epel-release >/dev/null 2>&1 || pkg_install epel-release
        pkg_install clamav clamd clamav-update
        # The packaged scan.conf ships disabled ("Example") and without the
        # socket that Exim uses (RHEL guide of clamav-unofficial-sigs).
        if [ -f /etc/clamd.d/scan.conf ]; then
            sed -i '/^Example$/d' /etc/clamd.d/scan.conf
            sed -i 's|^#LocalSocket /run/clamd.scan/clamd.sock|LocalSocket /run/clamd.scan/clamd.sock|' /etc/clamd.d/scan.conf
        fi
        command -v setsebool >/dev/null && setsebool -P antivirus_can_scan_system 1
        if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
            systemctl enable --now clamav-freshclam.service 2>/dev/null
            systemctl enable --now clamd@scan 2>/dev/null
        fi
    fi
    # Enables ClamAV and disables the other spam filters.
    "$DA_BUILD" update
    "$DA_BUILD" set clamav yes
    "$DA_BUILD" set easy_spam_fighter no
    "$DA_BUILD" set spamassassin no
    [ -f /etc/mail/spamassassin.cf ] && mv /etc/mail/spamassassin.cf /etc/mail/spamassassin.cf.back
    "$DA_BUILD" clamav
}

function da_configure_exim() {
    mkdir -p /etc/exim.easy_spam_fighter/
    download "$GITHUB_SPFBL/directadmin.acl_check_recipient.pre.conf" /etc/exim.acl_check_recipient.pre.conf
    download "$GITHUB_SPFBL/directadmin.acl_check_dkim.conf" /etc/exim.easy_spam_fighter/check_dkim.conf
    download "$GITHUB_SPFBL/directadmin.acl_check_message.pre.conf" /etc/exim.acl_check_message.pre.conf
    [ -f /etc/exim.variables.conf.custom.bak-spfbl ] || cp -p /etc/exim.variables.conf.custom /etc/exim.variables.conf.custom.bak-spfbl 2>/dev/null
    [ -f /etc/exim.strings.conf.custom.bak-spfbl ] || cp -p /etc/exim.strings.conf.custom /etc/exim.strings.conf.custom.bak-spfbl 2>/dev/null
    # Exim must reach the clamd actually running: Exim runs as "mail".
    find_clamd
    local socket="${CLAMD_SOCKET:-/run/clamd.scan/clamd.sock}"
    local current
    current=$(sed -n -E 's|^[[:space:]]*av_scanner[[:space:]]*=[[:space:]]*clamd:([^[:space:]]+).*|\1|p' /etc/exim.variables.conf.custom 2>/dev/null | tail -1)
    if [ -n "$current" ] && [ -S "$current" ]; then
        da_set_key /etc/exim.variables.conf.custom av_scanner "=" "clamd:$socket" keep
    else
        da_set_key /etc/exim.variables.conf.custom av_scanner "=" "clamd:$socket"
    fi
    if [ -n "$CLAMD_USER" ] && id "$CLAMD_USER" >/dev/null 2>&1; then
        usermod -aG mail "$CLAMD_USER"
    fi
    getent group virusgroup >/dev/null && usermod -aG virusgroup mail
    # Legacy spamd interface: every query now goes through the SPFBL client.
    da_unset_key /etc/exim.variables.conf.custom spamd_address
    # Frozen messages wait for "spfbl holding"; without this limit they never expire.
    da_set_key /etc/exim.variables.conf.custom timeout_frozen_after "=" "7d"
    da_set_key /etc/exim.strings.conf.custom RBL_DNS_LIST "==" ""
    # Custom variables only take effect after the Exim configuration is rebuilt.
    "$DA_BUILD" exim_conf
    da_restart_exim || exit 1
}

function da_uninstall() {
    # Disables ClamAV and enables the spam filters.
    "$DA_BUILD" set clamav no
    "$DA_BUILD" set clamav_exim no
    "$DA_BUILD" set proftpd_uploadscan no
    "$DA_BUILD" set pureftpd_uploadscan no
    "$DA_BUILD" set suhosin_php_uploadscan no
    "$DA_BUILD" set modsecurity_uploadscan no
    "$DA_BUILD" set easy_spam_fighter yes
    "$DA_BUILD" remove_clamav
    da_unset_key /etc/exim.variables.conf.custom spamd_address
    da_unset_key /etc/exim.variables.conf.custom av_scanner "clamd:"
    da_unset_key /etc/exim.variables.conf.custom timeout_frozen_after "7d"
    da_unset_key /etc/exim.strings.conf.custom RBL_DNS_LIST
    "$DA_BUILD" exim_conf
    "$DA_BUILD" proftpd
    "$DA_BUILD" clean
    "$DA_BUILD" php_ini
    "$DA_BUILD" rewrite_confs
    if [ -f /etc/mail/spamassassin.cf.back ]; then
        mv /etc/mail/spamassassin.cf.back /etc/mail/spamassassin.cf
        "$DA_BUILD" set spamassassin yes
        "$DA_BUILD" update
        "$DA_BUILD" spamassassin
    fi
    [ -x "$SIGS_SCRIPT" ] && "$SIGS_SCRIPT" --remove-script
    rm -f /etc/exim.acl_check_recipient.pre.conf
    rm -rf /etc/exim.easy_spam_fighter/
    rm -f /etc/exim.acl_check_message.pre.conf
    da_restart_exim
}

###########################################################################
# Pure Exim functions (Debian and Ubuntu)
###########################################################################

EXIM_SPFBL_DIR="/etc/exim4/spfbl"
EXIM_MACROS="/etc/exim4/exim4.conf.localmacros"
EXIM_MACROS_BACKUP="/etc/exim4/exim4.conf.localmacros.bak-spfbl"
EXIM_STATE="/var/lib/spfbl/irondome.state"
EXIM_BIN=""

function state_get() {
    # Reads a value recorded by the first installation.
    [ -f "$EXIM_STATE" ] && sed -n "s/^$1=//p" "$EXIM_STATE" | tail -1
}

function state_set_once() {
    # Records the original state only once: reinstalls and updates
    # must not overwrite what the host had before SPFBL.
    mkdir -p "$(dirname "$EXIM_STATE")"
    touch "$EXIM_STATE"
    grep -q "^$1=" "$EXIM_STATE" || echo "$1=$2" >> "$EXIM_STATE"
}

function exim_value() {
    # Effective value of a main option in the current configuration.
    "$EXIM_BIN" -bP -n "$1" 2>/dev/null
}

function exim_macro() {
    # Effective value of a macro in the current configuration.
    "$EXIM_BIN" -bP macro "$1" 2>/dev/null | sed -n "s/^$1[[:space:]]*=[[:space:]]*//p"
}

function exim_check() {
    # Everything that can stop the installation is checked here,
    # before any change in the host.
    if [ "$DISTRO_FAMILY" != "debian" ] && [ "$DISTRO_FAMILY" != "ubuntu" ]; then
        fail "Pure Exim is only supported on Debian and Ubuntu for now."
    fi
    EXIM_BIN=$(command -v exim4 || command -v exim)
    [ -n "$EXIM_BIN" ] || fail "The Exim binary was not found."
    command -v update-exim4.conf >/dev/null || fail "The Debian Exim configuration (exim4-config) was not found."
    if [ -f /etc/exim4/exim4.conf ]; then
        # Hand-written configuration: update-exim4.conf and its macros are ignored.
        fail "The file /etc/exim4/exim4.conf replaces the Debian configuration and is not supported."
    fi
    # Exim 4.96 splits the ${run} arguments before the expansion, so the
    # single quotes of the ACLs are safe for any sender or recipient.
    local version major minor
    version=$("$EXIM_BIN" -bV 2>/dev/null | sed -n 's/^Exim version \([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p' | head -1)
    major=${version%%.*}
    minor=${version#*.}
    if [ -z "$version" ] || [ "$major" -lt 4 ] || { [ "$major" -eq 4 ] && [ "$minor" -lt 96 ]; }; then
        fail "Exim ${version:-unknown} found. SPFBL Irondome requires Exim 4.96 or newer."
    fi
    echo "Exim version detected: $version"
    # Options and macros already defined by the admin are not overwritten.
    local name value
    for name in CHECK_RCPT_LOCAL_ACL_FILE CHECK_DATA_LOCAL_ACL_FILE; do
        value=$(exim_macro "$name")
        if [ -n "$value" ] && [[ $value != $EXIM_SPFBL_DIR/* ]]; then
            fail "The macro $name is already defined ($value). Installation aborted."
        fi
    done
    value=$(exim_value acl_smtp_dkim)
    if [ -n "$value" ] && [[ $value != $EXIM_SPFBL_DIR/* ]]; then
        fail "The option acl_smtp_dkim is already defined ($value). Installation aborted."
    fi
    value=$(exim_value av_scanner)
    if [ -n "$value" ] && ! grep -q "^# BEGIN SPFBL" "$EXIM_MACROS" 2>/dev/null; then
        fail "The option av_scanner is already defined ($value). Installation aborted."
    fi
}

function exim_install_clamav() {
    # Content scanning (malware condition) only exists in the heavy daemon.
    local daemon
    for daemon in exim4-daemon-heavy exim4-daemon-light; do
        if dpkg -s "$daemon" 2>/dev/null | grep -q '^Status: install ok installed'; then
            state_set_once EXIM_DAEMON "$daemon"
            break
        fi
    done
    if [ "$(state_get EXIM_DAEMON)" != "exim4-daemon-heavy" ]; then
        pkg_install exim4-daemon-heavy
    fi
    "$EXIM_BIN" -bV | grep -q 'Content_Scanning' || fail "This Exim build has no content scanning support."
    # ClamAV from the distro packages.
    if dpkg -s clamav-daemon 2>/dev/null | grep -q '^Status: install ok installed'; then
        state_set_once CLAMAV_PACKAGES "present"
    else
        state_set_once CLAMAV_PACKAGES "installed"
        pkg_install clamav clamav-daemon clamav-freshclam
    fi
    # clamd reads the files that Exim unpacks in its spool.
    if id -nG clamav 2>/dev/null | grep -qw Debian-exim; then
        state_set_once CLAMAV_GROUP "present"
    else
        state_set_once CLAMAV_GROUP "added"
        usermod -aG Debian-exim clamav
    fi
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        # clamd only starts after the first database download.
        if ! ls /var/lib/clamav/*.c[lv]d >/dev/null 2>&1; then
            systemctl stop clamav-freshclam.service 2>/dev/null
            freshclam
        fi
        systemctl enable --now clamav-freshclam.service 2>/dev/null
        systemctl enable clamav-daemon.service 2>/dev/null
        systemctl restart clamav-daemon.service
    fi
}

function exim_remove_block() {
    # Removes the lines between the SPFBL markers.
    local file="$1"
    [ -f "$file" ] || return 0
    awk '/^# BEGIN SPFBL$/{skip=1} !skip{print} /^# END SPFBL$/{skip=0}' "$file" > "$file.tmp"
    cat "$file.tmp" > "$file" && rm -f "$file.tmp"
}

function exim_write_block() {
    local socket="$1"
    exim_remove_block "$EXIM_MACROS"
    {
        echo "# BEGIN SPFBL"
        echo "CHECK_RCPT_LOCAL_ACL_FILE = $EXIM_SPFBL_DIR/acl_check_rcpt.conf"
        echo "CHECK_DATA_LOCAL_ACL_FILE = $EXIM_SPFBL_DIR/acl_check_data.conf"
        echo "acl_smtp_dkim = $EXIM_SPFBL_DIR/acl_check_dkim.conf"
        echo "av_scanner = clamd:$socket"
        # Frozen messages wait for "spfbl holding"; without this limit they never expire.
        if [ "$(state_get FROZEN_OPTION)" = "added" ]; then
            echo "timeout_frozen_after = 7d"
        fi
        echo "# END SPFBL"
    } >> "$EXIM_MACROS"
}

function exim_restart() {
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        systemctl restart exim4.service
    else
        invoke-rc.d exim4 restart
    fi
}

function exim_rebuild() {
    # Generates the final configuration and checks it before the restart.
    update-exim4.conf && "$EXIM_BIN" -bV >/dev/null
}

function exim_configure() {
    download "$GITHUB_SPFBL/exim.acl_check_rcpt.conf" "$EXIM_SPFBL_DIR/acl_check_rcpt.conf"
    download "$GITHUB_SPFBL/exim.acl_check_data.conf" "$EXIM_SPFBL_DIR/acl_check_data.conf"
    download "$GITHUB_SPFBL/exim.acl_check_dkim.conf" "$EXIM_SPFBL_DIR/acl_check_dkim.conf"
    # Backup of the only Exim file touched by SPFBL, on the first installation.
    if [ ! -f "$EXIM_MACROS_BACKUP" ]; then
        if [ -f "$EXIM_MACROS" ]; then
            cp -p "$EXIM_MACROS" "$EXIM_MACROS_BACKUP"
            state_set_once MACROS_FILE "present"
        else
            : > "$EXIM_MACROS_BACKUP"
            state_set_once MACROS_FILE "absent"
        fi
    fi
    # Only when the host has no limit for frozen messages.
    if [ -z "$(state_get FROZEN_OPTION)" ]; then
        local frozen
        frozen=$(exim_value timeout_frozen_after)
        if [ -z "$frozen" ] || [ "$frozen" = "0s" ]; then
            state_set_once FROZEN_OPTION "added"
        else
            state_set_once FROZEN_OPTION "present"
        fi
    fi
    find_clamd
    exim_write_block "${CLAMD_SOCKET:-/run/clamav/clamd.ctl}"
    if ! exim_rebuild; then
        # Leaves Exim as it was before this installation.
        exim_remove_block "$EXIM_MACROS"
        rm -rf "$EXIM_SPFBL_DIR"
        exim_rebuild
        fail "The new Exim configuration is invalid. The previous configuration was kept."
    fi
    exim_restart || fail "Exim could not be restarted."
}

function exim_uninstall() {
    EXIM_BIN=$(command -v exim4 || command -v exim)
    [ -x "$SIGS_SCRIPT" ] && "$SIGS_SCRIPT" --remove-script
    # Configuration: only the SPFBL block and files.
    exim_remove_block "$EXIM_MACROS"
    if [ "$(state_get MACROS_FILE)" = "absent" ] && [ -f "$EXIM_MACROS" ] && ! grep -q '[^[:space:]]' "$EXIM_MACROS"; then
        rm -f "$EXIM_MACROS"
    fi
    if [ -f "$EXIM_MACROS_BACKUP" ]; then
        if { [ -f "$EXIM_MACROS" ] && cmp -s "$EXIM_MACROS" "$EXIM_MACROS_BACKUP"; } ||
           { [ ! -f "$EXIM_MACROS" ] && [ ! -s "$EXIM_MACROS_BACKUP" ]; }; then
            rm -f "$EXIM_MACROS_BACKUP"
        else
            echo "WARNING: $EXIM_MACROS was changed after the SPFBL installation."
            echo "The original file was kept in $EXIM_MACROS_BACKUP."
        fi
    fi
    rm -rf "$EXIM_SPFBL_DIR"
    # Packages and groups, only when SPFBL changed them.
    if [ "$(state_get EXIM_DAEMON)" = "exim4-daemon-light" ]; then
        pkg_install exim4-daemon-light
    fi
    if [ "$(state_get CLAMAV_GROUP)" = "added" ]; then
        gpasswd -d clamav Debian-exim 2>/dev/null
    fi
    if [ "$(state_get CLAMAV_PACKAGES)" = "installed" ]; then
        DEBIAN_FRONTEND=noninteractive apt-get remove --yes clamav clamav-daemon clamav-freshclam
    fi
    rm -f "$EXIM_STATE"
    if [ -n "$EXIM_BIN" ]; then
        exim_rebuild || echo "WARNING: check the Exim configuration with update-exim4.conf." >&2
        exim_restart
    fi
}

###########################################################################
# Commands
###########################################################################

function is_installed() {
    if [ "$PANEL" = "cpanel" ]; then
        [ -f /usr/local/cpanel/etc/exim/acls/ACL_RECIPIENT_BLOCK/spfbl_end_recipient ]
    elif [ "$PANEL" = "exim" ]; then
        [ -f "$EXIM_SPFBL_DIR/acl_check_rcpt.conf" ]
    else
        [ -f /etc/exim.acl_check_recipient.pre.conf ]
    fi
}

function install() {
    detect_distro
    [ "$PANEL" = "exim" ] && exim_check
    install_dependencies
    install_client
    if ! "$SPFBL_CLIENT" version; then
        access_denied
    fi
    if [ "$PANEL" = "cpanel" ]; then
        cpanel_install_clamav
        install_sigs
        cpanel_configure_exim
    elif [ "$PANEL" = "exim" ]; then
        exim_install_clamav
        install_sigs
        exim_configure
    else
        da_install_clamav
        install_sigs
        da_configure_exim
    fi
    install_holding
    echo "SPFBL Irondome was successfully installed!"
    echo ""
    echo "Installing SPFBL Firewall solution..."
    firewall
}

function update() {
    if ! is_installed; then
        echo "The SPFBL Irondome was not installed yet."
        exit 1
    fi
    detect_distro
    [ "$PANEL" = "exim" ] && exim_check
    install_dependencies
    install_client
    # Signatures: script, master.conf and the SPFBL databases (spfbl.ldb included).
    install_sigs
    if [ "$PANEL" = "cpanel" ]; then
        cpanel_configure_exim
    elif [ "$PANEL" = "exim" ]; then
        exim_configure
    else
        da_configure_exim
    fi
    install_holding
    firewall
}

function uninstall() {
    if [ "$PANEL" = "cpanel" ]; then
        cpanel_uninstall
    elif [ "$PANEL" = "exim" ]; then
        exim_uninstall
    else
        da_uninstall
    fi
    uninstall_common
}

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must run as root."
    exit 1
fi

case "$1" in
    install)
        echo "[install] Installing SPFBL Irondome powered by SPFBL.net"
        detect_panel
        install
    ;;
    update)
        echo "[update] Updating SPFBL Irondome powered by SPFBL.net"
        detect_panel
        update
    ;;
    uninstall)
        echo "[uninstall] Uninstalling SPFBL Irondome powered by SPFBL.net"
        detect_panel
        uninstall
    ;;
    firewall)
        echo "[firewall] Installing SPFBL Firewall powered by SPFBL.net"
        detect_panel
        firewall
    ;;
    *)
        echo "*** Usage: $0 [install|update|uninstall|firewall]"
        exit 1
esac
