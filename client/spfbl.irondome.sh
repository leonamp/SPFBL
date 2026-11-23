#!/bin/bash
#
# SPFBL Irondome installer for cPanel, DirectAdmin, pure Exim and
# Postfix panels. The control panel is detected automatically.
# Pure Exim is supported on Debian and Ubuntu, with Exim 4.96 or newer.
# On CyberPanel, aaPanel, iRedMail and CWP, a compiled Exim works as a
# gateway on port 25, in front of their Postfix.
#
# Usage as root:
#    ./spfbl.irondome.sh [install|update|uninstall|firewall] [SPAMCENTER_API_KEY]
#
# Gateway only (CyberPanel, aaPanel, iRedMail and CWP), for a switch in steps:
#    ./spfbl.irondome.sh prepare [SPAMCENTER_API_KEY]
#        Everything but the switch: Exim is compiled and configured and
#        Postfix gets its internal ports. Port 25 stays with Postfix.
#    ./spfbl.irondome.sh switch
#        Exim takes port 25. If it fails, Postfix gets port 25 back.
#    ./spfbl.irondome.sh rollback
#        Postfix gets port 25 back at once. "switch" goes forward again.
# "install" runs prepare and switch together.
#
# install and prepare configure the SPFBL client first (as "config"
# below): without a valid SPFBL access key and a FQDN hostname validated
# by the SPFBL server, nothing is changed. update uses the spfbl.conf
# already there; without it, it asks for the key when run on a terminal,
# and otherwise goes on querying by IP, as before.
#
# Authentication on port 25 (gateway): the gateway does not offer AUTH on
# port 25, so the installation waits for 24 hours of Postfix log without
# authenticated logins there. When the administrator knows that nobody
# authenticates on port 25 anymore, the check can be skipped:
#    SPFBL_SASL_PORT25=none ./spfbl.irondome.sh install
#
# Installations not validated yet on a real host (CyberPanel, aaPanel): the
# code exists, but they are refused until the first installation together
# with SPFBL.net. For that validation only:
#    SPFBL_UNVALIDATED=yes ./spfbl.irondome.sh install
#
# Detection only (changes nothing):
#    ./spfbl.irondome.sh detect
#        Shows the control panel, the mail server (the process on port 25)
#        and the Linux found, and whether the Irondome supports them. A
#        server with a control panel uses the installation for that panel;
#        the pure MTA installation is only for servers without a panel.
#        Unsupported combinations: contact admin@spfbl.net with these lines.
#
# SPFBL client configuration only (no panel, package or MTA change):
#    ./spfbl.irondome.sh config
#        Writes /etc/spfbl/spfbl.conf, read by spfbl.sh 3.06 or newer,
#        with the SPFBL access key, after the SPFBL server validates the
#        hostname of this server for IPv4 and IPv6 (POST /client/).
#        Hostname: spfbl.sh sends the hostname in use by the kernel
#        (/proc/sys/kernel/hostname), so a hostname change reaches SPFBL
#        at once. It must be the FQDN of this server (hostnamectl
#        set-hostname mx.example.com).
#        The key already in the file is kept; it is asked for (without
#        echo) only when there is none. Optional environment variables:
#           SPFBL_KEY=...        replaces the key in the file;
#           SPFBL_GROUP=...      group allowed to read the file (the MTA
#                                user group; detected from Exim).
#
# The optional Spamcenter API key adds the Spamcenter databases to
# clamav-unofficial-sigs, as client/spfbl.spamcenter.sh does. Without the
# key in the command line, install and update take the key registered in
# the SPFBL account (spamcenter_api_key), read with the SPFBL access key of
# /etc/spfbl/spfbl.conf: added when missing, replaced when it changed. With
# no key in the account, the key already configured is kept.
#
# Spamcenter key only, on a server already with clamav-unofficial-sigs:
#    ./spfbl.irondome.sh spamcenter
#        Adds or replaces the Spamcenter databases in user.conf with the
#        key of the SPFBL account. Nothing else is changed.
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
# Version: 2.9

GITHUB_SPFBL="https://raw.githubusercontent.com/leonamp/SPFBL/master/client"
GITHUB_SIGS="https://raw.githubusercontent.com/extremeshok/clamav-unofficial-sigs/master"
SPFBL_CLIENT="/usr/local/bin/spfbl"
SIGS_SCRIPT="/usr/local/bin/clamav-unofficial-sigs.sh"
SIGS_DIR="/etc/clamav-unofficial-sigs"
CONTACT_URL="https://spfbl.net/en/contact"
CONTACT_EMAIL="admin@spfbl.net"
IRONDOME_VERSION="2.9"
SPAMCENTER_URL="https://api.spam.center/download/clamav"
SPAMCENTER_KEY=""
# Every additional database this script may configure; uninstall removes them.
ADDITIONAL_DB_FILES="spfbl.hsb spfbl.ldb spfbl.ign2 cpanel.ign2 spamcenter.ndb spamcenter.hsb"

PANEL=""
PANEL_NAME=""
DISTRO_ID=""
DISTRO_VERSION=""
DISTRO_FAMILY=""

SPFBL_CONF_DIR="/etc/spfbl"
SPFBL_CONF="$SPFBL_CONF_DIR/spfbl.conf"
SPFBL_SERVER="https://matrix.spfbl.net"
# Status of the SPFBL monitor at HetrixTools (status.spfbl.net), the same
# read-only key of spfbl.sh: only tells a scheduled maintenance apart from
# a failure when SPFBL does not answer.
HETRIX_URL="https://api.hetrixtools.com/v3/uptime-monitors?id=acf42641d16137913fcef0a2b40b4d41"
HETRIX_KEY="2e8532718d586454d2ee2bafe98a4bc9"

###########################################################################
# Common functions
###########################################################################

function fail() {
    echo "$@"
    echo "Please contact $CONTACT_EMAIL to resolve this issue."
    if [ -n "$DETECTED" ]; then
        echo "Include these lines in your message:"
        echo "$DETECTED"
    fi
    exit 1
}

###########################################################################
# Detection: control panel first, then the MTA
###########################################################################
#
# Each control panel has its own Irondome installation, because panels
# have their own automation, specialized in the MTA they support. Only a
# server with no control panel gets the installation for its pure MTA.

PANEL_FOUND=""
PANEL_VERSION=""
MTA_NAME=""
MTA_VERSION=""
MTA_NOTE=""
UNSUPPORTED_REASON=""
OS_NAME=""
DETECTED=""

function first_line() {
    [ -r "$1" ] && head -1 "$1" 2>/dev/null | tr -d '\r' | cut -c1-40
}

function detect_os_name() {
    if [ -r /etc/os-release ]; then
        OS_NAME=$( . /etc/os-release; echo "${PRETTY_NAME:-$NAME $VERSION_ID}" )
    else
        OS_NAME=$(first_line /etc/redhat-release)
    fi
    [ -n "$OS_NAME" ] || OS_NAME="unknown Linux"
}

function detect_any_panel() {
    # All known panels, supported or not. Only names and versions.
    PANEL_FOUND=""
    PANEL_VERSION=""
    if [ -x /usr/local/cpanel/cpanel ]; then
        PANEL_FOUND="cPanel"
        PANEL_VERSION=$(first_line /usr/local/cpanel/version)
    fi
    if [ -x /usr/local/directadmin/directadmin ] || [ -x /usr/local/directadmin/custombuild/build ]; then
        if [ -n "$PANEL_FOUND" ]; then
            PANEL_FOUND="$PANEL_FOUND+DirectAdmin"
            return
        fi
        PANEL_FOUND="DirectAdmin"
        PANEL_VERSION=$(sed -n 's/^version=//p' /usr/local/directadmin/conf/directadmin.conf 2>/dev/null | head -1)
    fi
    [ -n "$PANEL_FOUND" ] && return
    if [ -d /usr/local/CyberCP ]; then
        PANEL_FOUND="CyberPanel"
    elif [ -d /www/server/panel ]; then
        PANEL_FOUND="aaPanel"
    elif [ -f /etc/iredmail-release ] || [ -d /opt/iredapd ]; then
        PANEL_FOUND="iRedMail"
        PANEL_VERSION=$(first_line /etc/iredmail-release | awk '{print $1}')
    elif [ -d /usr/local/hestia ]; then
        PANEL_FOUND="HestiaCP"
        PANEL_VERSION=$(sed -n "s/^VERSION=['\"]\{0,1\}\([^'\"]*\).*/\1/p" /usr/local/hestia/conf/hestia.conf 2>/dev/null | head -1)
    elif [ -d /usr/local/vesta ]; then
        PANEL_FOUND="VestaCP/myVesta"
    elif [ -d /usr/local/mgr5 ]; then
        PANEL_FOUND="ISPmanager"
    elif [ -d /usr/local/webuzo ]; then
        PANEL_FOUND="Webuzo"
    elif [ -d /usr/local/fastpanel2 ] || [ -d /usr/local/fastpanel ]; then
        PANEL_FOUND="FASTPANEL"
    elif [ -d /usr/local/cwpsrv ]; then
        PANEL_FOUND="CWP (Control Web Panel)"
    elif [ -d /usr/local/psa ]; then
        PANEL_FOUND="Plesk"
        PANEL_VERSION=$(first_line /usr/local/psa/version | awk '{print $1}')
    elif [ -d /usr/local/ispconfig ]; then
        PANEL_FOUND="ISPConfig"
    elif [ -d /etc/webmin/virtual-server ]; then
        PANEL_FOUND="Virtualmin"
    elif [ -d /var/www/froxlor ]; then
        PANEL_FOUND="Froxlor"
    elif [ -d /home/clp ]; then
        PANEL_FOUND="CloudPanel"
    elif [ -f /etc/mailinabox.conf ]; then
        PANEL_FOUND="Mail-in-a-Box"
    elif [ -d /opt/zextras ]; then
        PANEL_FOUND="Carbonio"
    elif [ -d /opt/zimbra ]; then
        PANEL_FOUND="Zimbra"
    elif [ -d /opt/mailcow-dockerized ]; then
        PANEL_FOUND="mailcow"
    fi
}

function exim_binary() {
    local bin
    for bin in exim exim4 /usr/sbin/exim /usr/sbin/exim4; do
        command -v "$bin" >/dev/null 2>&1 && { command -v "$bin"; return 0; }
    done
    return 1
}

function detect_mta() {
    # The MTA is the process listening on port 25; when nothing listens,
    # the installed binaries tell which one is there.
    local owner bin
    MTA_NAME=""
    MTA_VERSION=""
    MTA_NOTE=""
    owner=" $(port_owner 25)"
    case "$owner" in
        *" docker-proxy "*|*" containerd"*|*" conmon "*|*" rootlessport "*|*" podman"*)
            MTA_NAME="container (Docker/Podman)" ;;
        *" exim"*)
            MTA_NAME="Exim" ;;
        *" master "*|*" postscreen "*)
            MTA_NAME="Postfix" ;;
        *" sendmail "*)
            MTA_NAME="Sendmail" ;;
        *" tcpserver "*|*" qmail-smtpd "*)
            MTA_NAME="qmail" ;;
        *" xinetd "*)
            [ -d /var/qmail ] && MTA_NAME="qmail" || MTA_NAME="unknown (xinetd)" ;;
        *" smtpd "*)
            MTA_NAME="OpenSMTPD" ;;
        *" couriertcpd "*|*" courieresmtpd "*)
            MTA_NAME="Courier-MTA" ;;
        *" stalwart"*)
            MTA_NAME="Stalwart" ;;
        *" maddy "*)
            MTA_NAME="Maddy" ;;
        *" java "*)
            # The SPFBL server itself (ServerSMTP) also receives on port 25.
            if pgrep -f 'SPFBL\.jar' >/dev/null 2>&1; then
                MTA_NAME="SPFBL (ServerSMTP)"
            else
                MTA_NAME="unknown (java)"
            fi
            ;;
        *" node "*)
            command -v haraka >/dev/null 2>&1 && MTA_NAME="Haraka" || MTA_NAME="unknown (node)" ;;
        *" axigen"*)
            MTA_NAME="Axigen" ;;
        *" icewarpd "*)
            MTA_NAME="IceWarp" ;;
        *" mailserver "*)
            [ -d /opt/kerio ] && MTA_NAME="Kerio Connect" || MTA_NAME="unknown (mailserver)" ;;
        " ")
            ;;
        *)
            MTA_NAME="unknown ($(echo $owner))" ;;
    esac
    if [ -z "$MTA_NAME" ]; then
        MTA_NOTE="nothing listening on port 25"
        if exim_binary >/dev/null; then
            MTA_NAME="Exim"
        elif command -v postconf >/dev/null 2>&1; then
            MTA_NAME="Postfix"
        elif [ -x /var/qmail/bin/qmail-smtpd ]; then
            MTA_NAME="qmail"
        elif [ -f /etc/smtpd.conf ] && command -v smtpd >/dev/null 2>&1; then
            MTA_NAME="OpenSMTPD"
        elif [ -f /etc/mail/sendmail.cf ]; then
            MTA_NAME="Sendmail"
        fi
    fi
    # Zimbra and Carbonio run their own Postfix.
    if [ "$MTA_NAME" = "Postfix" ] && [ -x /opt/zimbra/common/sbin/postconf ]; then
        MTA_VERSION=$(/opt/zimbra/common/sbin/postconf -h mail_version 2>/dev/null)
        return
    fi
    case "$MTA_NAME" in
        Exim)
            bin=$(exim_binary)
            [ -n "$bin" ] && MTA_VERSION=$("$bin" -bV 2>/dev/null | sed -n 's/^Exim version \([^ ]*\).*/\1/p' | head -1) ;;
        Postfix)
            MTA_VERSION=$(postconf -h mail_version 2>/dev/null) ;;
        OpenSMTPD)
            MTA_VERSION=$(smtpd -h 2>&1 | sed -n 's/.*OpenSMTPD \([^ ]*\).*/\1/p' | head -1) ;;
        Sendmail)
            MTA_VERSION=$(sendmail -d0.1 -bt </dev/null 2>/dev/null | sed -n 's/^Version \([^ ]*\).*/\1/p' | head -1) ;;
    esac
}

function detect_all() {
    detect_os_name
    detect_any_panel
    detect_mta
    local panel mta
    if [ -n "$PANEL_FOUND" ]; then
        panel="$PANEL_FOUND${PANEL_VERSION:+ $PANEL_VERSION}"
    else
        panel="no control panel"
    fi
    if [ -n "$MTA_NAME" ]; then
        mta="$MTA_NAME${MTA_VERSION:+ $MTA_VERSION}"
        if [ -n "$MTA_NOTE" ]; then
            mta="$mta ($MTA_NOTE)"
        else
            mta="$mta (port 25)"
        fi
    else
        mta="none found"
    fi
    DETECTED="Control panel: $panel
Mail server: $mta
Linux: $OS_NAME
Irondome: $IRONDOME_VERSION"
}

function select_mode() {
    # Supported combinations. Each panel has its own installation; the
    # pure MTA installation is only for servers without a panel.
    PANEL=""
    PANEL_NAME=""
    UNSUPPORTED_REASON=""
    case "$PANEL_FOUND" in
        "cPanel+DirectAdmin")
            ;;
        cPanel)
            PANEL="cpanel"; PANEL_NAME="cPanel" ;;
        DirectAdmin)
            PANEL="directadmin"; PANEL_NAME="DirectAdmin" ;;
        iRedMail)
            PANEL="gateway"; PANEL_NAME="$PANEL_FOUND" ;;
        CyberPanel|aaPanel)
            # The code exists, but no real installation validated it yet.
            # Only for that first validation: SPFBL_UNVALIDATED=yes.
            if [ "$SPFBL_UNVALIDATED" = "yes" ]; then
                PANEL="gateway"; PANEL_NAME="$PANEL_FOUND"
            else
                UNSUPPORTED_REASON="the $PANEL_FOUND installation was not validated yet"
            fi
            ;;
        "CWP (Control Web Panel)")
            PANEL="gateway"; PANEL_NAME="CWP" ;;
        "")
            case "$MTA_NAME" in
                Exim)
                    if exim_requirements; then
                        PANEL="exim"; PANEL_NAME="Exim"
                    fi
                    ;;
            esac
            ;;
    esac
    [ -n "$PANEL" ]
}

function exim_requirements() {
    # Same requirements of exim_check, for the detection: Debian or Ubuntu,
    # Exim 4.96 or newer and the Debian configuration (exim4-config).
    UNSUPPORTED_REASON=""
    local family="" like major minor
    if [ -r /etc/os-release ]; then
        family=$( . /etc/os-release; echo " $ID $ID_LIKE " | tr '[:upper:]' '[:lower:]')
    fi
    if [[ $family != *" debian "* && $family != *" ubuntu "* ]]; then
        UNSUPPORTED_REASON="the pure Exim installation requires Debian or Ubuntu"
    elif [ -n "$MTA_NOTE" ]; then
        UNSUPPORTED_REASON="Exim is installed, but it is not listening on port 25"
    elif [ -z "$MTA_VERSION" ]; then
        UNSUPPORTED_REASON="the Exim version could not be read"
    else
        major=${MTA_VERSION%%.*}
        minor=${MTA_VERSION#*.}
        minor=${minor%%[!0-9]*}
        if [ "$major" -lt 4 ] || { [ "$major" -eq 4 ] && [ "${minor:-0}" -lt 96 ]; }; then
            UNSUPPORTED_REASON="the pure Exim installation requires Exim 4.96 or newer"
        elif ! command -v update-exim4.conf >/dev/null 2>&1; then
            UNSUPPORTED_REASON="the Debian Exim configuration (exim4-config) was not found"
        elif [ -f /etc/exim4/exim4.conf ]; then
            UNSUPPORTED_REASON="/etc/exim4/exim4.conf replaces the Debian configuration"
        fi
    fi
    [ -z "$UNSUPPORTED_REASON" ]
}

function unsupported() {
    echo ""
    echo "$DETECTED"
    echo ""
    if [ "$PANEL_FOUND" = "cPanel+DirectAdmin" ]; then
        echo "Both cPanel and DirectAdmin were found in this host. Installation aborted."
    elif [ -n "$UNSUPPORTED_REASON" ]; then
        echo "The Irondome cannot be installed here: $UNSUPPORTED_REASON."
    elif [ -n "$PANEL_FOUND" ]; then
        echo "The Irondome does not have an installation for $PANEL_FOUND yet."
    elif [ -z "$MTA_NAME" ]; then
        echo "No mail server was found in this host."
    elif [ "$MTA_NAME" = "SPFBL (ServerSMTP)" ]; then
        echo "This host is an SPFBL server: its ServerSMTP already does the Irondome checks."
        exit 1
    elif [ -n "$UNSUPPORTED_REASON" ]; then
        echo "The Irondome cannot be installed here: $UNSUPPORTED_REASON."
    else
        echo "The Irondome does not have an installation for pure $MTA_NAME yet."
    fi
    echo "Please contact $CONTACT_EMAIL to request it,"
    echo "and include the lines above in your message."
    exit 1
}

function detect_panel() {
    detect_all
    select_mode || unsupported
    echo "Control panel detected: $PANEL_NAME"
}

function detect_installed() {
    # What this script installed on this host, whatever the panel and the
    # MTA look like now. uninstall, update, switch and rollback decide by
    # this, never by the compatibility check of a new installation: a
    # stopped MTA, a panel installed later or an older script must never
    # keep the Irondome from being updated or removed.
    PANEL=""
    PANEL_NAME=""
    if [ -x /opt/spfbl/exim/bin/exim ] && [ -f /opt/spfbl/exim/etc/exim.conf ]; then
        PANEL="gateway"
    elif [ -f /usr/local/cpanel/etc/exim/acls/ACL_RECIPIENT_BLOCK/spfbl_end_recipient ]; then
        PANEL="cpanel"; PANEL_NAME="cPanel"
    elif [ -f /etc/exim4/spfbl/acl_check_rcpt.conf ]; then
        PANEL="exim"; PANEL_NAME="Exim"
    elif [ -f /etc/exim.acl_check_recipient.pre.conf ] && grep -qi spfbl /etc/exim.acl_check_recipient.pre.conf 2>/dev/null; then
        PANEL="directadmin"; PANEL_NAME="DirectAdmin"
    fi
    [ -n "$PANEL" ] || return 1
    detect_all
    if [ "$PANEL" = "gateway" ]; then
        case "$PANEL_FOUND" in
            "CWP (Control Web Panel)") PANEL_NAME="CWP" ;;
            CyberPanel|aaPanel|iRedMail) PANEL_NAME="$PANEL_FOUND" ;;
            *) PANEL_NAME="Postfix gateway" ;;
        esac
    fi
    echo "Irondome installation found: $PANEL_NAME"
    # The host changed since the installation: only a warning.
    local current="$PANEL" current_name="$PANEL_NAME"
    if select_mode; then
        if [ "$PANEL" != "$current" ]; then
            echo "WARNING: this host now looks like a $PANEL_NAME host; the installed $current_name is used."
        fi
    else
        echo "WARNING: this combination is not supported for new installations ($(echo "$DETECTED" | sed -n '1,2p' | tr '\n' ';' | sed 's/;$//'))."
    fi
    PANEL="$current"
    PANEL_NAME="$current_name"
    return 0
}

function require_installed() {
    if ! detect_installed; then
        echo "SPFBL Irondome is not installed on this host."
        exit 1
    fi
}

function detect_report() {
    # "detect" command: shows what was found and changes nothing.
    detect_all
    echo "$DETECTED"
    if select_mode; then
        echo "Supported: yes ($PANEL_NAME installation)"
    else
        if [ "$MTA_NAME" = "SPFBL (ServerSMTP)" ]; then
            echo "Supported: no (this host is an SPFBL server; the Irondome is not needed)"
        elif [ -n "$UNSUPPORTED_REASON" ]; then
            echo "Supported: no ($UNSUPPORTED_REASON; contact $CONTACT_EMAIL)"
        else
            echo "Supported: no (contact $CONTACT_EMAIL to request it)"
        fi
    fi
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
        echo "Please contact $CONTACT_EMAIL to request it, and include the information below."
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
    # Installs only the given packages that are missing, without asking
    # anything. "install" of a package already installed would also
    # upgrade it, and the installer must not upgrade the host packages.
    local package missing=()
    for package in "$@"; do
        if command -v dpkg-query >/dev/null && command -v apt-get >/dev/null; then
            dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q 'ok installed' && continue
        elif command -v rpm >/dev/null; then
            # Also finds a package by what it provides (nmap-ncat, gnupg2...).
            rpm -q --whatprovides "$package" >/dev/null 2>&1 && continue
        fi
        missing+=("$package")
    done
    [ ${#missing[@]} -eq 0 ] && return 0
    if command -v apt-get >/dev/null; then
        DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-upgrade "${missing[@]}"
    elif command -v dnf >/dev/null; then
        dnf install -y "${missing[@]}"
    elif command -v yum >/dev/null; then
        yum install -y "${missing[@]}"
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
    # version keep their default value. QUERY_TIMEOUT is never kept: it
    # always takes the value of the new client. The key, the hostname and
    # the protocol live in /etc/spfbl/spfbl.conf, not in the script.
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
    done < <(awk '/^export PATH=/ {exit} /^[A-Z_]+=/ {sub(/=.*/, ""); print}' "$new" | grep -vE '^(COMMAND|NCAT|QUERY_TIMEOUT|SPFBL_CONF|SPFBL_KEY|LOCAL_HOSTNAME|IP_VERSION|CURL_KEY_CONFIG)$')
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
    if [ -r "$SPFBL_CONF" ] && grep -q '^version="3\.0[6-9]\|^version="3\.[1-9]' "$SPFBL_CLIENT" 2> /dev/null; then
        # Client with the access key: the refusal is of the key or of the hostname.
        echo "The SPFBL server refused the access key or the hostname of this server."
        echo "See the lines \"spfbl\" in the system log and the page MTA Clients of the"
        echo "SPFBL panel. To configure them again: $0 config"
        exit 1
    fi
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
    # /etc/clamd.d/*.conf: other instances of the RHEL family, like the
    # clamd@amavisd of iRedMail (/etc/clamd.d/amavisd.conf).
    local candidates=(/etc/clamd.d/scan.conf /etc/clamd.d/*.conf /etc/clamav/clamd.conf /usr/local/etc/clamd.conf /etc/clamd.conf)
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

function clamd_service_for() {
    # systemd unit that runs clamd with the configuration $1: clamd@<name>
    # of the RHEL family, or a single clamd.service whose ExecStart points
    # to it (CWP removes clamd@.service and runs amavisd.conf this way).
    local conf="$1" name unit
    case "$conf" in
        /etc/clamd.d/*.conf)
            name=$(basename "$conf" .conf)
            if systemctl cat "clamd@$name.service" >/dev/null 2>&1; then
                echo "clamd@$name.service"
                return 0
            fi
            for unit in clamd.service clamav-daemon.service; do
                if systemctl cat "$unit" 2>/dev/null | grep -E '^[[:space:]]*ExecStart' |
                        grep -qE "(-c|--config-file)[ =]$conf( |$)"; then
                    echo "$unit"
                    return 0
                fi
            done
            ;;
        /etc/clamav/clamd.conf)
            systemctl cat clamav-daemon.service >/dev/null 2>&1 && echo "clamav-daemon.service" && return 0 ;;
    esac
    return 1
}

function clamd_unit() {
    # systemd unit of the clamd found by find_clamd, if any.
    clamd_service_for "$CLAMD_CONF"
}

function clamav_tools() {
    # clamav-unofficial-sigs tests each database with clamscan and reloads
    # clamd with clamdscan. Some hosts have clamd without them (CWP).
    command -v clamscan >/dev/null && command -v clamdscan >/dev/null && return 0
    if [ "$DISTRO_FAMILY" = "rhel" ] || [ "$DISTRO_FAMILY" = "fedora" ]; then
        rpm -q epel-release >/dev/null 2>&1 || [ "$DISTRO_FAMILY" = "fedora" ] || pkg_install epel-release
        pkg_install clamav
    else
        pkg_install clamav
        command -v clamdscan >/dev/null || pkg_install clamdscan 2>/dev/null
    fi
}

function csf_allow_out() {
    # Outbound TCP port in the CSF firewall (TCP_OUT and TCP6_OUT), when
    # CSF is installed. Sanesecurity uses rsync (873); CSF rejects
    # unlisted outbound ports.
    local conf=/etc/csf/csf.conf port="$1" key changed=false value
    [ -f "$conf" ] || return 0
    for key in TCP_OUT TCP6_OUT; do
        value=$(sed -n "s/^$key[[:space:]]*=[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$conf" | head -1)
        grep -q "^$key[[:space:]]*=" "$conf" || continue
        if [[ ",$value," != *",$port,"* ]]; then
            sed -i "s/^\($key[[:space:]]*=[[:space:]]*\"[^\"]*\)\"/\1,$port\"/" "$conf"
            changed=true
        fi
    done
    if $changed; then
        echo "CSF: outbound port $port allowed (TCP_OUT/TCP6_OUT)."
        csf -r >/dev/null 2>&1
    fi
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

###########################################################################
# Spamcenter databases (client/spfbl.spamcenter.sh)
###########################################################################

function spamcenter_valid_key() {
    [[ "$1" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]
}

function spamcenter_current_key() {
    # Key already configured in user.conf, if any.
    [ -f "$SIGS_DIR/user.conf" ] || return 0
    grep -oE "${SPAMCENTER_URL}/[0-9a-f-]{36}/" "$SIGS_DIR/user.conf" | head -1 | cut -d/ -f6
}

function spamcenter_check() {
    # Both files must be reachable with this key from this host.
    # The key goes only in the URL required by the provider; it is never printed.
    local code1 code2 myIP
    code1=$(curl -o /dev/null -s --head --connect-timeout 10 -m 30 -w '%{http_code}' "$SPAMCENTER_URL/$SPAMCENTER_KEY/spamcenter.ndb")
    code2=$(curl -o /dev/null -s --head --connect-timeout 10 -m 30 -w '%{http_code}' "$SPAMCENTER_URL/$SPAMCENTER_KEY/spamcenter.hsb")
    if [ "$code1" != "200" ] || [ "$code2" != "200" ]; then
        myIP=$(curl -s https://matrix.spfbl.net/whatsmyip/)
        echo "This Spamcenter API key has not permission to access Spamcenter data using IP ${myIP:-unknown}."
        echo "Nothing was changed. Please contact us: $CONTACT_URL"
        exit 1
    fi
    echo "Spamcenter API key accepted."
}

function spamcenter_account_key() {
    # Spamcenter key registered in the SPFBL account (GET /user/properties/),
    # read with the SPFBL access key of spfbl.conf. Prints the key, or
    # nothing when there is no conf, no answer or no valid key. Neither key
    # is ever printed to the terminal.
    local key ipv out code body value
    key=$(conf_value SPFBL_KEY)
    conf_key_valid "$key" || return 0
    ipv=$(conf_value IP_VERSION)
    out=$(curl ${ipv:+-$ipv} -s --connect-timeout 10 -m 30 -w '\n%{http_code}' -K /dev/fd/3 \
        "$SPFBL_SERVER/user/properties/" 2> /dev/null \
        3<<< "header = \"Authorization: Bearer $key\"")
    code=${out##*$'\n'}
    body=${out%$'\n'*}
    [ "$code" = "200" ] || return 0
    value=$(printf '%s\n' "$body" | sed -n 's/^spamcenter_api_key=//p' | head -1 | tr -d '\r' | tr 'A-F' 'a-f')
    spamcenter_valid_key "$value" && echo "$value"
}

function spamcenter_prepare() {
    # Decides the key before any change: the one given in the command line
    # (tested), else the one in the SPFBL account (not tested: the access
    # depends on the IP list kept at Spamcenter), else the one in use.
    local current account
    current=$(spamcenter_current_key)
    if [ -n "$SPAMCENTER_KEY" ]; then
        spamcenter_check
        return
    fi
    account=$(spamcenter_account_key)
    if [ -n "$account" ]; then
        SPAMCENTER_KEY="$account"
        if [ -z "$current" ]; then
            echo "Adding the Spamcenter API key of the SPFBL account."
        elif [ "$current" != "$account" ]; then
            echo "Replacing the Spamcenter API key with the one of the SPFBL account."
        else
            echo "Spamcenter API key of the SPFBL account already configured."
        fi
    elif [ -n "$current" ]; then
        SPAMCENTER_KEY="$current"
        echo "Keeping the Spamcenter API key already configured."
    fi
}

function sigs_conf_perms() {
    # user.conf holds the Spamcenter key, but the cron of
    # clamav-unofficial-sigs runs as clam_user and must read it:
    # root:<clam_group> 640. With 600, the cron skips user.conf and
    # stops updating without any visible error.
    local file="$1" group
    group=$(sed -n 's/^clam_group="\(.*\)".*/\1/p' "$SIGS_DIR/os.conf" "$SIGS_DIR/user.conf" 2>/dev/null | tail -1)
    if [ -z "$group" ] || ! getent group "$group" >/dev/null; then
        for group in clamav clamupdate clam ""; do
            [ -n "$group" ] && getent group "$group" >/dev/null && break
        done
    fi
    if [ -n "$group" ]; then
        chown "root:$group" "$file" && chmod 640 "$file"
    else
        chmod 644 "$file"
    fi
}

function spamcenter_sync() {
    # "spamcenter" command: only the Spamcenter lines of user.conf, with
    # the key of the SPFBL account. The other databases stay as they are.
    local user_conf="$SIGS_DIR/user.conf" current account
    [ -r "$SPFBL_CONF" ] || fail "There is no $SPFBL_CONF yet. Run first: $0 config"
    [ -f "$user_conf" ] && grep -q '^declare -a additional_dbs=(' "$user_conf" || \
        fail "clamav-unofficial-sigs is not configured by SPFBL Irondome on this server. Run: $0 update"
    account=$(spamcenter_account_key)
    if [ -z "$account" ]; then
        echo "There is no valid Spamcenter API key in the SPFBL account (or SPFBL did not answer)."
        echo "Nothing was changed."
        exit 1
    fi
    current=$(spamcenter_current_key)
    if [ "$current" = "$account" ]; then
        echo "The Spamcenter API key of the SPFBL account is already configured. Nothing to change."
        return 0
    fi
    # Old Spamcenter lines out, new ones before the end of the block.
    awk -v url="$SPAMCENTER_URL" -v key="$account" '
        index($0, url "/") > 0 && /spamcenter\.(ndb|hsb)/ { next }
        /^additional_update_hours=.*# spfbl.irondome.sh$/ { next }
        /^\) #END ADDITIONAL DATABASES/ {
            printf "\t%s/%s/spamcenter.ndb\n", url, key
            printf "\t%s/%s/spamcenter.hsb\n", url, key
            print
            print ""
            print "additional_update_hours=\"1\" # spfbl.irondome.sh"
            next
        }
        { print }' "$user_conf" > "$user_conf.tmp" || fail "Could not write $user_conf.tmp."
    cat "$user_conf.tmp" > "$user_conf" && rm -f "$user_conf.tmp"
    sed -i -e :a -e '/^\n*$/{$d;N;ba' -e '}' "$user_conf"
    sigs_conf_perms "$user_conf"
    if [ -z "$current" ]; then
        echo "Spamcenter API key of the SPFBL account added to $user_conf."
    else
        echo "Spamcenter API key replaced in $user_conf."
    fi
    if [ -x "$SIGS_SCRIPT" ]; then
        echo "Updating the signatures..."
        "$SIGS_SCRIPT" > /dev/null 2>&1 || echo "clamav-unofficial-sigs returned an error: see its log."
    fi
}

function sigs_remove_script() {
    # --remove-script asks "Are you sure? [y/N]" and repeats the question
    # on any other answer: without a terminal (or with the output piped),
    # it would wait forever. The answer is given here.
    printf 'y\n' | "$SIGS_SCRIPT" --remove-script
}

function remove_additional_dbs() {
    # clamav-unofficial-sigs --remove-script does not delete the additional
    # databases from the clamd directory, so they are removed here.
    local dbs="" file
    [ -f "$SIGS_DIR/os.conf" ] && dbs=$(sed -n 's/^clam_dbs="\(.*\)"/\1/p' "$SIGS_DIR/os.conf" | tail -1)
    if [ -z "$dbs" ] || [ ! -d "$dbs" ]; then
        find_clamd >/dev/null
        dbs="$CLAMD_DBS"
    fi
    if [ -n "$dbs" ] && [ -d "$dbs" ]; then
        for file in $ADDITIONAL_DB_FILES; do
            rm -f "$dbs/$file" "$dbs/$file-bak"
        done
        command -v clamdscan >/dev/null && clamdscan --reload >/dev/null 2>&1
    fi
    # Also takes them out of the configuration that remove-script keeps.
    if [ -f "$SIGS_DIR/user.conf" ]; then
        awk '/^declare -a additional_dbs=\(/{skip=1} !skip{print} /END ADDITIONAL DATABASES/{skip=0}' "$SIGS_DIR/user.conf" | grep -v '# spfbl.irondome.sh$' > "$SIGS_DIR/user.conf.tmp"
        cat "$SIGS_DIR/user.conf.tmp" > "$SIGS_DIR/user.conf" && rm -f "$SIGS_DIR/user.conf.tmp"
    fi
    echo "SPFBL and Spamcenter databases were removed from ClamAV."
}

function configure_sigs_databases() {
    # SPFBL databases, replacing any previous block (no duplicates on reinstall).
    local user_conf="$SIGS_DIR/user.conf"
    [ -f "$user_conf" ] || download "$GITHUB_SIGS/config/user.conf" "$user_conf"
    awk '/^declare -a additional_dbs=\(/{skip=1} !skip{print} /END ADDITIONAL DATABASES/{skip=0}' "$user_conf" | grep -v '# spfbl.irondome.sh$' > "$user_conf.tmp"
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
        if [ -n "$SPAMCENTER_KEY" ]; then
            printf "\t%s/%s/spamcenter.ndb\n" "$SPAMCENTER_URL" "$SPAMCENTER_KEY"
            printf "\t%s/%s/spamcenter.hsb\n" "$SPAMCENTER_URL" "$SPAMCENTER_KEY"
        fi
        printf ") #END ADDITIONAL DATABASES\n\n"
        if [ -n "$SPAMCENTER_KEY" ]; then
            # Spamcenter is updated every hour (user.conf overrides master.conf).
            printf 'additional_update_hours="1" # spfbl.irondome.sh\n'
        fi
        # abuse.ch retired the URLhaus download (HTTP 410 since 11/2026).
        printf 'urlhaus_enabled="no" # spfbl.irondome.sh\n'
    } >> "$user_conf"
    # The file holds the Spamcenter key.
    sigs_conf_perms "$user_conf"
    # Activation required by the script (already present in recent user.conf).
    grep -q '^user_configuration_complete="yes"' "$user_conf" || echo 'user_configuration_complete="yes"' >> "$user_conf"
}

function install_sigs() {
    # Conflicts with this script when installed as a distro package.
    if command -v dpkg >/dev/null && dpkg -s clamav-unofficial-sigs >/dev/null 2>&1; then
        apt-get purge -y clamav-unofficial-sigs
    fi
    mkdir -p "$SIGS_DIR"
    [ "$PANEL" = "cpanel" ] || clamav_tools
    csf_allow_out 873
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
        # The base configuration may disable the reload or point it to
        # another clamd (os.rhel.conf: clamd@scan). Outside cPanel, whose
        # clamdscan is not in the PATH, the clamd found here is reloaded.
        local unit
        unit=$(clamd_unit)
        if [ "$PANEL" != "cpanel" ] && [ -n "$CLAMD_CONF" ] && command -v clamdscan >/dev/null; then
            echo "reload_dbs=\"yes\""
            echo "clamd_reload_opt=\"clamdscan --config-file=$CLAMD_CONF --reload\""
            [ -n "$unit" ] && echo "clamd_restart_opt=\"systemctl restart $unit\""
        fi
    } >> "$SIGS_DIR/os.conf"
    configure_sigs_databases
    "$SIGS_SCRIPT" --force
    # Each action option of clamav-unofficial-sigs runs alone and exits.
    "$SIGS_SCRIPT" --install-cron
    "$SIGS_SCRIPT" --install-logrotate
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
    sigs_remove_script
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
    [ -x "$SIGS_SCRIPT" ] && sigs_remove_script
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
    [ -x "$SIGS_SCRIPT" ] && sigs_remove_script
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
# Gateway functions: Exim on port 25 in front of the Postfix of a panel
###########################################################################

# Exim source compiled by this script. Check the latest release on
# https://www.exim.org and update both values together.
GW_EXIM_VERSION="4.100.1"
GW_EXIM_SHA256="e9fb41f6724a5b136d64c9d19dbc5f26494af879a3e7e3190f91639eaa79fa0d"
GW_EXIM_URL="https://ftp.exim.org/pub/exim/exim4/exim-$GW_EXIM_VERSION.tar.xz"

# Everything of the gateway lives in GW_DIR. Outside it there are only
# the user, the systemd links, the SPFBL block of master.cf and the
# group memberships needed to reach clamd.
GW_DIR="/opt/spfbl/exim"
GW_EXIM="$GW_DIR/bin/exim"
GW_USER="spfbl-exim"
GW_LOG_DIR="$GW_DIR/log"
GW_BACKUP_DIR="$GW_DIR/backup"
GW_VAR_DIR="$GW_DIR/var"
GW_UNIT_DIR="$GW_DIR/systemd"
GW_RELAY_SCRIPT="$GW_DIR/bin/spfbl-relay-hosts"
GW_MAINT_SCRIPT="$GW_DIR/bin/spfbl-exim-maint"
GW_GUARD_SCRIPT="$GW_DIR/bin/spfbl-postfix-guard"
GW_INBOUND_PORT="2525"
GW_LOCAL_PORT="2526"
POSTFIX_MASTER=""
# Layout of version 2.1, moved into GW_DIR by the update.
GW_OLD_UNIT="/etc/systemd/system/spfbl-exim.service"
GW_OLD_TLS_CRON="/etc/cron.hourly/spfbl-exim-tls"
GW_OLD_LOGROTATE="/etc/logrotate.d/spfbl-exim"
GW_OLD_LOG_DIR="/var/log/spfbl-exim"
GW_OLD_STATE="/var/lib/spfbl/irondome.state"

function port_owner() {
    # Names of all the processes listening on a TCP port: with postscreen,
    # port 25 lists postscreen first and master after it. Without -H and
    # without "pid=": old iproute2 (Ubuntu 14.04, CentOS 6/7) has neither.
    # netstat is the fallback where ss is missing.
    local names
    if command -v ss >/dev/null 2>&1; then
        names=$(ss -ltnp "( sport = :$1 )" 2>/dev/null | tail -n +2 | grep -oE '\("[^"]+",' | cut -d'"' -f2)
    fi
    if [ -z "$names" ] && command -v netstat >/dev/null 2>&1; then
        names=$(netstat -ltnp 2>/dev/null | awk -v p=":$1" '$4 ~ p"$" {n = split($7, a, "/"); if (n > 1) print a[2]}')
    fi
    echo "$names" | sed '/^$/d' | sort -u | tr '\n' ' '
}

function port_listening() {
    # Waits up to 10 seconds for an SMTP banner on 127.0.0.1.
    local port="$1" try banner
    for try in $(seq 1 10); do
        banner=$(timeout 5 bash -c "exec 3<>/dev/tcp/127.0.0.1/$port && head -1 <&3" 2>/dev/null)
        [[ $banner == 220* ]] && return 0
        sleep 1
    done
    return 1
}

function gw_installed() {
    [ -x "$GW_EXIM" ] && [ -f "$GW_DIR/etc/exim.conf" ]
}

function gw_state_file() {
    # The gateway keeps its state in GW_DIR; version 2.1 kept it in /var/lib/spfbl.
    EXIM_STATE="$GW_DIR/irondome.state"
    if [ -f "$GW_OLD_STATE" ] && [ ! -f "$EXIM_STATE" ] && [ -d "$GW_DIR" ]; then
        mv -f "$GW_OLD_STATE" "$EXIM_STATE"
        rmdir /var/lib/spfbl 2>/dev/null
    fi
}

function gw_check() {
    # Everything that can stop the installation is checked here,
    # before any change in the host.
    case "$DISTRO_FAMILY" in
        debian|ubuntu|rhel) ;;
        *) fail "The SPFBL gateway is only supported on Debian, Ubuntu and the RHEL family." ;;
    esac
    command -v postconf >/dev/null || fail "$PANEL_NAME was found, but its Postfix mail server is not installed."
    command -v systemctl >/dev/null || fail "The SPFBL gateway needs systemd."
    command -v ss >/dev/null || pkg_install iproute2 2>/dev/null || pkg_install iproute
    POSTFIX_MASTER="$(postconf -h config_directory)/master.cf"
    [ -f "$POSTFIX_MASTER" ] || fail "The Postfix file $POSTFIX_MASTER was not found."
    [ -n "$GW_EXIM_SHA256" ] || fail "The checksum of the Exim source is not defined in this script."
    gw_state_file
    if ! gw_installed; then
        [[ $(port_owner 25) == *master* ]] || fail "Postfix is not listening on port 25. Installation aborted."
        local port
        for port in "$GW_INBOUND_PORT" "$GW_LOCAL_PORT"; do
            [ -z "$(port_owner "$port")" ] || fail "The port $port is already in use. Installation aborted."
        done
        [ -n "$(gw_master_public)" ] || fail "The port 25 service was not found in $POSTFIX_MASTER."
    fi
    # Only while Postfix still has port 25: after the switch nobody can
    # authenticate there anymore.
    if [ -n "$(gw_master_public)" ]; then
        gw_check_webmail
        gw_check_sasl
    fi
    gw_check_tls
    gw_check_monit
    return 0
}

function gw_tls_files() {
    # Certificate and key of Postfix, the same ones the gateway copies.
    GW_TLS_SRC_CERT=$(postconf -h smtpd_tls_cert_file 2>/dev/null)
    GW_TLS_SRC_KEY=$(postconf -h smtpd_tls_key_file 2>/dev/null)
    local chain
    chain=$(postconf -h smtpd_tls_chain_files 2>/dev/null | awk '{print $1}')
    if [ -z "$GW_TLS_SRC_CERT" ] || [ "$GW_TLS_SRC_CERT" = "none" ] || [ ! -f "$GW_TLS_SRC_CERT" ]; then
        GW_TLS_SRC_CERT="$chain"
        GW_TLS_SRC_KEY="$chain"
    fi
    if [ -z "$GW_TLS_SRC_KEY" ] || [ "$GW_TLS_SRC_KEY" = "none" ]; then
        GW_TLS_SRC_KEY="$GW_TLS_SRC_CERT"
    fi
}

function gw_check_tls() {
    # Warnings only: without a valid certificate Exim still receives mail,
    # but STARTTLS fails or is not offered.
    gw_tls_files
    if [ -z "$GW_TLS_SRC_CERT" ] || [ ! -r "$GW_TLS_SRC_CERT" ] || [ ! -r "$GW_TLS_SRC_KEY" ]; then
        echo "WARNING: the Postfix certificate was not found. The gateway will not offer STARTTLS."
    elif command -v openssl >/dev/null; then
        if ! openssl x509 -in "$GW_TLS_SRC_CERT" -noout -checkend 0 >/dev/null 2>&1; then
            echo "WARNING: the Postfix certificate $GW_TLS_SRC_CERT has expired."
        elif ! openssl x509 -in "$GW_TLS_SRC_CERT" -noout -checkend 604800 >/dev/null 2>&1; then
            echo "WARNING: the Postfix certificate $GW_TLS_SRC_CERT expires in less than 7 days."
        fi
    fi
}

function gw_check_monit() {
    # Warning only: a monit rule for Postfix on port 25 would fight the gateway.
    systemctl is-active --quiet monit 2>/dev/null || return 0
    if grep -rqsiE 'postfix|port[[:space:]]+25([^0-9]|$)' /etc/monit.d /etc/monit/conf.d /etc/monit/conf-enabled /etc/monitrc /etc/monit/monitrc 2>/dev/null; then
        echo "WARNING: monit watches Postfix or port 25. After the switch, port 25 belongs to"
        echo "the Exim gateway: adjust the monit rule, or monit may restart Postfix in a loop."
    fi
}

function gw_webmail_files() {
    # Roundcube configurations of the panels with the gateway.
    local file
    for file in /usr/local/cwpsrv/var/services/roundcube/config/config.inc.php \
                /opt/www/roundcubemail/config/config.inc.php \
                /var/www/roundcubemail/config/config.inc.php \
                /usr/share/roundcubemail/config/config.inc.php \
                /etc/roundcubemail/config.inc.php; do
        [ -f "$file" ] && echo "$file"
    done
}

function gw_roundcube_value() {
    # Last value of $config['<name>'] in a Roundcube configuration.
    sed -n "s/^[[:space:]]*\\\$config\['$2'\][[:space:]]*=[[:space:]]*\(.*\);.*/\1/p" "$1" | tail -1 | tr -d "'\" "
}

function gw_check_webmail() {
    # A webmail of this host authenticating on port 25 never stops by
    # itself: it must move to the submission port before the switch.
    local file host port user myhost bad=""
    myhost=$(postconf -h myhostname 2>/dev/null)
    for file in $(gw_webmail_files); do
        host=$(gw_roundcube_value "$file" smtp_host)
        [ -n "$host" ] || host=$(gw_roundcube_value "$file" smtp_server)
        port=$(gw_roundcube_value "$file" smtp_port)
        user=$(gw_roundcube_value "$file" smtp_user)
        [ -n "$user" ] || continue
        case "$host" in
            ssl://*|tls://*) [[ $host == ssl://* ]] && [ -z "$port" ] && port=465; host=${host#*://} ;;
        esac
        if [[ $host =~ :([0-9]+)$ ]]; then
            port=${BASH_REMATCH[1]}
            host=${host%:*}
        fi
        host=${host#[}; host=${host%]}
        case "$host" in
            ""|localhost|127.0.0.1|::1|"$myhost") ;;
            *) continue ;;
        esac
        [ "${port:-25}" = "25" ] && bad="$bad $file"
    done
    [ -z "$bad" ] && return 0
    echo ""
    echo "The webmail of this host authenticates on port 25:"
    for file in $bad; do
        echo "    $file"
    done
    echo "The SPFBL gateway does not offer authentication on port 25, so the webmail"
    echo "would stop sending after the switch. Move it to the submission port, with"
    echo "these lines in the file above (the certificate must be valid for this name):"
    echo "    \$config['smtp_host'] = 'tls://$myhost:587';"
    echo "    \$config['smtp_port'] = 587;"
    echo "Older Roundcube versions use smtp_server instead of smtp_host."
    echo "Then send a test message through the webmail and run this installation again."
    exit 1
}

###########################################################################
# Authenticated relay on port 25
#
# Exim does not offer AUTH on port 25. Whoever sends authenticated mail
# through port 25 of Postfix must move to 587 or 465 before the switch.
###########################################################################

function gw_mail_log() {
    # Lines of postfix/smtpd since the date $1 (any "date -d" format).
    local since epoch lines file
    since=$(date -d "$1" '+%Y-%m-%d %H:%M:%S') || return 0
    epoch=$(date -d "$1" +%s)
    if command -v journalctl >/dev/null; then
        lines=$(journalctl -q -o short-iso --since "$since" -t postfix/smtpd 2>/dev/null)
        if [ -n "$lines" ]; then
            echo "$lines"
            return 0
        fi
    fi
    # Mail log file: classic ("Nov 21 13:00:01") or ISO timestamps.
    for file in /var/log/maillog /var/log/mail.log; do
        [ -f "$file" ] || continue
        tail -n 500000 "$file" | grep -E 'postfix/smtpd\[[0-9]+\]:' | awk -v since="$epoch" -v year="$(date +%Y)" -v now="$(date +%s)" '
            BEGIN {
                split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", m, " ")
                for (i = 1; i <= 12; i++) mon[m[i]] = i
            }
            {
                if ($1 ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T/) {
                    t = mktime(substr($1, 1, 4) " " substr($1, 6, 2) " " substr($1, 9, 2) " " \
                        substr($1, 12, 2) " " substr($1, 15, 2) " " substr($1, 18, 2))
                } else if ($1 in mon) {
                    split($3, h, ":")
                    t = mktime(year " " mon[$1] " " $2 " " h[1] " " h[2] " " h[3])
                    if (t > now + 86400) t = mktime((year - 1) " " mon[$1] " " $2 " " h[1] " " h[2] " " h[3])
                } else {
                    next
                }
                if (t >= since) print
            }'
        return 0
    done
}

function gw_sasl_report() {
    # Successful logins (lines with client= and sasl_username=), by user and client.
    grep -E 'postfix/smtpd\[[0-9]+\]: .*client=.*sasl_username=' | awk '
        {
            ts = ($1 ~ /^[0-9][0-9][0-9][0-9]-/) ? $1 : $1 " " $2 " " $3
            match($0, /client=[^,]+/); c = substr($0, RSTART + 7, RLENGTH - 7)
            match($0, /sasl_username=[^, ]+/); u = substr($0, RSTART + 14, RLENGTH - 14)
            k = u "  " c; n[k]++; last[k] = ts
        }
        END { for (k in n) printf "    %6d  %s  (last: %s)\n", n[k], k, last[k] }' | sort -k2
}

function gw_sasl_separable() {
    # True when every other public smtpd service of master.cf has its own
    # syslog_name: then "postfix/smtpd" in the log is port 25 only.
    awk '
        function flush(   port, host) {
            if (type == "inet" && cmd == "smtpd" && !inblock) {
                port = name; host = ""
                if (match(name, /:[^:]*$/)) { host = substr(name, 1, RSTART - 1); port = substr(name, RSTART + 1) }
                loopback = (host == "127.0.0.1" || host == "[::1]" || host == "localhost")
                if (port != "smtp" && port != "25" && !loopback && body !~ /syslog_name=/) bad = 1
            }
            type = ""
        }
        /^# BEGIN SPFBL$/ { flush(); inblock = 1; next }
        /^# END SPFBL$/ { flush(); inblock = 0; next }
        /^[^#[:space:]]/ { flush(); name = $1; type = $2; cmd = $8; body = $0; next }
        /^[[:space:]]+[^[:space:]#]/ { body = body " " $0 }
        END { flush(); exit bad }' "$POSTFIX_MASTER"
}

function gw_sasl_tag() {
    # Gives a syslog_name to every other public smtpd service of master.cf
    # (submission, smtps...), so that "postfix/smtpd" in the log is port
    # 25 only. Only log names change; the services stay the same.
    local tmp="$POSTFIX_MASTER.spfbl-tmp"
    cp -a "$POSTFIX_MASTER" "$POSTFIX_MASTER.spfbl-$(date +%Y%m%d%H%M%S)" || return 1
    awk '
        function label(name,   port) {
            port = name
            if (match(name, /:[^:]*$/)) port = substr(name, RSTART + 1)
            if (port == "submission" || port == "587") return "postfix/submission"
            if (port == "smtps" || port == "submissions" || port == "465") return "postfix/smtps"
            gsub(/[^A-Za-z0-9_.-]/, "_", port)
            return "postfix/smtpd-" port
        }
        function flush(   port, host, loopback) {
            if (n == 0) return
            if (type == "inet" && cmd == "smtpd" && !inblock) {
                port = name; host = ""
                if (match(name, /:[^:]*$/)) { host = substr(name, 1, RSTART - 1); port = substr(name, RSTART + 1) }
                loopback = (host == "127.0.0.1" || host == "[::1]" || host == "localhost")
                if (port != "smtp" && port != "25" && !loopback && body !~ /syslog_name=/) {
                    print entry[1]
                    print "  -o syslog_name=" label(name)
                    for (i = 2; i <= n; i++) print entry[i]
                    n = 0; return
                }
            }
            for (i = 1; i <= n; i++) print entry[i]
            n = 0
        }
        /^# BEGIN SPFBL$/ { flush(); inblock = 1; print; next }
        /^# END SPFBL$/ { flush(); inblock = 0; print; next }
        /^[^#[:space:]]/ { flush(); name = $1; type = $2; cmd = $8; body = $0; n = 1; entry[1] = $0; next }
        /^[[:space:]]+[^[:space:]#]/ && n { body = body " " $0; entry[++n] = $0; next }
        { flush(); print }
        END { flush() }' "$POSTFIX_MASTER" > "$tmp" || { rm -f "$tmp"; return 1; }
    cat "$tmp" > "$POSTFIX_MASTER" && rm -f "$tmp"
    gw_postfix_reload
}

function gw_check_sasl() {
    # Exim does not offer AUTH on port 25: the installation goes on only
    # after 24 hours without authenticated logins on port 25 of Postfix.
    local value report tagged since ready
    value=$(postconf -h smtpd_sasl_auth_enable 2>/dev/null)
    [ "$value" = "yes" ] || return 0
    if [ "$SPFBL_SASL_PORT25" = "none" ]; then
        echo "Authentication on port 25: check skipped (SPFBL_SASL_PORT25=none)."
        echo "The administrator confirmed that nobody authenticates on port 25."
        return 0
    fi
    if ! gw_sasl_separable; then
        # The log does not separate port 25 from the other SMTP ports yet:
        # the other services get their own syslog_name and the check
        # starts counting from now.
        gw_sasl_tag || fail "Could not give a syslog_name to the SMTP services of $POSTFIX_MASTER."
        gw_sasl_separable || fail "The SMTP services of $POSTFIX_MASTER still have no syslog_name."
        state_set_once SASL_TAGGED "$(date +%s)"
        echo ""
        echo "Postfix offers authentication (SASL) on port 25, and its log did not separate"
        echo "port 25 from the submission ports. The services submission and smtps of"
        echo "$POSTFIX_MASTER now have their own syslog_name (a backup was kept)."
    fi
    tagged=$(state_get SASL_TAGGED)
    since="24 hours ago"
    if [ -n "$tagged" ] && [ "$tagged" -gt "$(date -d "24 hours ago" +%s)" ]; then
        since="@$tagged"
    fi
    report=$(gw_mail_log "$since" | gw_sasl_report)
    if [ -n "$report" ]; then
        echo ""
        echo "Authenticated logins (SASL) on port 25 since $(date -d "$since" '+%Y-%m-%d %H:%M'):"
        echo "$report"
        echo ""
        echo "The SPFBL gateway does not offer authentication on port 25."
        echo "After the switch, these senders would have their mail refused."
        echo "Move them to the submission ports: 587 (STARTTLS) or 465 (TLS)."
        echo "Then run this installation again, 24 hours after the last login above."
        exit 1
    fi
    if [ -n "$tagged" ] && [ "$tagged" -gt "$(date -d "24 hours ago" +%s)" ]; then
        ready=$(date -d "@$((tagged + 86400))" '+%Y-%m-%d %H:%M')
        echo ""
        echo "No authenticated login on port 25 so far, but port 25 is logged apart only"
        echo "since $(date -d "@$tagged" '+%Y-%m-%d %H:%M'). The check needs 24 hours of log."
        echo "Nothing else was changed. Run this installation again after $ready."
        exit 1
    fi
    return 0
}

###########################################################################
# Postfix master.cf
###########################################################################

function gw_quota_policy() {
    # Dovecot quota policy (iRedMail: inet:127.0.0.1:12340). It refuses
    # full mailboxes at RCPT time; it is not a spam filter, so it stays on
    # the inbound port. Printed with commas, ready for a master.cf -o.
    postconf -h smtpd_recipient_restrictions 2>/dev/null | tr ',' ' ' |
        grep -oE 'check_policy_service[[:space:]]+[^[:space:]]+:12340' | head -1 | tr -s ' ' ','
}

function gw_master_awk() {
    # Shared parser of master.cf: an entry starts on a line without
    # leading space; the following indented lines belong to it.
    # Mode "public": prints the port 25 entries outside the SPFBL block.
    # Mode "block": prints the SPFBL services.
    # Mode "close": comments out those port 25 entries.
    [ -f "$POSTFIX_MASTER" ] || return 1
    local quota=""
    [ "$1" = "block" ] && quota=$(gw_quota_policy)
    awk -v mode="$1" -v inport="$GW_INBOUND_PORT" -v localport="$GW_LOCAL_PORT" -v quota="$quota" '
        function public_smtp(name, type,   i, host, port) {
            if (type != "inet") return 0
            i = match(name, /:[^:]*$/)
            if (i) { host = substr(name, 1, i - 1); port = substr(name, i + 1) }
            else { host = ""; port = name }
            # Loopback included: Exim listens on every address of port 25.
            return (port == "smtp" || port == "25")
        }
        /^# BEGIN SPFBL$/ { inblock = 1 }
        /^[^#[:space:]]/ {
            n++; name[n] = $1; type[n] = $2; chroot[n] = $5; command[n] = $8; extra[n] = ""
            pub[n] = !inblock && public_smtp($1, $2)
            closing = (mode == "close" && pub[n])
            if (closing) { print "#SPFBL# " $0; next }
            if (mode == "public" && pub[n]) print
        }
        /^[[:space:]]+[^[:space:]#]/ && n {
            extra[n] = extra[n] $0 "\n"
            if (closing) { print "#SPFBL# " $0; next }
        }
        /^# END SPFBL$/ { inblock = 0 }
        mode == "close" { print }
        END {
            if (mode != "block") exit
            # Original settings: the smtpd of port 25, or the smtpd behind postscreen.
            src = 0
            for (i = 1; i <= n; i++) if (pub[i] && command[i] == "smtpd") { src = i; break }
            if (!src) for (i = 1; i <= n; i++) if (name[i] == "smtpd" && type[i] == "pass") { src = i; break }
            ch = src ? chroot[src] : "n"
            print "# BEGIN SPFBL"
            print "# Inbound mail checked by the SPFBL Irondome gateway (Exim on port 25)."
            print "# Spam, SPF, DNSBL and antivirus checks were already done by the gateway:"
            print "# no content filter, header/body checks or milters here."
            print "127.0.0.1:" inport "      inet  n       -       " ch "       -       -       smtpd"
            print "  -o syslog_name=postfix/spfbl-inbound"
            print "  -o content_filter="
            print "  -o receive_override_options=no_header_body_checks,no_milters"
            print "  -o smtpd_client_restrictions="
            print "  -o smtpd_helo_restrictions="
            print "  -o smtpd_sender_restrictions="
            print "  -o smtpd_relay_restrictions=reject_unauth_destination"
            if (quota != "") print "  -o smtpd_recipient_restrictions=reject_unauth_destination," quota
            else print "  -o smtpd_recipient_restrictions=reject_unauth_destination"
            print "  -o smtpd_data_restrictions="
            print "  -o smtpd_end_of_data_restrictions="
            print "  -o smtpd_reject_unlisted_recipient=yes"
            print "  -o smtpd_sasl_auth_enable=no"
            print "  -o smtpd_tls_security_level=none"
            print "  -o smtpd_milters="
            print "# Mail from this host, with the original settings of port 25."
            print "127.0.0.1:" localport "      inet  n       -       " ch "       -       -       smtpd"
            if (src) printf "%s", extra[src]
            print "  -o syslog_name=postfix/spfbl-local"
            print "# END SPFBL"
        }' "$POSTFIX_MASTER"
}

function gw_master_public() {
    gw_master_awk public
}

function gw_postfix_reload() {
    # Starts Postfix if a previous master.cf left it stopped.
    postfix check || return 1
    if postfix status >/dev/null 2>&1; then
        postfix reload
    else
        postfix start
    fi
}

function gw_master_clean() {
    # master.cf without anything of SPFBL: the block of the internal
    # ports (and the blank line before it) goes away and the port 25
    # entries closed by the switch are open again. Changes made by the
    # panel after the installation are kept.
    awk '
        /^# BEGIN SPFBL$/ { skip = 1; pending = ""; next }
        skip { if (/^# END SPFBL$/) skip = 0; next }
        /^$/ { pending = pending "\n"; next }
        { printf "%s", pending; pending = ""; sub(/^#SPFBL# /, ""); print }
        END { printf "%s", pending }' "$POSTFIX_MASTER"
}

function gw_postfix_restore() {
    # master.cf as it was before the gateway, with port 25 back to Postfix.
    local clean
    clean=$(gw_master_clean) || return 1
    printf "%s\n" "$clean" > "$POSTFIX_MASTER"
    gw_postfix_reload
}

function gw_stop_exim() {
    # Stops the gateway Exim and makes sure that port 25 is free before
    # Postfix gets it back. "systemctl disable --now" is not enough: the
    # unit is a link into GW_DIR, and once it vanishes systemd may not stop
    # the daemon, which keeps port 25 and Postfix cannot bind it.
    local try pids
    systemctl stop spfbl-exim.service >/dev/null 2>&1
    for try in $(seq 1 10); do
        pids=$(pgrep -f "^$GW_DIR/bin/exim" 2>/dev/null)
        [ -z "$pids" ] && [[ $(port_owner 25) != *exim* ]] && break
        sleep 1
    done
    pids=$(pgrep -f "^$GW_DIR/bin/exim" 2>/dev/null)
    if [ -n "$pids" ]; then
        echo "The gateway Exim did not stop with systemd: ending its processes ($(echo $pids))."
        kill $pids 2>/dev/null
        sleep 2
        pids=$(pgrep -f "^$GW_DIR/bin/exim" 2>/dev/null)
        [ -n "$pids" ] && kill -9 $pids 2>/dev/null && sleep 1
    fi
    systemctl disable spfbl-exim.service >/dev/null 2>&1
    if [[ $(port_owner 25) == *exim* ]]; then
        echo "WARNING: an Exim process still holds port 25: $(ss -ltnp '( sport = :25 )' 2>/dev/null | tail -n +2 | head -2)"
        return 1
    fi
    return 0
}

function gw_abort() {
    # Something failed: Postfix gets port 25 back, as before the gateway.
    gw_stop_exim
    gw_postfix_restore
    fail "$1 Postfix was put back on port 25, with the master.cf it had before the gateway."
}

function gw_postfix_add_ports() {
    # Opens the internal ports. On the installation, Postfix keeps port 25
    # until the switch. With "close", the Exim gateway is already running
    # and port 25 is closed in the same reload, to avoid a bind conflict.
    if ! grep -q '^# BEGIN SPFBL$' "$POSTFIX_MASTER"; then
        # First installation, or the panel rewrote master.cf: this is the original.
        cp -p "$POSTFIX_MASTER" "$POSTFIX_MASTER.bak-spfbl"
        local block
        block=$(gw_master_awk block)
        printf "\n%s\n" "$block" >> "$POSTFIX_MASTER"
    fi
    if [ "$1" = "close" ] && [ -n "$(gw_master_public)" ]; then
        local closed
        closed=$(gw_master_awk close) && printf "%s\n" "$closed" > "$POSTFIX_MASTER"
    fi
    if command -v selinuxenabled >/dev/null && selinuxenabled; then
        command -v semanage >/dev/null || pkg_install policycoreutils-python-utils
        local port
        for port in "$GW_INBOUND_PORT" "$GW_LOCAL_PORT"; do
            semanage port -a -t smtp_port_t -p tcp "$port" 2>/dev/null ||
            semanage port -m -t smtp_port_t -p tcp "$port" 2>/dev/null
        done
    fi
    gw_postfix_reload || gw_abort "Postfix did not accept the internal ports."
    port_listening "$GW_INBOUND_PORT" && port_listening "$GW_LOCAL_PORT" ||
        gw_abort "Postfix is not answering on the ports $GW_INBOUND_PORT and $GW_LOCAL_PORT."
}

###########################################################################
# Exim
###########################################################################

function gw_install_build_deps() {
    if [ "$DISTRO_FAMILY" = "rhel" ]; then
        # pcre2-devel and gdbm-devel come from CRB (EL9 and EL10) or PowerTools (EL8).
        pkg_install dnf-plugins-core
        dnf config-manager --set-enabled crb 2>/dev/null || dnf config-manager --set-enabled powertools 2>/dev/null
        pkg_install gcc make pkgconf-pkg-config pcre2-devel openssl-devel gdbm-devel perl xz tar
    else
        pkg_install build-essential pkg-config libpcre2-dev libssl-dev libgdbm-dev perl xz-utils
    fi
}

function gw_user() {
    # System user of the gateway Exim. Created before "config", so that
    # spfbl.conf gets its group at once.
    if ! getent passwd "$GW_USER" >/dev/null; then
        useradd --system --user-group --no-create-home --home-dir "$GW_DIR/spool" --shell "$(command -v nologin || echo /sbin/nologin)" "$GW_USER"
    fi
}

function gw_dirs() {
    # Directories of GW_DIR. The Exim user writes in spool, log and var.
    gw_user
    mkdir -p "$GW_DIR/bin" "$GW_DIR/etc" "$GW_DIR/spool" "$GW_LOG_DIR" "$GW_VAR_DIR" "$GW_BACKUP_DIR" "$GW_UNIT_DIR"
    # The whole spool: a directory created by root inside it (a scan test,
    # for example) would stop Exim from unpacking messages for clamd.
    chown -R "$GW_USER:$GW_USER" "$GW_DIR/spool"
    chown "$GW_USER:$GW_USER" "$GW_LOG_DIR" "$GW_VAR_DIR"
    chmod 750 "$GW_DIR/spool" "$GW_LOG_DIR" "$GW_VAR_DIR"
    chmod 700 "$GW_BACKUP_DIR"
}

function gw_build() {
    # Compiles Exim into $GW_DIR, apart from the packages of the system.
    gw_dirs
    # Version 2.2 compiled Exim without IPv6: it is compiled again.
    if gw_installed && "$GW_EXIM" -bV 2>/dev/null | head -1 | grep -q "Exim version $GW_EXIM_VERSION " &&
            "$GW_EXIM" -bV 2>/dev/null | grep -qE '^Support for:.* IPv6( |$)'; then
        echo "Exim $GW_EXIM_VERSION is already compiled."
        return 0
    fi
    gw_install_build_deps
    local work source
    work=$(mktemp -d) || fail "Could not create a temporary directory."
    download "$GW_EXIM_URL" "$work/exim.tar.xz"
    if ! echo "$GW_EXIM_SHA256  $work/exim.tar.xz" | sha256sum -c --quiet; then
        rm -rf "$work"
        fail "The Exim source does not match the expected checksum."
    fi
    tar -xJf "$work/exim.tar.xz" -C "$work" || fail "The Exim source could not be extracted."
    source="$work/exim-$GW_EXIM_VERSION"
    mkdir -p "$source/Local"
    cat > "$source/Local/Makefile" <<EOF
# SPFBL Irondome gateway build of Exim.
BIN_DIRECTORY=$GW_DIR/bin
CONFIGURE_FILE=$GW_DIR/etc/exim.conf
EXIM_USER=ref:$GW_USER
SPOOL_DIRECTORY=$GW_DIR/spool
LOG_FILE_PATH=$GW_LOG_DIR/%slog
PID_FILE_PATH=/run/spfbl-exim/exim.pid
ROUTER_ACCEPT=yes
ROUTER_DNSLOOKUP=yes
ROUTER_MANUALROUTE=yes
ROUTER_REDIRECT=yes
TRANSPORT_SMTP=yes
TRANSPORT_APPENDFILE=yes
TRANSPORT_PIPE=yes
LOOKUP_DBM=yes
LOOKUP_LSEARCH=yes
# Without it, Exim only listens on IPv4 and the IPv6 of port 25 is lost.
HAVE_IPV6=YES
PCRE2_CONFIG=yes
USE_OPENSSL=yes
USE_OPENSSL_PC=openssl
TLS_LIBS=-lssl -lcrypto
WITH_CONTENT_SCAN=yes
USE_GDBM=yes
DBMLIB=-lgdbm
FIXED_NEVER_USERS=root
HEADERS_CHARSET="ISO-8859-1"
SYSTEM_ALIASES_FILE=/etc/aliases
CHOWN_COMMAND=/bin/chown
CHGRP_COMMAND=/bin/chgrp
CHMOD_COMMAND=/bin/chmod
TMPDIR="/tmp"
COMPRESS_COMMAND=/usr/bin/gzip
COMPRESS_SUFFIX=gz
ZCAT_COMMAND=/usr/bin/zcat
EOF
    echo "Compiling Exim $GW_EXIM_VERSION. This may take a few minutes..."
    if ! (cd "$source" && make -j"$(nproc)" && make install) > "$GW_LOG_DIR/build.log" 2>&1; then
        rm -rf "$work"
        fail "Exim compilation failed. See $GW_LOG_DIR/build.log."
    fi
    rm -rf "$work"
    "$GW_EXIM" -bV 2>/dev/null | grep -q 'Content_Scanning' || fail "The compiled Exim has no content scanning support."
    "$GW_EXIM" -bV 2>/dev/null | grep -qE '^Support for:.* IPv6( |$)' || fail "The compiled Exim has no IPv6 support."
}

function gw_links() {
    # "spfbl holding" calls exim and exiqgrep, and its PATH does not reach
    # GW_DIR. Another Exim of the system is never replaced.
    local tool current
    for tool in exim exiqgrep; do
        current=$(PATH=/sbin:/usr/sbin:/bin:/usr/bin command -v "$tool" 2>/dev/null)
        if [ -n "$current" ]; then
            echo "WARNING: $current already exists; \"spfbl holding\" will use it instead of the gateway $tool."
        else
            ln -sfn "$GW_DIR/bin/$tool" "/usr/local/sbin/$tool"
        fi
    done
}

function gw_clamav_databases() {
    # Downloads the official databases when the directory of the clamd
    # configuration $1 has none, and keeps freshclam updating them.
    local dbs
    dbs=$(awk '$1 == "DatabaseDirectory" {print $2}' "$1" 2>/dev/null | tail -1)
    dbs="${dbs:-/var/lib/clamav}"
    if ! ls "$dbs"/main.c[lv]d >/dev/null 2>&1; then
        echo "No ClamAV databases in $dbs yet: running freshclam."
        freshclam
    fi
    systemctl enable --now clamav-freshclam.service 2>/dev/null
}

function gw_install_clamav() {
    if [ "$DISTRO_FAMILY" = "rhel" ]; then
        # A clamd instance already installed is always reused, like the
        # clamd@amavisd of iRedMail, and started again if it was stopped.
        local conf name unit
        for conf in /etc/clamd.d/*.conf; do
            [ -f "$conf" ] || continue
            name=$(basename "$conf" .conf)
            [ "$name" = "scan" ] && continue
            grep -q '^LocalSocket[[:space:]]' "$conf" || continue
            unit=$(clamd_service_for "$conf") || continue
            state_set_once CLAMAV_PACKAGES "present"
            echo "Reusing the $unit service of this host ($conf)."
            command -v setsebool >/dev/null && setsebool -P antivirus_can_scan_system 1 2>/dev/null
            # The instance may never have run (CWP without Amavis): clamd
            # does not start without databases, and freshclam may be off.
            gw_clamav_databases "$conf"
            systemctl is-active --quiet "$unit" || systemctl enable --now "$unit"
            return 0
        done
        if rpm -q clamd >/dev/null 2>&1; then
            state_set_once CLAMAV_PACKAGES "present"
        else
            state_set_once CLAMAV_PACKAGES "installed"
            rpm -q epel-release >/dev/null 2>&1 || pkg_install epel-release
            pkg_install clamav clamd clamav-update
        fi
        if [ -f /etc/clamd.d/scan.conf ]; then
            sed -i '/^Example$/d' /etc/clamd.d/scan.conf
            sed -i 's|^#LocalSocket /run/clamd.scan/clamd.sock|LocalSocket /run/clamd.scan/clamd.sock|' /etc/clamd.d/scan.conf
        fi
        command -v setsebool >/dev/null && setsebool -P antivirus_can_scan_system 1
        if [ ! -f /var/lib/clamav/main.cvd ] && [ ! -f /var/lib/clamav/main.cld ]; then
            freshclam
        fi
        systemctl enable --now clamav-freshclam.service 2>/dev/null
        systemctl enable clamd@scan 2>/dev/null
        systemctl restart clamd@scan
    else
        if dpkg -s clamav-daemon 2>/dev/null | grep -q '^Status: install ok installed'; then
            state_set_once CLAMAV_PACKAGES "present"
        else
            state_set_once CLAMAV_PACKAGES "installed"
            pkg_install clamav clamav-daemon clamav-freshclam
        fi
        if ! ls /var/lib/clamav/*.c[lv]d >/dev/null 2>&1; then
            systemctl stop clamav-freshclam.service 2>/dev/null
            freshclam
        fi
        systemctl enable --now clamav-freshclam.service 2>/dev/null
        systemctl enable clamav-daemon.service 2>/dev/null
        systemctl restart clamav-daemon.service
    fi
}

function gw_clamd_access() {
    # clamd reads the files that Exim unpacks in its spool, and Exim must
    # open the clamd socket (iRedMail: /var/run/clamd.amavisd, 0770).
    find_clamd
    if [ -n "$CLAMD_USER" ] && id "$CLAMD_USER" >/dev/null 2>&1 &&
            ! id -nG "$CLAMD_USER" | tr ' ' '\n' | grep -qx "$GW_USER"; then
        usermod -aG "$GW_USER" "$CLAMD_USER"
        # A running process only gets a new group when it starts again:
        # until then clamd cannot read the spool and the scan is skipped.
        local unit
        unit=$(clamd_unit)
        if [ -n "$unit" ] && systemctl is-active --quiet "$unit"; then
            echo "Restarting $unit, so that $CLAMD_USER can read the gateway spool."
            systemctl restart "$unit"
            find_clamd >/dev/null
        else
            echo "WARNING: restart the clamd of $CLAMD_USER, so that it can read the gateway spool."
        fi
    fi
    local path group
    for path in "$(dirname "${CLAMD_SOCKET:-/nonexistent/x}")" "$CLAMD_SOCKET"; do
        [ -e "$path" ] || continue
        group=$(stat -c %G "$path" 2>/dev/null)
        case "$group" in
            ""|root|UNKNOWN|"$GW_USER") ;;
            *) id -nG "$GW_USER" | tr ' ' '\n' | grep -qx "$group" || usermod -aG "$group" "$GW_USER" ;;
        esac
    done
}

function gw_relay_script() {
    # Hosts allowed to send through the gateway: the mynetworks of Postfix,
    # read in real time. Exim runs this script on each check; the list is
    # only rebuilt when main.cf or a file it references changes.
    cat > "$GW_RELAY_SCRIPT" <<'EOF'
#!/bin/bash
# SPFBL gateway: the Postfix mynetworks as an Exim host list ("<;" separator).
# Written by spfbl.irondome.sh. Exim runs it as its own user.
set -f
CACHE="/opt/spfbl/exim/var/relay_hosts"
STAMP="$CACHE.stamp"
DEFAULT="<; 127.0.0.1 ; ::1"

# Same files, with the same time, size and inode: the cache is valid.
if [ -r "$CACHE" ] && [ -s "$CACHE" ] && [ -r "$STAMP" ] && [ -s "$STAMP" ]; then
    mapfile -t files < <(cut -d' ' -f4- "$STAMP")
    if [ "$(stat -c '%Y %s %i %n' "${files[@]}" 2>/dev/null)" = "$(cat "$STAMP")" ]; then
        cat "$CACHE"
        exit 0
    fi
fi

config=$(postconf -h config_directory 2>/dev/null)
[ -n "$config" ] || { printf '%s' "$DEFAULT"; exit 0; }
files=("$config/main.cf")
entries=(127.0.0.1 ::1)
for token in $(postconf -xh mynetworks 2>/dev/null | tr ',' ' '); do
    negate=""
    if [[ $token == !* ]]; then
        negate="! "
        token=${token#!}
    fi
    case "$token" in
        /*)
            # File with networks, separated by spaces, commas or lines.
            files+=("$token")
            for item in $(sed 's/#.*//' "$token" 2>/dev/null | tr ',' ' '); do
                entries+=("$negate$item")
            done
            ;;
        *:/*)
            # Lookup table (cidr:, hash:, texthash:...): the keys of its source file.
            path=${token#*:}
            files+=("$path")
            for item in $(sed 's/#.*//' "$path" 2>/dev/null | awk 'NF {print $1}'); do
                entries+=("$negate$item")
            done
            ;;
        *)
            entries+=("$negate$token")
            ;;
    esac
done

# Postfix writes IPv6 between brackets: [2001:db8::]/32 and [::1].
list="<;"
for item in "${entries[@]}"; do
    item=${item//\[/}
    item=${item//\]/}
    [ -n "$item" ] && list="$list $item ;"
done
list=${list% ;}

# Only the Exim user writes the cache (root runs it in "exim -bh" tests).
if [ ! -O "${CACHE%/*}" ]; then
    printf '%s' "$list"
    exit 0
fi
umask 022
temp="$CACHE.$$"
if printf '%s' "$list" > "$temp" 2>/dev/null && mv -f "$temp" "$CACHE" 2>/dev/null; then
    if ! { stat -c '%Y %s %i %n' "${files[@]}" > "$STAMP.$$" && mv -f "$STAMP.$$" "$STAMP"; } 2>/dev/null; then
        # A file could not be read: no stamp, the list is rebuilt next time.
        rm -f "$STAMP.$$" "$STAMP"
    fi
else
    rm -f "$temp"
fi
printf '%s' "$list"
EOF
    chmod 755 "$GW_RELAY_SCRIPT"
    rm -f "$GW_VAR_DIR/relay_hosts" "$GW_VAR_DIR/relay_hosts.stamp"
}

function gw_maint_script() {
    # Hourly maintenance of the gateway, by its own systemd timer: copy of
    # the Postfix certificate, readable by the Exim user (Exim is reloaded
    # only when it changes), and the daily rotation of the Exim logs.
    local cert key chain
    cert=$(postconf -h smtpd_tls_cert_file 2>/dev/null)
    key=$(postconf -h smtpd_tls_key_file 2>/dev/null)
    chain=$(postconf -h smtpd_tls_chain_files 2>/dev/null | awk '{print $1}')
    if [ -z "$cert" ] || [ "$cert" = "none" ] || [ ! -f "$cert" ]; then
        cert="$chain"
        key="$chain"
    fi
    [ -z "$key" ] || [ "$key" = "none" ] && key="$cert"
    if [ -z "$cert" ] || [ ! -f "$cert" ] || [ ! -f "$key" ]; then
        cert=""
        key=""
        rm -rf "$GW_DIR/etc/tls"
        echo "WARNING: the Postfix certificate was not found. Exim will not offer STARTTLS."
    fi
    cat > "$GW_MAINT_SCRIPT" <<EOF
#!/bin/bash
# SPFBL gateway maintenance. Written by spfbl.irondome.sh.
cert="$cert"
key="$key"
if [ -n "\$cert" ]; then
    dir="$GW_DIR/etc/tls"
    mkdir -p "\$dir"
    if ! cmp -s "\$cert" "\$dir/cert.pem" || ! cmp -s "\$key" "\$dir/key.pem"; then
        install -m 640 -o root -g $GW_USER "\$cert" "\$dir/cert.pem"
        install -m 640 -o root -g $GW_USER "\$key" "\$dir/key.pem"
        systemctl reload spfbl-exim.service 2>/dev/null
    fi
fi
# master.cf rewritten by the panel and not seen by the path unit.
[ -x "$GW_GUARD_SCRIPT" ] && "$GW_GUARD_SCRIPT"
# Exim logs: rotated once a day, 14 days kept.
today=\$(date +%Y%m%d)
if [ "\$(cat "$GW_VAR_DIR/logs-rotated" 2>/dev/null)" != "\$today" ]; then
    "$GW_DIR/bin/exicyclog" -k 14 >/dev/null 2>&1
    echo "\$today" > "$GW_VAR_DIR/logs-rotated"
fi
EOF
    chmod 755 "$GW_MAINT_SCRIPT"
    # Today's logs are not rotated by the first run.
    date +%Y%m%d > "$GW_VAR_DIR/logs-rotated"
    "$GW_MAINT_SCRIPT"
}

function gw_guard_script() {
    # Guard of the Postfix master.cf: panels may rewrite it (CWP "Rebuild
    # Mail Server", panel updates). With port 25 open again in master.cf,
    # Postfix cannot bind it (it belongs to Exim) and stops entirely. A
    # systemd path unit runs this script on every change of master.cf; the
    # hourly maintenance runs it too.
    {
        echo "#!/bin/bash"
        echo "# SPFBL gateway guard of the Postfix master.cf. Written by spfbl.irondome.sh."
        echo "POSTFIX_MASTER=\"$POSTFIX_MASTER\""
        echo "GW_INBOUND_PORT=\"$GW_INBOUND_PORT\""
        echo "GW_LOCAL_PORT=\"$GW_LOCAL_PORT\""
        declare -f gw_quota_policy gw_master_awk gw_master_public
        cat <<'EOF'
# Only while the gateway owns port 25 (switched and not rolled back).
systemctl is-enabled --quiet spfbl-exim.service 2>/dev/null || exit 0
[ -f "$POSTFIX_MASTER" ] || exit 0
exec 9>/run/spfbl-postfix-guard.lock
flock -w 30 9 || exit 0
if grep -q '^# BEGIN SPFBL$' "$POSTFIX_MASTER" && [ -z "$(gw_master_public)" ]; then
    exit 0
fi
logger -t spfbl-gateway "master.cf was rewritten: applying the gateway ports again."
cp -p "$POSTFIX_MASTER" "$POSTFIX_MASTER.rewritten-spfbl"
if ! grep -q '^# BEGIN SPFBL$' "$POSTFIX_MASTER"; then
    # The rewritten file is the new original of the panel.
    cp -p "$POSTFIX_MASTER" "$POSTFIX_MASTER.bak-spfbl"
    block=$(gw_master_awk block) && printf "\n%s\n" "$block" >> "$POSTFIX_MASTER"
fi
if [ -n "$(gw_master_public)" ]; then
    closed=$(gw_master_awk close) && printf "%s\n" "$closed" > "$POSTFIX_MASTER"
fi
if postfix check; then
    if postfix status >/dev/null 2>&1; then
        postfix reload
    else
        postfix start
    fi
    logger -t spfbl-gateway "master.cf fixed; Postfix reloaded."
else
    logger -t spfbl-gateway "master.cf fixed, but postfix check failed: see $POSTFIX_MASTER."
fi
EOF
    } > "$GW_GUARD_SCRIPT"
    chmod 755 "$GW_GUARD_SCRIPT"
}

function gw_csf_ignore() {
    # lfd reports unknown long running processes: the gateway Exim is
    # added to csf.pignore ("add") or taken out of it ("remove").
    local file=/etc/csf/csf.pignore line="exe:$GW_EXIM"
    [ -f "$file" ] || return 0
    if [ "$1" = "add" ]; then
        grep -qxF "$line" "$file" && return 0
        echo "$line" >> "$file"
    else
        grep -qxF "$line" "$file" || return 0
        grep -vxF "$line" "$file" > "$file.spfbl-tmp" && cat "$file.spfbl-tmp" > "$file"
        rm -f "$file.spfbl-tmp"
    fi
    if systemctl is-active --quiet lfd 2>/dev/null; then
        systemctl restart lfd >/dev/null 2>&1
    fi
}

function gw_units() {
    # Units in GW_DIR, linked into systemd.
    cat > "$GW_UNIT_DIR/spfbl-exim.service" <<EOF
[Unit]
Description=SPFBL Irondome gateway (Exim on port 25)
After=network-online.target postfix.service
Wants=network-online.target

[Service]
Type=simple
RuntimeDirectory=spfbl-exim
ExecStart=$GW_EXIM -bdf -q15m
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    cat > "$GW_UNIT_DIR/spfbl-exim-maint.service" <<EOF
[Unit]
Description=SPFBL Irondome gateway maintenance (certificate and logs)

[Service]
Type=oneshot
ExecStart=$GW_MAINT_SCRIPT
EOF
    cat > "$GW_UNIT_DIR/spfbl-exim-maint.timer" <<EOF
[Unit]
Description=SPFBL Irondome gateway maintenance, every hour

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
EOF
    cat > "$GW_UNIT_DIR/spfbl-postfix-guard.service" <<EOF
[Unit]
Description=SPFBL Irondome gateway guard of the Postfix master.cf

[Service]
Type=oneshot
ExecStart=$GW_GUARD_SCRIPT
EOF
    cat > "$GW_UNIT_DIR/spfbl-postfix-guard.path" <<EOF
[Unit]
Description=SPFBL Irondome gateway: watch the Postfix master.cf

[Path]
PathChanged=$POSTFIX_MASTER

[Install]
WantedBy=multi-user.target
EOF
    local unit
    for unit in spfbl-exim.service spfbl-exim-maint.service spfbl-exim-maint.timer spfbl-postfix-guard.service spfbl-postfix-guard.path; do
        # A unit file of version 2.1 in /etc/systemd/system is replaced by the link.
        if [ -f "/etc/systemd/system/$unit" ] && [ ! -L "/etc/systemd/system/$unit" ]; then
            rm -f "/etc/systemd/system/$unit"
        fi
        systemctl link "$GW_UNIT_DIR/$unit" >/dev/null 2>&1 ||
            ln -sf "$GW_UNIT_DIR/$unit" "/etc/systemd/system/$unit"
    done
    systemctl daemon-reload
    systemctl enable --now spfbl-exim-maint.timer >/dev/null 2>&1
    systemctl enable --now spfbl-postfix-guard.path >/dev/null 2>&1
}

function gw_migrate_layout() {
    # Version 2.1: hourly cron for the certificate, logrotate and logs in /var/log.
    rm -f "$GW_OLD_TLS_CRON" "$GW_OLD_LOGROTATE"
    if [ -d "$GW_OLD_LOG_DIR" ]; then
        cp -a "$GW_OLD_LOG_DIR/." "$GW_LOG_DIR/" 2>/dev/null
        rm -rf "$GW_OLD_LOG_DIR"
    fi
}

function gw_configure() {
    gw_dirs
    download "$GITHUB_SPFBL/exim.gateway.conf" "$GW_DIR/etc/exim.conf"
    download "$GITHUB_SPFBL/exim.acl_check_rcpt.conf" "$GW_DIR/etc/acl_check_rcpt.conf"
    download "$GITHUB_SPFBL/exim.acl_check_data.conf" "$GW_DIR/etc/acl_check_data.conf"
    download "$GITHUB_SPFBL/exim.acl_check_dkim.conf" "$GW_DIR/etc/acl_check_dkim.conf"
    gw_migrate_layout
    gw_links
    gw_clamd_access
    gw_relay_script
    gw_guard_script
    gw_maint_script
    gw_csf_ignore add
    local size
    size=$(postconf -h message_size_limit 2>/dev/null)
    {
        echo "# Values of this host, written by spfbl.irondome.sh."
        echo "GW_HOSTNAME = $(postconf -h myhostname)"
        echo "GW_SIZE_LIMIT = ${size:-52428800}"
        echo "GW_AV_SCANNER = clamd:${CLAMD_SOCKET:-/run/clamav/clamd.ctl}"
        echo "GW_INBOUND_PORT = $GW_INBOUND_PORT"
        echo "GW_LOCAL_PORT = $GW_LOCAL_PORT"
        if [ -f "$GW_DIR/etc/tls/cert.pem" ]; then
            echo "GW_TLS_CERT = $GW_DIR/etc/tls/cert.pem"
            echo "GW_TLS_KEY = $GW_DIR/etc/tls/key.pem"
        fi
    } > "$GW_DIR/etc/local.conf"
    "$GW_EXIM" -bV >/dev/null || fail "The Exim gateway configuration is invalid."
    gw_units
}

function gw_smtp_reply() {
    # Last line of an SMTP reply read from the descriptor 3.
    local line
    while IFS= read -r -t 10 line <&3; do
        line=${line%$'\r'}
        [[ $line =~ ^[0-9]{3}- ]] && continue
        echo "$line"
        return 0
    done
    echo "000 no reply"
}

function gw_smtp_rcpt() {
    # SMTP session with Postfix on 127.0.0.1:$1 until RCPT TO:<$2>.
    # Prints the RCPT reply. No message is sent.
    (
        exec 3<>"/dev/tcp/127.0.0.1/$1" || { echo "000 no connection"; exit 0; }
        gw_smtp_reply >/dev/null
        printf 'EHLO spfbl-test.localhost\r\n' >&3
        gw_smtp_reply >/dev/null
        printf 'MAIL FROM:<>\r\n' >&3
        gw_smtp_reply >/dev/null
        printf 'RCPT TO:<%s>\r\n' "$2" >&3
        gw_smtp_reply
        printf 'QUIT\r\n' >&3
    ) 2>/dev/null
}

function gw_test() {
    # The two paths through Postfix and the relay control of Exim.
    # Nothing is delivered and the SPFBL server is not queried.
    local reply local_rcpt
    # 1. Inbound port: no relay.
    reply=$(gw_smtp_rcpt "$GW_INBOUND_PORT" spfbl-relay-test@example.com)
    [[ $reply == 5* || $reply == 4* ]] ||
        gw_abort "Relay test failed: Postfix accepted mail for example.com on port $GW_INBOUND_PORT ($reply)."
    # 2. Inbound port: a local address is accepted (warning only: the
    #    postmaster of the host name may not exist in some panels).
    local_rcpt="postmaster@$(postconf -h myhostname)"
    reply=$(gw_smtp_rcpt "$GW_INBOUND_PORT" "$local_rcpt")
    [[ $reply == 250* ]] || echo "WARNING: Postfix on port $GW_INBOUND_PORT did not accept $local_rcpt: $reply"
    # 3. Local port: the hosts of mynetworks keep their relay.
    reply=$(gw_smtp_rcpt "$GW_LOCAL_PORT" spfbl-relay-test@example.com)
    [[ $reply == 250* ]] ||
        gw_abort "The hosts of mynetworks could not relay through Postfix on port $GW_LOCAL_PORT ($reply)."
    # 4. Exim asks Postfix about the recipient and refuses the relay.
    #    The fake session comes from a documentation IP.
    local result
    result=$(printf 'EHLO test.spfbl.net\r\nMAIL FROM:<>\r\nRCPT TO:<spfbl-relay-test@example.com>\r\nQUIT\r\n' |
        "$GW_EXIM" -bhc 192.0.2.1 2>/dev/null | grep -E '^[0-9]{3}[ -]' | tail -3)
    if echo "$result" | grep -q '^250 Accepted'; then
        gw_abort "Relay test failed: the gateway accepted mail for example.com."
    elif ! echo "$result" | grep -q 'Callout verification failed'; then
        echo "$result"
        gw_abort "The gateway could not check recipients through Postfix on port $GW_INBOUND_PORT."
    fi
    # 5. The Postfix networks must be read: they keep the original path.
    local relay
    relay=$(runuser -u "$GW_USER" -- "$GW_RELAY_SCRIPT" 2>/dev/null)
    [[ $relay == "<;"* ]] || gw_abort "The gateway could not read the Postfix mynetworks."
    echo "Gateway test passed: recipients checked by Postfix, relay closed, mynetworks relay kept."
    echo "Networks of this host (Postfix mynetworks): ${relay#<; }"
}

function gw_port25_v6() {
    # True when something listens on port 25 over IPv6.
    ss -ltnH "( sport = :25 )" 2>/dev/null | awk '{print $4}' | grep -q '^\['
}

function gw_public_check() {
    # SMTP banner through the public addresses of the host name.
    local name address banner
    name=$(postconf -h myhostname 2>/dev/null)
    # From the DNS, as the senders see it: /etc/hosts often has only the IPv4.
    local addresses
    if command -v dig >/dev/null; then
        addresses=$( { dig +short A "$name"; dig +short AAAA "$name"; } 2>/dev/null | grep -E '^[0-9a-fA-F.:]+$' | sort -u)
    else
        addresses=$(getent ahosts "$name" 2>/dev/null | awk '$1 !~ /^::ffff:/ {print $1}' | sort -u)
    fi
    for address in $addresses; do
        banner=$(timeout 5 bash -c "exec 3<>/dev/tcp/$address/25 && head -1 <&3" 2>/dev/null | tr -d '\r')
        echo "    $address: ${banner:-no answer}"
    done
}

function gw_switch() {
    # Postfix leaves port 25 and Exim takes it, in a few seconds. If
    # anything fails, Postfix gets port 25 back.
    local v6=false try
    gw_port25_v6 && v6=true
    if [ -n "$(gw_master_public)" ]; then
        local closed
        closed=$(gw_master_awk close) || gw_abort "The master.cf could not be read."
        printf "%s\n" "$closed" > "$POSTFIX_MASTER"
        gw_postfix_reload || gw_abort "Postfix did not accept the new master.cf."
        # postscreen holds a copy of the socket until it exits.
        for try in $(seq 1 15); do
            [ -z "$(port_owner 25)" ] && break
            sleep 1
        done
        [[ $(port_owner 25) == *master* ]] && gw_abort "Postfix did not leave port 25."
    fi
    systemctl enable spfbl-exim.service >/dev/null 2>&1
    systemctl restart spfbl-exim.service
    if ! port_listening 25 || [[ $(port_owner 25) != *exim* ]]; then
        journalctl -u spfbl-exim.service -n 10 --no-pager 2>/dev/null
        gw_abort "Exim could not take port 25."
    fi
    if $v6 && ! gw_port25_v6; then
        gw_abort "Exim is not listening on port 25 over IPv6, as Postfix was."
    fi
    echo "Port 25: Exim gateway. Postfix: 127.0.0.1:$GW_INBOUND_PORT and 127.0.0.1:$GW_LOCAL_PORT."
    echo "Port 25 through the public addresses of $(postconf -h myhostname):"
    gw_public_check
}

function gw_rollback() {
    # Postfix gets port 25 back at once. The internal ports stay, so
    # "switch" can go forward again without changing anything else.
    POSTFIX_MASTER="$(postconf -h config_directory)/master.cf"
    gw_installed || fail "The SPFBL gateway is not installed."
    gw_stop_exim
    if grep -q '^#SPFBL# ' "$POSTFIX_MASTER"; then
        local opened
        opened=$(sed 's/^#SPFBL# //' "$POSTFIX_MASTER")
        printf "%s\n" "$opened" > "$POSTFIX_MASTER"
    fi
    gw_postfix_reload || fail "Postfix did not accept the master.cf. Check it with \"postfix check\"."
    local try
    for try in $(seq 1 10); do
        [[ $(port_owner 25) == *master* ]] && break
        sleep 1
    done
    if [[ $(port_owner 25) == *master* ]]; then
        echo "Port 25: Postfix again. The gateway is stopped; run \"$0 switch\" to go forward."
    else
        fail "Postfix is not listening on port 25. Check the Postfix service."
    fi
    local queued
    queued=$("$GW_EXIM" -bpc 2>/dev/null)
    [ "${queued:-0}" -gt 0 ] && echo "WARNING: $queued messages wait in the gateway queue; they go out on the next switch."
    return 0
}

function gw_switched() {
    # The switch was done (and not undone by rollback).
    systemctl is-enabled --quiet spfbl-exim.service 2>/dev/null
}

function gw_ports() {
    # Internal ports in the Postfix master.cf. The panel may rewrite
    # master.cf in its updates, so it is checked every time.
    if ! grep -q '^# BEGIN SPFBL$' "$POSTFIX_MASTER" || [ -n "$(gw_master_public)" ]; then
        echo "Applying the gateway ports to the Postfix master.cf."
        if gw_switched && systemctl is-active --quiet spfbl-exim.service; then
            gw_postfix_add_ports close
        else
            gw_postfix_add_ports
        fi
    fi
}

function gw_notes() {
    # What changes for the mail of this host with the gateway.
    local relay mx address
    relay=$(runuser -u "$GW_USER" -- "$GW_RELAY_SCRIPT" 2>/dev/null)
    echo ""
    echo "Notes about the gateway on this host:"
    echo "  - Mail from the Postfix mynetworks is accepted by Exim without SPFBL checks"
    echo "    and reaches Postfix through 127.0.0.1:$GW_LOCAL_PORT, so Postfix logs it from 127.0.0.1."
    # Only when Amavis really runs (CWP installs it, but it may be off).
    if systemctl is-active --quiet amavisd 2>/dev/null || systemctl is-active --quiet amavis 2>/dev/null; then
        echo "  - Amavis sees that mail coming from 127.0.0.1 and treats it as originating"
        echo "    from this host: DKIM signing for local domains, no inbound spam scan."
    fi
    for mx in mx-br.spfbl.net mx-us.spfbl.net; do
        for address in $(getent ahosts "$mx" 2>/dev/null | awk '{print $1}' | sort -u); do
            if [[ " ${relay//;/ } " == *" $address "* ]]; then
                echo "  - $mx (SPFBL MX Gateway) is in mynetworks: its mail was already filtered"
                echo "    by SPFBL and is delivered without a second check."
                break
            fi
        done
    done
    echo "  - The original IP of each connection is in $GW_LOG_DIR/mainlog."
    echo "  - To give port 25 back to Postfix at any time: $0 rollback"
}

function gw_apply() {
    # Install and update: internal ports, tests and the port 25 switch.
    gw_ports
    gw_test
    gw_switch
}

function gw_uninstall() {
    POSTFIX_MASTER="$(postconf -h config_directory 2>/dev/null)/master.cf"
    gw_state_file
    [ -x "$SIGS_SCRIPT" ] && sigs_remove_script
    local keep=false clamav
    clamav=$(state_get CLAMAV_PACKAGES)
    if gw_installed; then
        # Delivers what is waiting while Postfix still listens on the internal ports.
        "$GW_EXIM" -q 2>/dev/null
        local frozen
        frozen=$("$GW_DIR/bin/exiqgrep" -z -c 2>/dev/null | grep -o '^[0-9]*')
        if [ "${frozen:-0}" -gt 0 ]; then
            local backup="$GW_BACKUP_DIR/spool-$(date +%Y%m%d%H%M%S).tar.gz"
            mkdir -p "$GW_BACKUP_DIR"
            tar -czf "$backup" -C "$GW_DIR" spool
            echo "WARNING: $frozen held messages were saved in $backup."
        fi
    fi
    ls -A "$GW_BACKUP_DIR" 2>/dev/null | grep -q . && keep=true
    gw_stop_exim
    systemctl disable --now spfbl-exim-maint.timer spfbl-postfix-guard.path 2>/dev/null
    # A test daemon started by hand (exim -bd -oX <port> -oP <file>).
    local pidfile
    for pidfile in /run/spfbl-exim-test.pid "$GW_VAR_DIR"/*.pid; do
        [ -f "$pidfile" ] && kill "$(cat "$pidfile")" 2>/dev/null && rm -f "$pidfile"
    done
    if [ -f "$POSTFIX_MASTER" ]; then
        gw_postfix_restore || echo "WARNING: Postfix did not accept the master.cf. Check it with \"postfix check\"."
    fi
    rm -f "$POSTFIX_MASTER.bak-spfbl" "$POSTFIX_MASTER.pre-switch-spfbl"
    if command -v selinuxenabled >/dev/null && selinuxenabled && command -v semanage >/dev/null; then
        semanage port -d -t smtp_port_t -p tcp "$GW_INBOUND_PORT" 2>/dev/null
        semanage port -d -t smtp_port_t -p tcp "$GW_LOCAL_PORT" 2>/dev/null
    fi
    # The whole manual installation of Exim, including the layout of version 2.1.
    local unit
    for unit in spfbl-exim.service spfbl-exim-maint.service spfbl-exim-maint.timer spfbl-postfix-guard.service spfbl-postfix-guard.path; do
        rm -f "/etc/systemd/system/$unit"
    done
    rm -f "$POSTFIX_MASTER.rewritten-spfbl" /run/spfbl-postfix-guard.lock
    gw_csf_ignore remove
    rm -f "$GW_OLD_TLS_CRON" "$GW_OLD_LOGROTATE"
    systemctl daemon-reload
    local tool
    for tool in exim exiqgrep; do
        [ "$(readlink "/usr/local/sbin/$tool")" = "$GW_DIR/bin/$tool" ] && rm -f "/usr/local/sbin/$tool"
    done
    if $keep; then
        # Only the backups of held messages stay.
        find "$GW_DIR" -mindepth 1 -maxdepth 1 ! -name "$(basename "$GW_BACKUP_DIR")" -exec rm -rf {} +
        echo "The backups of held messages stay in $GW_BACKUP_DIR."
    else
        rm -rf "$GW_DIR"
        rmdir /opt/spfbl 2>/dev/null
    fi
    rm -rf "$GW_OLD_LOG_DIR" /run/spfbl-exim
    # The clamd user leaves the group first: userdel only removes a
    # group without other members. userdel also takes spfbl-exim out of
    # the group of the clamd socket.
    local member
    for member in $(getent group "$GW_USER" | cut -d: -f4 | tr ',' ' '); do
        gpasswd -d "$member" "$GW_USER" >/dev/null 2>&1
    done
    getent passwd "$GW_USER" >/dev/null && userdel "$GW_USER"
    getent group "$GW_USER" >/dev/null && groupdel "$GW_USER"
    if [ "$clamav" = "installed" ]; then
        if command -v dpkg >/dev/null; then
            DEBIAN_FRONTEND=noninteractive apt-get remove --yes clamav clamav-daemon clamav-freshclam
        else
            dnf remove -y clamav clamd clamav-update 2>/dev/null || yum remove -y clamav clamd clamav-update
        fi
    fi
    rm -f "$EXIM_STATE" "$GW_OLD_STATE"
    if [[ $(port_owner 25) != *master* ]] && ! postfix status >/dev/null 2>&1; then
        # A reload that found port 25 still busy stops the Postfix master.
        postfix start >/dev/null 2>&1
        port_listening 25 >/dev/null 2>&1
    fi
    if [[ $(port_owner 25) == *master* ]]; then
        echo "Postfix is back on port 25."
    else
        echo "WARNING: Postfix is not listening on port 25. Check the Postfix service."
    fi
}

###########################################################################
# Commands
###########################################################################

###########################################################################
# SPFBL client configuration (/etc/spfbl/spfbl.conf)
###########################################################################

function conf_value() {
    # Value of a parameter in spfbl.conf, without quotes.
    [ -r "$SPFBL_CONF" ] || return 0
    awk -v n="$1" 'index($0, n "=") == 1 { v = substr($0, length(n) + 2); gsub(/^"|"$/, "", v); print v }' "$SPFBL_CONF" | tail -1
}

function conf_key_valid() {
    [[ "$1" =~ ^spfbl_[A-Za-z0-9_-]{52}$ ]]
}

function conf_group() {
    # Group of the MTA user, which runs spfbl.sh: from the running Exim
    # processes (cPanel mailnull, DirectAdmin mail, Debian-exim, gateway).
    if [ -n "$SPFBL_GROUP" ]; then
        getent group "$SPFBL_GROUP" > /dev/null || fail "The group $SPFBL_GROUP does not exist."
        echo "$SPFBL_GROUP"
        return
    fi
    # By the numeric GID: the ps group column cuts long names
    # ("Debian-exim" becomes "Debian-+").
    local gid name
    gid=$(ps -eo egid=,comm= 2> /dev/null | awk '$2 ~ /^exim/ && $1 != 0 { print $1 }' | sort -u | head -1)
    if [ -n "$gid" ]; then
        getent group "$gid" | cut -d: -f1
        return
    fi
    # Exim not running (yet): the group of the panel, if it exists.
    case "$PANEL" in
        gateway) name="$GW_USER" ;;
        cpanel) name="mailnull" ;;
        directadmin) name="mail" ;;
        exim) name="Debian-exim" ;;
    esac
    for name in $name exim Debian-exim; do
        if getent group "$name" > /dev/null; then
            echo "$name"
            return
        fi
    done
}

function conf_register() {
    # POST /client/ over IPv4 ($1 = 4) or IPv6 ($1 = 6). The key and the
    # hostname go through file descriptor 3: never on the command line.
    local out
    out=$(curl -"$1" -s --connect-timeout 10 -m 60 -X POST -w '\n%{http_code}' -K /dev/fd/3 \
        "$SPFBL_SERVER/client/" 2> /dev/null \
        3<<< "header = \"Authorization: Bearer $CONF_KEY\""$'\n'"header = \"X-SPFBL-Hostname: $CONF_HOSTNAME\"")
    REG_CODE=${out##*$'\n'}
    REG_BODY=${out%$'\n'*}
    REG_BODY=${REG_BODY%%$'\n'*}
}

function conf_reason() {
    # Explanation of a refused registration.
    case "$REG_BODY" in
        "INVALID FQDN NO_ADDRESS")
            echo "the hostname $CONF_HOSTNAME has no $2 record in DNS." ;;
        "INVALID FQDN IP_MISMATCH")
            echo "the $2 record of $CONF_HOSTNAME does not contain the $3 of this server." ;;
        "INVALID FQDN GENERIC")
            echo "$CONF_HOSTNAME is a generic provider name. Set a hostname of its own on this server." ;;
        "INVALID FQDN RESERVED_IP")
            echo "this server reaches SPFBL from a private or reserved IP." ;;
        "INVALID FQDN"*)
            echo "the hostname $CONF_HOSTNAME is invalid." ;;
        *INVALID_KEY*|"KEY REQUIRED")
            echo "the SPFBL access key is invalid." ;;
        *KEY_REVOKED*)
            echo "the SPFBL access key was revoked or expired. Create a new one in the SPFBL panel." ;;
        *BANNED*)
            echo "too many failures from this IP. Wait a few minutes and try again." ;;
        *)
            echo "unexpected answer (HTTP $REG_CODE)." ;;
    esac
}

function conf_fix_group() {
    # After the MTA is installed or rebuilt: the group of spfbl.conf may
    # not exist when "config" ran (gateway Exim built afterwards).
    [ -f "$SPFBL_CONF" ] || return 0
    local group
    group=$(conf_group)
    if [ -n "$group" ] && [ "$(stat -c %G "$SPFBL_CONF")" != "$group" ]; then
        chown "root:$group" "$SPFBL_CONF" && chmod 640 "$SPFBL_CONF" && \
            echo "$SPFBL_CONF readable by the group $group."
    fi
}

function spfbl_is_maintenance() {
    # Is the SPFBL monitor in a maintenance window? No answer: no.
    local status
    status=$(curl -s -f --connect-timeout 3 -m 5 -H "Authorization: Bearer $HETRIX_KEY" "$HETRIX_URL" 2> /dev/null)
    [[ $status =~ \"monitor_status\"[[:space:]]*:[[:space:]]*\"maint\" ]]
}

function spfbl_unavailable_code() {
    # HTTP codes of SPFBL not answering (no route, proxy, Cloudflare).
    [[ "$1" =~ ^(000|502|503|504|52[0-9]|530)$ ]]
}

function spfbl_unavailable() {
    # SPFBL did not answer: scheduled maintenance or communication failure.
    # The customer only has to try again later. On "update" (CONF_SOFT=1)
    # it goes on querying by IP; elsewhere nothing is changed.
    if spfbl_is_maintenance; then
        echo "SPFBL is under scheduled maintenance (https://status.spfbl.net)."
        echo "Try again in a few minutes."
    else
        echo "SPFBL did not answer. Check the connection of this server to"
        echo "$SPFBL_SERVER and try again in a few minutes."
    fi
    if [ -n "$CONF_SOFT" ]; then
        echo "Going on without $SPFBL_CONF: spfbl.sh keeps querying by IP."
        echo "Run \"$0 config\" later to use the SPFBL access key."
        return 1
    fi
    echo "Nothing was changed."
    exit 1
}

function client_check() {
    # SPFBL client installed: "spfbl version" must answer. Exit 26
    # (maintenance), 2 (timeout) and 3 (out of service) are SPFBL not
    # answering, not a refusal of this server.
    local rc
    "$SPFBL_CLIENT" version
    rc=$?
    if [ "$rc" = "0" ]; then
        return 0
    elif [ "$rc" = "26" ] || [ "$rc" = "2" ] || [ "$rc" = "3" ]; then
        CONF_SOFT="" spfbl_unavailable
    else
        access_denied
    fi
}

function conf_abort() {
    # Failure of the SPFBL client configuration. On "config", "install" and
    # "prepare" it stops everything; on "update" (CONF_SOFT=1) it goes on
    # without spfbl.conf, with spfbl.sh querying by IP as before.
    [ -n "$1" ] && echo "$1"
    if [ -n "$CONF_SOFT" ]; then
        echo "Going on without $SPFBL_CONF: spfbl.sh keeps querying by IP."
        echo "Run \"$0 config\" later to use the SPFBL access key."
        return 1
    fi
    echo "Nothing was changed."
    exit 1
}

function conf_write() {
    # Writes the file in one step: root:<MTA group>, mode 0640. Other
    # parameters already in the file are kept.
    local group="$1" temp="$SPFBL_CONF.tmp"
    mkdir -p "$SPFBL_CONF_DIR"
    chmod 755 "$SPFBL_CONF_DIR"
    (
        umask 077
        {
            echo "# SPFBL client configuration, read by spfbl.sh 3.06 or newer."
            echo "# Written by spfbl.irondome.sh config and kept on updates."
            echo "SPFBL_KEY=$CONF_KEY"
            [ -n "$CONF_IP_VERSION" ] && echo "IP_VERSION=$CONF_IP_VERSION"
            if [ -f "$SPFBL_CONF" ]; then
                # Other parameters; grep finding none is not an error.
                grep -vE '^(#|SPFBL_KEY=|SPFBL_HOSTNAME=|IP_VERSION=)' "$SPFBL_CONF" | grep -v '^[[:space:]]*$' || true
            fi
        } > "$temp"
    ) || fail "Could not write $temp."
    if ! chown "root:${group:-root}" "$temp"; then
        rm -f "$temp"
        fail "Could not set the group ${group:-root} on $SPFBL_CONF. Run again with SPFBL_GROUP=<group of the MTA user>."
    fi
    chmod 640 "$temp"
    mv -f "$temp" "$SPFBL_CONF"
}

function config() {
    command -v curl > /dev/null || { conf_abort "curl is required."; return 1; }
    # Key: the environment one, the one in the file, or asked for.
    CONF_KEY="$SPFBL_KEY"
    if [ -z "$CONF_KEY" ]; then
        CONF_KEY=$(conf_value SPFBL_KEY)
        [ -n "$CONF_KEY" ] && echo "Keeping the SPFBL access key already in $SPFBL_CONF."
    fi
    if [ -z "$CONF_KEY" ]; then
        if ! (exec < /dev/tty) 2> /dev/null; then
            conf_abort "No SPFBL access key and no terminal to ask for it. Run again with SPFBL_KEY=... in the environment."
            return 1
        fi
        echo "Create an access key in the SPFBL panel (Access keys) for this server."
        [ -n "$CONF_SOFT" ] && echo "Press Enter without a key to go on querying by IP."
        read -rs -p "SPFBL access key: " CONF_KEY < /dev/tty
        echo ""
        if [ -z "$CONF_KEY" ]; then
            conf_abort "No SPFBL access key given."
            return 1
        fi
    fi
    if ! conf_key_valid "$CONF_KEY"; then
        conf_abort "This is not a valid SPFBL access key (spfbl_..., 58 characters)."
        return 1
    fi
    # Hostname: the one in use by the kernel, the same that spfbl.sh
    # reads on every query. It must be the FQDN of this server.
    CONF_HOSTNAME=$(tr 'A-Z' 'a-z' < /proc/sys/kernel/hostname 2> /dev/null)
    [ -n "$CONF_HOSTNAME" ] || CONF_HOSTNAME=$(hostname 2> /dev/null | tr 'A-Z' 'a-z')
    if [[ ! "$CONF_HOSTNAME" == *.* || ! "$CONF_HOSTNAME" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]]; then
        echo "The hostname \"$CONF_HOSTNAME\" of this server is not a FQDN."
        echo "SPFBL Irondome needs the FQDN as the hostname of this server, with an"
        echo "A/AAAA record pointing to its IP. Set it and run again:"
        echo "   hostnamectl set-hostname mx.example.com"
        conf_abort ""
        return 1
    fi
    echo "Hostname of this server: $CONF_HOSTNAME"
    # Registration over IPv4 and IPv6. HTTP 000: no route for that protocol.
    local ok4="" ok6="" msg4="" msg6=""
    conf_register 4
    local code4="$REG_CODE"
    if [ "$REG_CODE" != "000" ] && spfbl_unavailable_code "$REG_CODE"; then
        spfbl_unavailable
        return 1
    elif [ "$REG_CODE" = "403" ] || [ "$REG_CODE" = "429" ]; then
        # Key refused or IP banned: the same for IPv6. Nothing is changed.
        conf_abort "Refused: $(conf_reason)"
        return 1
    elif [ "$REG_CODE" = "200" ]; then
        ok4=1
        echo "IPv4: $REG_BODY"
    elif [ "$REG_CODE" = "000" ]; then
        echo "IPv4: no connection to $SPFBL_SERVER."
    else
        msg4=$(conf_reason 4 A IPv4)
        echo "IPv4: refused: $msg4"
    fi
    conf_register 6
    if [ "$REG_CODE" != "000" ] && spfbl_unavailable_code "$REG_CODE"; then
        spfbl_unavailable
        return 1
    elif [ "$REG_CODE" = "200" ]; then
        ok6=1
        echo "IPv6: $REG_BODY"
    elif [ "$REG_CODE" = "000" ]; then
        echo "IPv6: no IPv6 connection to $SPFBL_SERVER."
    else
        msg6=$(conf_reason 6 AAAA IPv6)
        echo "IPv6: refused: $msg6"
    fi
    # Protocol of the queries: both, or only the accepted one.
    if [ -n "$ok4" ] && [ -n "$ok6" ]; then
        CONF_IP_VERSION=""
    elif [ -n "$ok4" ]; then
        CONF_IP_VERSION="4"
        [ -n "$msg6" ] && echo "The SPFBL queries will use only IPv4."
    elif [ -n "$ok6" ]; then
        CONF_IP_VERSION="6"
        [ -n "$msg4" ] && echo "The SPFBL queries will use only IPv6."
    elif [ "$code4" = "000" ] && [ "$REG_CODE" = "000" ]; then
        # No answer by either protocol: not a hostname problem.
        spfbl_unavailable
        return 1
    else
        echo "SPFBL Irondome needs a valid FQDN on this server: the SPFBL sends to it"
        echo "the release signals of held messages. Set the hostname of this server"
        echo "with an A/AAAA record pointing to its IP."
        conf_abort ""
        return 1
    fi
    local group
    group=$(conf_group)
    conf_write "$group"
    if [ -n "$group" ]; then
        echo "Configuration written to $SPFBL_CONF (root:$group, 0640)."
    else
        echo "Configuration written to $SPFBL_CONF (root:root, 0640)."
        echo "Warning: no Exim process found to set the group allowed to read it."
        echo "Run again with SPFBL_GROUP=<group of the MTA user>, or spfbl.sh will query by IP."
    fi
}

function is_installed() {
    if [ "$PANEL" = "cpanel" ]; then
        [ -f /usr/local/cpanel/etc/exim/acls/ACL_RECIPIENT_BLOCK/spfbl_end_recipient ]
    elif [ "$PANEL" = "exim" ]; then
        [ -f "$EXIM_SPFBL_DIR/acl_check_rcpt.conf" ]
    elif [ "$PANEL" = "gateway" ]; then
        gw_installed
    else
        [ -f /etc/exim.acl_check_recipient.pre.conf ]
    fi
}

function install() {
    detect_distro
    [ "$PANEL" = "exim" ] && exim_check
    [ "$PANEL" = "gateway" ] && gw_check
    install_dependencies
    [ "$PANEL" = "gateway" ] && gw_user
    # SPFBL access key and FQDN first: without them, nothing else changes.
    config
    spamcenter_prepare
    install_client
    client_check
    if [ "$PANEL" = "cpanel" ]; then
        cpanel_install_clamav
        install_sigs
        cpanel_configure_exim
    elif [ "$PANEL" = "exim" ]; then
        exim_install_clamav
        install_sigs
        exim_configure
    elif [ "$PANEL" = "gateway" ]; then
        gw_install_clamav
        install_sigs
        gw_build
        gw_configure
        gw_apply
    else
        da_install_clamav
        install_sigs
        da_configure_exim
    fi
    install_holding
    conf_fix_group
    echo "SPFBL Irondome was successfully installed!"
    [ "$PANEL" = "gateway" ] && gw_notes
    echo ""
    echo "Installing SPFBL Firewall solution..."
    firewall
}

function prepare() {
    # Gateway only: everything but the switch. Port 25 stays with Postfix.
    [ "$PANEL" = "gateway" ] || fail "\"prepare\" is only for the SPFBL gateway (CyberPanel, aaPanel, iRedMail and CWP). Use \"install\"."
    detect_distro
    gw_check
    install_dependencies
    gw_user
    # SPFBL access key and FQDN first: without them, nothing else changes.
    config
    spamcenter_prepare
    install_client
    client_check
    gw_install_clamav
    install_sigs
    gw_build
    gw_configure
    conf_fix_group
    gw_ports
    gw_test
    echo ""
    if gw_switched; then
        echo "The gateway is already on port 25."
    else
        echo "SPFBL Irondome gateway prepared. Port 25 is still with Postfix."
        echo "To switch port 25 to the gateway: $0 switch"
    fi
}

function switch() {
    # Gateway only: Exim takes port 25.
    [ "$PANEL" = "gateway" ] || fail "\"switch\" is only for the SPFBL gateway."
    gw_installed || fail "The SPFBL gateway is not prepared yet. Run: $0 prepare"
    detect_distro
    gw_check
    gw_ports
    gw_test
    gw_switch
    install_holding
    echo "SPFBL Irondome gateway is on port 25!"
    gw_notes
    echo ""
    echo "Installing SPFBL Firewall solution..."
    firewall
}

function rollback() {
    [ "$PANEL" = "gateway" ] || fail "\"rollback\" is only for the SPFBL gateway."
    gw_rollback
}

function update() {
    if ! is_installed; then
        echo "The SPFBL Irondome was not installed yet."
        exit 1
    fi
    detect_distro
    [ "$PANEL" = "exim" ] && exim_check
    [ "$PANEL" = "gateway" ] && gw_check
    install_dependencies
    # SPFBL access key: the one of spfbl.conf; without it, asked for on a
    # terminal. Any failure here only keeps the queries by IP.
    if [ -r "$SPFBL_CONF" ] && conf_key_valid "$(conf_value SPFBL_KEY)"; then
        echo "Using the SPFBL access key of $SPFBL_CONF."
    else
        CONF_SOFT=1 config || true
    fi
    spamcenter_prepare
    install_client
    # Signatures: script, master.conf and the SPFBL databases (spfbl.ldb included).
    install_sigs
    if [ "$PANEL" = "cpanel" ]; then
        cpanel_configure_exim
    elif [ "$PANEL" = "exim" ]; then
        exim_configure
    elif [ "$PANEL" = "gateway" ]; then
        gw_build
        gw_configure
        if gw_switched; then
            gw_apply
        else
            # Prepared or rolled back: port 25 stays with Postfix.
            gw_ports
            gw_test
            echo "Port 25 stays with Postfix. To switch it to the gateway: $0 switch"
        fi
    else
        da_configure_exim
    fi
    install_holding
    conf_fix_group
    firewall
}

function uninstall() {
    remove_additional_dbs
    if [ "$PANEL" = "cpanel" ]; then
        cpanel_uninstall
    elif [ "$PANEL" = "exim" ]; then
        exim_uninstall
    elif [ "$PANEL" = "gateway" ]; then
        gw_uninstall
    else
        da_uninstall
    fi
    uninstall_common
}

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must run as root."
    exit 1
fi

if [ -n "$2" ]; then
    case "$1" in
        install|update|prepare)
            # Same format as the Spamcenter panel shows (UUID); uppercase is accepted.
            set -- "$1" "$(echo "$2" | tr 'A-F' 'a-f')"
            if ! spamcenter_valid_key "$2"; then
                echo "This is not a valid Spamcenter API key."
                exit 1
            fi
            SPAMCENTER_KEY="$2"
        ;;
        *)
            echo "*** The Spamcenter API key is only accepted by install, update and prepare."
            exit 1
    esac
fi

case "$1" in
    install)
        echo "[install] Installing SPFBL Irondome powered by SPFBL.net"
        detect_panel
        install
    ;;
    update)
        echo "[update] Updating SPFBL Irondome powered by SPFBL.net"
        require_installed
        update
    ;;
    uninstall)
        echo "[uninstall] Uninstalling SPFBL Irondome powered by SPFBL.net"
        require_installed
        uninstall
    ;;
    firewall)
        echo "[firewall] Installing SPFBL Firewall powered by SPFBL.net"
        detect_panel
        firewall
    ;;
    prepare)
        echo "[prepare] Preparing SPFBL Irondome gateway powered by SPFBL.net"
        detect_panel
        prepare
    ;;
    switch)
        echo "[switch] Switching port 25 to SPFBL Irondome gateway powered by SPFBL.net"
        require_installed
        switch
    ;;
    rollback)
        echo "[rollback] Giving port 25 back to Postfix"
        # Emergency path: only the files of the gateway are needed.
        require_installed
        rollback
    ;;
    config)
        echo "[config] Configuring the SPFBL client powered by SPFBL.net"
        config
    ;;
    detect)
        echo "[detect] Control panel and mail server of this host (nothing is changed)"
        detect_report
    ;;
    spamcenter)
        echo "[spamcenter] Configuring the Spamcenter API key of the SPFBL account"
        spamcenter_sync
    ;;
    *)
        echo "*** Usage: $0 [install|update|uninstall|firewall] [SPAMCENTER_API_KEY]"
        echo "*** Gateway in steps: $0 [prepare [SPAMCENTER_API_KEY]|switch|rollback]"
        echo "*** SPFBL client configuration only: $0 config"
        echo "*** Show the control panel and mail server found (changes nothing): $0 detect"
        echo "*** Spamcenter API key of the SPFBL account only: $0 spamcenter"
        exit 1
esac
