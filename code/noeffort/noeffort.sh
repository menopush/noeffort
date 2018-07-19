#!/bin/sh

TOR_UID="debian-tor"
TOR_PORT="9040"
TOR_EXCLUDE="192.168.0.0/16 172.16.0.0/12 10.0.0.0/8"

function usage() {

    echo "noeffort by Steven Zaluk beta v1.0"
    echo "--start-tor-proxy : Routes all traffic through a tunnel under the tor proxy"
    echo "--stop-tor-proxy  : Stops Routing all traffic through tor"
    echo "--reload-tor-proxy : Reloads the tor service"
    echo "--tor-proxy-status : Shows the status of the tor service"

    echo "--start-i2p : Starts the I2P Router"
    echo "--stop-i2p  : Stops the I2P Router"

#    echo "--install [PACKAGE] : Installs specified package"
#    echo "--list-packages : Lists available packages for install"

    echo "--start-metsploit : Starts the metasploit-framework console"
    echo "--start-metaterpreter : Starters the meterpreter console"
    echo "--start-routersploit  : Starts the routersploit console"
    echo "--start-airgeddon : Starts the airgeddon script. Needs airgeddon module installed"

    echo "--vuln-scan : Starts a vulnerbility scan for your operating system using lynis. Needs lynis module installed"

    echo "--monitor-traffic : Monitors network packets using wireshark. With or without GUI"

    ## Check
    echo "--start-interface wlan0 : Starts wlan0 interface"
    echo "--start-interface mon0  : Starts mon0 interface"
    echo "--start-interface wlan0mon : Starts wlan0mon interface"

    echo "--stop-interface wlan0  : Stops wlan0 interface"
    echo "--stop-interface mon0   : Stops mon0 interface"
    echo "--stop-interface wlan0mon : Stops wlan0mon interface"

    echo "--capture-handshake : Captures WPA/WPA2 handshake using airodump-ng and aireplay-ng"
    echo "--crack-handshake   : Cracks WPA/WPA2 handshake using aircrack-ng"
    echo "--forge-packet [PACKET] : Forges a packet using packetforger-ng"
    echo "--send-packet [PACKET]  : Sends a specific packet to router"
    echo "--crack-password [FILE] : Cracks password with common encryptions"
}

function init() {

    echo "[noeffort | init]: Killing dangerous apps"
    killall -q chrome dropbox iceweasel skype icedove thunderbird firefox chromium xchat transmission deluge pidgin pidgin.orig

    echo "[noeffort | init]: Clearing dangerous cache files"
    bleachbit -c adobe_reader.cache chromium.cache chromium.current_session chromium.history elinks.history emesene.cache epiphany.cache firefox.url_history flash.cache flash.cookie google_chrome.cache google_chrome.history link2.history opera.cache opera.search_history opera.url_history &> /dev/null
}

function start_tor() {

    echo "[noeffort]: Checking for r00t"
    if [ $(id -u) -ne 0 ]; then
        echo -e "[noeffort]: This script needs r00t"
        exit 1
    fi

    echo "[noeffort]: Checking for resolvconf"
    if [[ ! -z `dpkg -l | grep resolvconf` ]]; then
        resolvconf_support=true;
        echo "[noeffort]: Found resolvconf"
    else
        resolvconf_support=false;
        echo "[noeffort]: Could not find resolvconf. Continuing without it"
    fi

    init

    echo "[noeffort | Tor]: Checking for running tor daemon"
    grep -q -x 'RUN_DAEMON="yes"' /etc/default/tor
    if [ $? -ne 0 ]; then
        echo -e "[noeffort | Tor]: Change yo god damn /etc/default/tor"
        exit 1
    fi

    echo "[noeffort | Tor]: Killing IPv6 Services"
    sed -i '/^.*/#kali-anonsurf$/d' /etc/sysctl.conf
    echo "net.ipv6.conf.all.disable_ipv6 = 1 #kali-anonsurf" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.disable_ipv6=1 #kali-anonsurf" >> /etc/sysctl.conf
    sysctl -p > /dev/null

    echo "[noeffort | Tor]: Checking for tor.pid at directory /var/run/tor/tor/pid"
    if [ ! -e /var/run/tor/tor.pid]; then
        echo -e "[noeffort | Tor]: Tor is not runnning. Starting it"
        service network-manager force-reload > /dev/null 2>&1
        killall dnsmasq > /dev/null 2>&1
        kilall nscd > /dev/null 2>&1
        service tor start
        sleep 1
    fi
    if ! [ -f /etc/network/iptables.rules ]; then
        echo -e "[noeffort | Tor]: Saving IPTables rules"
        iptables-save > /etc/network/iptables.rules
    fi

    iptables -F
    iptables -t nat -F

    if [ "$resolvconf_suppport" = false ]; then
        echo "[noeffort | Tor]: Modifing resolv.conf to use Tor and Private Internet DNS"
        cp /etc/resolv.conf /etc/resolv.conf.bak
        touch /etc/resolv.conf
    else
        echo "[noeffort | Tor]: Modifing resolvconf to use localhost and Private Internet DNS"
        cp /etc/resolvconf/resolv.conf.d/head{,.bak}
        resolvconf -u
    fi

    echo "[noeffort | Tor]: Setting IPTables"
    iptables -t nat -A OUTPUT -m owner --uid-owner $TOR_UID -j RETURN
    iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 53
    iptables -t nat -A OUTPUT -p tcp --dport 52 -j REDIRECT --to-ports 53
    iptables -t nat -A OUTPUT -p udp -m owner --uid-owner $TOR_UID -m udp --dport 53 -j REDIRECT --to-ports 53

    iptables -t nat -A OUTPUT -p tcp -d 10.192.0.0/10 -j REDIRECT --to-ports 9040
    iptables -t nat -A OUTPUT -p udp -d 10.192.0.0/10 -j REDIRECT --to-ports 9040

    for NET in $TOR_EXCLUDE 127.0.0.0/9 127.128.0.0/10; do
        iptables -t nat -A OUTPUT -d $NET -j RETURN
    done

    iptables -t nat -A OUTPUT -p tcp --syn -j REDIRECT --to-ports $TOR_PORT
    iptables -t nat -A OUTPUT -p udp -j REDIRECT --to-ports $TOR_PORT
    iptables -t nat -A OUTPUT -p icmp -j REDIRECT --to-ports $TOR_PORT

    iptables -a OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    for NET IN $TOR_EXCLUDE 127.0.0.0/8; do
        iptables -A OUTPUT -d $NET -j ACCEPT
    done

    iptables -A OUTPUT -m owner --uid-owner $TOR_UID -j ACCEPT
    iptables -A OUTPUT -j REJECT

    echo "[noeffort | Tor]: Tor tunnel and proxy has started"
}

function stop_tor() {

    if [ $(id -u) -ne 0 ]; then
        echo -e "[noeffort | Tor]: Script needs r00t"
        exit 1
    fi

    init

    echo "[noeffort | Tor]: Deleting IPTables rules"
    iptables -F
    iptables -t nat -F

    if [ -f /etc/network/iptables.rules ]; then
        echo "[noeffort | Tor]: Restoring your IPTables rules"
        iptables-restore < /etc/network/iptables.rules
        rm /etc/network/iptables.rules
    fi

    echo "[noeffort | Tor]: Restoring DNS Settings"
    if [ "$resolvconf_support" = false]; then
        if [ -e /etc/resolv.conf.bak ]; then
            rm /etc/resolv.conf
            cp /etc/resolv.conf.bak /etc/resolv.conf
        fi
    else
        mv /etc/resolvconf/resolv.conf.d/head{.bak,}
        resolvconf -u
    fi

    service tor stop

    echo -e "[noeffort | Tor]: Restarting IPv6 services"
    sed -i '/^.*\#kali-anonsurf$/d' /etc/sysctl.conf
    sysctl -p

    service network-manager force-reload > /dev/null 2>&1
    service nscd start > /dev/null 2>&1
    service dnsmasq start > /dev/null 2>&1

    echo -e "[noeffort | Tor]: Tor Proxy and Tunnel Stopped
}

function reload_tor() {
    echo "[noeffort | Tor]: Reloading Tor Service"
    service tor reload
    sleep 2
    echo "[noeffort | Tor]: Tor Service Reloaded"
}

function status_tor() {
    service tor status
}

function start_i2p() {

    if [ $(id -u) -ne 0 ]; then
        echo "[noeffort | I2P]: This script needs r00t"
        exit 1
    fi

    init

    echo "[noeffort | I2P]: Starting I2P Services"
    service tor stop

    echo "[noeffort]: Checking for resolvconf"
    if [ "$resolvconf_support" = false ]; then
        echo "[noeffort | I2P]: Modifing resolv.conf"
        cp /etc/resolv.conf /etc/resolv.conf.bak;
        tocuh /etc/resolv.conf;
        echo -e 'nameserver 127.0.0.1/nnameserver 209.222.18.222/nnameserver 209.222.18.218' > /etc/resolv.conf;
    else
        echo "[noeffort | I2P]: Modifing resoslvconf"
        cp /etc/resolvconf/resolv.conf.d/head{,.bak};
        echo -e 'nameserver 127.0.0.1/nnameserver 209.222.18.222/nnameserver 209.222.18.218' << /etc/resolvconf/resolv.conf.d/head;
        resolvconf -u;
    fi
    sudo -u i2psvc i2prouter start
    sleep 2
    xdg-open 'http://127.0.0.1:7657/home'
}

functiobn stop_i2p() {

    echo -e -n "[noeffort | I2P]: Stopping I2P Services"
    sudo -u i2pvsc i2prouter stop

    echo "[noeffort | I2P]: Restoring DNS Settings"
    if [ "$resolvconf_support" = false ]; then
        if [ -e /etc/resolv.conf.bak ]; then
            rm /etc/resolv.conf
            cp /etc/resolv.conf.bak /etc/resolv.conf
        fi
    else
        mv /etc/resolvconf/resolv.conf.d/head{.bak,}
        resolvconf -u
    fi
}

start_metasploit() {
    echo "[noeffort | msfconsole]: Starting the metasploit-framework console"
    msfconsole
}

start_meterp() {
    echo "[noeffort | msfmeteterpreter]: Starting the metasploit-framework meteterpreter"

}














