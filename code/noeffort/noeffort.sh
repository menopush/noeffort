#!/bin/sh

TOR_UID="debian-tor"
TOR_PORT="9040"
TOR_EXCLUDE="192.168.0.0/16 172.16.0.0/12 10.0.0.0/8"

function usage() {

    echo "────────────────────────────────────────────────────────────────────────────────"
    echo "─────────────▄▄██████████▄▄─────────────────────────────────────────────────────"
    echo "─────────────▀▀▀───██───▀▀▀─────────────────────────────────────────────────────"
    echo "─────▄██▄───▄▄████████████▄▄───▄██▄─────────────────────────────────────────────"
    echo "───▄███▀──▄████▀▀▀────▀▀▀████▄──▀███▄───────────────────────────────────────────"
    echo "──████▄─▄███▀──────────────▀███▄─▄████──────────────────────────────────────────"
    echo "─███▀█████▀▄████▄──────▄████▄▀█████▀███─────────────────────────────────────────"
    echo "─██▀──███▀─██████──────██████─▀███──▀██──────────NoEffort v1.0──────────────────"
    echo "──▀──▄██▀──▀████▀──▄▄──▀████▀──▀██▄──▀─────────────By menopush──────────────────"
    echo "─────███───────────▀▀───────────███─────────────────────────────────────────────"
    echo "─────██████████████████████████████─────────────────Wireless Hacking────────────"
    echo "─▄█──▀██──███───██────██───███──██▀──█▄───────────────and Exploit Tool──────────"
    echo "─███──███─███───██────██───███▄███──███─────────────────────────────────────────"
    echo "─▀██▄████████───██────██───████████▄██▀─────────────────────────────────────────"
    echo "──▀███▀─▀████───██────██───████▀─▀███▀──────────────────────────────────────────"
    echo "───▀███▄──▀███████────███████▀──▄███▀────────────With Package Manager───────────"
    echo "─────▀███────▀▀██████████▀▀▀───███▀─────────────────────────────────────────────"
    echo "───────▀─────▄▄▄───██───▄▄▄──────▀──────────────────────────────────────────────"
    echo "──────────── ▀▀███████████▀▀ ───────────────────────────────────────────────────"
    echo "────────────────────────────────────────────────────────────────────────────────"
    echo "noeffort [command] [arg] - THIS SCRIPT NEEDS R00T TO WORK                             "
    echo "::::::::::: ANONYMITY ::::::::::"
    echo "--start-tor-proxy : Routes all traffic through a tunnel under the tor proxy" # DONE
    echo "--stop-tor-proxy  : Stops Routing all traffic through tor" # DONE
    echo "--reload-tor-proxy : Reloads the tor service" # DONE
    echo "--tor-proxy-status : Shows the status of the tor service" # DONE
    echo "--start-i2p : Starts the I2P Router" # DONE
    echo "--stop-i2p  : Stops the I2P Router" # DONE
    echo "--change-mac : Changes your mac address to a random one" # DONE
    echo "::::::::::: PACKAGE MANAGEMENT ::::::::::"
    echo "--install [PACKAGE] : Installs specified package"
    echo "--list-packages : Lists available packages for install"
    echo "::::::::::::: EXPLOIT TOOLS :::::::::::::"
    echo "--start-metsploit : Starts the metasploit-framework console" # DONE
    echo "--start-routersploit  : Starts the routersploit console" # DONE
    echo "--start-beef : Starts the BrowsEr Exploitation Framework" # DONE
    echo "::::::::::::: WIRELESS TOOLS ::::::::::::"
    echo "--nmap-scan : Scans a specified IP Address for open ports" # DONE
    echo "--monitor-traffic : Monitors network packets using wireshark. With or without GUI" # DONE
    echo "--scan-open-ports  : Scans for open ports on your network"
    echo "--start-wlan0 : Starts wlan0 interface" # DONE
    echo "--start-mon0  : Starts mon0 interface" # DONE
    echo "--start-wlan0mon : Starts wlan0mon interface" # DONE
    echo "--start-eth0  : Starts eth0 interface" # DONE
    echo "--start-en0 : Starts en0 interface" # DONE
    echo "--stop-wlan0  : Stops wlan0 interface"
    echo "--stop-mon0   : Stops mon0 interface"
    echo "--stop-wlan0mon : Stops wlan0mon interface"
    echo "--stop-eth0  : Starts eth0 interface"
    echo "--stop-en0 : Starts en0 interface"
    echo "--capture-handshake : Captures WPA/WPA2 handshake using airodump-ng and aireplay-ng"
    echo "--crack-handshake [.CAP-FILE]  : Cracks WPA/WPA2 handshake using aircrack-ng"
    echo "--bruteforce-wps [ESSID] [INTERFACE] : Brute forces a wps pin"
    echo "--forge-packet [PACKET] : Forges a packet using packetforge-ng"
    echo "--send-packet [PACKET]  : Sends a specific packet to router"
    echo "--crack-password [FILE] : Cracks password with common encryptions"
    echo "::::::::::::: SYSTEM TOOLS ::::::::::::"
    echo "--login    : ###########################"
    echo "--shutdown : Shutsdown your computer" # DONE
    echo "--restart  : Restarts your computer" # DONE
    echo "--vuln-scan : Audits your system for vulnerbilities" # DONE
    echo "--linux-exploit-suggester : Suggest exploits to use on linux"
}

function init() {

    echo "[noeffort | init]: Killing dangerous apps"
    killall -q chrome dropbox iceweasel skype icedove thunderbird firefox chromium xchat transmission deluge pidgin pidgin.orig

    echo "[noeffort | init]: Clearing dangerous cache files"
    bleachbit -c adobe_reader.cache chromium.cache chromium.current_session chromium.history elinks.history emesene.cache epiphany.cache firefox.url_history flash.cache flash.cookie google_chrome.cache google_chrome.history link2.history opera.cache opera.search_history opera.url_history &> /dev/null
}

function login() {
    
}

function start_tor() {

    echo "[noeffort | privcheck]: Checking for r00t"
    if [ $(id -u) -ne 0 ]; then
        echo -e "[noeffort | error]: This script needs r00t"
        exit 1
    fi

    echo "[noeffort | Tor]: Checking for resolvconf"
    if [[ ! -z `dpkg -l | grep resolvconf` ]]; then
        resolvconf_support=true;
        echo "[noeffort | Tor]: Found resolvconf"
    else
        resolvconf_support=false;
        echo "[noeffort | Tor]: Could not find resolvconf. Continuing without it"
    fi

    init

    echo "[noeffort | Tor]: Checking for running tor daemon"
    grep -q -x 'RUN_DAEMON="yes"' /etc/default/tor
    if [ $? -ne 0 ]; then
        echo -e "[noeffort | error]: Change yo god damn /etc/default/tor"
        exit 1
    fi

    echo "[noeffort | Tor]: Killing IPv6 Services"
    sed -i '/^.*/#kali-anonsurf$/d' /etc/sysctl.conf
    echo "net.ipv6.conf.all.disable_ipv6 = 1 #kali-anonsurf" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.disable_ipv6=1 #kali-anonsurf" >> /etc/sysctl.conf
    sysctl -p > /dev/null

    echo "[noeffort | Tor]: Checking for tor.pid at directory /var/run/tor/tor/pid"
    if [ ! -e /var/run/tor/tor.pid]; then
        echo -e "[noeffort | Warning | Tor]: Tor is not runnning. Starting it"
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
    sudo iptables -t nat -A OUTPUT -m owner --uid-owner $TOR_UID -j RETURN
    sudo iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 53
    sudo iptables -t nat -A OUTPUT -p tcp --dport 52 -j REDIRECT --to-ports 53
    sudo iptables -t nat -A OUTPUT -p udp -m owner --uid-owner $TOR_UID -m udp --dport 53 -j REDIRECT --to-ports 53

    sudo iptables -t nat -A OUTPUT -p tcp -d 10.192.0.0/10 -j REDIRECT --to-ports 9040
    sudo iptables -t nat -A OUTPUT -p udp -d 10.192.0.0/10 -j REDIRECT --to-ports 9040

    for NET in $TOR_EXCLUDE 127.0.0.0/9 127.128.0.0/10; do
        sudo iptables -t nat -A OUTPUT -d $NET -j RETURN
    done

    sudo iptables -t nat -A OUTPUT -p tcp --syn -j REDIRECT --to-ports $TOR_PORT
    sudo iptables -t nat -A OUTPUT -p udp -j REDIRECT --to-ports $TOR_PORT
    sudo iptables -t nat -A OUTPUT -p icmp -j REDIRECT --to-ports $TOR_PORT

    sudo iptables -a OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    for NET IN $TOR_EXCLUDE 127.0.0.0/8; do
        sudo iptables -A OUTPUT -d $NET -j ACCEPT
    done

    sudo iptables -A OUTPUT -m owner --uid-owner $TOR_UID -j ACCEPT
    sudo iptables -A OUTPUT -j REJECT

    echo "[noeffort | Tor]: Tor tunnel and proxy has started"
}

function stop_tor() {

    echo "[noeffort | privcheck]: Checking for r00t"
    if [ $(id -u) -ne 0 ]; then
        echo -e "[noeffort | error]: Script needs r00t"
        exit 1
    fi

    init

    echo "[noeffort | Tor]: Deleting IPTables rules"
    sudo iptables -F
    sudo iptables -t nat -F

    if [ -f /etc/network/iptables.rules ]; then
        echo "[noeffort | Tor]: Restoring your IPTables rules"
        sudo iptables-restore < /etc/network/iptables.rules
        sudo rm /etc/network/iptables.rules
    fi

    echo "[noeffort | Tor]: Restoring DNS Settings"
    if [ "$resolvconf_support" = false]; then
        if [ -e /etc/resolv.conf.bak ]; then
            sudo rm /etc/resolv.conf
            sudo cp /etc/resolv.conf.bak /etc/resolv.conf
        fi
    else
        mv /etc/resolvconf/resolv.conf.d/head{.bak,}
        sudo resolvconf -u
    fi

    sudo service tor stop

    echo -e "[noeffort | Tor]: Restarting IPv6 services"
    sudo sed -i '/^.*\#kali-anonsurf$/d' /etc/sysctl.conf
    sudo sysctl -p

    sudo service network-manager force-reload > /dev/null 2>&1
    sudo service nscd start > /dev/null 2>&1
    sudo service dnsmasq start > /dev/null 2>&1

    echo -e "[noeffort | Tor]: Tor Proxy and Tunnel Stopped
}

function reload_tor() {
    echo "[noeffort | Tor]: Reloading Tor Service"
    sudo service tor reload
    sleep 2
    echo "[noeffort | Tor]: Tor Service Reloaded"
}

function status_tor() {
    sudo service tor status
}

function start_i2p() {

    echo "[noeffort | privcheck]: Checking for r00t"
    if [ $(id -u) -ne 0 ]; then
        echo "[noeffort | error]: This script needs r00t"
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

function stop_i2p() {

    echo "[noeffort | privcheck]: Checking for r00t"
    if [ $(id -u) -ne 0 ]; then
        echo "[noeffort | error]: This script needs r00t"
        exit 1
    fi

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

function change_mac() {

    echo "[noeffort | privcheck]: Checking for r00t"
    if [ $(id -u) -ne 0 ]; then
        echo "[noeffort | error]: This script needs r00t"
        exit 1
    fi

    echo "[noeffort | init]: Checking for net tools"
    which -a ifconfig
    if [[ $? != 0 ]]; then
        echo "[noeffort | error]: net-tools module not installed"
        echo "[noeffort | error]: Please install it either with apt-get or noeffort's package manager"
    fi

    echo "[noeffort | macchanger]: Shutting down eth0 interface"
    sudo ifconfig eth0 down

    echo "[noeffort | macchanger]: Randomly changing mac address and assigning it."
    sudo macchanger -r eth0
    sudo ifconfig eth0 up

    echo "[noeffort]: Mac Address Spoofed randomly"
}

function start_metasploit() {
    echo "[noeffort | msfconsole]: Starting the metasploit-framework console"
    msfconsole
}

function start_routersploit() {

    echo -e "[noeffort | privcheck]: Checking for r00t"
    if [ $(id -u) -ne 0 ]; then
        echo "[noeffort | error]: This script needs r00t"
        exit 1
    fi

    echo -e '[noeffort | init]: Checking for routersploit module"
    which -a rsf.py
    if [[ $? != 0 ]]; then
        echo "[noeffort | error]: RouterSploit module not installed"
        echo "[noeffort | error]: Please install routersploit either with apt-get or noeffort's package manager (--install routersploit)"
        exit 1
    fi

    echo -e "[noeffort | rsf]: Start routersploit console"
    rsf.py
}

start_beef() {
    echo "[noeffort | privcheck]: Checking for r00t"
    if [ $(id -u) -ne 0 ]; then
        echo "[noeffort | error]: This script needs root"
        exit 1
    fi

    echo "[noeffort | init]: Checking for beef module"
    which -a beef-xss
    if [[ $? != 0]]; then
        echo "[noeffort | error]: Beef module not installed"
        echo "[noeffort | error]: Please install beef either with apt-get or noeffort's package manager (--install beef)"
    fi

    echo "[noeffort | beef]: Starting the BrowsEr Exploitation Framework (Beef)"
    sudo beef-xss
}

function vuln_scan() {
    echo -e "[noeffort | privcheck]: Checking for r00t"
    if [ $(id -u) -ne 0 ]; then
        echo "[noeffort | error]: This script needs r00t"
        exit 1
    fi

    echo -e "[noeffort | init]: Checking for lynis module"
    which -a lynis
    if [[ $? != 0 ]]; then
        echo "[noeffort | error]: Lynis modules not installed"
        echo "[noeffort | error]: Please install Lynis either with apt-get or noeffort's package manager (--install lynis)"
        exit 1
    fi

    echo "[noeffort | Lynis]: Starting Vulnerbility scan"
    sudo lynis audit system
}

function shutdown_computer() {
    echo "[noeffort | privcheck]: Checking for r00t"
    if [ $(id -u) -ne 0 ]; then
        echo "[noeffort | error]: This script needs r00t"
        exit 1
    fi

    read -r -p "[noeffort | shutdown]: Are you sure you want to shut down your computer? " shutdownyn
    case "$shutdownyn" in
        [yY][eE][sS]|[yY])
            echo "[noeffort | shutdown]: Shutting down"
            sudo shutdown
            ;;
        *)
            echo "[noeffort | shutdown]: Ok. Exiting"
            exit 1
            ;;
    esac
}

function restart_computer() {
    echo "[noeffort | privcheck]: Checking for r00t"
    if [ $(id -u) -ne 0 ]; then
        echo "[noeffort | error]: This script needs r00t"
        exit 1
    fi

    read -r -p "[noeffort | restart]: Are your sure you want to restart your computer? " restartyn
    case "$restartyn" in
        [yY][eE][sS]|[yY])
            echo "[noeffort | restart]: Restarting"
            sudo restart
            ;;
        *)
            echo "[noeffort | restart]: Ok. Exiting"
            exit 1
            ;;
    esac
}

function nmap_scan() {

    echo "[noeffort | privcheck]: Checking for root"
    if [ $(id -u) -ne 0 ]; then
        echo "[noeffort | error]: This script needs r00t"
        exit 1
    fi

    read "Please enter the IP Address you wish to scan" $NMAP_ADDRESS

    echo "[noeffort | nmap]: Starting scan for $NMAP_ADDRESS"
    sudo nmap -p- -sS -Pn -n -vvv -oA nmap-host-ports $NMAP_ADDRESS
    echo "[noeffort | nmap]: Scan complete for IP: $NMAP_ADDRESS"
}

function monitor_traffic() {
    echo -e "[noeffort | privcheck]: Checking for root"
    if [ $(id -u) -ne 0 ]; then
        echo "[noeffort | error]: This script needs r00t"
        exit 1
    fi

    echo -e "[noeffort | privcheck]: Checking for wireshark module"
    which -a tshark
    if [[ $? != 0 ]]; then
        echo "[noeffort | error]: tshark and wireshark modules not installed"
        echo "[noeffort | error]: Please install tshark using either apt-get or noeffort's package manager (--install wireshark)"
        exit 1
    fi

    echo "[noeffort | tshark]: Starting tshark"
    sudo tshark
}

function start_wlanO() {
    echo "[noeffort | privcheck]: Checking for r00t"
    if [ $(id -u) -ne 0 ]; then
        echo "[noeffort | error]: This script needs r00t"
        exit 1
    fi

    echo "[noeffort | airmon-ng]: Starting wlan0 interface"
    sudo airmon-ng start wlan0
}

function start_monO() {
    echo "[noeffort | privcheck]: Checking for r00t"
    if [ $(id -u) -ne 0 ]; then
        echo "[noeffort | error]: This script needs r00t"
        exit 1
    fi

    echo "[noeffort | airmon-ng]: Starting mon0 interface"
    sudo airmon-ng start mon0
}

function start_wlanOmon() {

    echo "[noeffort | privcheck]: Checking for r00t"
    if [ $(id -u) -ne 0 ]; then
        echo "[noeffort | error]: This script needs r00t"
        exit 1
    fi

    echo "[noeffort | airmon-ng]: Starting wlan0mon"
    sudo airmon-ng start wlan0mon
}

function start_ethO() {

    echo "[noeffort | privcheck]: Checking for r00t"
    if [ $(id -u) -ne 0 ]; then
        echo "[noeffort | error]: This script needs r00t"
        exit 1
    fi

    echo "[noeffort | airmon-ng]: Starting eth0"
    sudo airmon-ng start eth0
}

function start_enO() {

    echo "[noeffort | privcheck]: Checking for r00t"
    if [ $(id -u) -ne 0 ]; then
        echo "[noeffort | error]: This script needs r00t"
        exit 1
    fi

    echo "[noeffort | airmon-ng]: Starting en0"
    sudo airmon-ng start en0
}







