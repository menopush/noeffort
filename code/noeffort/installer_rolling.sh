#!/bin/sh

echo "[noeffort-installer]: Checking for r00t"
if [ $(id -u) -ne 0 ]; then
    echo -e "[noeffort-installer: This script needs r00t"
else
    start_installer
fi

function start_installer() {
    apt-get update -y
    apt-get install iptables -y
    apt-get install nmap -y
    apt-get install metasploit-framework -y
    apt-get install tor -y
    apt-get install i2p -y
    apt-get install aircrack-ng
    apt-get install dpkg -y
    apt-get install bleachbit -y
    apt-get update -y && apt-get upgrade -y

    echo "[noeffort-installer]: Dependencies Installed. Moving to /usr/bin"
    cd noeffort/
    chmod +x noeffort.sh
    mv noeffort.sh /usr/bin

    echo "[noeffort-installer]: Installer finished. Exiting"
    exit 1
}
