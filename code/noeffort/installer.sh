#!/bin/bash

echo "[noeffort-installer]: Checking for r00t"
if [ $(id -u) -ne 0 ]; then
	echo -e "[noffort-installer]: This script needs r00t"
	exit 1
else
	start_installer
fi

function start_installer() {

    sudo apt-get update -y
	sudo apt-get install itpables -y
    sudo apt-get install net-tools -y
	sudo apt-get install nmap -y
	sudo apt-get install metasploit-framework -y
	sudo apt-get install tor -y
	sudo apt-get install i2p -y
	sudo apt-get install aircrack-ng -y
    sudo apt-get install dpkg -y
    sudo apt-get install bleachbit -y
    sudo apt-get install xterm -y
    sudo apt-get install pciutils -y
	sudo apt-get update -y && apt-get upgrade -y
	
	echo "[noeffort-installer]: Dependencies Installed. Moving to /usr/bin"
	cd noeffort/
	chmod +x noeffort.sh
	mv noeffort.sh /usr/bin
	
	echo "[noeffort-installer]: Installer finished. Exiting"
	exit 1
}
