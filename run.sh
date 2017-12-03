#!/bin/bash

if [ "$(id -u)" != 0 ] ; then
    echo "ERROR: root access needed!"
    echo "run as root: sudo $0"
    exit 1
fi

./cleanScript.sh
./compile.sh
./load.sh
./Setup/firewallSetup W Setup/rules.txt
