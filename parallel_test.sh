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

function test(){
    wget -O /dev/null http://www.cs.bham.ac.uk/ > /dev/null 2>&1 || { echo "Wget test failed"; exit 1 ;}
    echo "Wget test passed"
}

function test_1(){
    curl -o /dev/null http://www.cs.bham.ac.uk/ > /dev/null 2>&1 && { echo "Curl test failed"; exit 1 ;}
    echo "Curl test passed"
}

function test_2(){
    curl -o /dev/null https://www.cs.bham.ac.uk/ > /dev/null 2>&1 || { echo "Curl ssl test failed"; exit 1 ;}
    echo "Curl ssl test passed"
}


for i in {1..100} ; do
    test &
    test_1 &
    test_2 &
done

sleep 60
echo "All tests passed"
exit 0


