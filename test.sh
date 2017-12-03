#!/bin/sh

./load.sh
./Setup/firewallSetup W Setup/rules.txt
wget -O /dev/null http://www.cs.bham.ac.uk/ > /dev/null 2>&1 || { echo "Wget test failed"; exit 1 ;} 
echo "Wget test passed"
curl -o /dev/null http://www.cs.bham.ac.uk/ > /dev/null 2>&1 && { echo "Curl test failed"; exit 1 ;}
echo "Curl test passed"
curl -o /dev/null https://www.cs.bham.ac.uk/ > /dev/null 2>&1 || { echo "Curl ssl test failed"; exit 1 ;}
echo "Curl ssl test passed"
./cleanScript.sh
exit 0
