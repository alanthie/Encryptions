#!/bin/bash
echo "Hello World"

echo "--------------------------"
echo "-----------AL-------------"
echo "--------------------------"
cd /home/server/dev/Encryptions/testcase/test/AL
pwd
echo "--------------------------"
echo "-------AL ENCODE----------"
echo "--------------------------"
../../../bin/Release/crypto encode -cfg cfg.ini -v 1 -a 1 
../../../bin/Release/crypto showkeys -cfg cfg.ini 

echo "--------------------------"
echo "-------SENDING FILE-------"
echo "--------------------------"
cp -rf  /home/server/dev/Encryptions/testcase/test/AL/msg.zip.encrypted /home/server/dev/Encryptions/testcase/test/SAM/

echo "--------------------------"
echo "-----------SAM------------"
echo "--------------------------"
cd /home/server/dev/Encryptions/testcase/test/SAM
pwd
echo "--------------------------"
echo "------SAM DECODE----------"
echo "--------------------------"
../../../bin/Release/crypto decode -cfg cfg.ini -v 1 -a 1 
../../../bin/Release/crypto showkeys -cfg cfg.ini 
echo "--------------------------"
echo "------SAM ENCODE----------"
echo "--------------------------"
../../../bin/Release/crypto encode -cfg cfg.ini -v 1 -a 1 
../../../bin/Release/crypto showkeys -cfg cfg.ini 

echo "--------------------------"
echo "-------SENDING FILE-------"
echo "--------------------------"
cp -rf  /home/server/dev/Encryptions/testcase/test/SAM/msg.zip.encrypted /home/server/dev/Encryptions/testcase/test/AL/

echo "--------------------------"
echo "-----------AL-------------"
echo "--------------------------"
cd /home/server/dev/Encryptions/testcase/test/AL
pwd
echo "--------------------------"
echo "-------AL DECODE----------"
echo "--------------------------"
../../../bin/Release/crypto decode -cfg cfg.ini -v 1 -a 1 
../../../bin/Release/crypto showkeys -cfg cfg.ini

