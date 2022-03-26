#!/bin/bash

cd
cd openwifi
./wgd.sh
echo "SETTING UP MONITOR MODE"
./monitor_ch.sh sdr0 11

echo "COMPILING FILES"
cd inject_80211 ; make

echo "-----------------------------------------------------------"
echo "INJECTION WITH NORMAL HEX VALUE (6 CHARS)"
echo "-----------------------------------------------------------"
./inject_80211 -m n -r 0 -n 1 -s 64 sdr0 -c 0x214365

echo "-----------------------------------------------------------"
echo "INJECTION WITH A HEX VALUE CONSISTING OF LESS THAN 6 CHARS (5 chars)"
echo "-----------------------------------------------------------"
./inject_80211 -m n -r 0 -n 1 -s 64 sdr0 -c 0x14365

echo "-----------------------------------------------------------"
echo "INJECTION WITH A HEX VALUE CONSISTING OF LESS THAN 6 CHARS (4 chars)"
echo "-----------------------------------------------------------"
./inject_80211 -m n -r 0 -n 1 -s 64 sdr0 -c 0x4365


echo "-----------------------------------------------------------"
echo "INJECTION WITH A TOO LARGE HEX VALUE"
echo "-----------------------------------------------------------"
./inject_80211 -m n -r 0 -n 1 -s 64 sdr0 -c 0x89214365

