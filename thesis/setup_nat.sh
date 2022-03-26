#!/bin/bash

sudo ip addre add 192.168.10.1/24 dev eth0
sudo ifconfig eth0 up
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE
sudo ip route add 192.168.13.0/24 via 192.168.10.122 dev eth0
