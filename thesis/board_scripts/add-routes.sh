#!/bin/bash

sudo ip route add default via 192.168.10.1 dev eth0
sudo ip route add 192.168.13.0/24 via 0.0.0.0 dev sdr0
