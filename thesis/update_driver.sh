#!/bin/bash
cd /home/mordred/Desktop/openwifi/driver; scp `find ./ -name \*.ko` root@192.168.10.122:openwifi/
