#!/bin/bash

while true; do
    sudo dmesg -T -l debug | tail -n 30
    sleep 2
done

