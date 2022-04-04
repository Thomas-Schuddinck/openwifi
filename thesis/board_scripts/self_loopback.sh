#!/bin/bash
cd openwifi
./wgd.sh
./monitor_ch.sh sdr0 44
insmod side_ch.ko iq_len_init=8187
./side_ch_ctl wh11d0
./side_ch_ctl wh8d16
./sdrctl dev sdr0 set reg xpu 1 1
./side_ch_ctl wh5h0
./side_ch_ctl g0
