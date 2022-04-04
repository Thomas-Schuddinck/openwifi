
#!/bin/bash

numberOfInjections=100
numberOfRepetitions=1
type=i
startPosition=0
i=0
sleepTime=1

while getopts 'n:m:t:p:s:' flag;
do
    case "${flag}" in
        n)
            numberOfInjections=${OPTARG}
            if [[ -z $numberOfInjections ]]; then
                echo "provide an argument for number of injections"
                exit -1
            fi
            if [ $numberOfInjections -lt 1 ]; then
                echo "number of injections must be strictly positive!"
                exit -1
            fi
            ;;
        m)
            numberOfRepetitions=${OPTARG}
            if [[ -z $numberOfRepetitions ]]; then
                echo "provide an argument for number of repetitions"
                exit -1
            fi
            if [[ $numberOfRepetitions -lt 1 ]]; then
                echo "number of repetitions must be strictly positive!"
                exit -1
            fi
            ;;
        t)
            type=${OPTARG}
            if [[ -z $type ]]; then
                echo "provide an argument for type"
                exit -1
            fi
            if [[ $type != "i" ]] && [[ $type != "r" ]]; then
                echo "type must either be i(ncremental) or r(andom)"
                exit -1
            fi
            ;;
        p)
            temp=${OPTARG}
            if [[ -z $temp ]]; then
                echo "provide an argument for start position"
                exit -1
            fi
            if [[ ${temp:1:1} = "x" ]]; then
                temp=${temp:2}
                startPosition=$(( 16#$temp ))
            else
                startPosition=$temp
            fi
            if [[ $startPosition -lt 0 ]]; then
                echo "start position must be positive!"
                exit -1
            fi
            if [[ $startPosition -gt 16777215 ]]; then
                echo "start position must be less than 16777215 (or 0xffffff)"
                exit -1
            fi
            ;;
        s)
            sleepTime=${OPTARG}
            if [[ -z $sleepTime ]]; then
                echo "provide an argument for time between injections (in seconds)"
                exit -1
            fi
            if [[ $sleepTime -lt 0 ]]; then
                echo "sleep time must be positive!"
                exit -1
            fi
            ;;
    esac
done
cd
cd openwifi
./wgd.sh
echo "SETTING UP MONITOR MODE"
./monitor_ch.sh sdr0 11

echo "COMPILING FILES"
cd inject_80211 ; make

echo "-----------------------------------------------------------"
echo "			STARTING INJECTION"
echo "-----------------------------------------------------------"

echo "number of injections = $numberOfInjections"
echo "type = $type"
echo "start position = $startPosition"


if [[ $type = "i" ]] ; then
    while [[ $i -lt $numberOfInjections ]]; do
	if [[  $startPosition -gt 16777215 ]]; then
		echo "signal field reached max value. Exiting..."
		exit 0
	fi
        ./inject_80211 -m n -r 0 -n $numberOfRepetitions -s 64 sdr0 -c $( printf "0x%x" $startPosition)
        sleep $sleepTime
        ((startPosition++))
        ((i++))
    done
else
    while [[ $i -lt $numberOfInjections ]]; do
        startPosition=$(shuf -i 0-16777215 -n 1)
        ./inject_80211 -m n -r 0 -n $numberOfRepetitions -s 64 sdr0 -c $( printf "0x%x" $startPosition)
        sleep $sleepTime
        ((i++))
    done
fi
