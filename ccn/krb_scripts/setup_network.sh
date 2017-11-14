#!/usr/bin/bash

#NUMBER_PRODUCERS=$1

echo "\n\nUsage: sh setup_network.sh <NUMBER_PRODUCERS> <MODE>\n\n"


    ## Router
	nice -n -20 ~/Desktop/projects/CCNx_Distillery/build/Athena/ccnx/forwarder/athena/command-line/athena/athena &
    sleep 2s

    ## TGT Producer
	nice -n -20 ../b/ccnxKRB_Server -a TGT &
    sleep 2s

    ## CGT Producer
	nice -n -20 ../b/ccnxKRB_Server -t TGS &
    sleep 2s

    ## KRB-CCN Content Producer
    nice -n -20 ../b/ccnxKRB_Server -k ccnx:/localhost/uci/edu/fileA & 
    sleep 2s

    ## Regular Content Producer
    nice -n -20 ../b/ccnxKRB_Server -p ccnx:/localhost/content &

sleep 3s
#sh start_producers.sh ../b/ccnxVPN_Server ccnx:/producer $NUMBER_PRODUCERS

