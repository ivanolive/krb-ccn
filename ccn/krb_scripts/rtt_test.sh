#!/usr/bin/bash

rm tgt_rtt.csv
rm cgt_rtt.csv
rm krb_rtt.csv
rm reg_rtt.csv

for j in `seq 1 10`;
do
    N=$((300 * $j))
    echo $N > pings.csv
    echo $N
    for i in `seq 0 3`;
    do
        ## TGT Req
        nice -10 ../b/ccnxKRB_Client a ivan ccnx:/localhost >> tgt_rtt.csv
        sleep 1s

        ## CGT Req
        nice -10 ../b/ccnxKRB_Client t ivan ccnx:/localhost ccnx:/localhost/uci/edu/fileA >> cgt_rtt.csv
        sleep 1s

        ## KRB-CCN Content Req
        nice -10 ../b/ccnxKRB_Client k ivan ccnx:/localhost ccnx:/localhost/uci/edu/fileA >> krb_rtt.csv
        sleep 1s

        ## Regular Content Req
        nice -10 ../b/ccnxKRB_Client p content >> reg_rtt.csv
        sleep 1s

    done

    echo "" >> tgt_rtt.csv
    echo "" >> cgt_rtt.csv
    echo "" >> krb_rtt.csv
    echo "" >> reg_rtt.csv
done
