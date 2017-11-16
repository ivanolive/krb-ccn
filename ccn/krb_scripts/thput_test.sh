#!/usr/bin/bash

rm tgt_thput.csv
rm cgt_thput.csv
rm krb_thput.csv
rm reg_thput.csv

for j in `seq 1 10`;
do
    N=$((200 * $j))
    echo $N > pings.csv
    echo $N
    for i in `seq 0 4`;
    do
        nice -10 ../b/ccnxKRB_Client k ivan ccnx:/localhost ccnx:/localhost/uci/edu/fileA >> tgt_thput.csv
        sleep 1s

    done

    echo "" >> tgt_thput.csv
done
