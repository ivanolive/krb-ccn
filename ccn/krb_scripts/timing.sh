rm *_time.csv

c=1
while [ $c -le 100 ]
do
    sh run_client.sh
done
