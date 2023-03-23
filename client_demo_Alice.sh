IP_address=$(hostname -I)
set -- $IP_address
IP=$1
echo Using IP address: $IP

python3 client.py $IP 6677 Alice password