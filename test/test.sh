#!/bin/bash
IP_SERVER=127.0.0.1
PORT_SERVER=9999

echo -n "Messaggio da spedire al server: "
read m
cd ../server 
./server $PORT_SERVER &
sleep 0.1
cd ../client
./client $IP_SERVER $PORT_SERVER $m
killall server
