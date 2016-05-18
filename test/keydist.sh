#!/bin/bash
echo -n "Client ID a cui distribuire la chiave: "
read cid
cd ../common
./keydist $cid
