#!/bin/bash

echo -n "Numero di chiavi da generare: "
read nk

cd ../common/
./keygen $nk
