# Key Exchange Protocol

## Requirements

The Key Exchange Protocol has been tested only on Ubuntu Linux.
To compile the Key Exchange Protocol `libssl-dev`, `libgnutls-dev` and `libcrypto++-dev` are required.

	sudo apt-get install libssl-dev libgnutls-dev libcrypto++-dev

## Install

Clone the repository and then compile with `make`:

	git clone https://github.com/ValerioLuconi/Key-Exchange-Protocol.git
	cd Key-Exchange-Protocol
	make

## Test

First execute `./test/auto.sh` to distribute keys. Then `./test/test.sh` to run a simple test. At the moment tests are in italian.
