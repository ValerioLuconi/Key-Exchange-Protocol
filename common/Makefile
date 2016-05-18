project: keydist keygen encrypt.o utility.o

keydist: utility.o keydist.cpp
	g++ keydist.cpp utility.o -o keydist -lssl

keygen: utility.o keygen.cpp
	g++ keygen.cpp utility.o -o keygen -lssl

utility.o: utility.h

encrypt.o: encrypt.h
