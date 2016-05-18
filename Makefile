all:
	@cd common;		\
	make;			\
	cd ../protocol;		\
	make;			\
	cd ../client;		\
	make;			\
	cd ../server;		\
	make;

clean:
	@cd common;		\
	rm *.o keygen keydist;	\
	cd ../protocol;		\
	rm *.o;			\
	cd ../client;		\
	rm client;		\
	cd ../server;		\
	rm server;
