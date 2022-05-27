all: libcustomsignal.dylib a.out

gadget.o : gadget.c
	gcc -g -c gadget.c

signal.o : signal.c
	gcc -g -c signal.c

hexdump.o : hexdump.c
	gcc -g -c hexdump.c

libcustomsignal.dylib: signal.o gadget.o hexdump.o
	gcc -dynamiclib signal.o gadget.o hexdump.o -lcapstone -lkeystone -g -o libcustomsignal.dylib

aes-ni.o: aes-ni.c
	gcc -maes -g -c aes-ni.c

a.out: aes-ni.o
	gcc -maes -g aes-ni.o