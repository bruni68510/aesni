all: libcustomsignal.dylib a.out

gadget.o : gadget.c
	gcc -c gadget.c

signal.o : signal.c
	gcc -c signal.c

libcustomsignal.dylib: signal.o gadget.o
	gcc -dynamiclib signal.o gadget.o -lcapstone -o libcustomsignal.dylib

a.out: aes-ni.c
	gcc -maes aes-ni.c