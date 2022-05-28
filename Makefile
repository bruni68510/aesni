all: compile/aesni compile/libcustomsignal.dylib

compile/gadget.o : gadget.c
	gcc -g -c gadget.c -o compile/gadget.o -I.

compile/main.o : main.c
	gcc -g -c main.c -o compile/main.o

compile/hexdump.o : hexdump.c
	gcc -g -c hexdump.c -o compile/hexdump.o

compile/libcustomsignal.dylib: compile/main.o compile/gadget.o compile/hexdump.o
	gcc -dynamiclib compile/main.o compile/gadget.o compile/hexdump.o -lcapstone -lkeystone -lLIEF -g -o compile/libcustomsignal.dylib

compile/aes-ni.o: aes-ni.c
	gcc -maes -g -c aes-ni.c -o compile/aes-ni.o

compile/aesni: compile/aes-ni.o
	gcc -maes -g compile/aes-ni.o -o compile/aesni
	objdump -d compile/aesni

clean:
	rm compile/*.o