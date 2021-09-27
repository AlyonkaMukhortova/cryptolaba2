all: cipher

cipher: main.o debug.o
	gcc main.o debug.o -o cipher

main.o: main.c
	gcc -c main.c

debug.o: debug.c
	gcc -c debug.c

clean:
	rm -rf *.o cipher
