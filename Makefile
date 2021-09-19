all: cipher

cipher: main.o
	gcc main.o -o cipher

main.o: main.c
	gcc -c main.c

clean:
	rm -rf *.o mask
