#Makefile
all: sum-nbo

sum-nbo: main.o
	g++ -o sum-nbo main.o
	gcc make-bin.c -o make-bin
	./make-bin

main.o: main.cpp
	g++ -c -o main.o main.cpp

clean:
	rm -f sum-nbo
	rm -f make-bin
	rm -f *.o
	rm -f *.bin
