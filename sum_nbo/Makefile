#Makefile
all: sum-nbo

sum-nbo: main.o
	g++ -o sum-nbo main.o

main.o: main.cpp
	g++ -c -o main.o main.cpp

clean:
	rm -f sum-nbo
	rm -f *.o

