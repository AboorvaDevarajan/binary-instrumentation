HEADERS = 

default: test

test.o: test.c $(HEADERS)
	gcc -ldl -lrt -c test.c -o test.o

test: test.o
	gcc -ldl -lrt test.o -o test

clean:
	-rm -f test.o
	-rm -f test
