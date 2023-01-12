HEADERS = 

default: test

test.o: test.c $(HEADERS)
	gcc -c test.c -o test.o

test: test.o
	gcc test.o -o test

clean:
	-rm -f test.o
	-rm -f test
