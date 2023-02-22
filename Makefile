HEADERS = 

default: test

test.o: test.c $(HEADERS)
	gcc -g *.c -c -fPIC
	gcc -g foo.o -shared -o libfoo.so

test: test.o
	gcc -g -ldl -L`pwd` test.c -lfoo -o test

clean:
	-rm -f test.o
	-rm -f test
