CC=gcc
CFLAGS=-g -Wall
OBJS=obj/bistro_patch.o
BIN=bin/bistro_patch

all:$(BIN)

bin/bistro_patch: 
	$(CC) -g src/shared.c -c -fPIC -o obj/shared.o
	$(CC) -fPIC -g obj/shared.o -shared -o lib/libshared.so
	gcc -Wall -g -ldl -L`pwd`/lib -lshared src/bistro_patch.c -o bin/bistro_patch

clean:
	$(RM) -r bin/* obj/* lib/*
