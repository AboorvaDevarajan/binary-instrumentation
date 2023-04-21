CC=gcc
CFLAGS=-g -Wall
OBJS=obj/bistro_patch.o
BIN=bin/bistro_patch

all:$(BIN)

bin/bistro_patch: 
	$(CC) -g src/shared.c -c -fPIC -o obj/shared.o
	$(CC) -fPIC -g obj/shared.o -shared -o libshared.so
	gcc -Wall -g -ldl -L`pwd` -lshared src/bistro_patch.c -o bin/bistro_patch

clean:
	$(RM) -r bin/* obj/*
