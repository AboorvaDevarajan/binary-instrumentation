CC=clang
CFLAGS=-g -Wall
OBJS=obj/bistro_patch.o
BIN=bin/bistro_patch

all:$(BIN)

bin/bistro_patch: $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o bin/bistro_patch

obj/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@
clean:
	$(RM) -r bin/* obj/*