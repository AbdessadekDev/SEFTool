CC = gcc
CFLAGS = -Wall -g -Iinclude
LIBFLAGS = -luuid -lcrypto -lssl

SRC = $(wildcard src/*.c)
OBJ = $(patsubst src/%.c,bin/%.o,$(SRC))
HEADER = $(wildcard include/*.h)
TARGET = bin/sfetool

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $@ $(LIBFLAGS)

bin/%.o: src/%.c $(HEADER)
	$(CC) $(CFLAGS) -c $< -o $@

test_auth: test/test_auth.c src/auth.c src/utils.c
	gcc -o bin/test_auth test/test_auth.c src/auth.c src/utils.c -Iinclude -Itest $(LIBFLAGS)
	./bin/test_auth

run:
	./$(TARGET)

clean:
	rm -f $(TARGET) $(OBJ) bin/test*

.PHONY: run clean