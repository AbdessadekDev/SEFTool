CC = gcc

CFLAGS = -Wall -g -Iinclude

SRC = src/main.c src/seftool.c src/utils.c

OBj = bin/main.o bin/seftool.o bin/utils.o

HEADER = include/seftool.h include/utils.h

TARGET = bin/seftool

$(TARGET): $(OBj)
	$(CC) $< -o $@

bin/utils.o: src/utils.c $(HEADER)
	$(CC) $(CFLAGS) -c src/utils.c -o bin/utils.o

bin/seftool.o: src/seftool.c $(HEADER)
	$(CC) $(CFLAGS) -c src/seftool.c -o bin/seftool.o

bin/main.o: src/main.c 
	$(CC) $(CFLAGS) -c src/main.c -o bin/main.o

run:
	./$(TARGET)

clean:
	rm $(TARGET) $(OBj)

.PHONY: run clean