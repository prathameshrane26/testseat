CC = gcc
CFLAGS = -Wall -Wextra -Iinclude -I/usr/include/postgresql -O3

ifeq ($(OS),Windows_NT)
    LIBS = -lws2_32 -lpq
    TARGET = server.exe
else
    LIBS = -lpthread -ldl -lpq
    TARGET = server.exe
endif

all: clean $(TARGET)

$(TARGET): src/main.o src/optimizer.o src/parser.o src/arena.o src/mongoose.o src/sqlite3.o
	$(CC) $^ -o $@ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f src/*.o $(TARGET)