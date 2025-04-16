CC = gcc
CFLAGS = -Wall -Wextra -fPIC
SOURCES = src/demo_lib.c
OBJECTS = $(SOURCES:.c=.o)
INCLUDE = -Iinclude
TARGET = libdemo_lib.so

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) -shared -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)
