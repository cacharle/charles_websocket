all: examples/echo

CCFLAGS = -Wall -Wextra -g -march=native -mtune=native -O3 -Iinclude -Isrc

examples/echo: examples/echo.c libccws.a
	gcc $(CCFLAGS) -L. -lccws $<

libccws.a: src/frame.o src/handshake.o src/utils.o src/server.o
	ar rcs $@ $^

%.o: %.c
	gcc $(CCFLAGS) $(shell pkg-config --cflags openssl zlib) -o $@ -c $<

clean:
	rm -vf src/*.o server

re: clean all
