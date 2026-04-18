all: examples/echo

CCFLAGS = -Wall -Wextra -g -march=native -mtune=native -O3 -Iinclude -Isrc -Iinclude/cacharle/ws

examples/echo: examples/echo.c libccws.a
	gcc $(CCFLAGS) -o $@ $< -L. -lccws $(shell pkg-config --libs openssl zlib)

libccws.a: src/frame.o src/handshake.o src/utils.o src/server.o
	ar rcs $@ $^

%.o: %.c
	gcc $(CCFLAGS) $(shell pkg-config --cflags openssl zlib) -o $@ -c $<

clean:
	rm -vf src/*.o server examples/echo libccws.a

re: clean all
