all: server

server: src/main.o src/frame.o src/handshake.o src/utils.o src/server.o
	gcc -o server $(shell pkg-config --libs openssl zlib) $^

%.o: %.c
	gcc -Wall -Wextra -g -march=native -mtune=native -O3 -Isrc $(shell pkg-config --cflags openssl zlib) -o $@ -c $<

clean:
	rm -vf *.o server

re: clean all
