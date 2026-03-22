all: server

server: main.o frame.o handshake.o utils.o server.o
	gcc -o server $(shell pkg-config --libs openssl zlib) $^

%.o: %.c
	gcc -Wall -Wextra -g -march=native -mtune=native -O3 $(shell pkg-config --cflags openssl zlib) -o $@ -c $<

clean:
	rm -vf *.o server

re: clean all
