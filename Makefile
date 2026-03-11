all: server

server: main.o frame.o handshake.o utils.o server.o
	gcc -o server -lssl -lcrypto $^

%.o: %.c
	gcc -Wall -Wextra -g -o $@ -c $<

clean:
	rm -vf *.o server
