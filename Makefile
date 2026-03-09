all: server

server: main.o frame.o handshake.o utils.o
	gcc -o server -lssl -lcrypto $^

%.o: %.c
	gcc -g -o $@ -c $<

clean:
	rm -vf *.o server
