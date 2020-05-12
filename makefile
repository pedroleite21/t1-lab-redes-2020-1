client: client.c
	gcc -pthread  client.c -o client

client2: client2.c
	gcc -pthread client2.c -o client2

server: server.c
	gcc server.c -o server
