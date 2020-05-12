client: client.c
	gcc -pthread  client.c -o client

server: recv_raw.c
	gcc recv_raw.c -o recv_raw
