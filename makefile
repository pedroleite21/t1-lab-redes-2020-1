all: client.c
	gcc -pthread -o client client.c
clean:
	$(RM) client
