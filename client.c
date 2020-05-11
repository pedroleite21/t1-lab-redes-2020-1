//gcc -pthread -o client client.c

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h> 
#include <errno.h> 
#include <netdb.h>
#include <net/if.h>
#include <netinet/ether.h>
#include "raw.h"
#include <pthread.h>
#include <ctype.h>
#include <ifaddrs.h>

#define PROTO_UDP	17
#define DST_PORT	8000

char this_mac[6];
char bcast_mac[6] =	{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
char dst_mac[6] =	{0x00, 0x00, 0x00, 0x22, 0x22, 0x22};
char src_mac[6] =	{0x00, 0x00, 0x00, 0x33, 0x33, 0x33};

const char* NICK = "NICK";
const char* JOIN = "JOIN";
const char* REMOVE = "REMOVE";
const char* CREATE = "CREATE";
const char* PART = "PART";
const char* NAMES = "NAMES";
const char* KICK = "KICK";
const char* MSG = "MSG";
const char* PRIVMSG = "PRIVMSG";
const char* QUIT = "QUIT";

union eth_buffer buffer_u;
struct ifaddrs *id;

int hasUser = 1;
char user[10];

//send
	struct ifreq if_idx, if_mac, ifopts;
	char ifName[IFNAMSIZ];
	struct sockaddr_ll socket_address;
	int sockfd, numbytes;
	uint8_t msg[] = "hello world!! =)";
//receive
	struct ifreq ifopts;
	char ifName[IFNAMSIZ];
	int sockfd, numbytes;
	char *p;
	char pkgReturn[150];

void toUppercase(char* string)
{
	while (*string++ = toupper(*string));
}

int receiveConfirmation(int argc, char *argv[]) {
	int confirmation = 0;
	char *message;
	if (argc > 1)
		strcpy(ifName, argv[1]);
	else
		strcpy(ifName, DEFAULT_IF);

	/* Open RAW socket */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
		perror("socket");
	
	/* Set interface to promiscuous mode */
	strncpy(ifopts.ifr_name, ifName, IFNAMSIZ-1);
	ioctl(sockfd, SIOCGIFFLAGS, &ifopts);
	ifopts.ifr_flags |= IFF_PROMISC;
	ioctl(sockfd, SIOCSIFFLAGS, &ifopts);

	while(1) {
		numbytes = recvfrom(sockfd, buffer_u.raw_data, ETH_LEN, MSG_DONTWAIT , NULL, NULL);
		if (
			buffer_u.cooked_data.ethernet.eth_type == ntohs(ETH_P_IP) 
			&& buffer_u.cooked_data.payload.ip.src[0] == 10
			&& buffer_u.cooked_data.payload.ip.src[1] == 0
			&& buffer_u.cooked_data.payload.ip.src[2] == 0
			&& buffer_u.cooked_data.payload.ip.src[3] == 22
			&& numbytes > 0
		)	{
			sscanf((char *)&buffer_u.cooked_data.payload.udp.udphdr + sizeof(struct udp_hdr), "%d %s", &confirmation, &message);
			return confirmation;
		};
	};

	return 1;
}

void receive(int argc, char *argv[]){
	/* Get interface name */
	if (argc > 1)
		strcpy(ifName, argv[1]);
	else
		strcpy(ifName, DEFAULT_IF);

	/* Open RAW socket */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
		perror("socket");
	
	/* Set interface to promiscuous mode */
	strncpy(ifopts.ifr_name, ifName, IFNAMSIZ-1);
	ioctl(sockfd, SIOCGIFFLAGS, &ifopts);
	ifopts.ifr_flags |= IFF_PROMISC;
	ioctl(sockfd, SIOCSIFFLAGS, &ifopts);

	/* End of configuration. Now we can receive data using raw sockets. */

	while (1){
		numbytes = recvfrom(sockfd, buffer_u.raw_data, ETH_LEN, MSG_DONTWAIT , NULL, NULL);
		if (buffer_u.cooked_data.ethernet.eth_type == ntohs(ETH_P_IP)){
			// printf("IP packet, %d bytes - src ip: %d.%d.%d.%d dst ip: %d.%d.%d.%d proto: %d\n",
				// numbytes,
				// buffer_u.cooked_data.payload.ip.src[0], buffer_u.cooked_data.payload.ip.src[1],
				// buffer_u.cooked_data.payload.ip.src[2], buffer_u.cooked_data.payload.ip.src[3],
				// buffer_u.cooked_data.payload.ip.dst[0], buffer_u.cooked_data.payload.ip.dst[1],
				// buffer_u.cooked_data.payload.ip.dst[2], buffer_u.cooked_data.payload.ip.dst[3],
				// buffer_u.cooked_data.payload.ip.proto
			// );
			if (buffer_u.cooked_data.payload.ip.proto == PROTO_UDP && buffer_u.cooked_data.payload.udp.udphdr.dst_port == ntohs(DST_PORT)){
				p = (char *)&buffer_u.cooked_data.payload.udp.udphdr + ntohs(buffer_u.cooked_data.payload.udp.udphdr.udp_len);
				*p = '\0';
				printf("src port: %d dst port: %d size: %d msg: %s", 
				ntohs(buffer_u.cooked_data.payload.udp.udphdr.src_port), ntohs(buffer_u.cooked_data.payload.udp.udphdr.dst_port),
				ntohs(buffer_u.cooked_data.payload.udp.udphdr.udp_len), (char *)&buffer_u.cooked_data.payload.udp.udphdr + sizeof(struct udp_hdr)
				); 
			}
			continue;
		}
				
		// printf("got a packet, %d bytes\n", numbytes);
	}

}

uint32_t ipchksum(uint8_t *packet)
{
	uint32_t sum=0;
	uint16_t i;

	for(i = 0; i < 20; i += 2)
		sum += ((uint32_t)packet[i] << 8) | (uint32_t)packet[i + 1];
	while (sum & 0xffff0000)
		sum = (sum & 0xffff) + (sum >> 16);
	return sum;
}

void sending(int argc, char *argv[]){
/* Get interface name */
	if (argc > 1)
		strcpy(ifName, argv[1]);
	else
		strcpy(ifName, DEFAULT_IF);

	/* Open RAW socket */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
		perror("socket");

	/* Set interface to promiscuous mode */
	strncpy(ifopts.ifr_name, ifName, IFNAMSIZ-1);
	ioctl(sockfd, SIOCGIFFLAGS, &ifopts);
	ifopts.ifr_flags |= IFF_PROMISC;
	ioctl(sockfd, SIOCSIFFLAGS, &ifopts);

	/* Get the index of the interface */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
		perror("SIOCGIFINDEX");
	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	socket_address.sll_halen = ETH_ALEN;

	/* Get the MAC address of the interface */
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
		perror("SIOCGIFHWADDR");
	memcpy(this_mac, if_mac.ifr_hwaddr.sa_data, 6);

	/* End of configuration. Now we can send data using raw sockets. */

	/* Fill the Ethernet frame header */
	memcpy(buffer_u.cooked_data.ethernet.dst_addr, bcast_mac, 6);
	memcpy(buffer_u.cooked_data.ethernet.src_addr, src_mac, 6);
	buffer_u.cooked_data.ethernet.eth_type = htons(ETH_P_IP);

	/* Fill IP header data. Fill all fields and a zeroed CRC field, then update the CRC! */
	buffer_u.cooked_data.payload.ip.ver = 0x45;
	buffer_u.cooked_data.payload.ip.tos = 0x00;
	buffer_u.cooked_data.payload.ip.len = htons(sizeof(struct ip_hdr) + sizeof(struct udp_hdr) + strlen(msg));
	buffer_u.cooked_data.payload.ip.id = htons(0x00);
	buffer_u.cooked_data.payload.ip.off = htons(0x00);
	buffer_u.cooked_data.payload.ip.ttl = 50;
	buffer_u.cooked_data.payload.ip.proto = 17; //0xff;// 17 é o protocolo udp
	buffer_u.cooked_data.payload.ip.sum = htons(0x0000);//calcula como 0 o checksum para que no final apos incluir os valores corretos, fazer o checksum denoovo e incluí-lo

	buffer_u.cooked_data.payload.ip.src[0] = 10;
	buffer_u.cooked_data.payload.ip.src[1] = 0;
	buffer_u.cooked_data.payload.ip.src[2] = 0;
	buffer_u.cooked_data.payload.ip.src[3] = 20;
	buffer_u.cooked_data.payload.ip.dst[0] = 10;
	buffer_u.cooked_data.payload.ip.dst[1] = 0;
	buffer_u.cooked_data.payload.ip.dst[2] = 0;
	buffer_u.cooked_data.payload.ip.dst[3] = 22;
	buffer_u.cooked_data.payload.ip.sum = htons((~ipchksum((uint8_t *)&buffer_u.cooked_data.payload.ip) & 0xffff));//pega-se o primeiro byte do cabeçalho ip como endereço para ipchsum executar

	/* Fill UDP header */
	buffer_u.cooked_data.payload.udp.udphdr.src_port = htons(555);
	buffer_u.cooked_data.payload.udp.udphdr.dst_port = htons(666);
	buffer_u.cooked_data.payload.udp.udphdr.udp_len = htons(sizeof(struct udp_hdr) + strlen(msg));
	buffer_u.cooked_data.payload.udp.udphdr.udp_chksum = 0;

	/* Fill UDP payload */
	memcpy(buffer_u.raw_data + sizeof(struct eth_hdr) + sizeof(struct ip_hdr) + sizeof(struct udp_hdr), msg, strlen(msg));

	/* Send it.. */
	memcpy(socket_address.sll_addr, dst_mac, 6);
	if (sendto(sockfd, buffer_u.raw_data, sizeof(struct eth_hdr) + sizeof(struct ip_hdr) + sizeof(struct udp_hdr) + strlen(msg), 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
		printf("Send failed\n");
}

int sendTerminal(int argc, char *argv[]) {
	char command[15];
	char *arg;

	int ret;

	printf("Bem vindo ao Bate-Papo\n");

	while(1) {
		if (hasUser == 1) {
			printf("Você não tem um NICK definido\n");
			printf("Exemplo: /nick user\n");
			fflush(stdin);
			scanf("/%s %s", command, &arg);
			toUppercase(command);
			if (strcmp(command, NICK) == 0) {
				// enviar pro servidor se tem user name disponivel
				sprintf(msg, "%s %s", command, &arg);
				sending(argc, argv);
				// wait for confirmation
				ret = receiveConfirmation(argc,argv);
				printf("%d\n", ret);
				if (ret == 0) {
					hasUser = 0;
					strcpy(user, &arg);
				} else {
					printf("Já tem esse user na nossa database\n");
					return -1;
				}
			}
		} else {
			printf("Bem vindo user %s", &user);
			scanf("%s %s", command, &arg);
		}
	}
	
	return 0;
}



int main(int argc, char *argv[])
{
	pthread_t send_thread;//waits for a send request and send
	pthread_t receive_thread;//waits for a receive

	pthread_create(&send_thread, NULL, (void *) sendTerminal, NULL);
	pthread_join(send_thread, NULL);
	pthread_create(&receive_thread, NULL, (void *) receive, NULL);
	pthread_join(receive_thread, NULL);

	//receive(argc, argv);

	//sending(argc, argv);


	return 0;
}
