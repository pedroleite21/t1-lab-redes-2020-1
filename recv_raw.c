#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include "raw.h"
#include <stdbool.h>

#define PROTO_UDP	17
#define DST_PORT	8000

struct ifreq if_idx, if_mac, ifopts;
char ifName[IFNAMSIZ];
struct sockaddr_ll socket_address;
int sockfd, numbytes;
uint8_t msg[] = "hello world!! =)";

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
const char* LIST = "LIST";

union eth_buffer buffer_u;
union eth_buffer buffer_send;

struct PROFILES {
	char *user;
	char ip[4];
};

struct CHANNELS {
	char *name;
	struct PROFILES users[5];
};

struct PROFILES users[100];
struct CHANNELS channels[20];

bool isUsernameDuplicated(char *user) {
	int i = 0;
	for (i; i < sizeof(users); i++) {
		if (users[i].user == NULL) {
			users[i].user = user;
			printf("%s\n", &users[i].user);
			return 0;
		}
		if (strcmp(&users[i].user, &user) == 0) {
			printf("%s %s\n", &users[i].user, &user);
			printf("Já existe\n");
			return 1;	
		};
	};

	return 0;
}

bool isChannelDuplicated(char *name) {
	int i = 0;
	for (i; i < sizeof(channels); i++) {
		if (channels[i].name == NULL) {
			channels[i].name = name;
			printf("%s\n", &channels[i].name);
			return 0;
		}
		if (strcmp(&channels[i].name, &name) == 0) {
			printf("%s %s\n", &channels[i].name, &name);
			printf("Já existe\n");
			return 1;	
		};
	};

	return 0;
};

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
	printf("got here");
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
	buffer_u.cooked_data.payload.ip.src[3] = 22;
	buffer_u.cooked_data.payload.ip.dst[0] = buffer_send.cooked_data.payload.ip.dst[0];
	buffer_u.cooked_data.payload.ip.dst[1] = buffer_send.cooked_data.payload.ip.dst[1];
	buffer_u.cooked_data.payload.ip.dst[2] = buffer_send.cooked_data.payload.ip.dst[2];
	buffer_u.cooked_data.payload.ip.dst[3] = buffer_send.cooked_data.payload.ip.dst[3];
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

int main(int argc, char *argv[])
{
	struct ifreq ifopts;
	char ifName[IFNAMSIZ];
	int sockfd, numbytes;
	char *p;

	char *fromClient;
	char command[15];
	char *arg1;
	char *arg2;
	char *arg3;
	char srcIp[4];
	int ret = 0;
	
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
		if (buffer_u.cooked_data.ethernet.eth_type == ntohs(ETH_P_IP)
			&& buffer_u.cooked_data.payload.ip.dst[0] == 10
			&& buffer_u.cooked_data.payload.ip.dst[1] == 0
			&& buffer_u.cooked_data.payload.ip.dst[2] == 0
			&& buffer_u.cooked_data.payload.ip.dst[3] == 22
		&& numbytes > 0){
			printf("IP packet, %d bytes - src ip: %d.%d.%d.%d dst ip: %d.%d.%d.%d proto: %d\n",
				numbytes,
				buffer_u.cooked_data.payload.ip.src[0], buffer_u.cooked_data.payload.ip.src[1],
				buffer_u.cooked_data.payload.ip.src[2], buffer_u.cooked_data.payload.ip.src[3],
				buffer_u.cooked_data.payload.ip.dst[0], buffer_u.cooked_data.payload.ip.dst[1],
				buffer_u.cooked_data.payload.ip.dst[2], buffer_u.cooked_data.payload.ip.dst[3],
				buffer_u.cooked_data.payload.ip.proto
			);
			fromClient = (char *)&buffer_u.cooked_data.payload.udp.udphdr + sizeof(struct udp_hdr);
			sscanf(fromClient, "%s %s %s %s", &command, &arg1, &arg2, &arg3);
			
			buffer_send.cooked_data.payload.ip.dst[0] = buffer_u.cooked_data.payload.ip.src[0]; 
			buffer_send.cooked_data.payload.ip.dst[1] = buffer_u.cooked_data.payload.ip.src[1]; 
			buffer_send.cooked_data.payload.ip.dst[2] = buffer_u.cooked_data.payload.ip.src[2]; 
			buffer_send.cooked_data.payload.ip.dst[3] = buffer_u.cooked_data.payload.ip.src[3];

			// COMMAND NICK
			if (strcmp(command, NICK) == 0) {			
				if(isUsernameDuplicated(arg1) == 0) {
					printf("Deu tudo certo\n");
					sprintf(msg, "%d OK", 0);
					sending(argc, argv);
				} else {
					printf("Tem alguém com o mesmo user\n");
					sprintf(msg, "%d ERROR", 1);
					sending(argc, argv);
				};	
			} else if (strcmp(command, CREATE) == 0) {
				printf("CREATE\n");
				if(isChannelDuplicated(arg1) == 0) {
					printf("Deu tudo certo\n");
					sprintf(msg, "%d OK", 0);
					sending(argc, argv);
				} else {
					printf("Já existe esse channel \n");
					sprintf(msg, "%d ERROR", 1);
					sending(argc, argv);
				}
			} else if (strcmp(command, JOIN) == 0) {
				printf("JOIN!\n")
			};
			
			memset(&command, 0, sizeof(command));
			

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

	return 0;
}
