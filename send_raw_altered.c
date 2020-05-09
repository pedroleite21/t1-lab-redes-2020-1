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

#define TRUE 1
#define FALSE 0

const char* NICK = "nick";
const char* JOIN = "join";

char this_mac[6];
char bcast_mac[6] =	{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
char dst_mac[6] =	{0x00, 0x00, 0x00, 0x22, 0x22, 0x22};
char src_mac[6] =	{0x00, 0x00, 0x00, 0x33, 0x33, 0x33};

union eth_buffer buffer_u;

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

/*int main(int argc, char *argv[])*/
/*{*/
/*	struct ifreq if_idx, if_mac, ifopts;*/
/*	char ifName[IFNAMSIZ];*/
/*	struct sockaddr_ll socket_address;*/
/*	int sockfd, numbytes;*/
/*	uint8_t msg[] = "hello world!! =)";*/


	/* Get interface name */
/*	if (argc > 1)*/
/*		strcpy(ifName, argv[1]);*/
/*	else*/
/*		strcpy(ifName, DEFAULT_IF);*/

	/* Open RAW socket */
/*	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)*/
/*		perror("socket");*/

	/* Set interface to promiscuous mode */
/*	strncpy(ifopts.ifr_name, ifName, IFNAMSIZ-1);*/
/*	ioctl(sockfd, SIOCGIFFLAGS, &ifopts);*/
/*	ifopts.ifr_flags |= IFF_PROMISC;*/
/*	ioctl(sockfd, SIOCSIFFLAGS, &ifopts);*/

	/* Get the index of the interface */
/*	memset(&if_idx, 0, sizeof(struct ifreq));*/
/*	strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);*/
/*	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)*/
/*		perror("SIOCGIFINDEX");*/
/*	socket_address.sll_ifindex = if_idx.ifr_ifindex;*/
/*	socket_address.sll_halen = ETH_ALEN;*/

	/* Get the MAC address of the interface */
/*	memset(&if_mac, 0, sizeof(struct ifreq));*/
/*	strncpy(if_mac.ifr_name, ifName, IFNAMSIZ-1);*/
/*	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)*/
/*		perror("SIOCGIFHWADDR");*/
/*	memcpy(this_mac, if_mac.ifr_hwaddr.sa_data, 6);*/

	/* End of configuration. Now we can send data using raw sockets. */

	/* Fill the Ethernet frame header */
/*	memcpy(buffer_u.cooked_data.ethernet.dst_addr, bcast_mac, 6);*/
/*	memcpy(buffer_u.cooked_data.ethernet.src_addr, src_mac, 6);*/
/*	buffer_u.cooked_data.ethernet.eth_type = htons(ETH_P_IP);*/

	/* Fill IP header data. Fill all fields and a zeroed CRC field, then update the CRC! */
/*	buffer_u.cooked_data.payload.ip.ver = 0x45;*/
/*	buffer_u.cooked_data.payload.ip.tos = 0x00;*/
/*	buffer_u.cooked_data.payload.ip.len = htons(sizeof(struct ip_hdr) + sizeof(struct udp_hdr) + strlen(msg));*/
/*	buffer_u.cooked_data.payload.ip.id = htons(0x00);*/
/*	buffer_u.cooked_data.payload.ip.off = htons(0x00);*/
/*	buffer_u.cooked_data.payload.ip.ttl = 50;*/
/*	buffer_u.cooked_data.payload.ip.proto = 17; //0xff;*/
/*	buffer_u.cooked_data.payload.ip.sum = htons(0x0000);*/

/*	buffer_u.cooked_data.payload.ip.src[0] = 192;*/
/*	buffer_u.cooked_data.payload.ip.src[1] = 168;*/
/*	buffer_u.cooked_data.payload.ip.src[2] = 5;*/
/*	buffer_u.cooked_data.payload.ip.src[3] = 25;*/
/*	buffer_u.cooked_data.payload.ip.dst[0] = 192;*/
/*	buffer_u.cooked_data.payload.ip.dst[1] = 168;*/
/*	buffer_u.cooked_data.payload.ip.dst[2] = 6;*/
/*	buffer_u.cooked_data.payload.ip.dst[3] = 6;*/
/*	buffer_u.cooked_data.payload.ip.sum = htons((~ipchksum((uint8_t *)&buffer_u.cooked_data.payload.ip) & 0xffff));*/

	/* Fill UDP header */
/*	buffer_u.cooked_data.payload.udp.udphdr.src_port = htons(555);*/
/*	buffer_u.cooked_data.payload.udp.udphdr.dst_port = htons(666);*/
/*	buffer_u.cooked_data.payload.udp.udphdr.udp_len = htons(sizeof(struct udp_hdr) + strlen(msg));*/
/*	buffer_u.cooked_data.payload.udp.udphdr.udp_chksum = 0;*/

	/* Fill UDP payload */
/*	memcpy(buffer_u.raw_data + sizeof(struct eth_hdr) + sizeof(struct ip_hdr) + sizeof(struct udp_hdr), msg, strlen(msg));*/

	/* Send it.. */
/*	memcpy(socket_address.sll_addr, dst_mac, 6);*/
/*	if (sendto(sockfd, buffer_u.raw_data, sizeof(struct eth_hdr) + sizeof(struct ip_hdr) + sizeof(struct udp_hdr) + strlen(msg), 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)*/
/*		printf("Send failed\n");*/

/*	return 0;*/
/*}*/

int main(int argc, char *argv[]){
	int hasNick = FALSE;
	char command[15];
	char *arg;

	int ret;

	printf("Bem vindo ao Bate-Papo\n");
	
	while(1) {
		if (hasNick == TRUE) {
			break;
		} else {
			printf("Você não tem um NICK definido, defina o seu com o comando /nick.\n");
			printf("Exemplo: /nick user\n");
			fflush(stdin);
			scanf("/%s %s", command, &arg);
			// uppercase command
			if (strcmp (command, NICK) == 0) {
				printf("strings match. nick: %s\n", &arg);	
			}
			// enviar pro servidor se tem username disponivel
			break;
		}
	} 

	
	return 0;
}
