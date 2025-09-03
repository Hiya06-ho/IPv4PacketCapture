#include <stdio.h>
#include <pcap.h>
#include <winsock2.h>
#include <windows.h>
#include <stdint.h>
#include <ctype.h>

void init_winsock();
pcap_t* open_capture_handle(const char* dev, char* errbuf, pcap_t* handle);
pcap_if_t* choose_device(pcap_if_t* alldevs, pcap_if_t* d, pcap_t* handle, char errbuf[PCAP_ERRBUF_SIZE], int choice);
void analyze_ipv4_packet(const u_char* pkt_data, struct pcap_pkthdr* header, struct eth_header* eth);
void capture_loop(pcap_t* handle, u_char* pkt_data, int re, struct pcap_pkthdr* header);
void print_hex_ascii(const u_char* payload, int len);

#define MAC_ADDR_FMT "%02X:%02X:%02X:%02X:%02X:%02X"
#define MAC_ADDR_FMT_ARGS(addr) addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]

struct ip_header {
	unsigned char  protocol;
	unsigned int   saddr;
	unsigned int   daddr;
};

struct eth_header {
	unsigned char dest[6];
	unsigned char src[6];
	unsigned short type;
};

int main(void)
{
	init_winsock();

	pcap_if_t* alldevs;
	pcap_if_t* d;
	pcap_t* handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	int choice = 0;

	const char* dev = choose_device(&alldevs, &d, &handle, errbuf, choice);

	handle = open_capture_handle(dev, errbuf, handle);

	WSACleanup();

	return 0;
}

void init_winsock()
{
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		printf("Winsock 초기화 실패\n");
	}
}

pcap_t* open_capture_handle(const char* dev, char* errbuf, pcap_t* handle)
{
	struct pcap_pkthdr* header;
	const u_char* pkt_data;
	int re = 0;

	handle = pcap_open_live(dev, 65535, 1, 1000, errbuf);

	if (handle == NULL)
	{
		printf("      패킷 캡쳐 실패\n");
		return NULL;
	}

	while (1)
		capture_loop(handle, &pkt_data, re, &header);

	pcap_close(handle);
}

void capture_loop(pcap_t* handle, u_char* pkt_data, int re, struct pcap_pkthdr* header)
{
	printf("\n--------------------------------------------------------------------\n\n");
	re = pcap_next_ex(handle, &header, &pkt_data);
	if (re == 0)
		return 0;

	struct eth_header* eth = (struct eth_header*)pkt_data;
	if (ntohs(eth->type) == 0x0800)
		analyze_ipv4_packet(pkt_data, header, eth);
	else if (ntohs(eth->type) == 0x0806)
		printf("ARP 패킷입니다.\n");
	else if (ntohs(eth->type) == 0x86DD)
		printf("IPv6 패킷입니다.\n");
	else
		printf("알 수 없는 Ethernet 타입: 0x%04X\n", ntohs(eth->type));

	const u_char* packet = pkt_data;
	int packet_len = header->len;
	print_hex_ascii(packet, packet_len);
}

void analyze_ipv4_packet(const u_char* pkt_data, struct pcap_pkthdr* header, struct eth_header* eth)
{
	printf("IPv4 패킷 길이: %d\n", header->len);

	struct ip_header* ip = (struct ip_header*)(pkt_data + 14);

	printf("출발지: %s\n", inet_ntoa(*(struct in_addr*)&ip->saddr));
	printf("목적지: %s\n\n", inet_ntoa(*(struct in_addr*)&ip->daddr));

	printf("출발지 MAC주소: "MAC_ADDR_FMT"\n", MAC_ADDR_FMT_ARGS(eth->src));
	printf("목적지 MAC주소: "MAC_ADDR_FMT"\n", MAC_ADDR_FMT_ARGS(eth->dest));
	printf("프로토콜: %d\n\n", ip->protocol);
}

pcap_if_t* choose_device(pcap_if_t* alldevs, pcap_if_t* d, pcap_t* handle, char errbuf[PCAP_ERRBUF_SIZE], int choice )
{
	printf("\n****************************************************************************\n\n");

	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		printf("장치 검색 실패: %s\n", errbuf);
		return 1;
	}

	int i = 0;
	for (d = alldevs; d != NULL; d = d->next)
	{
		printf("      %d번 장치: %s\n", ++i, d->name);
		if (d->description)
			printf("            설명: %s\n\n", d->description);
		else
			printf("            설명 없음\n\n");
	}

	printf("\n****************************************************************************\n");
	printf("\n      어떤 장치를 선택하시겠습니까?: ");
	scanf("%d", &choice);

	d = alldevs;
	for (int j = 1; j < choice && d != NULL; j++)
		d = d->next;

	system("cls");

	printf("\n****************************************************************************\n\n");
	printf("      선택된 장치: %s\n", d->name);
	printf("\n****************************************************************************\n\n");

	pcap_freealldevs(alldevs);

	return d->name;
}

void print_hex_ascii(const u_char* payload, int len)
{
	int line_width = 16;
	int offset = 0;
	const u_char* ch = payload;
	int cnt = 0;
	int j = 0;
	printf("data >> \n");

	for (int i = 0; offset < len; offset += 16)
	{
		if (offset != 0)
			printf("00%d\t", offset);

		for (; i < offset; i++)
		{
			printf("%02x ", ch[i]);
			cnt++;
		}

		if ((i + 1) % 16 == 1)
			printf("\t");

		for (; j < offset; j++)
		{
			if (isprint(ch[j]) == 1)
				printf("%c", ch[j]);
			else
				printf(".");
		}

		printf("\n");
		if (cnt == 64)
			break;
	}
}
