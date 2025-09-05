#include <stdio.h>
#include <pcap.h>
#include <winsock2.h>
#include <stdint.h>
#include <ctype.h>

void init_winsock();
pcap_t* open_capture_handle(const char* dev, char* errbuf, pcap_t* handle, int filter);
const char* choose_device(pcap_if_t* alldevs, pcap_if_t* d, pcap_t* handle, char errbuf[PCAP_ERRBUF_SIZE], int choice);
void analyze_ipv4_packet(const u_char* pkt_data, struct pcap_pkthdr* header, struct eth_header* eth);
void capture_loop(pcap_t* handle, int filter);
void print_hex_ascii(const u_char* payload, int len);
void analyze_ARP_packet(struct eth_header* eth, const unsigned char* pkt_data);
int choose_filter(int filter);

#define MAC_ADDR_FMT "%02X:%02X:%02X:%02X:%02X:%02X" 
#define MAC_ADDR_FMT_ARGS(addr) addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]

struct ip_header {
	unsigned char version;
	unsigned char tos;
	unsigned short total_len;
	unsigned short id;
	unsigned short frag_off;
	unsigned char ttl;
	unsigned char protocol;
	unsigned short check;
	unsigned int saddr;
	unsigned int daddr;
};

struct eth_header {
	unsigned char dest[6];
	unsigned char src[6];
	unsigned short type;
};

#pragma pack(push, 2)
struct arp_header {
	unsigned short htype;
	unsigned short ptype;
	unsigned char hlen;
	unsigned char plen;
	unsigned short opcode;
	unsigned char sender_mac[6];
	struct in_addr sender_ip;
	unsigned char target_mac[6];
	struct in_addr target_ip;
};
#pragma pack(pop)

int main(void)
{
	init_winsock();

	pcap_if_t* alldevs;
	pcap_if_t* d;
	pcap_t* handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	int choice = 0, filter = 0;

	const char* dev = choose_device(&alldevs, &d, &handle, errbuf, choice);

	filter = choose_filter(filter);

	handle = open_capture_handle(dev, errbuf, handle, filter);

	WSACleanup();

	return 0;
}

void init_winsock()
{
	WSADATA wsaData;

	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
		printf("Winsock 초기화 실패\n");
}

pcap_t* open_capture_handle(const char* dev, char* errbuf, pcap_t* handle, int filter)
{
	handle = pcap_open_live(dev, 65535, 1, 1000, errbuf);

	struct pcap_pkthdr* header = NULL;
	const u_char* pkt_data = NULL;
	int re = pcap_next_ex(handle, &header, &pkt_data);

	if (handle == NULL)
	{
		printf("      패킷 캡처 실패\n");
		return NULL;
	}

	capture_loop(handle, filter);

	pcap_close(handle);

	return handle;
}

void capture_loop(pcap_t* handle, int filter)
{
	struct pcap_pkthdr* header;
	const u_char* pkt_data;

	while (1)
	{
		int re = pcap_next_ex(handle, &header, &pkt_data);

		if (re != 1)
			continue;

		const u_char* packet = pkt_data;
		int packet_len = header->len;

		struct eth_header* eth = (struct eth_header*)pkt_data;

		if ((filter == 1) && (ntohs(eth->type) == 0x0800))
		{
			analyze_ipv4_packet(pkt_data, header, eth);
			print_hex_ascii(packet, packet_len);
		}

		if ((filter == 2) && (ntohs(eth->type) == 0x0806))
		{
			analyze_ARP_packet(eth, packet);
		}
	}
}

void analyze_ARP_packet(struct eth_header* eth, const unsigned char* pkt_data)
{
	printf("\n--------------------------------------------------------------------\n\n");

	struct arp_header* arp = (struct arp_header*)(pkt_data + 14);

	unsigned short opcode = ntohs(arp->opcode);

	if (opcode == 0x0001) {
		printf(" ******* request ******* \n");
		printf(" Sender IP : %s\n ", inet_ntoa(arp->sender_ip));
		printf("Target IP : %s\n ", inet_ntoa(arp->target_ip));
		printf("\n");
	}

	if (opcode == 0x0002) {
		printf(" ********  reply  ******** \n");
		printf(" Sender IP  : %s\n ", inet_ntoa(arp->sender_ip));
		printf("Sender MAC : ");
		for (int i = 0; i <= 5; i++)
			printf("%02x:", arp->sender_mac[i]);
		printf("\n");

		printf("\nTarget IP  : %s\n ", inet_ntoa(arp->target_ip));
		printf("\nDst MAC : ");
		for (int i = 0; i <= 5; i++)
			printf("%02x:", arp->target_mac[i]);
		printf("\n\n");
	}
}

void analyze_ipv4_packet(const u_char* pkt_data, struct pcap_pkthdr* header, struct eth_header* eth)
{
	printf("\n--------------------------------------------------------------------\n\n");

	printf("\n====== IPv4 packet ======\n");
	printf("IPv4 패킷 길이: %d\n", header->len);

	struct ip_header* ip = (struct ip_header*)(pkt_data + 14);

	printf("출발지: %s\n", inet_ntoa(*(struct in_addr*)&ip->saddr));
	printf("목적지: %s\n\n", inet_ntoa(*(struct in_addr*)&ip->daddr));

	printf("출발지 MAC주소: "MAC_ADDR_FMT"\n", MAC_ADDR_FMT_ARGS(eth->src));
	printf("목적지 MAC주소: "MAC_ADDR_FMT"\n", MAC_ADDR_FMT_ARGS(eth->dest));

	printf("프로토콜: %d\n\n", ip->protocol);
}

const char* choose_device(pcap_if_t* alldevs, pcap_if_t* d, pcap_t* handle, char errbuf[PCAP_ERRBUF_SIZE], int choice)
{
	printf("\n****************************************************************************\n\n");

	if (pcap_findalldevs(&alldevs, errbuf) == -1)
		printf("장치 검색 실패: %s\n", errbuf);

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

	printf("\n****************************************************************************\n\n");
	printf("      선택된 장치: %s\n", d->name);
	printf("\n****************************************************************************\n\n");

	system("cls");

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

int choose_filter(int filter)
{
	printf("\n****************************************************************************\n\n");
	printf("      패킷 유형을 선택하세요. ( [1] IPv4 [2] ARP ) :     ");
	scanf("%d", &filter);

	return filter;
}
