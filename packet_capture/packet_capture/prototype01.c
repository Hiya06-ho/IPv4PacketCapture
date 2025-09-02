//������� ���̺귯�� 
#include <stdio.h>
#include <pcap.h>
#include <winsock2.h>
#include <windows.h>
#include <stdint.h>

//MAC�ּ� ��� ��ũ��
#define MAC_ADDR_FMT "%02X:%02X:%02X:%02X:%02X:%02X"
#define MAC_ADDR_FMT_ARGS(addr) addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]

//��Ŷ�� �м��ϱ� ���� ����ü : ��� ������ ����
struct ip_header {
	unsigned char  protocol;   // ��������
	unsigned int   saddr;      // ����� IP
	unsigned int   daddr;      // ������ IP
};

struct eth_header {
	//dest�� src�� ������ ��, ����� ��
	unsigned char dest[6];
	unsigned char src[6];
	unsigned short type;
};

//���� ����
int main(void)
{
	/*
	���� �Լ��� ȣ���ϱ� ���� ���� �ʱ�ȭ�ϴ� �Լ�
	inet_ntoa()�� ���� ip�ּ� ��ȯ �Լ��� ����ϱ� ���� �����Լ� ���
	*/
	WSADATA wsaData;

	//�ʱ�ȭ Ȯ��
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		printf("Winsock �ʱ�ȭ ����\n");
		return 1;
	}

	//pcap_if_t : ��Ʈ��ũ ��ġ ������ ��� ����ü(������Ϸ� ����)
	pcap_if_t* alldevs;
	pcap_if_t* d;
	pcap_t* handle;
	
	//������ ���� ���� �޸�
	char errbuf[PCAP_ERRBUF_SIZE];

	//��Ʈ��ũ ��ġ ��� ��ȣ
	int choice = 0;

	printf("\n****************************************************************************\n\n");

	//��밡���� ��� ��Ʈ��ũ ��ġ ����� �������� �����ϸ� -1�� ��ȯ
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		//�����ϸ� ��ġ �˻� ���и� ���
		printf("��ġ �˻� ����: %s\n", errbuf);
		return 1;
	}

	//�ݺ�����
	int i = 0;

	//d�� NULL�� �� ������ �������� �ѱ�
	for (d = alldevs; d != NULL; d = d->next)
	{
		//���° ��ġ�� � �̸��� ��Ʈ��ũ ��ġ���� ���
		printf("      %d�� ��ġ: %s\n", ++i, d->name);

		//��Ʈ��ũ ��ġ�� ������ ����ϰų� ���� ������ �������� �ʱ�
		if (d->description)
			printf("            ����: %s\n\n", d->description);
		else
			printf("            ���� ����\n\n");
	}

	printf("\n****************************************************************************\n");    

	//����� ��ġ�� ��ȣ�� �Է¹ޱ�
	printf("\n      � ��ġ�� �����Ͻðڽ��ϱ�?: ");
	scanf("%d", &choice);

	//d�� ��Ʈ��ũ ��ġ ���� ����ü�� ù ��° ��ġ�� �ű�
	d = alldevs;

	//����ڰ� ������ ��ȣ choice��ŭ ����ü�� �ѱ�
	for (int j = 1; j < choice && d != NULL; j++)
		d = d->next;

	system("cls");

	printf("\n****************************************************************************\n\n");

	//���õ� ��ġ�� �����
	printf("      ���õ� ��ġ: %s\n", d->name);

	printf("\n****************************************************************************\n\n");

	const char* dev = d->name;

	//��Ʈ��ũ ��ġ ����� �������� �Լ��� ����
	pcap_freealldevs(alldevs);

	/*��Ŷ ĸó�� �����ϴ� �Լ� (����)

		pcap_t* pcap_open_live(
			const char *device,  // ĸó�� ��Ʈ��ũ ��ġ �̸�
			int snaplen,          // �ִ� ĸó ���� (����Ʈ)
			int promisc,          // 1: promiscuous mode, 0: �Ϲ� ���
			int to_ms,            // ��Ŷ ĸó ��� �ð� (�и���)
			char *errbuf          // ���� �޽��� ����
		);

	*/
	handle = pcap_open_live(dev, 65535, 1, 1000, errbuf);

	if (handle == NULL)
	{
		printf("      ��Ŷ ĸ�� ����\n");
		return 1;
	}
	
	//��Ŷ �ݺ��ؼ� ĸó
	while (1)
	{
		/*
		IPv4��Ŷ�� �м��Ұǵ� Ethernet Ÿ�� ���尡 0x0800�̸� IPv4��Ŷ��
		*/

		//��Ŷ ��� ����ü
		struct pcap_pkthdr* header;
		//��Ŷ ������ ����ü
		const u_char* pkt_data;

		printf("\n--------------------------------------------------------------------\n\n");
		//�� ��Ŷ�� ó����

		//���� ethernet����� type�ʵ� ���� ��Ŷ ������ �� �� ����
		struct eth_header* eth = (struct eth_header*)pkt_data;
		if (ntohs(eth->type) == 0x0800)
		{
			//������� len���� ������
			printf("IPv4 ��Ŷ ����: %d\n", header->len);

			//ipv4�� ��Ŷ�� 14����Ʈ?�� 14�� ����
			struct ip_header* ip = (struct ip_header*)(pkt_data + 14);

			//����ü���� �����ͼ� ���
			printf("�����: %s\n", inet_ntoa(*(struct in_addr*)&ip->saddr));
			printf("������: %s\n\n", inet_ntoa(*(struct in_addr*)&ip->daddr));

			//���ּ� ��� ��ũ�η� �����ϰ� ���
			printf("����� MAC�ּ�: "MAC_ADDR_FMT"\n", MAC_ADDR_FMT_ARGS(eth->src));
			printf("������ MAC�ּ�: "MAC_ADDR_FMT"\n", MAC_ADDR_FMT_ARGS(eth->dest));
			printf("��������: %d\n\n", ip->protocol);
		}
		//���� �ٸ� ��Ŷ�̸� � ��Ŷ���� ���
		else if(ntohs(eth->type) == 0x0806)
			printf("ARP ��Ŷ�Դϴ�.\n");
		else if (ntohs(eth->type) == 0x86DD)
			printf("IPv6 ��Ŷ�Դϴ�.\n");
		else 
			printf("�� �� ���� Ethernet Ÿ��: 0x%04X\n", ntohs(eth->type));
	}

	//��Ŷ ĸó �Լ� �ݱ�
	pcap_close(handle);

	//���� �Լ� �ݱ�
	WSACleanup();

	return 0;
}