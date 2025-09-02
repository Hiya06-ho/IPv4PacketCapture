//헤더파일 라이브러리 
#include <stdio.h>
#include <pcap.h>
#include <winsock2.h>
#include <windows.h>
#include <stdint.h>

//MAC주소 출력 매크로
#define MAC_ADDR_FMT "%02X:%02X:%02X:%02X:%02X:%02X"
#define MAC_ADDR_FMT_ARGS(addr) addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]

//패킷을 분석하기 위한 구조체 : 헤더 구조로 제작
struct ip_header {
	unsigned char  protocol;   // 프로토콜
	unsigned int   saddr;      // 출발지 IP
	unsigned int   daddr;      // 목적지 IP
};

struct eth_header {
	//dest와 src는 목적지 맥, 출발지 맥
	unsigned char dest[6];
	unsigned char src[6];
	unsigned short type;
};

//메인 시작
int main(void)
{
	/*
	소켓 함수를 호출하기 전에 원소 초기화하는 함수
	inet_ntoa()와 같은 ip주소 변환 함수를 사용하기 위해 소켓함수 사용
	*/
	WSADATA wsaData;

	//초기화 확인
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		printf("Winsock 초기화 실패\n");
		return 1;
	}

	//pcap_if_t : 네트워크 장치 정보를 담는 구조체(헤더파일로 선언)
	pcap_if_t* alldevs;
	pcap_if_t* d;
	pcap_t* handle;
	
	//에러를 담을 버퍼 메모리
	char errbuf[PCAP_ERRBUF_SIZE];

	//네트워크 장치 목록 번호
	int choice = 0;

	printf("\n****************************************************************************\n\n");

	//사용가능한 모든 네트워크 장치 목록을 가져오고 실패하면 -1을 반환
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		//실패하면 장치 검색 실패를 출력
		printf("장치 검색 실패: %s\n", errbuf);
		return 1;
	}

	//반복문용
	int i = 0;

	//d가 NULL이 될 때까지 다음으로 넘김
	for (d = alldevs; d != NULL; d = d->next)
	{
		//몇번째 장치가 어떤 이름의 네트워크 장치인지 출력
		printf("      %d번 장치: %s\n", ++i, d->name);

		//네트워크 장치의 설명을 출력하거나 되지 않으면 설명하지 않기
		if (d->description)
			printf("            설명: %s\n\n", d->description);
		else
			printf("            설명 없음\n\n");
	}

	printf("\n****************************************************************************\n");    

	//사용할 장치의 번호를 입력받기
	printf("\n      어떤 장치를 선택하시겠습니까?: ");
	scanf("%d", &choice);

	//d의 네트워크 장치 정보 구조체를 첫 번째 위치로 옮김
	d = alldevs;

	//사용자가 선택한 번호 choice만큼 구조체를 넘김
	for (int j = 1; j < choice && d != NULL; j++)
		d = d->next;

	system("cls");

	printf("\n****************************************************************************\n\n");

	//선택된 장치를 출력함
	printf("      선택된 장치: %s\n", d->name);

	printf("\n****************************************************************************\n\n");

	const char* dev = d->name;

	//네트워크 장치 목록을 가져오는 함수를 닫음
	pcap_freealldevs(alldevs);

	/*패킷 캡처를 시작하는 함수 (구조)

		pcap_t* pcap_open_live(
			const char *device,  // 캡처할 네트워크 장치 이름
			int snaplen,          // 최대 캡처 길이 (바이트)
			int promisc,          // 1: promiscuous mode, 0: 일반 모드
			int to_ms,            // 패킷 캡처 대기 시간 (밀리초)
			char *errbuf          // 에러 메시지 버퍼
		);

	*/
	handle = pcap_open_live(dev, 65535, 1, 1000, errbuf);

	if (handle == NULL)
	{
		printf("      패킷 캡쳐 실패\n");
		return 1;
	}
	
	//패킷 반복해서 캡처
	while (1)
	{
		/*
		IPv4패킷만 분석할건데 Ethernet 타입 빌드가 0x0800이면 IPv4패킷임
		*/

		//패킷 헤더 구조체
		struct pcap_pkthdr* header;
		//패킷 데이터 구조체
		const u_char* pkt_data;

		printf("\n--------------------------------------------------------------------\n\n");
		//한 패킷씩 처리함

		//만약 ethernet헤더의 type필드 따라서 패킷 종류를 알 수 있음
		struct eth_header* eth = (struct eth_header*)pkt_data;
		if (ntohs(eth->type) == 0x0800)
		{
			//헤더에서 len길이 가져옴
			printf("IPv4 패킷 길이: %d\n", header->len);

			//ipv4는 패킷이 14바이트?라서 14를 더함
			struct ip_header* ip = (struct ip_header*)(pkt_data + 14);

			//구조체에서 가져와서 출력
			printf("출발지: %s\n", inet_ntoa(*(struct in_addr*)&ip->saddr));
			printf("목적지: %s\n\n", inet_ntoa(*(struct in_addr*)&ip->daddr));

			//맥주소 출력 매크로로 간단하게 출력
			printf("출발지 MAC주소: "MAC_ADDR_FMT"\n", MAC_ADDR_FMT_ARGS(eth->src));
			printf("목적지 MAC주소: "MAC_ADDR_FMT"\n", MAC_ADDR_FMT_ARGS(eth->dest));
			printf("프로토콜: %d\n\n", ip->protocol);
		}
		//만약 다른 패킷이면 어떤 패킷인지 출력
		else if(ntohs(eth->type) == 0x0806)
			printf("ARP 패킷입니다.\n");
		else if (ntohs(eth->type) == 0x86DD)
			printf("IPv6 패킷입니다.\n");
		else 
			printf("알 수 없는 Ethernet 타입: 0x%04X\n", ntohs(eth->type));
	}

	//패킷 캡처 함수 닫기
	pcap_close(handle);

	//소켓 함수 닫기
	WSACleanup();

	return 0;
}