# Network Packet Analyzer

네트워크 패킷 캡처 및 분석 프로그램 프로젝트

---

## 00. 개요

### 01. 패킷 분석기란?
패킷 스니퍼(Packet Sniffer) 혹은 네트워크 분석기(Network Analyzer)는  
네트워크를 통과하는 트래픽을 분석하고 기록할 수 있는 프로그램입니다.

### 02. 패킷 분석기가 필요한 이유와 프로젝트 목표

- **네트워크 문제 진단**
  - 지연, 패킷 손실, 통신 불능 등 문제 발생 시 원인 파악
  - 장비 문제인지 공격인지 식별 가능

- **보안 위협 탐지**
  - 비정상 트래픽 패턴(포트 스캔, 비정상 프로토콜 사용) 감지
  - 해킹 시도나 정보 유출 정황 조기 포착 가능

- **데이터 엿보기(패킷 스니핑)**
  - 암호화되지 않은 패킷 캡처 가능
  - 네트워크 도청 원리 이해

- **보안 취약점 분석**
  - 특정 서비스/프로토콜에서 약한 부분 탐지
  - 공격 포인트 확보

- **악성코드 및 공격 행위 추적**
  - 악성 파일/메일 전송 경로 분석
  - 비정상 패킷 추적로 감염 경로 및 확산 방식 파악

- **사이버 공격 대응**
  - DDoS 공격 시 유형 파악
  - 공격 출발지(IP, Botnet 규모 등) 추적

### 프로젝트 범위

- **분석할 프로토콜**
  - IPv4 패킷
  - ARP 패킷

- **지원할 기능**
  - 사용 가능한 네트워크 인터페이스 탐색 및 선택
  - 선택된 인터페이스에서 실시간 패킷 캡처
  - 캡처된 패킷의 유형(IPv4, ARP) 식별
  - IPv4 및 ARP 헤더 파싱 및 정보 출력

- **프로젝트 목표**
  - **기술적 목표**
    - 라이브러리를 이용한 패킷 캡처 원리 이해
    - 이더넷, IPv4, ARP 헤더 구조 파싱 및 출력
    - 필터 기반 패킷 선택 및 분석 구현
  - **학습적 목표**
    - 네트워크 계층 구조 이해(이더넷 → IP → 상위 프로토콜)
    - 보안/해킹 관점에서 패킷 분석 필요성 체감
    - TCP/UDP, ICMP 등 분석 확장을 위한 기반 마련

---

## 01. 개념

### 00. 네트워크 패킷이란?
- 통신망을 통해 전송하기 쉽게 데이터를 잘게 나눈 전송 단위
- 큰 데이터를 그대로 보내면 효율이 떨어지므로 작은 조각(패킷)으로 나누어 전송

### 01. 패킷의 구조
- **헤더(Header)** : 송·수신지 주소, 프로토콜 종류, 길이 등 제어 정보 포함
- **페이로드(Payload)** : 실제 전송하려는 데이터
- **트레일러(Trailer)** : 오류 검출 코드 등 포함 (일부 프로토콜)

**IPv4 헤더 주요 필드**
- Version, Header Length
- Type-of-Service Flags
- Total Packet Length
- Fragment Identifier, Fragmentation Flags + Offset
- Time-to-Live
- Protocol Identifier
- Header Checksum
- Source / Destination IP

### 02. IPv4 개요
- 인터넷에서 가장 많이 사용되는 네트워크 계층 프로토콜
- 32비트 주소 체계 → 약 43억 개 IP 주소 제공
- 주요 헤더 정보
  - Version, Header Length, Total Length
  - Source IP, Destination IP
  - Protocol (TCP, UDP 등 상위 계층 식별)

### 03. ARP 개요
- **ARP(Address Resolution Protocol)** : IP → MAC 주소 변환
- **주요 메시지**
  - ARP Request : IP → MAC 주소 요청
  - ARP Reply : 요청 받은 시스템이 MAC 주소를 알려줌
- **ARP 헤더 주요 필드**
  - Hardware Type, Protocol Type
  - Hardware Address Length, Protocol Address Length
  - Operation (Request=1, Reply=2)
  - Sender / Target MAC
  - Sender / Target IP

### 04. 헤더 구조에 따른 구조체 설계
- IPv4 헤더 구조체
- Ethernet 헤더 구조체
- ARP 헤더 구조체

---

## 02. 개발 환경

### 01. 사용 언어
- C언어

### 02. 사용 라이브러리
| 헤더 파일 | 용도 |
|-----------|------|
| stdio.h | 표준 입출력 함수 (printf, scanf) |
| pcap.h | 패킷 캡처 기능 제공 |
| winsock2.h | Windows 소켓 API |
| stdint.h | 자료형 정의 (uint8_t, uint16_t 등) |
| ctype.h | 문자 판별/변환 (isprint) |
| windows.h | Windows API |

### 03. 사용 패키지
- Npcap
- Visual Studio

---

## 03. 프로그램 구조

### 동작 흐름
1. 시작 화면: 네트워크 인터페이스 선택
   - 사용 가능한 인터페이스 목록 표시
   - 사용자 선택 → 패킷 캡처 준비
2. 패킷 캡처 시작
   - 캡처할 패킷 종류 선택
     - IPv4 패킷
     - ARP 패킷
3. 결과 출력
   - 수신 패킷의 헤더 정보 및 일부 데이터 화면 출력
   - IPv4 : 출발지/목적지 IP, MAC, 프로토콜, 패킷 길이
   - ARP : Sender/Target IP, Sender/Target MAC, Request/Reply 구분

### 한계와 개선점
- IPv4와 ARP만 분석 가능 → TCP, UDP, ICMP 등 확장 필요
- 콘솔창 사용 → GUI 추가 가능
- 하나의 C 파일에 코드 존재 → 모듈화 필요

---

## 참고 자료
- [네이버 블로그: 패킷 분석 개요](https://naver.me/FfBBivJP)
- [Velog: PCAP 패킷 캡처 가이드](https://velog.io/@white-jelly/%ED%8C%A8%ED%82%B7-%EC%BA%A1%EC%B2%98-PCAP-vovp9ub3)
- [Google 공유 자료](https://share.google/Igbzp20gqKySFnaHd)
- [YouTube: PCAP 패킷 분석 영상](https://youtu.be/V1ZgssWMlRY?si=Q7Q-8LfAjwjDVLjz)
- [네이버 블로그: 실습 예제](https://blog.naver.com/kdepirate/50035609491)
- [Tistory 블로그: PCAP 기본 설정](https://randalp.tistory.com/9)
- [Tistory 블로그: 패킷 캡처 실습](https://thfist-1071.tistory.com/122)
- [Tistory 블로그: ARP/IPv4 분석](https://kaspyx.tistory.com/14)
- [Tistory 블로그: 헤더 파싱 방법](https://lsea.tistory.com/236)
- [Tistory 블로그: 패킷 데이터 출력](https://tttsss77.tistory.com/122)
- [Tistory 블로그: Wireshark 연동](https://run-it.tistory.com/16)
- [네이버 블로그: 네트워크 분석 팁](https://m.blog.naver.com/iamchancokr/60184885058)
- [Tistory: What Documentary](https://whatdocumentary.tistory.com/5)
- [Tistory 블로그: 패킷 분석 예제](https://biji-jjigae.tistory.com/46)
- [Tistory 블로그: 네트워크 실습](https://jin8371.tistory.com/24)
- [Tistory 블로그: 패킷 분석 응용](https://sugerent.tistory.com/240)

-
- [Tistory: What Documentary](https://www.tistory.com/)
