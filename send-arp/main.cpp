#include <cstdio>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <cstring>
#include <net/if_dl.h>
#include <ifaddrs.h>
#include "ethhdr.h"
#include "arphdr.h"


#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

#define MAX_PAIR 10

typedef struct {
    char* sender_ip;
    Mac sender_mac;
    char* target_ip;
    Mac target_mac;
} IpPair;

typedef struct {
    char* dev_;
    IpPair pairs[MAX_PAIR];
    int count;
} Param;

Param param = {
    .dev_ = nullptr,
    .pairs = {},
    .count = 0
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc < 4 || (argc - 2) % 2 != 0) {
        printf("syntax: send-arp-test <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2> ...]\n");
        printf("example: send-arp-test eth0 192.168.0.10 192.168.0.1 192.168.0.20 192.168.0.1\n");
        return false;
    }

    param->dev_ = argv[1];
    int pair_count = (argc - 2) / 2;
    if (pair_count > MAX_PAIR) {
        fprintf(stderr, "Too many IP pairs! Maximum allowed is %d.\n", MAX_PAIR);
        return false;
    }

    for (int i = 0; i < pair_count; i++) {
        param->pairs[i].sender_ip = argv[2 + i * 2];
        param->pairs[i].target_ip = argv[3 + i * 2];
    }
    param->count = pair_count;

    return true;
}

Mac getMyMac(const char* dev) {
    struct ifaddrs* ifaddr;
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(1);
    }

    for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;
        if ((strcmp(ifa->ifa_name, dev) == 0) && (ifa->ifa_addr->sa_family == AF_LINK)) {
            struct sockaddr_dl* sdl = (struct sockaddr_dl*)ifa->ifa_addr;
            uint8_t* mac = (uint8_t*)LLADDR(sdl);
            Mac result(mac);
            freeifaddrs(ifaddr);
            return result;
        }
    }

    fprintf(stderr, "No such device or no MAC address found\n");
    freeifaddrs(ifaddr);
    exit(1);
}

Mac getMacFromIp(char ipAddr) {
    return Mac("");
}

void setArpPacket(EthArpPacket* packet, Param param) {

}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv)) return -1;

    printf("Interface: %s\n", param.dev_);
    for (int i = 0; i < param.count; i++) {
        printf("#%u Sender: %s → Target: %s\n", i+1, param.pairs[i].sender_ip, param.pairs[i].target_ip);
    }

    Mac myMac = getMyMac(param.dev_);

	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, 0, 0, 0, errbuf);
	if (pcap == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", param.dev_, errbuf);
		return EXIT_FAILURE;
	}
    for (int i=0; i<param.count; i++) {
        EthArpPacket packet;

        char* senderIp = param.pairs[i].sender_ip;
        char* targetIp = param.pairs[i].target_ip;

        packet.eth_.dmac_ = Mac("00:00:00:00:00:00");
        packet.eth_.smac_ = myMac;
        packet.eth_.type_ = htons(EthHdr::Arp);

        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::Size;
        packet.arp_.pln_ = Ip::Size;
        packet.arp_.op_ = htons(ArpHdr::Reply);
        packet.arp_.smac_ = myMac;
        packet.arp_.sip_ = htonl(Ip(targetIp));
        packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
        packet.arp_.tip_ = htonl(Ip(senderIp));

        int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
        }
    }
	pcap_close(pcap);
}
