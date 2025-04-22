#include <cstdio>
#include <cstring>
#include <pcap.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "ethhdr.h"
#include "arphdr.h"

#define MAX_PAIR 10
#define MAX_ATTEMPTS 5
#define WAIT_USEC 10000

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

typedef struct {
    Ip sender_ip; // host byte order
    Ip target_ip; // host byte order
    Mac sender_mac;
} IpPair;

typedef struct {
    char* dev_;
    IpPair pairs[MAX_PAIR];
    int count;
    Mac myMac;
    Ip myIp;
} Param;

Param params = {
    .dev_ = nullptr,
    .pairs = {},
    .count = 0,
    .myMac = Mac(),
    .myIp = Ip()
};

void usage() {
    printf("syntax: send-arp-test <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2> ...]\n");
    printf("example: send-arp-test eth0 192.168.0.20 192.168.0.1\n");
};

void getMyInfo(Param* params) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        exit(1);
    }

    struct ifreq ifr;
    strncpy(ifr.ifr_name, params->dev_, IFNAMSIZ);

    // my MAC address
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl - get MAC");
        close(fd);
        exit(1);
    }
    params->myMac = Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);

    // my IP address
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl - get IP");
        close(fd);
        exit(1);
    }
    struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
    params->myIp = Ip(ntohl(ipaddr->sin_addr.s_addr));

    close(fd);
}

bool parse(Param* params, int argc, char* argv[]) {
    if (argc < 4 || (argc - 2) % 2 != 0) {
        usage();
        return false;
    }

    params->dev_ = argv[1];
    getMyInfo(params); // my information(ip, mac)

    params->count = (argc - 2) / 2;
    if (params->count > MAX_PAIR) {
        fprintf(stderr, "[ERROR] Too many IP pairs! Maximum allowed is %d.\n", MAX_PAIR);
        return false;
    }

    for (int i=0; i<params->count; i++) { // 192.0.0.1 => network byte => host byte
        params->pairs[i].sender_ip = Ip(ntohl(inet_addr(argv[2 + i * 2])));
        params->pairs[i].target_ip = Ip(ntohl(inet_addr(argv[3 + i * 2])));
    }

    return true;
}

Mac queryMacByArp(Ip senderIp) {
    pcap_t* pcap;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap = pcap_open_live(params.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "[ERROR] pcap_open_live(%s) failed: %s\n", params.dev_, errbuf);
        exit(1);
    }

    EthArpPacket packet;
    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ = params.myMac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = params.myMac;
    packet.arp_.sip_ = htonl(params.myIp);
    packet.arp_.tip_ = htonl(senderIp);

    if (pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket)) != 0) {
        fprintf(stderr, "[ERROR] send ARP request failed: %s\n", pcap_geterr(pcap));
        exit(1);
    }

    for (int attempt=0; attempt<MAX_ATTEMPTS; ++attempt) {
        struct pcap_pkthdr* header;
        const u_char* pkt;
        int res = pcap_next_ex(pcap, &header, &pkt);
        if (res == 0) { // if no resposne, wait and retry
            usleep(WAIT_USEC);
            continue;
        }
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            fprintf(stderr, "[ERROR] pcap_next_ex failed: %s\n", pcap_geterr(pcap));
            break;
        }

        EthArpPacket* recv = (EthArpPacket*)pkt;
        if (recv->eth_.type() != EthHdr::Arp) continue;
        if (recv->arp_.op() != ArpHdr::Reply) continue;
        if (recv->arp_.sip() != senderIp) continue;

        Mac senderMac = recv->arp_.smac();
        pcap_close(pcap);
        return senderMac;
    }

    fprintf(stderr, "[ERROR] No ARP reply received for IP %s\n", std::string(senderIp).c_str());
    pcap_close(pcap);
    exit(1);
}

int main(int argc, char* argv[]) {
    if (!parse(&params, argc, argv)) return -1;

    printf("Interface: %s\n", params.dev_);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(params.dev_, 0, 0, 0, errbuf); // only sending
    if (pcap == nullptr) {
        fprintf(stderr, "[ERROR] couldn't open device %s(%s)\n", params.dev_, errbuf);
        return EXIT_FAILURE;
    }

    for (int i=0; i<params.count; i++) {
        EthArpPacket packet;
        Ip senderIp = params.pairs[i].sender_ip;
        Ip targetIp = params.pairs[i].target_ip;
        Mac senderMac = queryMacByArp(senderIp);

        packet.eth_.dmac_ = senderMac;
        packet.eth_.smac_ = params.myMac;
        packet.eth_.type_ = htons(EthHdr::Arp);

        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::Size;
        packet.arp_.pln_ = Ip::Size;
        packet.arp_.op_ = htons(ArpHdr::Reply);
        packet.arp_.smac_ = params.myMac;
        packet.arp_.sip_ = htonl(targetIp); // network byte order
        packet.arp_.tmac_ = senderMac;
        packet.arp_.tip_ = htonl(senderIp);

        int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "[ERROR] pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
        }

        printf("#%u Sender: %s , Target: %s\n", i + 1,
               std::string(senderIp).c_str(),
               std::string(targetIp).c_str());
    }
    pcap_close(pcap);
}
