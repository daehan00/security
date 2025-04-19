#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>
#include <libnet-headers.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

void formatMac(const u_char* mac, char* outBuf, size_t bufSize) {
    snprintf(outBuf, bufSize, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 0, 1000, errbuf); // promiscuous mode off
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue; // timeout
        if (res == -1 || res == -2) { // error
            printf("pcap_next_ex error: %s\n", pcap_geterr(pcap));
            break;
        }

        // ethernet header valid check
        if (header->caplen < SIZE_ETHERNET) continue;

        // IPv4 packet only
        const struct sniff_ethernet* eth = (struct sniff_ethernet*)(packet);
        if (ntohs(eth->ether_type) != 0x0800) {  // Not IPv4
            continue;
        }

        const struct sniff_ip* ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
        // ip header valid check
        uint32_t sizeIp = IP_HL(ip) * 4;
        if (sizeIp < SIZE_IP_MINIMUM || sizeIp > SIZE_IP_MAXIMUM) continue;


        // TCP packet only
        if (ip->ip_p != IPPROTO_TCP) {
            continue;
        }

        const struct sniff_tcp* tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + sizeIp);
        // tcp header valid check
        uint32_t sizeTcp = TH_OFF(tcp) * 4;
        if (sizeTcp < SIZE_IP_MINIMUM || sizeTcp > SIZE_IP_MAXIMUM) continue;

        char srcMac[18];
        char dstMac[18];
        char dstIp[INET_ADDRSTRLEN];
        char srcIp[INET_ADDRSTRLEN];
        formatMac(eth->ether_shost, srcMac, sizeof(srcMac));
        formatMac(eth->ether_dhost, dstMac, sizeof(dstMac));
        inet_ntop(AF_INET, &(ip->ip_dst), dstIp, sizeof(dstIp));
        inet_ntop(AF_INET, &(ip->ip_src), srcIp, sizeof(srcIp));

        printf("[Header]\n");
        printf(" %-8s %-17s   %-8s %-17s\n", "Dst MAC :", dstMac, "Src MAC:", srcMac);
        printf(" %-8s %-17s   %-8s %-17s\n", "Dst IP  :", dstIp, "Src IP:", srcIp);
        printf(" %-8s %-8u            %-8s %-8u\n", "Dst Port:", ntohs(tcp->th_dport), "Src Port:", ntohs(tcp->th_sport));

        uint32_t payloadOffset = SIZE_ETHERNET + sizeIp + sizeTcp;
        const u_char* payload = packet + SIZE_ETHERNET + sizeIp + sizeTcp;
        int payloadLen = header->caplen - payloadOffset;

        if (payloadLen > 0) {
            printf("[Payload]\n ");
            int printLen;
            if (payloadLen > 20) {
                printLen = 20;
            } else printLen = payloadLen;

            for (int i = 0; i < printLen; ++i) {
                printf("%02X ", payload[i]);
                if ((i + 1) % 16 == 0) printf("\n ");
            }
            printf("\n");
        }
        printf("-------------------------------------------------------------\n");
    }
    pcap_close(pcap);
}
