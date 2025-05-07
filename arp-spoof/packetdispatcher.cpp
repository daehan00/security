#include "packetdispatcher.h"
#include "libnet-headers.h"

PacketDispatcher::PacketDispatcher(PacketQueue* queue, const IpFlow& flow, QObject* parent)
    : QThread(parent), queue(queue), flow(flow)
{}

void PacketDispatcher::stop() {
    running = false;
    emit logMessage("[Dispatcher] 스레드 종료");
}

void PacketDispatcher::setInfector(Infector* i) {
    infector = i;
    emit logMessage("[Dispatcher] set infector");

}

void PacketDispatcher::run() {
    emit logMessage("[Dispatcher] 스레드 시작됨");
    while (running) {
        struct pcap_pkthdr* header;
        const u_char* pkt;

        int res = pcap_next_ex(flow.handle, &header, &pkt);
        if (res == 0) continue; // timeout
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) break;

        processPacket(header, pkt);
    }
}

void PacketDispatcher::processPacket(const struct pcap_pkthdr* header, const u_char* packet) {
    // if (header->caplen > 1500) return;

    PEthHdr eth = (PEthHdr)packet;
    if (eth->type() == EthHdr::Arp) {
        EthArpPacket* arp = (EthArpPacket*)packet;
        if (arp->arp_.op() == ArpHdr::Reply &&
            arp->arp_.sip() == flow.sender_ip &&
            arp->arp_.tmac() == flow.sender_mac) {
            // 감염이 풀렸다고 판단
            if (infector) infector->trigger();
        }
        return; // ARP는 큐에 넣지 않음
    }

    if (eth->type() != EthHdr::Ip4) return;

    // IP 검사
    const struct sniff_ip* ip_hdr = (struct sniff_ip*)(packet + sizeof(EthHdr));
    Ip src_ip = Ip(ntohl(ip_hdr->ip_src.s_addr));
    Ip dst_ip = Ip(ntohl(ip_hdr->ip_dst.s_addr));

    SharedPacket spkt;
    spkt.data = QByteArray((const char*)packet, header->caplen);

    if (src_ip == flow.sender_ip && dst_ip == flow.target_ip) {
        spkt.toSender = false; // sender → target
        queue->enqueue(spkt);
    } else if (src_ip == flow.target_ip && dst_ip == flow.sender_ip) {
        spkt.toSender = true; // target → sender
        queue->enqueue(spkt);
    }
}
