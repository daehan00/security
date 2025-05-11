#include "packetdispatcher.h"
#include "sniff_headers.h"

PacketDispatcher::PacketDispatcher(PacketQueue* queue, const IpFlow& flow, QObject* parent)
    : QThread(parent), queue(queue), flow(flow)
{}

void PacketDispatcher::stop() {
    running = false;
    emit logMessage("[Dispatcher] 스레드 종료");
}

void PacketDispatcher::setInfector(Infector* i) {
    infector = i;
}

void PacketDispatcher::run() {
    emit logMessage("[Dispatcher] 스레드 시작됨");
    while (running) {
        struct pcap_pkthdr* header;
        const u_char* pkt;

        int res = pcap_next_ex(flow.handle, &header, &pkt);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            emit fatalError("[Dispatcher] 패킷 수집 실패: " + QString(pcap_geterr(flow.handle)));
            break;
        }
        processPacket(header, pkt);
    }
}

void PacketDispatcher::handleArpPacket(const EthArpPacket& arp) {
    static const Mac BroadcastMac("ff:ff:ff:ff:ff:ff");

    if (arp.arp_.op_ == ArpHdr::Request &&
        arp.arp_.sip_ == flow.target_ip &&
        arp.eth_.dmac_ == BroadcastMac &&
        infector) {
        infector->trigger();
    }
}

void PacketDispatcher::handleIpPacket(const PEthHdr eth, const u_char* packet, int len) {
    const struct sniff_ip* ip_hdr = (struct sniff_ip*)(packet + sizeof(EthHdr));

    Ip src_ip = Ip(ntohl(ip_hdr->ip_src.s_addr));
    Ip dst_ip = Ip(ntohl(ip_hdr->ip_dst.s_addr));

    SharedPacket spkt;
    spkt.data = QByteArray((const char*)packet, len);

    if (src_ip == flow.sender_ip || eth->smac() == flow.sender_mac) {
        spkt.toSender = false;
        queue->enqueue(spkt);
    } else if (dst_ip == flow.sender_ip && eth->dmac() == flow.my_mac) {
        spkt.toSender = true;
        queue->enqueue(spkt);
    }
}

void PacketDispatcher::processPacket(const struct pcap_pkthdr* header, const u_char* packet) {
    // if (header->caplen > 1500) return;

    EthHdr* eth = reinterpret_cast<EthHdr*>(const_cast<u_char*>(packet));
    if (eth->type() == EthHdr::Arp) {
        EthArpPacket arp = *reinterpret_cast<const EthArpPacket*>(packet);
        handleArpPacket(arp);
        return;
    }

    if (eth->type() != EthHdr::Ip4) return;

    handleIpPacket(eth, packet, header->caplen);
}
