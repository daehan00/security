#include "packetrelay.h"

PacketRelay::PacketRelay(PacketQueue* queue, const IpFlow& flow, QObject* parent)
    : QThread(parent), queue(queue), flow(flow)
{}

void PacketRelay::stop() {
    running = false;
    queue->stop();
    emit logMessage("[Relay] 스레드 종료");
}

void PacketRelay::run() {
    emit logMessage("[Relay] 스레드 시작됨");
    while (running) {
        SharedPacket packet = queue->dequeue();
        if (packet.data.isEmpty()) break;

        if (auto eth = packet.ethHdr()) {
            eth->smac_ = flow.my_mac;
            if (packet.toSender) {
                eth->dmac_ = flow.sender_mac;
            } else {
                eth->dmac_ = flow.target_mac;
            }
        }

        QMutexLocker locker(&pcapSendMutex);
        int res = pcap_sendpacket(flow.handle,
                                  reinterpret_cast<const u_char*>(packet.data.data()),
                                  packet.data.size());
        if (res != 0) {
            fprintf(stderr, "[ERROR] pcap_sendpacket failed: %s\n", pcap_geterr(flow.handle));
        }
    }
}
