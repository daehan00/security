#ifndef COMMON_H
#define COMMON_H

#include <QString>

#include <QQueue>
#include <QMutex>
#include <QWaitCondition>

#include "ip.h"
#include "mac.h"
#include "ethhdr.h"
#include "arphdr.h"
#include "pcap.h"

struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};

struct IpFlow {
    QString iface;
    Ip sender_ip; // host byte order
    Ip target_ip; // host byte order
    Ip my_ip;
    Mac sender_mac;
    Mac target_mac;
    Mac my_mac;
    pcap_t* handle;
};

struct SharedPacket {
    QByteArray data;
    bool toSender; // true면 sender로 보내기, false면 target으로

    PEthHdr ethHdr() {
        if (static_cast<size_t>(data.size()) < sizeof(EthHdr)) return nullptr;
        return reinterpret_cast<PEthHdr>(data.data());
    }
};

class PacketQueue {
public:
    void enqueue(const SharedPacket& packet);
    SharedPacket dequeue(); // blocking
    void stop(); // relay에서 종료 시 사용

private:
    QQueue<SharedPacket> queue;
    QMutex mutex;
    QWaitCondition cond;
    bool running = true;
};

void saveMyIpMacAddr(IpFlow& flow);

#endif
