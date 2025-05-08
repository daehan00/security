#ifndef PACKETDISPATCHER_H
#define PACKETDISPATCHER_H

#include <QThread>
#include "common.h"
#include <infector.h>

class PacketDispatcher : public QThread {
    Q_OBJECT
public:
    PacketDispatcher(PacketQueue* queue, const IpFlow& flow, QObject* parent = nullptr);
    void stop();
    void setInfector(Infector* infector);

signals:
    void logMessage(const QString&);

protected:
    void run() override;

private:
    PacketQueue* queue;
    IpFlow flow;
    std::atomic<bool> running {true};
    Infector* infector = nullptr;

    void handleArpPacket(const EthArpPacket& arp);
    void handleIpPacket(const PEthHdr eth, const u_char* packet, int len);
    void processPacket(const struct pcap_pkthdr* header, const u_char* packet);
};

#endif // PACKETDISPATCHER_H
