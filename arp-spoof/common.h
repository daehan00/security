#ifndef COMMON_H
#define COMMON_H

#include <QString>

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

void getMyInfo(IpFlow& flow);

#endif
