#ifndef COMMON_H
#define COMMON_H

#include <QString>
#include <QPair>
#include <vector>
#include "ip.h"
#include "mac.h"
#include "ethhdr.h"
#include "arphdr.h"
#include "pcap.h"

struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};

typedef struct {
    char* interface;
    Ip sender_ip; // host byte order
    Ip target_ip; // host byte order
    Mac sender_mac;
    Mac my_mac;
} IpFlow;

struct ArpEntry {
    Ip ip;
    Mac mac;
};

struct FlowPair {
    Ip senderIp;
    Mac senderMac;
    Ip targetIp;
    Mac targetMac;
};

using ArpTable = std::vector<ArpEntry>;
using FlowList = std::vector<FlowPair>;

#endif
