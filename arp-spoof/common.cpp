#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>

#include "common.h"

void PacketQueue::enqueue(const SharedPacket& packet) {
    QMutexLocker locker(&mutex);
    queue.enqueue(packet);
    cond.wakeOne();
}

SharedPacket PacketQueue::dequeue() {
    QMutexLocker locker(&mutex);
    while (queue.isEmpty() && running) {
        cond.wait(&mutex);
    }
    if (!running && queue.isEmpty()) return SharedPacket();
    return queue.dequeue();
}

void PacketQueue::stop() {
    QMutexLocker locker(&mutex);
    running = false;
    cond.wakeAll();
}

void saveMyIpMacAddr(IpFlow& flow) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        exit(1);
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, flow.iface.toStdString().c_str(), IFNAMSIZ - 1);

    // MAC 주소 얻기
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl - get MAC");
        close(fd);
        exit(1);
    }
    flow.my_mac = Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);

    // IP 주소 얻기
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl - get IP");
        close(fd);
        exit(1);
    }
    struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
    flow.my_ip = Ip(ipaddr->sin_addr.s_addr);

    close(fd);
}

QMutex pcapSendMutex;
