#ifndef PACKETRELAY_H
#define PACKETRELAY_H

#include "common.h"

class PacketRelay : public QThread {
    Q_OBJECT
public:
    explicit PacketRelay(PacketQueue* queue, const IpFlow& flow, QObject* parent = nullptr);
    void stop();

signals:
    void logMessage(const QString&);
    void fatalError(const QString& msg);

protected:
    void run() override;

private:
    PacketQueue* queue;
    IpFlow flow;
    std::atomic<bool> running {true};
};

#endif // PACKETRELAY_H
