#ifndef INFECTOR_H
#define INFECTOR_H

# include <QThread>
#include <QMutex>
#include <QWaitCondition>
#include <atomic>

#include "common.h"

class Infector : public QThread {
    Q_OBJECT

public:
    explicit Infector(const IpFlow& flow, QObject* parent = nullptr);
    ~Infector();

    void trigger();       // 외부에서 즉시 감염 요청
    void killTrigger();   // 스레드 종료 요청

signals:
    void logMessage(const QString&);


protected:
    void run() override;


private:
    IpFlow flow;
    EthArpPacket senderInfectionPacket;
    EthArpPacket targetInfectionPacket;

    enum class InfectTarget {
        Sender,
        Target
    };

    QMutex mutex;
    QWaitCondition cond;
    std::atomic<bool> triggered {false};
    std::atomic<bool> running {true};

    void sendInfection(InfectTarget target);  // ARP 감염 패킷 전송
};

#endif // INFECTOR_H
