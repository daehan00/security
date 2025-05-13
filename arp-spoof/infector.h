#ifndef INFECTOR_H
#define INFECTOR_H

# include <QThread>
#include <atomic>

#include "common.h"

class Infector : public QThread {
    Q_OBJECT

public:
    explicit Infector(const IpFlow& flow, QObject* parent = nullptr);
    ~Infector();

    void trigger();
    void stop();

signals:
    void logMessage(const QString&);
    void fatalError(const QString& msg);

protected:
    void run() override;

private:
    IpFlow flow;
    EthArpPacket senderInfectionPacket;
    EthArpPacket targetInfectionPacket;

    std::atomic<bool> triggered {false};
    std::atomic<bool> running {true};

    QMutex mutex;
    QWaitCondition cond;

    void sendInfection(bool toSender);
};

#endif // INFECTOR_H
