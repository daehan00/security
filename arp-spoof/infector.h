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

    enum class InfectTarget {
        Sender,
        Target
    };

    QMutex mutex;
    QWaitCondition cond;
    std::atomic<bool> triggered {false};
    std::atomic<bool> running {true};

    void sendInfection(InfectTarget target);
};

#endif // INFECTOR_H
