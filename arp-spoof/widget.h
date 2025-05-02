#ifndef WIDGET_H
#define WIDGET_H

#include <QWidget>
#include <QThread>
#include <QTableWidgetItem>

#include "packetdispatcher.h"
#include "packetrelay.h"
#include "infector.h"

QT_BEGIN_NAMESPACE
namespace Ui {
class Widget;
}
QT_END_NAMESPACE

class Widget : public QWidget
{
    Q_OBJECT

public:
    explicit Widget(const QString& interface, QWidget *parent = nullptr);
    ~Widget();

private slots:
    void on_startPb_clicked();
    void on_stopPb_clicked();
    void on_ipAddrTable_itemClicked(QTableWidgetItem *item);

private:
    void initUiState();
    void loadArpTable(); // ARP 테이블 로딩
    void updateStatus(const QString& msg); // 로그 출력

    QString dev_;  // 선택된 인터페이스
    QString senderIp_;
    QString targetIp_;
    QVector<QPair<QString, QString>> arpTable_;

    void initUi();
    void connectSignals();
    void updateStartStopState();
    void loadArpDataToTable();
    void log(const QString& msg);

    Ui::Widget *ui;
    QString iface_; // 선택된 인터페이스
    QList<ArpEntry> arpEntries_; // 로드된 ARP 테이블 정보

    PacketDispatcher* dispatcher;
    PacketRelay* relay;
    Infector* infector;
};
#endif // WIDGET_H
