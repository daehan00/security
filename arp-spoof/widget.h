#ifndef WIDGET_H
#define WIDGET_H

#include <QWidget>

#include "packetdispatcher.h"
#include "packetrelay.h"
#include "infector.h"

QT_BEGIN_NAMESPACE
namespace Ui { class Widget; }
QT_END_NAMESPACE

class Widget : public QWidget
{
    Q_OBJECT

public:
    Widget(QWidget *parent = nullptr);
    ~Widget();

private slots:
    void on_setInterfacePb_clicked();
    void on_startPb_clicked();
    void on_stopPb_clicked();
    void on_ipAddrTable_cellDoubleClicked(int row, int column);
    void on_clearPb_clicked();

    void onFatalError(const QString& msg);

private:
    Ui::Widget *ui;

    IpFlow flow;
    PacketQueue* queue = nullptr;
    PacketDispatcher* dispatcher = nullptr;
    PacketRelay* relay = nullptr;
    Infector* infector = nullptr;

    void updateUiOnAttackState(bool busy);
    void appendStatus(const QString& msg);
    bool loadArpTable(const QString iface);
    void buildFlowFromUi(IpFlow& flow);

    bool initAttackFlow();
    void createThreads();
    void connectThreadSignals();
    void startThreads();
};
#endif // WIDGET_H
