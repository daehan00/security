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
    Widget(QWidget *parent = nullptr);
    ~Widget();

    bool loadArpTable(const QString);
    void appendStatus(const QString&);

private slots:
    void on_setInterfacePb_clicked();
    void on_startPb_clicked();
    void on_stopPb_clicked();

    void on_ipAddrTable_cellDoubleClicked(int row, int column);

private:
    Ui::Widget *ui;
    PacketDispatcher* dispatcher;
    PacketRelay* relay;
    Infector* infector;
};
#endif // WIDGET_H
