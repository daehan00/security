#include "widget.h"
#include "ui_widget.h"
#include <QMessageBox>


Widget::Widget(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Widget)
{
    ui->setupUi(this);
    setPb();
}

Widget::~Widget()
{
    delete ui;
}

void Widget::changeMoney(int diff, bool reset) {
    if (reset) {
        money = 0;
    } else {
        money += diff;
    }
    ui->lcdNumber->display(money);
    setPb();
}

void Widget::returnMoney() {
    int coin[4] = {500, 100, 50, 10};
    QString msg = "잔돈: ";
    for (int i=0; i<4; i++) {
        int change = money / coin[i];
        if (change>0) {
            msg += QString::number(coin[i]) + "원 " + QString::number(change) + "개, ";
        }
        money = money % coin[i];
    }
    msg.chop(2);
    showMsgbox(msg);
}

void Widget::showMsgbox(QString msg) {
    QMessageBox::information(this, "알림", msg);
}

void Widget::setPb() {
    QList<QPushButton*> buttons = {
        ui->pbReset,
        ui->pbCoffee,
        ui->pbTea,
        ui->pbMilk
    };

    int price[4]  = {1, 100, 150, 200};

    for (int i=0; i<buttons.size(); i++) {
        buttons[i]->setEnabled(money >= price[i]);
    }
}


void Widget::on_pb10_clicked()
{
    changeMoney(10);
}


void Widget::on_pb50_clicked()
{
    changeMoney(50);
}


void Widget::on_pb100_clicked()
{
    changeMoney(100);
}


void Widget::on_pb500_clicked()
{
    changeMoney(500);
}


void Widget::on_pbReset_clicked()
{
    returnMoney();
    changeMoney(0, true);
}


void Widget::on_pbCoffee_clicked()
{
    changeMoney(-100);
    showMsgbox("Coffee");
}


void Widget::on_pbTea_clicked()
{
    changeMoney(-150);
    showMsgbox("Tea");
}


void Widget::on_pbMilk_clicked()
{
    changeMoney(-200);
    showMsgbox("Milk");
}


