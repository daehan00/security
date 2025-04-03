#include "widget.h"
#include "ui_widget.h"
# include <QMessageBox>

// int money{0};


Widget::Widget(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Widget)
{
    ui->setupUi(this);
}

Widget::~Widget()
{
    delete ui;
}

void Widget::changeMoney(int diff) {
    money += diff;
    ui->lcdNumber->display(money);
}

bool Widget::checkMoney(int cost) {
    if (money > cost) {
        return true;
    } else{
        return false;
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


void Widget::on_pbClear_clicked()
{
    money = 0;
    ui->lcdNumber->display(money);
    QMessageBox msgbx;
    msgbx.information(nullptr,"remain", "10won");
}


void Widget::on_pbCoffee_clicked()
{
    QMessageBox msgbx;
    if (checkMoney(100)) {
        changeMoney(-100);
        msgbx.information(nullptr,"Output", "10won");
    } else {

    }
}


void Widget::on_pbMilktea_clicked()
{

}


void Widget::on_pbJasmintea_clicked()
{

}


void Widget::on_pbLatte_clicked()
{

}

