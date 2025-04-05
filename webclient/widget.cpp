#include "widget.h"
#include "ui_widget.h"

Widget::Widget(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Widget)
{
    ui->setupUi(this);

    socket_ = &tcpSocket_;
    QObject::connect(&tcpSocket_, &QAbstractSocket::connected, this, &Widget::doConnected);
    QObject::connect(&tcpSocket_, &QAbstractSocket::disconnected, this, &Widget::doDisconnected);
    QObject::connect(&tcpSocket_, &QIODevice::readyRead, this, &Widget::doReadyRead);
    QObject::connect(&sslSocket_, &QAbstractSocket::connected, this, &Widget::doConnected);
    QObject::connect(&sslSocket_, &QAbstractSocket::disconnected, this, &Widget::doDisconnected);
    QObject::connect(&sslSocket_, &QIODevice::readyRead, this, &Widget::doReadyRead);

    connect(&tcpSocket_, &QAbstractSocket::stateChanged, this, &Widget::updatePb);
    connect(&sslSocket_, &QAbstractSocket::stateChanged, this, &Widget::updatePb);
}

Widget::~Widget()
{
    delete ui;
}

void Widget::updatePb() {
    QAbstractSocket::SocketState state = socket_->state();
    bool disable=false;

    if (state==QAbstractSocket::ConnectedState) {
        ui->pbConnect->setEnabled(false);
        ui->pbSend->setEnabled(true);
        ui->pbDisconnect->setEnabled(true);
        disable=true;
    } else if (state==QAbstractSocket::UnconnectedState) {
        ui->pbConnect->setEnabled(true);
        ui->pbSend->setEnabled(false);
        ui->pbDisconnect->setEnabled(false);
    }
    ui->cbSsl->setDisabled(disable);
    ui->leHost->setDisabled(disable);
    ui->lePort->setDisabled(disable);

}

void Widget::doConnected() {
    QString msg = "connected\r\n";
    ui->pteMessage->insertPlainText(msg);
}

void Widget::doDisconnected() {
    QString msg = "disconnected\r\n";
    ui->pteMessage->insertPlainText(msg);
}

void Widget::doReadyRead() {
    QString msg = socket_->readAll();
    ui->pteMessage->insertPlainText((msg));
}

void Widget::on_pbConnect_clicked()
{
    QString msg;
    if (socket_==&sslSocket_) {
        sslSocket_.connectToHostEncrypted(ui->leHost->text(), ui->lePort->text().toUShort());
        msg = "connect with SSL\r\n";
    } else {
        tcpSocket_.connectToHost(ui->leHost->text(), ui->lePort->text().toUShort());
        msg = "connect with TCP\r\n";
    }
    ui->pteMessage->insertPlainText(msg);
}


void Widget::on_pbDisconnect_clicked()
{
    socket_->disconnectFromHost();
}


void Widget::on_pbSend_clicked()
{
    socket_->write(ui->pteSend->toPlainText().toUtf8());
}


void Widget::on_pbClear_clicked()
{
    ui->pteMessage->clear();
}


void Widget::on_cbSsl_checkStateChanged(const Qt::CheckState &arg1)
{
    if (arg1==Qt::Checked) {
        socket_ = &sslSocket_;
        ui->lePort->setText("443");
    } else {
        socket_ = &tcpSocket_;
        ui->lePort->setText("80");
    }
}

