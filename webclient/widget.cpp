#include "widget.h"
#include "ui_widget.h"

Widget::Widget(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Widget)
{
    ui->setupUi(this);
    loadSettings();
    updatePb();

    QList<QAbstractSocket*> sockets = {&tcpSocket_, &sslSocket_};

    for (QAbstractSocket* sk : sockets) {
        QObject::connect(sk, &QAbstractSocket::connected, this, &Widget::doConnected);
        QObject::connect(sk, &QAbstractSocket::disconnected, this, &Widget::doDisconnected);
        QObject::connect(sk, &QIODevice::readyRead, this, &Widget::doReadyRead);
        QObject::connect(sk, &QAbstractSocket::stateChanged, this, &Widget::updatePb);
    };
}

Widget::~Widget()
{
    delete ui;
}

void Widget::updatePb() {
    QAbstractSocket::SocketState state = socket_->state();

    // 연결 상태 확인
    bool connected = false;
    if (state==QAbstractSocket::ConnectedState) {
        connected=true;
    }

    // con에서 활성화하는 객체와 비활성화하는 객체 배열
    QList<QWidget*> con = {ui->pbSend, ui->pbDisconnect};
    QList<QWidget*> dCon = {ui->pbConnect, ui->cbSsl, ui->leHost, ui->lePort};

    // 활성/비활성 적용
    for (QWidget* item : con) {
        item->setEnabled(connected);
    }
    for (QWidget* item : dCon) {
        item->setDisabled(connected);
    }
}

void Widget::saveSettings() {
    QFile file("config.txt");
    if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream out(&file);
        out << ui->leHost->text() << "\n";
        out << ui->lePort->text() << "\n";
        out << (ui->cbSsl->isChecked() ? "1\n" : "0\n");

        out << ui->pteSend->toPlainText();
        if (!ui->pteSend->toPlainText().endsWith('\n'))
            out << "\n";

        out << "<GEOM>\n";
        out << saveGeometry().toBase64() << "\n";


        file.close();
    }
}

void Widget::loadSettings() {
    QFile file("config.txt");

    // 기본값 설정
    if (!file.exists()) {
        ui->leHost->setText("www.naver.com");
        ui->lePort->setText("80");
        ui->pteSend->setPlainText("GET / HTTP/1.1\r\nHost: www.naver.com\r\n\r\n");
        socket_ = &tcpSocket_; // 기본값 socket_ 포인터 설정
        return;
    }

    if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QTextStream in(&file);
        QString line;

        ui->leHost->setText(in.readLine());
        ui->lePort->setText(in.readLine());
        QString sslValue = in.readLine();
        ui->cbSsl->setChecked(sslValue.trimmed() == "1");
        if (ui->cbSsl->isChecked()) { // 기본값 socket_ 포인터 설정
            socket_ = &sslSocket_;
        } else {
            socket_ = &tcpSocket_;
        }

        QString message;
        while (!in.atEnd()) {
            line = in.readLine();
            if (line == "<GEOM>")
                break;
            message += line + "\n";
        }
        ui->pteSend->setPlainText(message);

        // geometry 파싱
        if (!in.atEnd()) {
            QByteArray geometry = QByteArray::fromBase64(in.readLine().toUtf8());
            restoreGeometry(geometry);
        }

        file.close();
    }
}


void Widget::closeEvent(QCloseEvent *event) {
    saveSettings();
    QWidget::closeEvent(event);
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

