#include "widget.h"
#include "ui_widget.h"

#include <QProcess>
#include <QDateTime>
#include <QMessageBox>

Widget::Widget(QWidget *parent)
    : QWidget(parent), ui(new Ui::Widget)
{
    ui->setupUi(this);
    updateUiOnAttackState(false);
}

Widget::~Widget() {
    delete ui;
}

// UI 상태 및 로그 관리

void Widget::updateUiOnAttackState(bool busy) {
    ui->startPb->setEnabled(!busy);
    ui->setInterfacePb->setEnabled(!busy);
    ui->ipAddrTable->setEnabled(!busy);
    ui->stopPb->setEnabled(busy);
    ui->clearPb->setEnabled(!busy && !ui->senderIpTb->toPlainText().trimmed().isEmpty());
}

void Widget::appendStatus(const QString& msg) {
    QString time = QDateTime::currentDateTime().toString("hh:mm:ss");
    ui->logTb->append("[" + time + "] " + msg);
}

// ==============================
// Flow 초기화 및 스레드 관리

void Widget::buildFlowFromUi(IpFlow& flow) {
    flow.iface = ui->interfaceTe->toPlainText().trimmed();
    flow.sender_ip = Ip(ui->senderIpTb->toPlainText().toStdString());
    flow.target_ip = Ip(ui->targetIpTb->toPlainText().toStdString());
    flow.sender_mac = Mac(ui->senderMacTb->toPlainText().toStdString());
    flow.target_mac = Mac(ui->targetMacTb->toPlainText().toStdString());
    saveMyIpMacAddr(flow);

    char errbuf[PCAP_ERRBUF_SIZE];
    QByteArray ifaceBytes = flow.iface.toUtf8();
    flow.handle = pcap_open_live(ifaceBytes.constData(), BUFSIZ, 1, 1, errbuf);
    if (!flow.handle) {
        QMessageBox::critical(this, "오류", "인터페이스 열기에 실패했습니다: " + QString(errbuf));
    }
}

bool Widget::initAttackFlow() {
    IpFlow newFlow;
    buildFlowFromUi(newFlow);
    if (!newFlow.handle) return false;
    flow = newFlow;
    return true;
}

void Widget::createThreads() {
    queue = new PacketQueue();
    dispatcher = new PacketDispatcher(queue, flow);
    infector = new Infector(flow);
    relay = new PacketRelay(queue, flow);
    dispatcher->setInfector(infector);
}

void Widget::connectThreadSignals() {
    connect(dispatcher, &PacketDispatcher::logMessage, this, &Widget::appendStatus);
    connect(infector, &Infector::logMessage, this, &Widget::appendStatus);
    connect(relay, &PacketRelay::logMessage, this, &Widget::appendStatus);

    connect(dispatcher, &PacketDispatcher::fatalError, this, &Widget::onFatalError);
    connect(infector, &Infector::fatalError, this, &Widget::onFatalError);
    connect(relay, &PacketRelay::fatalError, this, &Widget::onFatalError);
}

void Widget::startThreads() {
    dispatcher->start();
    infector->start();
    relay->start();
}

// ==============================
// UI 슬롯 함수

void Widget::on_setInterfacePb_clicked() {
    QString iface = ui->interfaceTe->toPlainText().trimmed();
    if (iface.isEmpty()) {
        QMessageBox::warning(this, "오류", "인터페이스를 입력해주세요.");
        return;
    }

    if (loadArpTable(iface)) {
        appendStatus("[INFO] " + iface + " ARP 테이블 불러오기 완료");
    } else {
        QMessageBox::warning(this, "오류", "인터페이스의 ARP 테이블을 불러올 수 없습니다.");
    }
}

void Widget::on_startPb_clicked() {
    appendStatus("[INFO] 공격 시작 (sender: " + ui->senderIpTb->toPlainText() + ")");
    updateUiOnAttackState(true);

    if (!initAttackFlow()) {
        updateUiOnAttackState(false);
        return;
    }

    createThreads();
    connectThreadSignals();
    startThreads();
}

void Widget::on_stopPb_clicked() {
    appendStatus("[INFO] 공격 중지 요청됨");

    if (dispatcher && dispatcher->isRunning()) dispatcher->stop();
    if (relay && relay->isRunning()) relay->stop();
    if (infector && infector->isRunning()) infector->stop();

    if (dispatcher && dispatcher->isRunning()) dispatcher->wait();
    if (relay && relay->isRunning()) relay->wait();
    if (infector && infector->isRunning()) infector->wait();

    delete dispatcher; dispatcher = nullptr;
    delete relay;      relay = nullptr;
    delete infector;   infector = nullptr;

    updateUiOnAttackState(false);
}

void Widget::on_clearPb_clicked() {
    ui->senderIpTb->clear();
    ui->senderMacTb->clear();
    ui->targetIpTb->clear();
    ui->targetMacTb->clear();
    appendStatus("[INFO] Sender/Target 초기화 완료");
    updateUiOnAttackState(false);
}

void Widget::on_ipAddrTable_cellDoubleClicked(int row, int column) {
    if (row < 0 || column < 0) return;

    QTableWidgetItem* ipItem = ui->ipAddrTable->item(row, 0);
    QTableWidgetItem* macItem = ui->ipAddrTable->item(row, 1);
    if (!ipItem || !macItem) return;

    QString ip = ipItem->text();
    QString mac = macItem->text();

    if (ui->targetIpTb->toPlainText().isEmpty()) {
        ui->targetIpTb->setPlainText(ip);
        ui->targetMacTb->setPlainText(mac);
    } else if (ui->senderIpTb->toPlainText().isEmpty()) {
        ui->senderIpTb->setPlainText(ip);
        ui->senderMacTb->setPlainText(mac);
    } else {
        QMessageBox::information(this, "알림", "Target/Sender 가 이미 모두 설정되어 있습니다.");
    }

    updateUiOnAttackState(false);
}

void Widget::onFatalError(const QString& msg) {
    appendStatus("[FATAL] " + msg);
    QMessageBox::critical(this, "오류", msg);

    if (dispatcher) { dispatcher->stop(); delete dispatcher; dispatcher = nullptr; }
    if (relay)      { relay->stop();      delete relay;      relay = nullptr; }
    if (infector)   { infector->stop();   delete infector;   infector = nullptr; }

    updateUiOnAttackState(false);
}

// ==============================
// 유틸 함수: ARP 테이블 로드

bool Widget::loadArpTable(const QString iface) {
    ui->ipAddrTable->clearContents();
    ui->ipAddrTable->setRowCount(0);

    QProcess arp;
    QEventLoop loop;
    QObject::connect(&arp, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), &loop, &QEventLoop::quit);
    arp.start("arp", {"-a"});
    if (!arp.waitForStarted()) {
        appendStatus("[ERROR] arp 시작 실패");
        return false;
    }
    loop.exec();

    QString output = arp.readAllStandardOutput();
    QStringList lines = output.split('\n');
    static const QRegularExpression re(R"(\(?([\d\.]+)\)?\s+at\s+([0-9a-fA-F:]+)\s+(?:\[\w+\]\s+)?on\s+(\w+))");

    int row = 0;
    for (const QString& line : lines) {
        QRegularExpressionMatch match = re.match(line);
        if (!match.hasMatch()) continue;

        QString ip = match.captured(1);
        QString mac = match.captured(2);
        QString dev = match.captured(3);
        if (dev != iface) continue;

        ui->ipAddrTable->insertRow(row);
        ui->ipAddrTable->setItem(row, 0, new QTableWidgetItem(ip));
        ui->ipAddrTable->setItem(row, 1, new QTableWidgetItem(mac));
        row++;
    }

    return row != 0;
}
// ==============================
