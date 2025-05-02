#include "widget.h"
#include "ui_widget.h"

#include <QFile>
#include <QProcess>
#include <QDateTime>
#include <QMessageBox>

Widget::Widget(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Widget)
{
    ui->setupUi(this);
}

Widget::~Widget() {
    delete ui;
}

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
    static const QRegularExpression re(
        R"(\(?([\d\.]+)\)?\s+at\s+([0-9a-fA-F:]+)\s+(?:\[\w+\]\s+)?on\s+(\w+))"
        );

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

void Widget::appendStatus(const QString& msg) {
    QString time = QDateTime::currentDateTime().toString("hh:mm:ss");
    ui->logTb->append("[" + time + "] " + msg);
}

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
        return;
    }
}

void Widget::on_startPb_clicked() {
    appendStatus("[INFO] 공격 시작 (sender: " + ui->senderIpTb->toPlainText() + ")");
    // 실제 공격 로직 연결 예정
}

void Widget::on_stopPb_clicked() {
    appendStatus("[INFO] 공격 중지 요청됨");
    // 공격 스레드 정지 로직 예정
}

void Widget::on_ipAddrTable_cellDoubleClicked(int row, int column) {
    if (row < 0 || column < 0) return;

    // IP 주소는 항상 0번째 열에 있다고 가정
    QTableWidgetItem* item = ui->ipAddrTable->item(row, 0);
    if (!item) return;

    QString ip = item->text();

    // 타겟/보내는 쪽 중 어디에 넣을지는 상황에 따라 다르게 처리 가능
    // 여기서는 target → sender 순으로 선택

    if (ui->targetIpTb->toPlainText().isEmpty()) {
        ui->targetIpTb->setPlainText(ip);
    } else if (ui->senderIpTb->toPlainText().isEmpty()) {
        ui->senderIpTb->setPlainText(ip);
    } else {
        // 이미 둘 다 채워진 경우 사용자에게 알림
        QMessageBox::information(this, "알림", "Target/Sender IP가 이미 모두 설정되어 있습니다.");
    }
}

