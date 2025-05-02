#include "widget.h"
#include "ui_widget.h"

#include <QProcess>
#include <QMessageBox>
#include <QTableWidgetItem>

Widget::Widget(const QString& interface, QWidget *parent)
    : QWidget(parent), ui(new Ui::Widget), iface_(interface)
{
    ui->setupUi(this);
    initUiState();
    loadArpTable();
}

Widget::~Widget()
{
    delete ui;
}

void Widget::initUiState()
{
    ui->startPb->setEnabled(false);
    ui->stopPb->setEnabled(false);
    ui->senderIpTb->clear();
    ui->targetIpTb->clear();
    ui->statusTb->clear();
}

void Widget::loadArpTable()
{
    QProcess proc;
    proc.start("arp", QStringList() << "-n");
    proc.waitForFinished();
    QString output = proc.readAllStandardOutput();

    QStringList lines = output.split('\n');
    ui->ipAddrTable->setRowCount(0);
    arpEntries_.clear();

    for (const QString& line : lines) {
        if (line.startsWith("Address") || line.trimmed().isEmpty()) continue;
        QStringList parts = line.split(QRegExp("\\s+"));
        if (parts.size() < 3) continue;

        QString ip = parts[0];
        QString mac = parts[2];
        ArpEntry entry = { ip, mac };
        arpEntries_.append(entry);

        int row = ui->ipAddrTable->rowCount();
        ui->ipAddrTable->insertRow(row);
        ui->ipAddrTable->setItem(row, 0, new QTableWidgetItem(ip));
        ui->ipAddrTable->setItem(row, 1, new QTableWidgetItem(mac));

        // target 자동 설정: 192.168.0.1 또는 x.x.x.1인 경우 gateway로 판단
        if (ip.endsWith(".1")) {
            ui->targetIpTb->setText(ip);
        }
    }

    updateStatus(QString("[INFO] ARP 테이블 %1개 항목 로드됨").arg(arpEntries_.size()));
}

void Widget::on_ipAddrTable_itemClicked(QTableWidgetItem *item)
{
    int row = item->row();
    if (row >= 0 && row < arpEntries_.size()) {
        const QString& ip = arpEntries_[row].ip;
        ui->senderIpTb->setText(ip);

        // 둘 다 설정되었으면 start 버튼 활성화
        if (!ui->targetIpTb->text().isEmpty()) {
            ui->startPb->setEnabled(true);
        }
    }
}

void Widget::on_startPb_clicked()
{
    updateStatus("[INFO] ARP spoofing 시작...");
    ui->startPb->setEnabled(false);
    ui->stopPb->setEnabled(true);

    // 실제 감염 스레드 시작은 여기에 추가
}

void Widget::on_stopPb_clicked()
{
    updateStatus("[INFO] ARP spoofing 중단됨");
    ui->startPb->setEnabled(true);
    ui->stopPb->setEnabled(false);

    // 스레드 종료 처리 필요
}

void Widget::updateStatus(const QString& msg)
{
    ui->statusTb->append(msg);
}
