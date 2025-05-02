#include "loader.h"
#include "ui_loader.h"
#include <QMessageBox>
#include <QFile>
#include <QTextStream>
#include <QDebug>
#include <QRegularExpression>

Loader::Loader(QWidget *parent)
    : QDialog(parent)
    , ui(new Ui::Loader)
{
    ui->setupUi(this);
}

Loader::~Loader()
{
    delete ui;
}

QString Loader::getInterfaceName() const
{
    return iface_;
}

QVector<QPair<QString, QString>> Loader::getArpTable() const
{
    return arpTable_;
}

void Loader::on_confirmPb_clicked()
{
    QString dev = ui->interfaceLe->text().trimmed();
    if (!validateInterface(dev)) {
        QMessageBox::warning(this, "Error", "유효하지 않은 인터페이스입니다.");
        return;
    }

    iface_ = dev;
    arpTable_ = loadArpTable(dev);
    if (arpTable_.isEmpty()) {
        QMessageBox::warning(this, "Error", "ARP 테이블이 비어있습니다.");
        return;
    }

    accept();
}

bool Loader::validateInterface(const QString& dev)
{
    QFile file("/sys/class/net/" + dev + "/address");
    return file.exists();
}

QVector<QPair<QString, QString>> Loader::loadArpTable(const QString& dev)
{
    QVector<QPair<QString, QString>> result;

    QFile file("/proc/net/arp");
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        qWarning() << "ARP 테이블을 열 수 없습니다.";
        return result;
    }

    QTextStream in(&file);
    in.readLine(); // 첫 줄은 헤더

    QRegularExpression re("^([0-9\\.]+)\\s+\\S+\\s+\\S+\\s+([0-9a-fA-F:]{17})\\s+\\S+\\s+" + dev + "$");

    while (!in.atEnd()) {
        QString line = in.readLine();
        QRegularExpressionMatch match = re.match(line);
        if (match.hasMatch()) {
            QString ip = match.captured(1);
            QString mac = match.captured(2);
            result.append(qMakePair(ip, mac));
        }
    }

    return result;
}
