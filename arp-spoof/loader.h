#ifndef LOADER_H
#define LOADER_H

#include <QDialog>
#include <QString>
#include <QVector>
#include <QPair>

namespace Ui {
class Loader;
}

class Loader : public QDialog
{
    Q_OBJECT

public:
    explicit Loader(QWidget *parent = nullptr);
    ~Loader();

    QString getInterfaceName() const;
    QVector<QPair<QString, QString>> getArpTable() const;

private slots:
    void on_confirmPb_clicked();

private:
    Ui::Loader *ui;
    QString iface_;
    QVector<QPair<QString, QString>> arpTable_;

    bool validateInterface(const QString& dev);
    QVector<QPair<QString, QString>> loadArpTable(const QString& dev);
};

#endif // LOADER_H
