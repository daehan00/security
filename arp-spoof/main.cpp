#include "loader.h"
#include "widget.h"
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    Loader loader;
    if (loader.exec() != QDialog::Accepted) {
        return 0; // 사용자가 취소했거나 유효하지 않은 입력
    }

    // Loader에서 선택된 인터페이스를 가져와 Widget에 전달
    QString iface = loader.getInterface();
    Widget w(iface);
    w.show();

    return app.exec();
}
