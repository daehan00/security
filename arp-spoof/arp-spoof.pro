QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++17

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0
SOURCES += \
        arphdr.cpp \
        common.cpp \
        ethhdr.cpp \
        infector.cpp \
        ip.cpp \
        mac.cpp \
        main.cpp \
        packetdispatcher.cpp \
        packetrelay.cpp \
        widget.cpp

HEADERS += \
        arphdr.h \
        common.h \
        ethhdr.h \
        infector.h \
        ip.h \
        mac.h \
        packetdispatcher.h \
        packetrelay.h \
        widget.h

FORMS += \
    widget.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target
