TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
        arp_spoof.cpp \
        main.cpp

HEADERS += \
    sendarp_header.h

LIBS += -L/usr/local/lib/ -lpcap
LIBS += -L/usr/local/lib/ -lpthread

QMAKE_CXXFLAGS_WARN_OFF -= -Wunused-variable
QMAKE_CFLAGS_WARN_OFF -= -Wunused-variable
