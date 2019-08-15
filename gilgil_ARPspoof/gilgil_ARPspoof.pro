TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
        main.cpp

HEADERS += \
    sendarp_header.h

LIBS += -L/usr/local/lib/ -lpcap
LIBS += -L/usr/local/lib/ -lpthread
