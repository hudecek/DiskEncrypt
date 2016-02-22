TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lgcrypt -lcryptopp
SOURCES += main.cpp

include(deployment.pri)
qtcAddDeployment()

