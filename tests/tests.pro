QT       += core testlib gui widgets printsupport

TEMPLATE = app
TARGET = PurgeXTests
CONFIG  += console
CONFIG  -= app_bundle

SOURCES += \
    test_main.cpp \
    ../core/WipeEngine.cpp \
    ../core/AuditLog.cpp \
    ../cert/CertManager.cpp \
    ../cert/qrcodegen.cpp \
    ../forensics/ForensicEngine.cpp

HEADERS += \
    ../core/WipeEngine.h \
    ../core/AuditLog.h \
    ../cert/CertManager.h \
    ../cert/qrcodegen.hpp \
    ../forensics/ForensicEngine.h \
    ../forensics/FileSignatures.h

INCLUDEPATH += .. ../core ../cert ../forensics

win32 {
    LIBS += -lsetupapi
}
unix:!macx {
    LIBS += -lrt
}
