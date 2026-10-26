QT       += core testlib gui widgets printsupport

TEMPLATE = app
TARGET = PurgeXTests
CONFIG  += console c++17
CONFIG  -= app_bundle

SOURCES += \
    test_main.cpp \
    ../core/WipeEngine.cpp \
    ../core/AuditLog.cpp \
    ../cert/CertManager.cpp \
    ../cert/qrcodegen.cpp \
    ../forensics/ForensicEngine.cpp

HEADERS += \
    test_wipe_verify.h \
    test_wipe_engine.h \
    test_forensic_engine.h \
    test_cert_manager.h \
    ../core/WipeEngine.h \
    ../core/AuditLog.h \
    ../core/AppPaths.h \
    ../cert/CertManager.h \
    ../cert/qrcodegen.hpp \
    ../forensics/ForensicEngine.h \
    ../forensics/FileSignatures.h

INCLUDEPATH += .. ../core ../cert ../forensics

LIBS += -lcrypto

win32 {
    LIBS += -lws2_32 -lcrypt32
}
unix:!macx {
    LIBS += -lrt
}
