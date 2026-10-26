QT       += core gui widgets printsupport

TEMPLATE = app
TARGET = PurgeX
CONFIG   += c++17

SOURCES += \
    main.cpp \
    core/WipeEngine.cpp \
    core/AuditLog.cpp \
    ui/MainWindow.cpp \
    ui/ForensicWidget.cpp \
    ui/AuditWidget.cpp \
    cli/CLIManager.cpp \
    cert/CertManager.cpp \
    cert/qrcodegen.cpp \
    forensics/ForensicEngine.cpp

HEADERS += \
    core/WipeEngine.h \
    core/AuditLog.h \
    core/AppPaths.h \
    ui/MainWindow.h \
    ui/ForensicWidget.h \
    ui/AuditWidget.h \
    cli/CLIManager.h \
    cert/CertManager.h \
    cert/qrcodegen.hpp \
    forensics/ForensicEngine.h \
    forensics/FileSignatures.h

RESOURCES += resources.qrc

INCLUDEPATH += core ui cli cert forensics

# OpenSSL (libcrypto): RSA key generation, certificate signing and verification.
# Ubuntu/Debian: libssl-dev   Fedora: openssl-devel   MSYS2: mingw-w64-ucrt-x86_64-openssl
LIBS += -lcrypto

win32 {
    LIBS += -lws2_32 -lcrypt32
}

unix:!macx {
    LIBS += -lrt
}
