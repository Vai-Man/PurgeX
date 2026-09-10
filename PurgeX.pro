QT       += core gui widgets printsupport

TEMPLATE = app
TARGET = PurgeX

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

# Windows specific
win32 {
    LIBS += -lsetupapi
}

# Linux specific
unix:!macx {
    LIBS += -lrt
}
