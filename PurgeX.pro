QT       += core gui widgets printsupport

TEMPLATE = app
TARGET = PurgeX

SOURCES += \
    main.cpp \
    core/WipeEngine.cpp \
    ui/MainWindow.cpp \
    cli/CLIManager.cpp \
    cert/CertManager.cpp

HEADERS += \
    core/WipeEngine.h \
    ui/MainWindow.h \
    cli/CLIManager.h \
    cert/CertManager.h

RESOURCES += resources.qrc

INCLUDEPATH += core ui cli cert

# Windows specific
win32 {
    LIBS += -lsetupapi
}

# Linux specific
unix:!macx {
    LIBS += -lrt
}


