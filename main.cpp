#include <QApplication>
#include <QIcon>
#include <QFile>
#include <QStyleFactory>
#include <QMessageBox>

#include "ui/MainWindow.h"
#include "cli/CLIManager.h"

#ifdef Q_OS_WIN
#include <windows.h>
#include <cstdio>
#include <fcntl.h>
#include <io.h>

// The GUI build uses the Windows subsystem, which has no console of its own. For CLI use:
//  - if stdin/stdout/stderr were redirected (file or pipe), talk to those handles;
//  - otherwise attach to the terminal that launched us so the output is visible.
static CliStreams connectStandardStreams()
{
    CliStreams streams;
    const HANDLE hIn  = GetStdHandle(STD_INPUT_HANDLE);
    const HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    const HANDLE hErr = GetStdHandle(STD_ERROR_HANDLE);
    auto usable = [](HANDLE h) { return h && h != INVALID_HANDLE_VALUE; };

    const bool attached = AttachConsole(ATTACH_PARENT_PROCESS);

    auto open = [&](HANDLE h, const char *mode, const char *consoleName, FILE *fallback) -> FILE * {
        FILE *f = nullptr;
        if (usable(h)) {
            const int fd = _open_osfhandle(reinterpret_cast<intptr_t>(h), 0);
            if (fd != -1) f = _fdopen(fd, mode);
        } else if (attached) {
            f = fopen(consoleName, mode);
        }
        if (f && mode[0] == 'w') setvbuf(f, nullptr, _IONBF, 0);
        return f ? f : fallback;
    };
    streams.in  = open(hIn,  "r", "CONIN$",  stdin);
    streams.out = open(hOut, "w", "CONOUT$", stdout);
    streams.err = open(hErr, "w", "CONOUT$", stderr);
    return streams;
}
#endif

int main(int argc, char *argv[]) {
    const bool cliMode = (argc > 1);
    CliStreams streams;

    if (cliMode) {
#ifdef Q_OS_WIN
        streams = connectStandardStreams();
#else
        // Certificates are rendered through Qt's text engine, which needs a platform
        // plugin; fall back to the offscreen one on machines without a display.
        if (qEnvironmentVariableIsEmpty("DISPLAY") && qEnvironmentVariableIsEmpty("WAYLAND_DISPLAY")
            && qEnvironmentVariableIsEmpty("QT_QPA_PLATFORM"))
            qputenv("QT_QPA_PLATFORM", "offscreen");
#endif
    }

    QApplication app(argc, argv);
    app.setApplicationName("PurgeX");
    app.setApplicationVersion("1.0.0");
    app.setOrganizationName("PurgeX");

    QIcon appIcon(":/app_icon.jpg");
    if (appIcon.isNull() && QFile::exists("app_icon.jpg"))
        appIcon = QIcon("app_icon.jpg");
    if (!appIcon.isNull())
        app.setWindowIcon(appIcon);

    if (cliMode) {
        CLIManager cliManager(&app, streams);
        return cliManager.run();
    }

    app.setStyle(QStyleFactory::create("Fusion"));

    MainWindow window;
    window.show();

    return app.exec();
}
