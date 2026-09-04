#include <QApplication>
#include <QIcon>
#include <QCommandLineParser>
#include <QStyleFactory>
#include <QMessageBox>

#include "ui/MainWindow.h"
#include "cli/CLIManager.h"

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    app.setApplicationName("PurgeX");
    app.setApplicationVersion("1.0.0");
    app.setOrganizationName("PurgeX");
    app.setOrganizationDomain("purgex.com");
    // Try to load icon from Qt resources first, then from file system
    QIcon appIcon;
    
    // Try Qt resource first
    if (QFile::exists(":/app_icon.jpg")) {
        appIcon = QIcon(":/app_icon.jpg");
    } else {
        // Fallback to file system - look in executable directory
        QString exePath = QCoreApplication::applicationDirPath();
        QStringList iconPaths = {
            "app_icon.ico", "app_icon.jpg", "app_icon.png", "icon.ico", "icon.png",
            exePath + "/app_icon.ico", exePath + "/app_icon.jpg", exePath + "/app_icon.png"
        };
        for (const QString &path : iconPaths) {
            if (QFile::exists(path)) {
                appIcon = QIcon(path);
                break;
            }
        }
    }
    if (!appIcon.isNull()) {
        app.setWindowIcon(appIcon);
    }

    // Check for CLI mode - if any arguments are provided, use CLI mode
    if (argc > 1) {
        // CLI mode
        CLIManager cliManager(&app);
        return cliManager.run();
    }

    // GUI mode
    app.setStyle(QStyleFactory::create("Fusion"));

    MainWindow window;
    window.show();

    return app.exec();
}
