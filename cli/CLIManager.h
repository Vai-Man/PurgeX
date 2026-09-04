#ifndef PURGEX_CLIMANAGER_H
#define PURGEX_CLIMANAGER_H

#include <QCoreApplication>
#include <QCommandLineParser>
#include <QStringList>
#include <QTextStream>
#include <QTimer>
#include <QEventLoop>

#include "../core/WipeEngine.h"
#include "../cert/CertManager.h"

class CLIManager : public QObject {
    Q_OBJECT

public:
    explicit CLIManager(QCoreApplication *app, QObject *parent = nullptr);
    
    int run();
    
private slots:
    void onProgress(int percentage, const QString &status);
    void onFinished(bool success, const QString &message);
    void onWarning(const QString &message);
    void handleInterrupt();

private:
    void setupParser();
    void setupSignalHandling();
    void printUsage();
    void printVersion();
    void printDrives();
    int wipeFiles(const QStringList &files, const QString &pattern, int passes, bool verify, bool certificate);
    int wipeFolder(const QString &folder, const QString &pattern, int passes, bool verify, bool certificate);
    int wipeDrive(const QString &drive, const QString &pattern, bool fullDrive, bool certificate);
    int secureEraseSSD(const QString &device);
    int verifyCertificate(const QString &certificateFile);
    
    QCoreApplication *app;
    QCommandLineParser parser;
    WipeEngine *wipeEngine;
    CertManager *certManager;
    QTextStream out;
    QTextStream err;
    bool verbose;
    bool interrupted;
    QEventLoop *eventLoop;
};

#endif // PURGEX_CLIMANAGER_H
