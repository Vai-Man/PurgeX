#ifndef PURGEX_CLIMANAGER_H
#define PURGEX_CLIMANAGER_H

#include <QCoreApplication>
#include <QCommandLineParser>
#include <QStringList>
#include <cstdio>
#include <QTextStream>

#include "../core/WipeEngine.h"
#include "../cert/CertManager.h"
#include "../forensics/ForensicEngine.h"

// The C streams the CLI talks to. On Windows the GUI-subsystem executable has no console,
// so main() opens the right ones (parent console, or the redirected file / pipe).
struct CliStreams {
    FILE *in  = stdin;
    FILE *out = stdout;
    FILE *err = stderr;
};

// Exit codes: 0 = success, 1 = operation failed or was cancelled, 2 = invalid usage.
class CLIManager : public QObject {
    Q_OBJECT

public:
    explicit CLIManager(QCoreApplication *app, const CliStreams &streams = CliStreams(),
                        QObject *parent = nullptr);

    int run();

private slots:
    void onProgress(int percentage, const QString &status);
    void onWarning(const QString &message);

private:
    void setupParser();
    void printDrives();
    bool parsePattern(const QString &name, WipePattern *out) const;
    bool confirmDestructive(const QString &what);
    int  runWipe(const WipeConfig &config);
    int  runRecovery();
    int  verifyCertificate(const QString &certificateFile, const QString &qrPayload = QString());
    int  usageError(const QString &message);

    QCoreApplication *app;
    QCommandLineParser parser;
    QCommandLineOption helpOption{"help"};
    QCommandLineOption versionOption{"version"};
    WipeEngine *wipeEngine;
    CertManager *certManager;
    FILE *inFile;
    QTextStream out;
    QTextStream err;
    bool verbose = false;
    int lastLineLength = 0;
};

#endif // PURGEX_CLIMANAGER_H
