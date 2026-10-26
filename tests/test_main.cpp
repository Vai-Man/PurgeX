#include <QApplication>
#include <QTemporaryDir>
#include <QtTest/QtTest>

#include "test_wipe_verify.h"
#include "test_wipe_engine.h"
#include "test_forensic_engine.h"
#include "test_cert_manager.h"

// Runs one suite. If PURGEX_TEST_LOG_DIR is set, each suite also writes <name>.txt there.
template <class T>
static int runSuite(const char *name, const QStringList &baseArgs)
{
    QStringList args = baseArgs;
    const QString logDir = qEnvironmentVariable("PURGEX_TEST_LOG_DIR");
    if (!logDir.isEmpty())
        args << "-o" << QString("%1/%2.txt,txt").arg(logDir, name) << "-o" << "-,txt";
    T suite;
    return QTest::qExec(&suite, args);
}

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);

    // Keep certificates, the audit log, logs and signing keys out of the developer's real
    // Documents folder and key store.
    QTemporaryDir home;
    if (!home.isValid()) {
        qCritical("could not create a temporary data directory");
        return 2;
    }
    qputenv("PURGEX_HOME", home.path().toLocal8Bit());

    const QStringList args = app.arguments();
    int status = 0;
    status |= runSuite<TestWipeVerify>("wipe_verify", args);
    status |= runSuite<TestWipeEngine>("wipe_engine", args);
    status |= runSuite<TestForensicEngine>("forensic_engine", args);
    status |= runSuite<TestCertManager>("cert_manager", args);
    return status;
}
