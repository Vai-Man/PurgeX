#ifndef PURGEX_APPPATHS_H
#define PURGEX_APPPATHS_H

#include <QDir>
#include <QStandardPaths>
#include <QString>
#include <QtGlobal>

// ---------------------------------------------------------------------------
// AppPaths — single source of truth for where PurgeX keeps its data.
//
// The PURGEX_HOME environment variable relocates everything (certificates,
// audit log, session logs, signing keys). The unit tests rely on it so they
// never touch a real user's Documents folder or signing key.
// ---------------------------------------------------------------------------
namespace AppPaths {

inline QString dataRoot()
{
    const QByteArray overridePath = qgetenv("PURGEX_HOME");
    if (!overridePath.isEmpty())
        return QDir::cleanPath(QString::fromLocal8Bit(overridePath));

    QString base = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
    if (base.isEmpty()) base = QDir::homePath();
    return QDir(base).filePath("PurgeX");
}

inline QString certificatesDir() { return QDir(dataRoot()).filePath("certificates"); }
inline QString logsDir()         { return QDir(dataRoot()).filePath("logs"); }
inline QString auditLogPath()    { return QDir(dataRoot()).filePath("audit_log.json"); }

inline QString keyDir()
{
    if (!qgetenv("PURGEX_HOME").isEmpty())
        return QDir(dataRoot()).filePath("keys");

    QString base = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    if (base.isEmpty()) base = QDir::homePath() + "/.purgex";
    return base;
}

inline QString ensureDir(const QString &path)
{
    QDir().mkpath(path);
    return path;
}

} // namespace AppPaths

#endif // PURGEX_APPPATHS_H
