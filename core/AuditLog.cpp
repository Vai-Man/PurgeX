#include "AuditLog.h"

#include <QDir>
#include <QFile>
#include <QStandardPaths>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include <QUuid>
#include <QDebug>

// ---------------------------------------------------------------------------
// AuditEntry serialization
// ---------------------------------------------------------------------------
QJsonObject AuditEntry::toJson() const
{
    QJsonObject obj;
    obj["id"]                 = id;
    obj["type"]               = type;
    obj["timestamp"]          = timestamp.toString(Qt::ISODate);
    obj["target"]             = target;
    obj["algorithm"]          = algorithm;
    obj["status"]             = status;
    obj["verificationStatus"] = verificationStatus;
    obj["verificationNote"]   = verificationNote;
    obj["certPath"]           = certPath;
    obj["bytesProcessed"]     = static_cast<double>(bytesProcessed);
    obj["details"]            = details;
    return obj;
}

AuditEntry AuditEntry::fromJson(const QJsonObject &obj)
{
    AuditEntry e;
    e.id                 = obj["id"].toString();
    e.type               = obj["type"].toString();
    e.timestamp          = QDateTime::fromString(obj["timestamp"].toString(), Qt::ISODate);
    e.target             = obj["target"].toString();
    e.algorithm          = obj["algorithm"].toString();
    e.status             = obj["status"].toString();
    e.verificationStatus = obj["verificationStatus"].toString();
    e.verificationNote   = obj["verificationNote"].toString();
    e.certPath           = obj["certPath"].toString();
    e.bytesProcessed     = static_cast<qint64>(obj["bytesProcessed"].toDouble());
    e.details            = obj["details"].toString();
    return e;
}

// ---------------------------------------------------------------------------
// AuditLog
// ---------------------------------------------------------------------------
AuditLog::AuditLog(QObject *parent) : QObject(parent)
{
    // Resolve storage path: Documents/PurgeX/audit_log.json
    QString base = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
    if (base.isEmpty()) base = QDir::homePath();

    QDir dir(QDir(base).filePath("PurgeX"));
    if (!dir.exists()) dir.mkpath(".");
    m_logPath = dir.filePath("audit_log.json");

    load(); // Load any existing records on construction
}

bool AuditLog::load()
{
    QFile f(m_logPath);
    if (!f.exists()) return true; // No log yet — that's fine

    if (!f.open(QIODevice::ReadOnly)) {
        qWarning() << "AuditLog: cannot open log file for reading:" << m_logPath;
        return false;
    }

    QByteArray data = f.readAll();
    f.close();

    QJsonParseError pe;
    QJsonDocument doc = QJsonDocument::fromJson(data, &pe);
    if (pe.error != QJsonParseError::NoError || !doc.isArray()) {
        qWarning() << "AuditLog: invalid JSON in log file — starting fresh.";
        return false;
    }

    m_entries.clear();
    for (const QJsonValue &v : doc.array()) {
        if (v.isObject())
            m_entries.prepend(AuditEntry::fromJson(v.toObject())); // newest first after reverse
    }

    return true;
}

bool AuditLog::save() const
{
    QJsonArray arr;
    // Store oldest first in file; we present newest first in UI
    QList<AuditEntry> reversed = m_entries;
    std::reverse(reversed.begin(), reversed.end());
    for (const AuditEntry &e : reversed)
        arr.append(e.toJson());

    QFile f(m_logPath);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        qWarning() << "AuditLog: cannot open log file for writing:" << m_logPath;
        return false;
    }

    f.write(QJsonDocument(arr).toJson(QJsonDocument::Indented));
    f.close();
    return true;
}

bool AuditLog::append(const AuditEntry &entry)
{
    m_entries.prepend(entry); // newest first in memory
    return save();
}

QList<AuditEntry> AuditLog::filter(const QString  &type,
                                   const QString  &status,
                                   const QDateTime &from,
                                   const QDateTime &to) const
{
    QList<AuditEntry> out;
    for (const AuditEntry &e : m_entries) {
        if (!type.isEmpty()   && e.type   != type)   continue;
        if (!status.isEmpty() && e.status != status) continue;
        if (from.isValid()    && e.timestamp < from) continue;
        if (to.isValid()      && e.timestamp > to)   continue;
        out.append(e);
    }
    return out;
}

AuditEntry AuditLog::findById(const QString &id) const
{
    for (const AuditEntry &e : m_entries)
        if (e.id == id) return e;
    return AuditEntry{};
}

QString AuditLog::generateId()
{
    return QUuid::createUuid().toString(QUuid::WithoutBraces);
}
