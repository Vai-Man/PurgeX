#ifndef PURGEX_AUDITLOG_H
#define PURGEX_AUDITLOG_H

#include <QObject>
#include <QString>
#include <QList>
#include <QDateTime>
#include <QJsonObject>

// ---------------------------------------------------------------------------
// AuditEntry — one record in the persistent audit log
// ---------------------------------------------------------------------------
struct AuditEntry {
    QString   id;                // UUID-like unique identifier
    QString   type;              // "wipe" | "recovery" | "verification"
    QDateTime timestamp;
    QString   target;            // Summary of what was acted on
    QString   algorithm;         // Wipe pattern or scan mode
    QString   status;            // "success" | "failed" | "cancelled" | "partial"
    QString   verificationStatus;// "verified" | "unverified" | "not_applicable" | "limitation"
    QString   verificationNote;  // Human-readable caveat (e.g. SSD note)
    QString   certPath;          // Absolute path to generated certificate (may be empty)
    qint64    bytesProcessed;
    QString   details;           // Free-form extra info

    QJsonObject toJson() const;
    static AuditEntry fromJson(const QJsonObject &obj);
};

// ---------------------------------------------------------------------------
// AuditLog — singleton-style JSON-backed audit store
// ---------------------------------------------------------------------------
class AuditLog : public QObject {
    Q_OBJECT

public:
    explicit AuditLog(QObject *parent = nullptr);

    // Append a new entry and persist immediately
    bool append(const AuditEntry &entry);

    // Load all records from disk
    bool load();

    // Get all entries (most recent first)
    QList<AuditEntry> entries() const { return m_entries; }

    // Filter by type, status, or date range (empty string = any)
    QList<AuditEntry> filter(const QString &type,
                             const QString &status,
                             const QDateTime &from = QDateTime(),
                             const QDateTime &to   = QDateTime()) const;

    // Retrieve a single entry by id
    AuditEntry findById(const QString &id) const;

    // Path to the JSON file
    QString logFilePath() const { return m_logPath; }

    // Generate a simple unique ID
    static QString generateId();

private:
    bool save() const;

    QString           m_logPath;
    QList<AuditEntry> m_entries;
};

#endif // PURGEX_AUDITLOG_H
