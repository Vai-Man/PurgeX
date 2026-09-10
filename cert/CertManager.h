#ifndef PURGEX_CERTMANAGER_H
#define PURGEX_CERTMANAGER_H

#include <QObject>
#include <QString>
#include <QStringList>

// ---------------------------------------------------------------------------
// CertDetails — input data for certificate generation
//
// Canonicalization spec (for hash and QR verification):
//   The verifiable hash is SHA-256 of the compact JSON encoding of:
//   { "subject", "method", "targets", "bytesProcessed", "timestamp" }
//   Keys are in exactly that order. Values are the UTF-8 Qt JSON encoding.
//   The resulting hex hash + "_PurgeX" is embedded as the QR payload.
//   The companion verifier must rebuild this exact JSON to reproduce the hash.
// ---------------------------------------------------------------------------
struct CertDetails {
    QString     subject;
    QString     method;
    QStringList targets;
    qulonglong  bytesProcessed{0};

    // Extended fields (optional — empty string = not set)
    QString operationType;      // e.g. "host-level-overwrite", "filesystem-wipe",
                                //       "verified-host-level-overwrite", "forensic-recovery"
    QString verificationStatus; // "verified" | "unverified" | "failed" | "not_performed" | "limitation"
    QString verificationNote;   // Human-readable caveat (e.g. SSD limitation)
};

class CertManager : public QObject {
    Q_OBJECT
public:
    explicit CertManager(QObject *parent = nullptr);

    bool generateCertificates(const CertDetails &details, QWidget *parent);
    bool verifyJsonCertificate(const QString &jsonPath, QString *message, QWidget *parent);

private:
    QString ensureKeypair(QWidget *parent);
    bool signWithOpenSSL(const QString &privateKeyPath, const QByteArray &data,
                         QByteArray &outSignature, QString *errMsg);
    bool verifyWithOpenSSL(const QString &publicKeyPath, const QByteArray &data,
                           const QByteArray &signature, QString *errMsg);
    bool writeJsonCertificate(const QString &outPath, const CertDetails &details,
                              const QByteArray &dataHash, const QByteArray &signature,
                              const QString &timestamp, const QString &qrPayload);
    bool writePdfCertificate(const QString &outPath, const CertDetails &details,
                             const QByteArray &dataHashHex, const QByteArray &signatureHex,
                             const QString &timestamp, const QString &qrPayload);
};

#endif // PURGEX_CERTMANAGER_H
