#ifndef PURGEX_CERTMANAGER_H
#define PURGEX_CERTMANAGER_H

#include <QObject>
#include <QString>
#include <QStringList>
#include <QMap>

class QWidget;

// ---------------------------------------------------------------------------
// CertDetails — input data for certificate generation
//
// Canonicalization spec (for hash, signature and QR verification):
//   The signed/hashed document is the COMPACT JSON encoding (Qt's QJsonDocument,
//   keys sorted alphabetically, UTF-8) of:
//     { "bytesProcessed", "method", "subject", "targets", "timestamp" }
//   SHA-256 of those bytes, hex encoded, plus the suffix "_PurgeX", is the QR
//   payload. The RSA-SHA256 (PKCS#1 v1.5) signature covers the same bytes.
//   The certificate embeds the signer's public key so it can be checked on any
//   machine; trust in that key is established by comparing its fingerprint.
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

    // Device passport: hardware / OS facts about the machine and drive the job ran on.
    // When non-empty it is part of the signed document.
    QMap<QString, QString> device;
};

class CertManager : public QObject {
    Q_OBJECT
public:
    explicit CertManager(QObject *parent = nullptr);

    // Writes a JSON + PDF certificate pair. Output paths are optionally returned.
    bool generateCertificates(const CertDetails &details, QWidget *parent,
                              QString *pdfPathOut = nullptr, QString *jsonPathOut = nullptr);

    // Returns true only if the content hash matches AND the RSA signature is valid.
    bool verifyJsonCertificate(const QString &jsonPath, QString *message, QWidget *parent);

    // Checks a scanned QR payload against a certificate: the certificate itself must verify
    // and the payload must equal the one embedded in it.
    bool verifyQrPayload(const QString &jsonPath, const QString &scannedPayload, QString *message);

    // SHA-256 fingerprint (hex) of a PEM public key, used to identify the signer.
    static QString publicKeyFingerprint(const QByteArray &publicKeyPem);

private:
    QString ensureKeypair();
    bool writeJsonCertificate(const QString &outPath, const CertDetails &details,
                              const QByteArray &dataHash, const QByteArray &signature,
                              const QString &timestamp, const QString &qrPayload,
                              const QByteArray &publicKeyPem);
    bool writePdfCertificate(const QString &outPath, const CertDetails &details,
                             const QString &dataHashHex, const QString &signatureHex,
                             const QString &timestamp, const QString &qrPayload,
                             const QString &signerFingerprint);
};

#endif // PURGEX_CERTMANAGER_H
