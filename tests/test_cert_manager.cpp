// test_cert_manager.cpp
// Unit tests for CertManager QR payload and certificate integrity
//
// Tests:
//   1. generateCertificates() produces a valid JSON file
//   2. JSON file contains a qrPayload field matching <sha256hex>_PurgeX
//   3. Independently reproduce the hash from canonical data and confirm it matches
//   4. Modifying any canonical field causes a hash mismatch
//   5. verifyJsonCertificate() returns true for an unmodified certificate

#include <QtTest/QtTest>
#include <QFile>
#include <QDir>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QCryptographicHash>
#include <QStandardPaths>
#include <QDirIterator>
#include "../cert/CertManager.h"

class TestCertManager : public QObject {
    Q_OBJECT

private:
    // Helper: find the most recently created JSON certificate
    QString latestJsonCert() {
        QString certDir = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation)
                          + "/PurgeX/certificates/json";
        QDir dir(certDir);
        if (!dir.exists()) return QString();

        QStringList files = dir.entryList({"PurgeX_Certificate_*.json"}, QDir::Files, QDir::Time);
        if (files.isEmpty()) return QString();
        return dir.filePath(files.first());
    }

private slots:
    void initTestCase() {}
    void cleanupTestCase() {}

    void testCertGeneratesJsonFile() {
        CertDetails d;
        d.subject        = "Test Subject";
        d.method         = "Test Method";
        d.targets        = QStringList{"file1.txt", "file2.txt"};
        d.bytesProcessed = 12345;
        d.operationType  = "filesystem-wipe";
        d.verificationStatus = "verified";

        CertManager cm;
        bool ok = cm.generateCertificates(d, nullptr);
        QVERIFY2(ok, "generateCertificates should return true");

        QString jsonPath = latestJsonCert();
        QVERIFY2(!jsonPath.isEmpty(), "A JSON certificate file should have been created");
        QVERIFY2(QFile::exists(jsonPath), "JSON certificate file should exist on disk");
    }

    void testQrPayloadFormat() {
        // Generate a fresh cert
        CertDetails d;
        d.subject        = "QR Test";
        d.method         = "NIST SP 800-88 (1 pass)";
        d.targets        = QStringList{"document.pdf"};
        d.bytesProcessed = 999999;

        CertManager cm;
        cm.generateCertificates(d, nullptr);

        QString jsonPath = latestJsonCert();
        QVERIFY2(!jsonPath.isEmpty(), "JSON cert must exist");

        QFile f(jsonPath);
        QVERIFY(f.open(QIODevice::ReadOnly));
        QJsonDocument doc = QJsonDocument::fromJson(f.readAll());
        f.close();
        QVERIFY(doc.isObject());

        QJsonObject obj = doc.object();
        QString qrPayload = obj["qrPayload"].toString();
        QVERIFY2(!qrPayload.isEmpty(), "qrPayload field must be present");
        QVERIFY2(qrPayload.endsWith("_PurgeX"),
                 "qrPayload must end with '_PurgeX' application identifier");

        // The hash part should be 64 hex characters (SHA-256)
        QString hashPart = qrPayload.left(qrPayload.length() - 7); // strip "_PurgeX"
        QCOMPARE(hashPart.length(), 64);

        // Verify it's a valid hex string
        bool isHex = true;
        for (QChar c : hashPart) {
            if (!c.isLetterOrNumber() || (c.isLetter() && !c.isLower())) {
                // Allow lowercase hex only
                if (!(c >= 'a' && c <= 'f') && !c.isDigit()) {
                    isHex = false;
                    break;
                }
            }
        }
        QVERIFY2(isHex, "Hash part of qrPayload should be 64 lowercase hex characters");
    }

    void testQrHashReproducible() {
        // Generate cert and independently reproduce the hash from the stored canonical fields
        CertDetails d;
        d.subject        = "Reproducibility Test";
        d.method         = "Gutmann (35 passes)";
        d.targets        = QStringList{"alpha.doc", "beta.xlsx"};
        d.bytesProcessed = 4096000;

        CertManager cm;
        cm.generateCertificates(d, nullptr);

        QString jsonPath = latestJsonCert();
        QVERIFY(!jsonPath.isEmpty());

        QFile f(jsonPath);
        QVERIFY(f.open(QIODevice::ReadOnly));
        QJsonDocument doc = QJsonDocument::fromJson(f.readAll());
        f.close();
        QJsonObject obj = doc.object();

        // Reproduce canonical JSON exactly as CertManager does
        QJsonObject canonical;
        canonical["subject"]        = obj["subject"].toString();
        canonical["method"]         = obj["method"].toString();
        canonical["targets"]        = obj["targets"].toArray();
        canonical["bytesProcessed"] = obj["bytesProcessed"].toDouble();
        canonical["timestamp"]      = obj["timestamp"].toString();
        QByteArray canonicalBytes = QJsonDocument(canonical).toJson(QJsonDocument::Compact);

        QByteArray recomputedHash = QCryptographicHash::hash(canonicalBytes,
                                                              QCryptographicHash::Sha256);
        QString expectedQr = QString::fromLatin1(recomputedHash.toHex()) + "_PurgeX";
        QString storedQr   = obj["qrPayload"].toString();

        QCOMPARE(storedQr, expectedQr);
    }

    void testTamperedCertFails() {
        CertDetails d;
        d.subject        = "Tamper Test";
        d.method         = "Zero Fill";
        d.targets        = QStringList{"secret.txt"};
        d.bytesProcessed = 1;

        CertManager cm;
        cm.generateCertificates(d, nullptr);

        QString jsonPath = latestJsonCert();
        QVERIFY(!jsonPath.isEmpty());

        // Read the cert and tamper with the bytesProcessed field
        QFile f(jsonPath);
        QVERIFY(f.open(QIODevice::ReadOnly));
        QByteArray data = f.readAll();
        f.close();

        QJsonDocument doc = QJsonDocument::fromJson(data);
        QJsonObject obj = doc.object();
        obj["bytesProcessed"] = static_cast<double>(999999); // tamper!

        // Write tampered version to a temp file
        QString tamperedPath = jsonPath + ".tampered.json";
        QFile tf(tamperedPath);
        QVERIFY(tf.open(QIODevice::WriteOnly));
        tf.write(QJsonDocument(obj).toJson());
        tf.close();

        QString msg;
        bool valid = cm.verifyJsonCertificate(tamperedPath, &msg, nullptr);
        QVERIFY2(!valid, "Tampered certificate should fail verification");
        QVERIFY2(msg.contains("TAMPER"), "Error message should mention tamper detection");

        QFile::remove(tamperedPath);
    }

    void testVerifyUnmodifiedCert() {
        // This test only passes if OpenSSL is available; hash check is the fallback
        CertDetails d;
        d.subject        = "Unmodified Verify Test";
        d.method         = "NIST SP 800-88 (3 passes)";
        d.targets        = QStringList{"report.pdf"};
        d.bytesProcessed = 2048;

        CertManager cm;
        cm.generateCertificates(d, nullptr);

        QString jsonPath = latestJsonCert();
        QVERIFY(!jsonPath.isEmpty());

        QString msg;
        bool valid = cm.verifyJsonCertificate(jsonPath, &msg, nullptr);
        // Hash verification should always pass for an unmodified cert
        QVERIFY2(valid, QString("Unmodified cert should verify clean. Message: %1").arg(msg).toUtf8());
    }
};

#include "test_cert_manager.moc"
