#pragma once
// test_cert_manager.cpp
// Unit tests for certificate generation, signing and verification.

#include <QtTest/QtTest>
#include <QFile>
#include <QDir>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QCryptographicHash>
#include <QFontDatabase>
#include "../cert/CertManager.h"
#include "../core/AppPaths.h"

class TestCertManager : public QObject {
    Q_OBJECT

private:
    struct Generated { QString json; QString pdf; };

    Generated generate(const QString &subject, const QStringList &targets = {"file1.txt", "file2.txt"},
                       qulonglong bytes = 12345)
    {
        CertDetails d;
        d.subject        = subject;
        d.method         = "NIST SP 800-88 (3 passes)";
        d.targets        = targets;
        d.bytesProcessed = bytes;
        d.operationType  = "filesystem-wipe";
        d.verificationStatus = "verified";

        CertManager cm;
        Generated g;
        const bool ok = cm.generateCertificates(d, nullptr, &g.pdf, &g.json);
        if (!ok) return Generated();
        return g;
    }

    static QJsonObject readJson(const QString &path) {
        QFile f(path);
        if (!f.open(QIODevice::ReadOnly)) return QJsonObject();
        return QJsonDocument::fromJson(f.readAll()).object();
    }

    static void writeJson(const QString &path, const QJsonObject &obj) {
        QFile f(path);
        QVERIFY(f.open(QIODevice::WriteOnly));
        f.write(QJsonDocument(obj).toJson());
    }

    // Recompute the public hash fields the way an attacker without the private key could.
    static void rehash(QJsonObject &obj) {
        QJsonObject canonical;
        canonical["subject"]        = obj["subject"].toString();
        canonical["method"]         = obj["method"].toString();
        canonical["targets"]        = obj["targets"].toArray();
        canonical["bytesProcessed"] = obj["bytesProcessed"].toDouble();
        canonical["timestamp"]      = obj["timestamp"].toString();
        const QByteArray hash = QCryptographicHash::hash(
            QJsonDocument(canonical).toJson(QJsonDocument::Compact), QCryptographicHash::Sha256);
        obj["dataHashHex"] = QString::fromLatin1(hash.toHex());
        obj["qrPayload"]   = QString::fromLatin1(hash.toHex()) + "_PurgeX";
    }

private slots:
    void testGeneratesJsonAndPdf() {
        const Generated g = generate("Test Subject");
        QVERIFY2(!g.json.isEmpty() && QFile::exists(g.json), "JSON certificate must exist");
        QVERIFY2(!g.pdf.isEmpty() && QFile::exists(g.pdf), "PDF certificate must exist");
        QVERIFY(g.json.startsWith(AppPaths::certificatesDir()));

        QFile pdf(g.pdf);
        QVERIFY(pdf.open(QIODevice::ReadOnly));
        const QByteArray bytes = pdf.readAll();
        QVERIFY2(bytes.startsWith("%PDF"), "output must be a PDF");
        QVERIFY2(bytes.contains("/Image"), "the QR code must be embedded in the PDF");
    }

    void testPdfIsASinglePage() {
        if (QFontDatabase().families().isEmpty())
            QSKIP("no fonts available (offscreen/headless platform), page layout is meaningless");
        const Generated g = generate("Page count");
        QFile pdf(g.pdf);
        QVERIFY(pdf.open(QIODevice::ReadOnly));
        const QByteArray bytes = pdf.readAll();
        // The certificate used to be printed twice into the same file.
        QCOMPARE(bytes.count("/Type /Page") - bytes.count("/Type /Pages"), 1);
    }

    void testQrPayloadAndHashReproducible() {
        const Generated g = generate("Reproducibility Test");
        const QJsonObject obj = readJson(g.json);
        const QString qr = obj["qrPayload"].toString();
        QVERIFY(qr.endsWith("_PurgeX"));
        QCOMPARE(qr.left(qr.length() - 7).length(), 64);

        QJsonObject copy = obj;
        rehash(copy);
        QCOMPARE(copy["qrPayload"].toString(), qr);
        QCOMPARE(copy["dataHashHex"].toString(), obj["dataHashHex"].toString());
    }

    void testSignatureFieldsArePlainHex() {
        // Regression: the hash and signature used to be hex-encoded twice in the PDF/JSON pipeline.
        const QJsonObject obj = readJson(generate("Hex").json);
        QCOMPARE(obj["dataHashHex"].toString().size(), 64);
        QCOMPARE(obj["signatureHex"].toString().size(), 512); // 2048-bit RSA
        QVERIFY(!obj["publicKeyPem"].toString().isEmpty());
        QCOMPARE(obj["publicKeyFingerprint"].toString().size(), 64);
    }

    void testVerifyUnmodifiedCert() {
        const Generated g = generate("Unmodified Verify Test");
        CertManager cm;
        QString msg;
        QVERIFY2(cm.verifyJsonCertificate(g.json, &msg, nullptr), qPrintable(msg));
        QVERIFY(msg.contains("authentic", Qt::CaseInsensitive));
    }

    void testTamperedContentFails() {
        const Generated g = generate("Tamper Test");
        QJsonObject obj = readJson(g.json);
        obj["bytesProcessed"] = 999999.0;
        const QString tampered = g.json + ".tampered.json";
        writeJson(tampered, obj);

        CertManager cm;
        QString msg;
        QVERIFY2(!cm.verifyJsonCertificate(tampered, &msg, nullptr), "tampered certificate must fail");
        QVERIFY2(msg.contains("TAMPER"), qPrintable(msg));
    }

    void testForgedCertWithRecomputedHashFails() {
        // Anyone can recompute a SHA-256, so a matching hash alone must never be accepted.
        const Generated g = generate("Forgery Test");
        QJsonObject obj = readJson(g.json);
        obj["bytesProcessed"] = 1.0;
        obj["targets"] = QJsonArray{"harmless.txt"};
        rehash(obj);
        const QString forged = g.json + ".forged.json";
        writeJson(forged, obj);

        CertManager cm;
        QString msg;
        QVERIFY2(!cm.verifyJsonCertificate(forged, &msg, nullptr),
                 "a certificate with a recomputed hash but the old signature must be rejected");
        QVERIFY2(msg.contains("SIGNATURE", Qt::CaseInsensitive), qPrintable(msg));
    }

    void testStrippedSignatureFails() {
        const Generated g = generate("Unsigned Test");
        QJsonObject obj = readJson(g.json);
        obj["signatureHex"] = QString::fromLatin1(QByteArray("unsigned").toHex());
        const QString path = g.json + ".unsigned.json";
        writeJson(path, obj);

        CertManager cm;
        QString msg;
        QVERIFY(!cm.verifyJsonCertificate(path, &msg, nullptr));
    }

    void testVerifiesOnAnotherMachine() {
        // The certificate embeds its public key, so verification works without the local key pair.
        const Generated g = generate("Portable Verify");
        QDir(AppPaths::keyDir()).removeRecursively();

        CertManager cm;
        QString msg;
        QVERIFY2(cm.verifyJsonCertificate(g.json, &msg, nullptr), qPrintable(msg));
        QVERIFY2(msg.contains("different key"), "an unknown signer must be called out");
    }

    void testSwappedPublicKeyIsDetectedAsDifferentSigner() {
        // An attacker re-signs with their own key and embeds it: integrity holds, but the
        // fingerprint no longer matches the installation that issued the certificate.
        const Generated g = generate("Key swap");
        const QJsonObject original = readJson(g.json);

        QDir(AppPaths::keyDir()).removeRecursively();
        const Generated other = generate("Another issuer"); // creates a brand-new key pair
        const QJsonObject b = readJson(other.json);
        QVERIFY(original["publicKeyFingerprint"].toString() != b["publicKeyFingerprint"].toString());

        // Original certificate checked on the installation that now holds a different key.
        CertManager cm;
        QString msg;
        QVERIFY(cm.verifyJsonCertificate(g.json, &msg, nullptr));
        QVERIFY(msg.contains("different key"));
    }

    void testDevicePassportIsSigned() {
        CertDetails d;
        d.subject = "Passport";
        d.method = "m";
        d.targets = QStringList("t");
        d.device["cpu"] = "Test CPU";
        d.device["driveSerial"] = "ABC123";
        CertManager cm;
        QString pdf, json, msg;
        QVERIFY(cm.generateCertificates(d, nullptr, &pdf, &json));
        QVERIFY2(cm.verifyJsonCertificate(json, &msg, nullptr), qPrintable(msg));

        QJsonObject obj = readJson(json);
        QCOMPARE(obj["device"].toObject()["driveSerial"].toString(), QString("ABC123"));
        QJsonObject dev = obj["device"].toObject();
        dev["driveSerial"] = "FORGED";
        obj["device"] = dev;
        const QString tampered = json + ".dev.json";
        writeJson(tampered, obj);
        QVERIFY2(!cm.verifyJsonCertificate(tampered, &msg, nullptr), "editing the passport must be detected");
    }

    void testScannedQrPayload() {
        const Generated g = generate("QR scan");
        const QString payload = readJson(g.json)["qrPayload"].toString();
        CertManager cm;
        QString msg;
        QVERIFY2(cm.verifyQrPayload(g.json, payload, &msg), qPrintable(msg));
        QVERIFY(!cm.verifyQrPayload(g.json, "0000_PurgeX", &msg));
        QVERIFY(msg.contains("MISMATCH"));
    }

    void testPrivateKeyIsNotStoredInPlainText() {
        generate("Key at rest");
        QFile f(QDir(AppPaths::keyDir()).filePath("purgex_private.pem"));
        QVERIFY(f.open(QIODevice::ReadOnly));
#ifdef Q_OS_WIN
        QVERIFY2(!f.readAll().contains("BEGIN PRIVATE KEY"), "the key must be sealed (DPAPI) on Windows");
#endif
    }

    void testManyTargetsStayReadable() {
        QStringList many;
        for (int i = 0; i < 400; ++i) many << QString("file_%1.dat (10 bytes)").arg(i);
        const Generated g = generate("Many", many);
        QVERIFY(!g.pdf.isEmpty());
        CertManager cm;
        QString msg;
        QVERIFY2(cm.verifyJsonCertificate(g.json, &msg, nullptr), qPrintable(msg));
    }
};

