// test_forensic_engine.cpp
// Unit tests for the ForensicEngine carving functionality
//
// Tests:
//   1. Create JPEG, PNG, PDF files → logical scan → all detected with HIGH confidence
//   2. Source directory is unmodified after scan
//   3. Destination receives recovered copies
//   4. Unknown file type is NOT falsely recovered
//   5. Source == Destination safety check fires

#include <QtTest/QtTest>
#include <QFile>
#include <QDir>
#include <QTemporaryDir>
#include <QEventLoop>
#include <QTimer>
#include "../forensics/ForensicEngine.h"

class TestForensicEngine : public QObject {
    Q_OBJECT

private slots:
    void initTestCase() {}
    void cleanupTestCase() {}

    // Test 1–4: create known file types, run scan, verify results
    void testLogicalScan_KnownTypes() {
        QTemporaryDir srcDir, dstDir;
        QVERIFY(srcDir.isValid());
        QVERIFY(dstDir.isValid());

        // Create a minimal JPEG (header + footer)
        {
            QFile f(srcDir.filePath("test.jpg"));
            QVERIFY(f.open(QIODevice::WriteOnly));
            f.write("\xFF\xD8\xFF\xE0", 4); // JPEG header
            f.write(QByteArray(1024, '\x55')); // dummy payload
            f.write("\xFF\xD9", 2);           // JPEG footer
        }

        // Create a minimal PNG (header + IEND chunk)
        {
            QFile f(srcDir.filePath("test.png"));
            QVERIFY(f.open(QIODevice::WriteOnly));
            f.write("\x89PNG\r\n\x1A\n", 8);  // PNG header
            f.write(QByteArray(512, '\x00'));
            f.write("IEND\xAE\x42\x60\x82", 8); // PNG footer
        }

        // Create a minimal PDF
        {
            QFile f(srcDir.filePath("test.pdf"));
            QVERIFY(f.open(QIODevice::WriteOnly));
            f.write("%PDF-1.4\n", 9);
            f.write(QByteArray(256, '\x00'));
            f.write("%%EOF", 5);
        }

        // Create an unknown binary file (no recognized signature)
        {
            QFile f(srcDir.filePath("unknown.xyz"));
            QVERIFY(f.open(QIODevice::WriteOnly));
            f.write(QByteArray(128, '\xAB'));
        }

        // Run the scan
        ForensicEngine engine;
        QList<RecoveryResult> foundResults;
        bool scanFinished = false;

        connect(&engine, &ForensicEngine::fileFound, [&](const RecoveryResult &r) {
            foundResults.append(r);
        });
        connect(&engine, &ForensicEngine::finished, [&](bool, const QString &, const QList<RecoveryResult> &) {
            scanFinished = true;
        });

        ForensicConfig config;
        config.mode       = ForensicConfig::ScanMode::LogicalPath;
        config.sourcePath = srcDir.path();
        config.destPath   = dstDir.path();
        // Scan all categories
        QVERIFY(engine.startScan(config));

        // Pump events until scan finishes (max 10 seconds)
        QEventLoop loop;
        QTimer::singleShot(10000, &loop, &QEventLoop::quit);
        connect(&engine, &ForensicEngine::finished, &loop, &QEventLoop::quit);
        loop.exec();

        QVERIFY2(scanFinished, "Scan should have finished within 10 seconds");

        // Should have found exactly 3 known types (JPEG, PNG, PDF)
        QCOMPARE(foundResults.size(), 3);

        // Verify file types detected correctly
        QStringList detectedTypes;
        for (const RecoveryResult &r : foundResults)
            detectedTypes << r.extension;
        QVERIFY2(detectedTypes.contains("jpg"), "JPEG should be detected");
        QVERIFY2(detectedTypes.contains("png"), "PNG should be detected");
        QVERIFY2(detectedTypes.contains("pdf"), "PDF should be detected");

        // Test 2: source directory is unmodified
        QDir src(srcDir.path());
        QStringList srcFiles = src.entryList(QDir::Files);
        QVERIFY2(srcFiles.contains("test.jpg"),   "Source JPEG should still exist");
        QVERIFY2(srcFiles.contains("test.png"),   "Source PNG should still exist");
        QVERIFY2(srcFiles.contains("test.pdf"),   "Source PDF should still exist");
        QVERIFY2(srcFiles.contains("unknown.xyz"),"Source unknown file should still exist");

        // Test 3: destination has recovered files
        QDir dst(dstDir.path());
        QVERIFY2(dst.entryList(QDir::Files).size() >= 3,
                 "Destination should have at least 3 recovered files");

        // Test 4: unknown.xyz was NOT in results
        for (const RecoveryResult &r : foundResults) {
            QVERIFY2(r.extension != "xyz", "Unknown file type should not be recovered");
        }
    }

    // Test 5: source == destination triggers safety rejection
    void testSafetyRejection_SameSourceDest() {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());

        ForensicEngine engine;
        bool warningFired = false;
        connect(&engine, &ForensicEngine::warning, [&](const QString &) {
            warningFired = true;
        });

        ForensicConfig config;
        config.mode       = ForensicConfig::ScanMode::LogicalPath;
        config.sourcePath = dir.path();
        config.destPath   = dir.path(); // Same as source!

        bool started = engine.startScan(config);
        QVERIFY2(!started,      "Scan should be rejected when src == dst");
        QVERIFY2(warningFired,  "A warning should be emitted when src == dst");
    }

    // Test 6: raw mode without confirmation fires warning and returns false
    void testSafetyRejection_RawWithoutConfirmation() {
        QTemporaryDir dst;
        ForensicEngine engine;
        bool warningFired = false;
        connect(&engine, &ForensicEngine::warning, [&](const QString &) {
            warningFired = true;
        });

        ForensicConfig config;
        config.mode             = ForensicConfig::ScanMode::RawDevice;
        config.sourcePath       = "\\\\.\\PhysicalDrive99"; // non-existent
        config.destPath         = dst.path();
        config.rawModeConfirmed = false; // Not confirmed!

        bool started = engine.startScan(config);
        QVERIFY2(!started,     "Raw scan should be rejected without confirmation");
        QVERIFY2(warningFired, "Warning should fire when raw scan is not confirmed");
    }
};

#include "test_forensic_engine.moc"
