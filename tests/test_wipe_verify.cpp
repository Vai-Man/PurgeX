// test_wipe_verify.cpp
// Unit tests for WipeEngine verification functionality
//
// Tests:
//   1. Zero-fill wipe + verify → PASS
//   2. Write random data after zero-fill, verify detects mismatch → FAIL
//   3. verifyFreeSpace probe round-trip (creates/verifies/deletes probe file)

#include <QtTest/QtTest>
#include <QFile>
#include <QDir>
#include <QTemporaryDir>
#include <QTemporaryFile>
#include "../core/WipeEngine.h"

class TestWipeVerify : public QObject {
    Q_OBJECT

private slots:
    void initTestCase()  {}
    void cleanupTestCase() {}

    // Test 1: write zero-fill pattern, read it back, expect PASS
    void testVerifyZeroFill_Pass() {
        QTemporaryFile f;
        QVERIFY(f.open());
        // Write 1 MB of zeros
        const qint64 sz = 1 * 1024 * 1024;
        f.write(QByteArray(sz, '\x00'));
        f.flush();
        f.seek(0);
        f.close();

        WipeEngine engine;
        VerificationResult vr = engine.verifyFile(f.fileName(), WipePattern::ZERO_FILL);

        QVERIFY2(vr.performed,    "Verification should have been performed");
        QVERIFY2(vr.passed,       "Zero-fill verify should PASS on a freshly zeroed file");
        QCOMPARE(vr.sectorsFailed, (qint64)0);
    }

    // Test 2: write zeros, then corrupt a byte, expect FAIL
    void testVerifyZeroFill_Fail() {
        QTemporaryFile f;
        QVERIFY(f.open());
        const qint64 sz = 512 * 1024; // 512 KB
        f.write(QByteArray(sz, '\x00'));
        f.flush();
        // Corrupt one byte in the middle
        f.seek(sz / 2);
        f.write(QByteArray(1, '\xFF'));
        f.flush();
        f.close();

        WipeEngine engine;
        VerificationResult vr = engine.verifyFile(f.fileName(), WipePattern::ZERO_FILL);

        QVERIFY2(vr.performed, "Verification should have been performed");
        // The corrupted file should cause at least one chunk to fail
        QVERIFY2(!vr.passed, "Zero-fill verify should FAIL on corrupted file");
        QVERIFY2(vr.sectorsFailed > 0, "Should report at least one failed sector");
    }

    // Test 3: verifyFreeSpace round-trip
    void testVerifyFreeSpace() {
        QTemporaryDir td;
        QVERIFY(td.isValid());

        WipeEngine engine;
        VerificationResult vr = engine.verifyFreeSpace(td.path(), WipePattern::ZERO_FILL);

        QVERIFY2(vr.performed, "Free-space verification should have been performed");
        QVERIFY2(vr.passed,    "Free-space verify should PASS in a writable temp directory");
        // Probe file should have been cleaned up
        QVERIFY2(!QFile::exists(td.path() + "/PurgeX_Verify/purgex_verify_probe.dat"),
                 "Probe file should be cleaned up after verification");
    }

    // Test 4: verifyFile on a non-existent path returns performed=true, passed=false
    void testVerifyMissingFile() {
        WipeEngine engine;
        VerificationResult vr = engine.verifyFile("/nonexistent/path/file.dat", WipePattern::ZERO_FILL);
        QVERIFY2(vr.performed, "performed should be true even for missing file");
        QVERIFY2(!vr.passed,   "passed should be false for a missing file");
    }
};

#include "test_wipe_verify.moc"
