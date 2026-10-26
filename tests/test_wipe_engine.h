#pragma once
// test_wipe_engine.cpp
// Unit tests for patterns, file/folder wiping, the worker pipeline and the audit log.

#include <QtTest/QtTest>
#include <QFile>
#include <QDir>
#include <QTemporaryDir>
#include <QSignalSpy>
#include <QRandomGenerator>
#include <filesystem>
#include "../core/WipeEngine.h"
#include "../core/AuditLog.h"
#include "../core/AppPaths.h"
#include "../cert/CertManager.h"

class TestWipeEngine : public QObject {
    Q_OBJECT

private:
    static void makeFile(const QString &path, qint64 size, char fill = 'x') {
        QDir().mkpath(QFileInfo(path).absolutePath());
        QFile f(path);
        QVERIFY(f.open(QIODevice::WriteOnly));
        f.write(QByteArray(int(size), fill));
    }

private slots:
    // ---- patterns -----------------------------------------------------------
    void testEffectivePasses() {
        QCOMPARE(WipeEngine::effectivePasses(WipePattern::NIST_800_88_1_PASS, 9), 1);
        QCOMPARE(WipeEngine::effectivePasses(WipePattern::NIST_800_88_3_PASS, 1), 3);
        QCOMPARE(WipeEngine::effectivePasses(WipePattern::NIST_800_88_7_PASS, 1), 7);
        QCOMPARE(WipeEngine::effectivePasses(WipePattern::GUTMANN_35_PASS, 1), 35);
        QCOMPARE(WipeEngine::effectivePasses(WipePattern::RANDOM, 4), 4);
        QCOMPARE(WipeEngine::effectivePasses(WipePattern::ZERO_FILL, 0), 1);
    }

    void testNistSequence() {
        WipeEngine e;
        QCOMPARE(e.generatePattern(WipePattern::NIST_800_88_3_PASS, 64, 0), QByteArray(64, '\x00'));
        QCOMPARE(e.generatePattern(WipePattern::NIST_800_88_3_PASS, 64, 1), QByteArray(64, '\xFF'));
        const QByteArray r1 = e.generatePattern(WipePattern::NIST_800_88_3_PASS, 4096, 2);
        const QByteArray r2 = e.generatePattern(WipePattern::NIST_800_88_3_PASS, 4096, 2);
        QVERIFY2(r1 != r2, "the random pass must differ between calls");
        QVERIFY(r1 != QByteArray(4096, '\x00'));
        QCOMPARE(e.generatePattern(WipePattern::NIST_800_88_1_PASS, 8, 0), QByteArray(8, '\x00'));
    }

    void testGutmannSequence() {
        WipeEngine e;
        QCOMPARE(e.generatePattern(WipePattern::GUTMANN_35_PASS, 6, 4), QByteArray(6, '\x55'));
        QCOMPARE(e.generatePattern(WipePattern::GUTMANN_35_PASS, 6, 5), QByteArray(6, '\xAA'));
        QCOMPARE(e.generatePattern(WipePattern::GUTMANN_35_PASS, 6, 6), QByteArray::fromHex("924924924924"));
        // Three-byte patterns stay phase-aligned across chunk boundaries.
        QCOMPARE(e.generatePattern(WipePattern::GUTMANN_35_PASS, 3, 6, 1), QByteArray::fromHex("492492"));
        QCOMPARE(e.generatePattern(WipePattern::GUTMANN_35_PASS, 4, 28, 0), QByteArray::fromHex("6DB6DB6D"));
        QCOMPARE(e.generatePattern(WipePattern::GUTMANN_35_PASS, 3, 24), QByteArray(3, '\xFF'));
        QVERIFY(e.generatePattern(WipePattern::GUTMANN_35_PASS, 64, 0) != e.generatePattern(WipePattern::GUTMANN_35_PASS, 64, 0));
    }

    void testAlternatingSwapsEveryPass() {
        WipeEngine e;
        QCOMPARE(e.generatePattern(WipePattern::ALTERNATING, 4, 0), QByteArray::fromHex("55AA55AA"));
        QCOMPARE(e.generatePattern(WipePattern::ALTERNATING, 4, 1), QByteArray::fromHex("AA55AA55"));
    }

    // ---- files and folders ----------------------------------------------------
    void testWipeFile_RemovesAndVerifies() {
        QTemporaryDir dir;
        const QString path = dir.filePath("secret.bin");
        makeFile(path, 1024 * 1024 + 123);

        WipeEngine e;
        QVERIFY2(e.wipeFiles({path}, WipePattern::NIST_800_88_3_PASS, 3, true), qPrintable(e.lastMessage()));
        QVERIFY(!QFile::exists(path));
        QVERIFY(QDir(dir.path()).entryList(QDir::Files).isEmpty()); // no renamed leftovers
        const VerificationResult vr = e.lastFileVerification();
        QVERIFY(vr.performed);
        QVERIFY2(vr.passed, qPrintable(vr.note));
        QCOMPARE(vr.sectorsChecked, qint64(1));
        QVERIFY(!e.isRunning());
    }

    void testWipeFolder_ActuallyWorks() {
        // Regression: wipeFolder() marked the engine as running and then called wipeFiles(),
        // which refused to start - so wiping a folder always failed.
        QTemporaryDir dir;
        const QString folder = dir.filePath("project");
        makeFile(folder + "/a.txt", 5000);
        makeFile(folder + "/sub/b.txt", 7000);
        makeFile(folder + "/sub/deeper/c.bin", 9000);

        WipeEngine e;
        QVERIFY2(e.wipeFolder(folder, WipePattern::ZERO_FILL, 1), qPrintable(e.lastMessage()));
        QVERIFY2(!QDir(folder).exists(), "the folder and its sub-folders must be removed");
    }

    void testWipeFiles_AcceptsFoldersInTheList() {
        QTemporaryDir dir;
        makeFile(dir.filePath("keep_out/one.txt"), 100);
        makeFile(dir.filePath("single.txt"), 100);

        WipeEngine e;
        QVERIFY(e.wipeFiles({dir.filePath("keep_out"), dir.filePath("single.txt")}, WipePattern::ONE_FILL, 1));
        QVERIFY(!QFile::exists(dir.filePath("single.txt")));
        QVERIFY(!QDir(dir.filePath("keep_out")).exists());
    }

    void testWipeMissingFileFails() {
        WipeEngine e;
        QVERIFY(!e.wipeFiles({"/definitely/not/here.txt"}, WipePattern::ZERO_FILL, 1));
        QVERIFY(!e.lastMessage().isEmpty());
        QVERIFY(!e.isRunning());
    }

    void testEmptyFile() {
        QTemporaryDir dir;
        const QString path = dir.filePath("empty.txt");
        makeFile(path, 0);
        WipeEngine e;
        QVERIFY(e.wipeFiles({path}, WipePattern::NIST_800_88_3_PASS, 3, true));
        QVERIFY(!QFile::exists(path));
    }

    void testSymlinkIsRemovedNotFollowed() {
        QTemporaryDir dir;
        const QString target = dir.filePath("target.txt");
        const QString link = dir.filePath("link.txt");
        makeFile(target, 2048, 'T');
        std::error_code ec;
        std::filesystem::create_symlink(target.toStdString(), link.toStdString(), ec);
        if (ec) QSKIP("symbolic links are not available in this environment");

        WipeEngine e;
        QVERIFY(e.wipeFiles({link}, WipePattern::ZERO_FILL, 1));
        QVERIFY2(QFile::exists(target), "the link target must survive");
        QFile f(target);
        QVERIFY(f.open(QIODevice::ReadOnly));
        QCOMPARE(f.readAll(), QByteArray(2048, 'T'));
    }

    void testCancelStopsCleanly() {
        QTemporaryDir dir;
        const QString path = dir.filePath("big.bin");
        makeFile(path, 8 * 1024 * 1024);

        WipeEngine e;
        const QMetaObject::Connection c = QObject::connect(
            &e, &WipeEngine::progress, &e, [&e](int, const QString &) { e.cancel(); }, Qt::DirectConnection);
        QVERIFY(!e.wipeFiles({path}, WipePattern::GUTMANN_35_PASS, 35));
        QVERIFY(e.lastMessage().contains("cancel", Qt::CaseInsensitive));
        QVERIFY(!e.isRunning());
        // A cancelled engine can be used again.
        QObject::disconnect(c);
        QVERIFY(e.wipeFiles({path}, WipePattern::ZERO_FILL, 1));
        QVERIFY(!QFile::exists(path));
    }

    void testConcurrentStartIsRefused() {
        WipeEngine e;
        e.running = true;
        QVERIFY(!e.wipeFiles({"x"}, WipePattern::ZERO_FILL, 1));
        e.running = false;
    }

    void testFreeSpaceRejectsInvalidDrive() {
        WipeEngine e;
        QVERIFY(!e.wipeFreeSpace("/definitely/not/a/drive", WipePattern::ZERO_FILL, 1));
        QVERIFY(!e.isRunning());
    }

    void testSystemDiskIsProtected() {
#ifdef Q_OS_WIN
        QString sys = QString::fromLocal8Bit(qgetenv("SystemDrive"));
        if (sys.isEmpty()) sys = "C:";
        QVERIFY(WipeEngine::isSystemDevice(sys));
        QVERIFY(WipeEngine::physicalDriveNumber(sys) >= 0);
#else
        QSKIP("Windows-specific disk mapping check");
#endif
    }

    // ---- worker pipeline (what the GUI and CLI run) ----------------------------
    void testWorker_FullPipeline() {
        QTemporaryDir dir;
        const QString path = dir.filePath("report.docx");
        makeFile(path, 300000);

        WipeEngine engine;
        WipeConfig cfg;
        cfg.target = WipeTarget::FILES;
        cfg.pattern = WipePattern::NIST_800_88_3_PASS;
        cfg.passes = 3;
        cfg.verify = true;
        cfg.generateCertificate = true;
        cfg.paths = QStringList(path);

        WipeWorker worker(cfg, &engine);
        QSignalSpy spy(&worker, &WipeWorker::finished);
        worker.start();
        QTRY_COMPARE_WITH_TIMEOUT(spy.count(), 1, 30000);
        worker.wait();

        QVERIFY2(spy.first().at(0).toBool(), qPrintable(spy.first().at(1).toString()));
        QVERIFY(!QFile::exists(path));
        QVERIFY(QFile::exists(worker.certificatePdfPath()));
        QVERIFY(QFile::exists(worker.certificateJsonPath()));

        CertManager cm;
        QString msg;
        QVERIFY2(cm.verifyJsonCertificate(worker.certificateJsonPath(), &msg, nullptr), qPrintable(msg));

        const AuditEntry last = AuditLog().entries().first();
        QCOMPARE(last.type, QString("wipe"));
        QCOMPARE(last.status, QString("success"));
        QCOMPARE(last.verificationStatus, QString("verified"));
        QCOMPARE(last.certPath, worker.certificatePdfPath());
    }

    void testWorker_FailureIsAudited() {
        WipeEngine engine;
        WipeConfig cfg;
        cfg.target = WipeTarget::FILES;
        cfg.paths = QStringList("/no/such/file.bin");
        cfg.generateCertificate = true;

        const int before = AuditLog().entries().size();
        WipeWorker worker(cfg, &engine);
        QSignalSpy spy(&worker, &WipeWorker::finished);
        worker.start();
        QTRY_COMPARE_WITH_TIMEOUT(spy.count(), 1, 15000);
        worker.wait();

        QVERIFY(!spy.first().at(0).toBool());
        QVERIFY(worker.certificatePdfPath().isEmpty()); // never certify a failed wipe
        const QList<AuditEntry> entries = AuditLog().entries();
        QCOMPARE(entries.size(), before + 1);
        QCOMPARE(entries.first().status, QString("failed"));
    }

    // ---- audit log --------------------------------------------------------------
    void testAuditLog_AppendFilterFind() {
        AuditLog log;
        AuditEntry e;
        e.id = AuditLog::generateId();
        e.type = "recovery";
        e.timestamp = QDateTime::currentDateTime();
        e.target = "disk.img";
        e.status = "success";
        QVERIFY(log.append(e));

        AuditLog reloaded;
        QCOMPARE(reloaded.findById(e.id).target, QString("disk.img"));
        QVERIFY(!reloaded.filter("recovery", "success").isEmpty());
        QVERIFY(reloaded.filter("wipe", "no-such-status").isEmpty());
        QCOMPARE(reloaded.entries().first().id, e.id); // newest first
    }

    void testAuditLog_CorruptFileIsPreserved() {
        QFile f(AppPaths::auditLogPath());
        QVERIFY(f.open(QIODevice::WriteOnly | QIODevice::Truncate));
        f.write("{ this is not json");
        f.close();

        AuditLog log;
        QVERIFY(log.entries().isEmpty());
        QStringList backups = QDir(AppPaths::dataRoot()).entryList({"audit_log.json.corrupt-*"}, QDir::Files);
        QVERIFY2(!backups.isEmpty(), "the unreadable log must be kept, not silently overwritten");

        AuditEntry e;
        e.id = AuditLog::generateId();
        QVERIFY(log.append(e));
    }
};

