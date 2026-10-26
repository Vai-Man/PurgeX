#pragma once
// test_forensic_engine.cpp
// Unit tests for the ForensicEngine (logical scan, raw sector carving, safety checks)

#include <QtTest/QtTest>
#include <QFile>
#include <QDir>
#include <QTemporaryDir>
#include <QEventLoop>
#include <QTimer>
#include <QCryptographicHash>
#include "../forensics/ForensicEngine.h"

namespace fx {

inline QByteArray hex(const char *h) { return QByteArray::fromHex(h); }

inline QByteArray be16(int v) { QByteArray b; b.append(char(v >> 8)); b.append(char(v)); return b; }
inline QByteArray be32(quint32 v) { QByteArray b; for (int s = 24; s >= 0; s -= 8) b.append(char(v >> s)); return b; }
inline QByteArray le16(int v) { QByteArray b; b.append(char(v)); b.append(char(v >> 8)); return b; }
inline QByteArray le32(quint32 v) { QByteArray b; for (int s = 0; s < 32; s += 8) b.append(char(v >> s)); return b; }

// JPEG with an optional EXIF thumbnail whose end-of-image marker sits INSIDE the file.
inline QByteArray makeJpeg(int scanBytes, bool exifThumbnail)
{
    QByteArray j = hex("FFD8");
    j += hex("FFE000104A46494600010100000100010000");              // JFIF APP0 (len 16)
    if (exifThumbnail) {
        QByteArray body = QByteArray("Exif\0\0", 6) + hex("FFD8FFE000") + QByteArray(40, '\x07') + hex("FFD9");
        j += hex("FFE1") + be16(body.size() + 2) + body;
    }
    j += hex("FFDA0008010100003F00");                                // SOS header
    QByteArray scan;
    for (int i = 0; i < scanBytes; ++i) scan.append(char(0x11 + (i % 50)));
    scan += hex("FF00") + QByteArray(8, '\x22') + hex("FFD0") + QByteArray(8, '\x33'); // stuffing + RST0
    return j + scan + hex("FFD9");
}

inline QByteArray pngChunk(const char *type, const QByteArray &data)
{
    return be32(data.size()) + QByteArray(type, 4) + data + hex("DEADBEEF");
}

inline QByteArray makePng(int idatBytes)
{
    return hex("89504E470D0A1A0A") + pngChunk("IHDR", QByteArray(13, '\x01'))
         + pngChunk("IDAT", QByteArray(idatBytes, '\x5A')) + pngChunk("IEND", QByteArray());
}

inline QByteArray makeGif()
{
    return QByteArray("GIF89a") + hex("01000100000000") + hex("2C000000000100010000")
         + hex("02") + hex("03112233") + hex("00") + hex("3B");
}

inline QByteArray makePdf(int bodyBytes)
{
    return QByteArray("%PDF-1.4\n") + QByteArray(bodyBytes, 'p') + QByteArray("\n%%EOF");
}

// Minimal "stored" ZIP with a single entry.
inline QByteArray makeZip(const QByteArray &entryName, const QByteArray &data)
{
    QByteArray local = hex("504B0304") + le16(20) + le16(0) + le16(0) + le16(0) + le16(0)
                     + le32(0) + le32(data.size()) + le32(data.size()) + le16(entryName.size()) + le16(0)
                     + entryName + data;
    QByteArray central = hex("504B0102") + le16(20) + le16(20) + le16(0) + le16(0) + le16(0) + le16(0)
                       + le32(0) + le32(data.size()) + le32(data.size()) + le16(entryName.size())
                       + le16(0) + le16(0) + le16(0) + le16(0) + le32(0) + le32(0) + entryName;
    QByteArray eocd = hex("504B0506") + le16(0) + le16(0) + le16(1) + le16(1)
                    + le32(central.size()) + le32(local.size()) + le16(0);
    return local + central + eocd;
}

inline QByteArray makeWav(int dataBytes)
{
    QByteArray fmt = QByteArray("fmt ") + le32(16) + le16(1) + le16(1) + le32(8000) + le32(8000) + le16(1) + le16(8);
    QByteArray data = QByteArray("data") + le32(dataBytes) + QByteArray(dataBytes, '\x80');
    return QByteArray("RIFF") + le32(4 + fmt.size() + data.size()) + QByteArray("WAVE") + fmt + data;
}

struct Outcome {
    bool finished = false;
    bool ok = false;
    QString message;
    QList<RecoveryResult> found;
};

// Runs a scan and waits for it. The context object (the loop) lives on the test thread, so
// the connections are queued - exactly like the GUI. That only works if the result types are
// registered with Qt's metatype system.
inline Outcome runScan(ForensicEngine &engine, const ForensicConfig &cfg, bool *started = nullptr)
{
    Outcome out;
    QEventLoop loop;
    QObject::connect(&engine, &ForensicEngine::fileFound, &loop,
                     [&](const RecoveryResult &r) { out.found.append(r); });
    QObject::connect(&engine, &ForensicEngine::finished, &loop,
                     [&](bool ok, const QString &msg, const QList<RecoveryResult> &) {
                         out.finished = true; out.ok = ok; out.message = msg; loop.quit();
                     });
    QTimer::singleShot(30000, &loop, &QEventLoop::quit);
    const bool s = engine.startScan(cfg);
    if (started) *started = s;
    if (s) loop.exec();
    return out;
}

inline void writeAll(const QString &path, const QByteArray &data)
{
    QFile f(path);
    QVERIFY(f.open(QIODevice::WriteOnly));
    f.write(data);
}

inline QByteArray readAll(const QString &path)
{
    QFile f(path);
    return f.open(QIODevice::ReadOnly) ? f.readAll() : QByteArray();
}

} // namespace fx

class TestForensicEngine : public QObject {
    Q_OBJECT

private slots:
    // ---- logical scan ------------------------------------------------------
    void testLogicalScan_KnownTypes() {
        QTemporaryDir srcDir, dstDir;
        QVERIFY(srcDir.isValid() && dstDir.isValid());

        fx::writeAll(srcDir.filePath("test.jpg"), fx::makeJpeg(300, false));
        fx::writeAll(srcDir.filePath("test.png"), fx::makePng(200));
        fx::writeAll(srcDir.filePath("test.pdf"), fx::makePdf(256));
        fx::writeAll(srcDir.filePath("unknown.xyz"), QByteArray(128, '\xAB'));

        ForensicEngine engine;
        ForensicConfig config;
        config.mode       = ForensicConfig::ScanMode::LogicalPath;
        config.sourcePath = srcDir.path();
        config.destPath   = dstDir.path();
        const fx::Outcome o = fx::runScan(engine, config);

        QVERIFY2(o.finished, "finished() must reach the test thread (RecoveryResult metatype registered?)");
        QVERIFY2(o.ok, qPrintable(o.message));
        QCOMPARE(o.found.size(), 3);

        QStringList exts;
        for (const RecoveryResult &r : o.found) {
            exts << r.extension;
            QCOMPARE(r.confidence, RecoveryConfidence::HIGH);
            QCOMPARE(r.status, RecoveryStatus::Recovered);
            QCOMPARE(r.sha256.size(), 64);
        }
        exts.sort();
        QCOMPARE(exts, (QStringList{"jpg", "pdf", "png"}));

        // The source is untouched and the recovered copy is byte-identical.
        QVERIFY(QFile::exists(srcDir.filePath("test.jpg")));
        QVERIFY(QFile::exists(srcDir.filePath("unknown.xyz")));
        for (const RecoveryResult &r : o.found) {
            const QString original = srcDir.filePath("test." + r.extension);
            QCOMPARE(fx::readAll(r.destinationPath), fx::readAll(original));
        }
    }

    void testLogicalScan_SiblingFolderIsNotInsideSource() {
        // "/data" and "/data2" share a string prefix but are different folders.
        QTemporaryDir root;
        QVERIFY(root.isValid());
        QVERIFY(QDir(root.path()).mkpath("data"));
        QVERIFY(QDir(root.path()).mkpath("data2"));
        fx::writeAll(root.filePath("data/a.png"), fx::makePng(64));

        ForensicEngine engine;
        ForensicConfig config;
        config.sourcePath = root.filePath("data");
        config.destPath   = root.filePath("data2");
        bool started = false;
        const fx::Outcome o = fx::runScan(engine, config, &started);
        QVERIFY2(started, "a sibling folder with a common prefix must be an allowed destination");
        QVERIFY(o.finished);
        QCOMPARE(o.found.size(), 1);
    }

    // ---- raw carving -------------------------------------------------------
    void testRawCarving_DiskImage() {
        const QByteArray jpgPlain = fx::makeJpeg(2000, false);
        const QByteArray jpgThumb = fx::makeJpeg(3000, true);   // contains an FFD9 inside EXIF
        const QByteArray png      = fx::makePng(1500);
        const QByteArray gif      = fx::makeGif();
        const QByteArray pdf      = fx::makePdf(5000);
        const QByteArray docx     = fx::makeZip("word/document.xml", QByteArray(900, 'd'));
        const QByteArray zip      = fx::makeZip("readme.txt", QByteArray(700, 'z'));
        const QByteArray wav      = fx::makeWav(1200);

        // Lay the files out on 512-byte sector boundaries inside an otherwise empty "disk".
        QByteArray disk(3 * 1024 * 1024, '\0');
        QMap<qint64, QByteArray> placed;
        auto place = [&](qint64 sectorNo, const QByteArray &data) {
            const qint64 off = sectorNo * 512;
            disk.replace(int(off), data.size(), data);
            placed.insert(off, data);
        };
        place(3,    jpgPlain);
        place(40,   jpgThumb);
        place(100,  png);
        place(200,  gif);
        place(300,  pdf);
        place(400,  docx);
        place(500,  zip);
        place(600,  wav);
        place(2000, png);                                         // a second copy further in
        // Noise that must NOT be reported: a signature that is not sector aligned,
        // and a bare "BM" that is not a real bitmap header.
        disk.replace(int(900 * 512 + 100), png.size(), png);
        disk.replace(int(1000 * 512), 2, "BM");

        QTemporaryDir work, dstDir;
        QVERIFY(work.isValid() && dstDir.isValid());
        const QString image = work.filePath("disk.img");
        fx::writeAll(image, disk);

        ForensicEngine engine;
        ForensicConfig config;
        config.mode             = ForensicConfig::ScanMode::RawDevice;
        config.sourcePath       = image;
        config.destPath         = dstDir.path();
        config.rawModeConfirmed = true;
        const fx::Outcome o = fx::runScan(engine, config);

        QVERIFY2(o.finished, "raw scan must report completion");
        QVERIFY2(o.ok, qPrintable(o.message));
        QCOMPARE(o.found.size(), placed.size());

        QStringList wanted, got;
        for (const RecoveryResult &r : o.found) {
            QVERIFY2(placed.contains(r.originalOffset), qPrintable(QString("unexpected hit at %1").arg(r.originalOffset)));
            const QByteArray expected = placed.value(r.originalOffset);
            const QByteArray recovered = fx::readAll(r.destinationPath);
            QCOMPARE(recovered.size(), expected.size());            // exact length, no trailing junk
            QVERIFY2(recovered == expected, qPrintable("content differs: " + r.fileType));
            QCOMPARE(r.confidence, RecoveryConfidence::HIGH);
            QCOMPARE(r.sha256, QString::fromLatin1(QCryptographicHash::hash(expected, QCryptographicHash::Sha256).toHex()));
            got << QString("%1@%2").arg(r.extension).arg(r.originalOffset / 512);
        }
        got.sort();
        wanted << "jpg@3" << "jpg@40" << "png@100" << "gif@200" << "pdf@300"
               << "docx@400" << "zip@500" << "wav@600" << "png@2000";
        wanted.sort();
        QCOMPARE(got, wanted);

        // The image itself was never modified.
        QCOMPARE(fx::readAll(image), disk);
    }

    void testRawCarving_TruncatedFileIsFlagged() {
        // A PNG whose IEND chunk was overwritten: carved, but never reported as complete.
        QByteArray png = fx::makePng(800);
        png.chop(12);
        QByteArray disk(256 * 1024, '\0');
        disk.replace(512 * 4, png.size(), png);

        QTemporaryDir work, dstDir;
        const QString image = work.filePath("broken.img");
        fx::writeAll(image, disk);

        ForensicEngine engine;
        ForensicConfig config;
        config.mode = ForensicConfig::ScanMode::RawDevice;
        config.sourcePath = image;
        config.destPath = dstDir.path();
        config.rawModeConfirmed = true;
        const fx::Outcome o = fx::runScan(engine, config);
        QVERIFY(o.finished);
        QVERIFY(!o.found.isEmpty());
        QVERIFY(o.found.first().status != RecoveryStatus::Recovered);
        QVERIFY(o.found.first().confidence != RecoveryConfidence::HIGH);
    }

    void testRawCarving_LookalikesAreRejected() {
        // Short or weak magic numbers sit at sector starts in unrelated data: none of them
        // may turn into recovered "files" (they used to be carved up to their size cap).
        QByteArray disk(8 * 1024 * 1024, '\xFF');
        for (int sector : {10, 200, 3000, 9000}) {
            disk.replace(sector * 512, 2, "BM");
            disk.replace((sector + 1) * 512, 2, "MZ");
            disk.replace((sector + 2) * 512, 3, QByteArray::fromHex("1F8B08"));
            disk.replace((sector + 3) * 512, 5, "<?xml");
            disk.replace((sector + 4) * 512, 4, "fLaC");
            disk.replace((sector + 5) * 512, 3, "ID3");
            disk.replace((sector + 6) * 512, 4, "RIFF");
        }
        QTemporaryDir work, dstDir;
        const QString image = work.filePath("noise.img");
        fx::writeAll(image, disk);

        ForensicEngine engine;
        ForensicConfig config;
        config.mode = ForensicConfig::ScanMode::RawDevice;
        config.sourcePath = image;
        config.destPath = dstDir.path();
        config.rawModeConfirmed = true;
        const fx::Outcome o = fx::runScan(engine, config);
        QVERIFY(o.finished);
        QVERIFY2(o.found.isEmpty(), qPrintable(QString("%1 false positive(s)").arg(o.found.size())));
        QVERIFY(QDir(dstDir.path()).entryList(QDir::Files).isEmpty());
    }

    // ---- safety gates ------------------------------------------------------
    void testSafetyRejection_SameSourceDest() {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());

        ForensicEngine engine;
        bool warningFired = false;
        connect(&engine, &ForensicEngine::warning, [&](const QString &) { warningFired = true; });

        ForensicConfig config;
        config.mode       = ForensicConfig::ScanMode::LogicalPath;
        config.sourcePath = dir.path();
        config.destPath   = dir.path();

        QVERIFY2(!engine.startScan(config), "Scan should be rejected when src == dst");
        QVERIFY2(warningFired, "A warning should be emitted when src == dst");
        QVERIFY2(!engine.isRunning(), "A rejected scan must not leave the engine 'running'");
    }

    void testSafetyRejection_DestInsideSource() {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        ForensicEngine engine;
        ForensicConfig config;
        config.sourcePath = dir.path();
        config.destPath   = dir.filePath("recovered");
        QVERIFY(!engine.startScan(config));
    }

    void testSafetyRejection_RawWithoutConfirmation() {
        QTemporaryDir dst;
        ForensicEngine engine;
        bool warningFired = false;
        connect(&engine, &ForensicEngine::warning, [&](const QString &) { warningFired = true; });

        ForensicConfig config;
        config.mode             = ForensicConfig::ScanMode::RawDevice;
        config.sourcePath       = "\\\\.\\PhysicalDrive99"; // non-existent
        config.destPath         = dst.path();
        config.rawModeConfirmed = false;

        QVERIFY2(!engine.startScan(config), "Raw scan should be rejected without confirmation");
        QVERIFY2(warningFired, "Warning should fire when raw scan is not confirmed");
    }

    void testRawScan_MissingSourceIsRejectedCleanly() {
        QTemporaryDir dst;
        ForensicEngine engine;
        ForensicConfig config;
        config.mode             = ForensicConfig::ScanMode::RawDevice;
        config.sourcePath       = dst.filePath("does-not-exist.img");
        config.destPath         = dst.filePath("out");
        config.rawModeConfirmed = true;
        QVERIFY(!engine.startScan(config));
        QVERIFY(!engine.isRunning());
    }
};

