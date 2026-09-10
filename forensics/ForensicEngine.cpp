#include "ForensicEngine.h"

#include <QFile>
#include <QDir>
#include <QDirIterator>
#include <QFileInfo>
#include <QDateTime>
#include <QRandomGenerator>
#include <QApplication>
#include <QDebug>
#include <cassert>

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
static QString uniqueDestPath(const QString &destDir, const QString &ext, int index)
{
    QString ts = QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss");
    return QDir(destDir).filePath(
        QString("recovered_%1_%2.%3").arg(index, 6, 10, QChar('0')).arg(ts).arg(ext));
}

// ---------------------------------------------------------------------------
// ForensicEngine
// ---------------------------------------------------------------------------
ForensicEngine::ForensicEngine(QObject *parent) : QObject(parent) {}

bool ForensicEngine::startScan(const ForensicConfig &config)
{
    if (running) return false;

    // ---- Safety gate: source and destination must not overlap ----
    QFileInfo srcInfo(config.sourcePath);
    QFileInfo dstInfo(config.destPath);
    QString srcAbs = srcInfo.absoluteFilePath();
    QString dstAbs = dstInfo.absoluteFilePath();

    if (dstAbs.startsWith(srcAbs) && config.mode == ForensicConfig::ScanMode::LogicalPath) {
        emit warning("Destination must not be inside the source directory. Scan aborted.");
        return false;
    }

    // ---- Safety gate: raw mode requires explicit confirmation ----
    if (config.mode == ForensicConfig::ScanMode::RawDevice && !config.rawModeConfirmed) {
        emit warning("Raw device scan requires explicit user confirmation. Scan aborted.");
        return false;
    }

    // Ensure destination exists
    QDir().mkpath(config.destPath);

    running  = true;
    cancelled = false;

    auto *worker = new ForensicWorker(config, this, this);
    connect(worker, &QThread::finished,  worker, &QObject::deleteLater);
    worker->start();
    return true;
}

void ForensicEngine::cancel()
{
    cancelled = true;
}

// ---------------------------------------------------------------------------
// Logical scan — walks the source directory, matches file headers
// ---------------------------------------------------------------------------
void ForensicEngine::runLogicalScan(const ForensicConfig &config)
{
    QList<FileSignature> allSigs = builtinSignatures();

    // Filter by category if requested
    QList<FileSignature> activeSigs;
    for (const FileSignature &sig : allSigs) {
        if (config.categories.isEmpty() || config.categories.contains(sig.category))
            activeSigs.append(sig);
    }

    if (activeSigs.isEmpty()) {
        emit finished(false, "No file signatures match the selected categories.", {});
        running = false;
        return;
    }

    // Enumerate files
    QStringList filePaths;
    QDirIterator it(config.sourcePath,
                    QDir::Files | QDir::Hidden | QDir::System,
                    QDirIterator::Subdirectories);
    while (it.hasNext()) {
        filePaths.append(it.next());
        if (cancelled) break;
    }

    if (cancelled) {
        emit finished(false, "Scan cancelled.", {});
        running = false;
        return;
    }

    QList<RecoveryResult> results;
    int total   = filePaths.size();
    int fileIdx = 0;

    for (const QString &path : filePaths) {
        if (cancelled) break;

        int pct = total > 0 ? (fileIdx * 100) / total : 0;
        emit progress(pct, QString("Scanning: %1").arg(QFileInfo(path).fileName()));

        RecoveryResult r = matchLogicalFile(path, activeSigs, config.destPath, fileIdx);
        if (r.status != RecoveryStatus::Unrecoverable || !r.destinationPath.isEmpty()) {
            results.append(r);
            emit fileFound(r);
        }

        ++fileIdx;
    }

    QString msg = cancelled
        ? "Scan cancelled."
        : QString("Scan complete. %1 file(s) found.").arg(results.size());

    emit finished(!cancelled, msg, results);
    running = false;
}

// ---------------------------------------------------------------------------
// Raw device scan — sliding-window header search across raw bytes
// ---------------------------------------------------------------------------
void ForensicEngine::runRawScan(const ForensicConfig &config)
{
    // Verify the source is an accessible device/file — ALWAYS ReadOnly
    QFile device(config.sourcePath);
    if (!device.open(QIODevice::ReadOnly | QIODevice::Unbuffered)) {
        emit finished(false,
            QString("Cannot open source device (ReadOnly): %1 — %2")
                .arg(config.sourcePath, device.errorString()),
            {});
        running = false;
        return;
    }

    // Determine device size
    qint64 deviceSize = device.size();
    if (deviceSize <= 0) {
        // For raw devices Qt often returns 0; try seeking to end
        if (device.seek(device.size())) {
            deviceSize = device.pos();
        }
    }

    QList<FileSignature> allSigs = builtinSignatures();
    QList<FileSignature> activeSigs;
    for (const FileSignature &sig : allSigs) {
        if (config.categories.isEmpty() || config.categories.contains(sig.category))
            activeSigs.append(sig);
    }

    // Build the minimum header length needed for the sliding window
    int maxHdrLen = 0;
    for (const FileSignature &sig : activeSigs)
        maxHdrLen = qMax(maxHdrLen, sig.header.size() + sig.headerOffset);

    const qint64 chunkSize = 1 * 1024 * 1024; // 1 MB
    QByteArray   window;
    window.reserve(chunkSize + maxHdrLen);

    QList<RecoveryResult> results;
    qint64 offset  = 0;
    int    fileIdx = 0;

    emit progress(0, "Starting raw device scan...");

    while (!cancelled) {
        QByteArray chunk = device.read(chunkSize);
        if (chunk.isEmpty()) break;

        window.append(chunk);

        // Scan the window for each signature's header
        for (const FileSignature &sig : activeSigs) {
            int searchFrom = 0;
            while (true) {
                int pos = window.indexOf(sig.header, searchFrom);
                if (pos < 0) break;

                // Ensure header is at the correct offset
                if (sig.headerOffset > 0 && pos < sig.headerOffset) {
                    searchFrom = pos + 1;
                    continue;
                }

                qint64 carveOffset = offset + pos - (window.size() - chunk.size());
                if (carveOffset < 0) carveOffset = 0;

                // Seek the device to the found offset and carve
                device.seek(carveOffset);
                RecoveryResult r = carveFromDevice(device, carveOffset, sig, config.destPath, fileIdx++);
                if (r.status != RecoveryStatus::Unrecoverable || r.recoveredBytes > 0) {
                    results.append(r);
                    emit fileFound(r);
                }

                // Seek back to continue main scan
                qint64 resumeAt = offset + chunk.size();
                device.seek(resumeAt);

                searchFrom = pos + 1;
                if (cancelled) break;
            }
            if (cancelled) break;
        }

        // Keep overlap for cross-boundary header detection
        if (window.size() > maxHdrLen)
            window = window.right(maxHdrLen);

        offset += chunk.size();

        if (deviceSize > 0) {
            int pct = static_cast<int>((offset * 100) / deviceSize);
            emit progress(pct, QString("Raw scan: %1 MB scanned, %2 file(s) found")
                .arg(offset / (1024 * 1024)).arg(results.size()));
        }

        if (chunk.size() < chunkSize) break; // EOF
    }

    device.close();

    // SAFETY ASSERTION: verify we never opened for write
    Q_ASSERT(!device.isOpen());

    QString msg = cancelled
        ? "Raw scan cancelled."
        : QString("Raw scan complete. %1 file(s) recovered.").arg(results.size());

    emit finished(!cancelled, msg, results);
    running = false;
}

// ---------------------------------------------------------------------------
// Carve a single file from an open raw device at a known offset
// ---------------------------------------------------------------------------
RecoveryResult ForensicEngine::carveFromDevice(QIODevice   &source,
                                               qint64       headerOffset,
                                               const FileSignature &sig,
                                               const QString &destDir,
                                               int           fileIndex)
{
    RecoveryResult r;
    r.sourcePath    = "(raw device)";
    r.originalOffset = headerOffset;
    r.fileType      = sig.name;
    r.extension     = sig.extension;
    r.category      = sig.category;
    r.status        = RecoveryStatus::Unrecoverable;
    r.recoveredBytes = 0;

    // Source must already be seeked to headerOffset by caller
    const qint64 readChunk = 64 * 1024;
    QByteArray   content;
    bool         footerFound = false;

    while (content.size() < sig.maxSize && !cancelled) {
        QByteArray block = source.read(readChunk);
        if (block.isEmpty()) break;

        if (!sig.footer.isEmpty()) {
            int fi = block.indexOf(sig.footer);
            if (fi >= 0) {
                content.append(block.left(fi + sig.footer.size()));
                footerFound = true;
                break;
            }
        }
        content.append(block);
    }

    if (content.isEmpty()) {
        r.notes = "No data could be read from device at this offset.";
        return r;
    }

    // Write recovered content
    QString outPath = uniqueDestPath(destDir, sig.extension, fileIndex);
    QFile out(outPath);
    if (!out.open(QIODevice::WriteOnly)) {
        r.notes = QString("Cannot write to destination: %1").arg(out.errorString());
        return r;
    }
    out.write(content);
    out.close();

    r.destinationPath = outPath;
    r.recoveredBytes  = content.size();
    r.confidence      = computeConfidence(footerFound, content.size() < sig.maxSize,
                                          content.size(), sig.maxSize);
    r.status          = footerFound ? RecoveryStatus::Recovered
                                    : RecoveryStatus::PartiallyRecovered;
    if (!footerFound && !sig.footer.isEmpty())
        r.notes = "Footer not found — file may be truncated.";

    return r;
}

// ---------------------------------------------------------------------------
// Logical file match — check a filesystem file against active signatures
// ---------------------------------------------------------------------------
RecoveryResult ForensicEngine::matchLogicalFile(const QString &filePath,
                                                const QList<FileSignature> &activeSigs,
                                                const QString &destDir,
                                                int fileIndex)
{
    RecoveryResult r;
    r.sourcePath     = filePath;
    r.originalOffset = 0;
    r.status         = RecoveryStatus::Unrecoverable;
    r.recoveredBytes = 0;

    // SAFETY: strictly ReadOnly
    QFile src(filePath);
    if (!src.open(QIODevice::ReadOnly)) {
        r.notes = QString("Cannot open source file (ReadOnly): %1").arg(src.errorString());
        return r;
    }

    // Read just enough bytes to test all headers
    const int PROBE = 256;
    QByteArray probe = src.read(PROBE);
    src.seek(0);

    const FileSignature *matched = nullptr;
    for (const FileSignature &sig : activeSigs) {
        int off = sig.headerOffset;
        if (off + sig.header.size() > probe.size()) continue;
        if (probe.mid(off, sig.header.size()) == sig.header) {
            matched = &sig;
            break;
        }
    }

    if (!matched) {
        src.close();
        return r; // no signature match
    }

    r.fileType  = matched->name;
    r.extension = matched->extension;
    r.category  = matched->category;

    // Read and write the file in chunks to avoid massive memory allocation
    qint64 fileBytes = src.size();
    if (fileBytes > matched->maxSize) fileBytes = matched->maxSize;

    QString outPath = uniqueDestPath(destDir, matched->extension, fileIndex);
    QFile out(outPath);
    if (!out.open(QIODevice::WriteOnly)) {
        r.notes = QString("Cannot write to destination: %1").arg(out.errorString());
        return r;
    }

    qint64 bytesCopied = 0;
    const qint64 chunkSize = 1024 * 1024; // 1 MB
    bool footerFound = false;

    // If it has a footer, we keep track of the last few bytes to check for it
    QByteArray trailingWindow;
    int footerLen = matched->footer.size();

    while (bytesCopied < fileBytes && !cancelled) {
        qint64 toRead = qMin(chunkSize, fileBytes - bytesCopied);
        QByteArray chunk = src.read(toRead);
        if (chunk.isEmpty()) break;

        out.write(chunk);
        bytesCopied += chunk.size();

        if (footerLen > 0) {
            trailingWindow.append(chunk);
            if (trailingWindow.size() > footerLen * 2) {
                // Keep only the end of the window to avoid unbounded growth
                trailingWindow = trailingWindow.right(footerLen * 2);
            }
            if (trailingWindow.contains(matched->footer)) {
                footerFound = true;
            }
        }
    }

    out.close();
    src.close();

    if (cancelled) {
        QFile::remove(outPath);
        return r;
    }

    r.destinationPath = outPath;
    r.recoveredBytes  = bytesCopied;
    r.confidence      = computeConfidence(footerFound || matched->footer.isEmpty(),
                                          bytesCopied < matched->maxSize,
                                          bytesCopied, matched->maxSize);
    r.status = (r.confidence == RecoveryConfidence::LOW)
        ? RecoveryStatus::PartiallyRecovered
        : RecoveryStatus::Recovered;

    if (!footerFound && !matched->footer.isEmpty())
        r.notes = "Footer not found — file may be incomplete.";

    return r;
}

// ---------------------------------------------------------------------------
// Confidence computation
// ---------------------------------------------------------------------------
RecoveryConfidence ForensicEngine::computeConfidence(bool footerFound,
                                                     bool sizeSane,
                                                     qint64 bytesRead,
                                                     qint64 maxSize)
{
    if (footerFound && sizeSane)  return RecoveryConfidence::HIGH;
    if (bytesRead > 512)          return RecoveryConfidence::MEDIUM;
    Q_UNUSED(maxSize);
    return RecoveryConfidence::LOW;
}

QString ForensicEngine::confidenceString(RecoveryConfidence c)
{
    switch (c) {
        case RecoveryConfidence::HIGH:   return "High";
        case RecoveryConfidence::MEDIUM: return "Medium";
        case RecoveryConfidence::LOW:    return "Low";
    }
    return "Unknown";
}

QString ForensicEngine::statusString(RecoveryStatus s)
{
    switch (s) {
        case RecoveryStatus::Recovered:          return "Recovered";
        case RecoveryStatus::PartiallyRecovered: return "Partial";
        case RecoveryStatus::Unrecoverable:      return "Unrecoverable";
    }
    return "Unknown";
}

// ---------------------------------------------------------------------------
// ForensicWorker
// ---------------------------------------------------------------------------
ForensicWorker::ForensicWorker(const ForensicConfig &cfg,
                               ForensicEngine       *eng,
                               QObject              *parent)
    : QThread(parent), config(cfg), engine(eng) {}

void ForensicWorker::run()
{
    if (config.mode == ForensicConfig::ScanMode::LogicalPath)
        engine->runLogicalScan(config);
    else
        engine->runRawScan(config);
}
