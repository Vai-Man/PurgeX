#ifndef PURGEX_FORENSICENGINE_H
#define PURGEX_FORENSICENGINE_H

#include <QObject>
#include <QString>
#include <QStringList>
#include <QThread>
#include <QList>
#include <QIODevice>
#include <atomic>
#include "FileSignatures.h"

// ---------------------------------------------------------------------------
// Confidence level for a recovered item
// ---------------------------------------------------------------------------
enum class RecoveryConfidence {
    HIGH,    // Header + footer both matched; file size within bounds
    MEDIUM,  // Header matched; no footer found but content looks valid
    LOW      // Header detected; read was incomplete or content truncated
};

// ---------------------------------------------------------------------------
// Status of a single recovery result
// ---------------------------------------------------------------------------
enum class RecoveryStatus {
    Recovered,          // File written to destination successfully
    PartiallyRecovered, // Truncated due to end-of-stream or max-size limit
    Unrecoverable       // Header detected but could not produce usable output
};

// ---------------------------------------------------------------------------
// A single recovery result record
// ---------------------------------------------------------------------------
struct RecoveryResult {
    QString       sourcePath;       // Original source path or device + offset
    QString       destinationPath;  // Where the recovered file was written
    QString       fileType;         // e.g. "JPEG Image"
    QString       extension;        // e.g. "jpg"
    QString       category;         // e.g. "Image"
    qint64        originalOffset;   // Byte offset within the source (raw mode)
    qint64        recoveredBytes;   // How many bytes were written
    RecoveryConfidence confidence;
    RecoveryStatus     status;
    QString       notes;            // e.g. "Footer not found — file may be truncated"
};

// ---------------------------------------------------------------------------
// Configuration for a forensic scan
// ---------------------------------------------------------------------------
struct ForensicConfig {
    enum class ScanMode { LogicalPath, RawDevice };

    ScanMode    mode            = ScanMode::LogicalPath;
    QString     sourcePath;     // Directory path (logical) or \\.\PhysicalDriveN (raw)
    QString     destPath;       // Output directory — MUST differ from sourcePath
    QStringList categories;     // Empty = all categories; otherwise filter by category name
    bool        rawModeConfirmed = false; // Must be true for raw device mode to proceed
};

// ---------------------------------------------------------------------------
// ForensicEngine — read-only carving engine
//
// SAFETY CONTRACT: This engine NEVER writes to sourcePath or any sub-path of
// sourcePath. All writes go exclusively to ForensicConfig::destPath.
// The source is always opened with QIODevice::ReadOnly.
// Any code path that would issue a write/delete/rename on the source is
// rejected at runtime via Q_ASSERT and an early-return error signal.
// ---------------------------------------------------------------------------
class ForensicEngine : public QObject {
    Q_OBJECT
    friend class ForensicWorker;

public:
    explicit ForensicEngine(QObject *parent = nullptr);

    // Start a scan in a dedicated thread. Returns false if already running.
    bool startScan(const ForensicConfig &config);

    // Request graceful cancellation
    void cancel();

    bool isRunning() const { return running; }

signals:
    void progress(int percentage, const QString &status);
    void fileFound(const RecoveryResult &result);
    void finished(bool success, const QString &message, const QList<RecoveryResult> &results);
    void warning(const QString &message);

private:
    void runLogicalScan(const ForensicConfig &config);
    void runRawScan(const ForensicConfig &config);

    // Match and attempt to extract a single file at the given offset in an open device
    RecoveryResult carveFromDevice(QIODevice &source,
                                   qint64 headerOffset,
                                   const FileSignature &sig,
                                   const QString &destDir,
                                   int fileIndex);

    // Check a single file path against all active signatures
    RecoveryResult matchLogicalFile(const QString &filePath,
                                    const QList<FileSignature> &activeSigs,
                                    const QString &destDir,
                                    int fileIndex);

    // Confidence + status helpers
    static RecoveryConfidence computeConfidence(bool footerFound, bool sizeSane, qint64 bytesRead, qint64 maxSize);
    static QString confidenceString(RecoveryConfidence c);
    static QString statusString(RecoveryStatus s);

    std::atomic<bool> running{false};
    std::atomic<bool> cancelled{false};
};

// ---------------------------------------------------------------------------
// ForensicWorker — runs the scan off the main thread
// ---------------------------------------------------------------------------
class ForensicWorker : public QThread {
    Q_OBJECT

public:
    explicit ForensicWorker(const ForensicConfig &config,
                            ForensicEngine       *engine,
                            QObject              *parent = nullptr);

protected:
    void run() override;


private:
    ForensicConfig config;
    ForensicEngine *engine;
};

#endif // PURGEX_FORENSICENGINE_H
