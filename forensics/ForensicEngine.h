#ifndef PURGEX_FORENSICENGINE_H
#define PURGEX_FORENSICENGINE_H

#include <QObject>
#include <QString>
#include <QStringList>
#include <QThread>
#include <QList>
#include <QMetaType>
#include <QPointer>
#include <atomic>
#include "FileSignatures.h"

class RawReader;
class ForensicWorker;

// ---------------------------------------------------------------------------
// Confidence level for a recovered item
// ---------------------------------------------------------------------------
enum class RecoveryConfidence {
    HIGH,    // Length proven by the file's own structure (footer, size field, chunk walk)
    MEDIUM,  // Header validated, but the end of the file could only be estimated
    LOW      // Header matched, little or nothing could be validated
};

// ---------------------------------------------------------------------------
// Status of a single recovery result
// ---------------------------------------------------------------------------
enum class RecoveryStatus {
    Recovered,          // Complete file written to the destination
    PartiallyRecovered, // Written, but truncated / length estimated
    Unrecoverable       // Header detected but no usable output could be produced
};

// ---------------------------------------------------------------------------
// A single recovery result record
// ---------------------------------------------------------------------------
struct RecoveryResult {
    QString       sourcePath;                 // Source file path, or the device for raw scans
    QString       destinationPath;            // Where the recovered file was written
    QString       fileType;                   // e.g. "JPEG Image"
    QString       extension;                  // e.g. "jpg"
    QString       category;                   // e.g. "Image"
    QString       sha256;                     // SHA-256 of the recovered bytes
    qint64        originalOffset = 0;         // Byte offset within the source (raw mode)
    qint64        recoveredBytes = 0;         // How many bytes were written
    RecoveryConfidence confidence = RecoveryConfidence::LOW;
    RecoveryStatus     status     = RecoveryStatus::Unrecoverable;
    QString       notes;                      // e.g. "Footer not found - file may be truncated"
};
Q_DECLARE_METATYPE(RecoveryResult)
Q_DECLARE_METATYPE(QList<RecoveryResult>)

// ---------------------------------------------------------------------------
// Configuration for a forensic scan
// ---------------------------------------------------------------------------
struct ForensicConfig {
    enum class ScanMode { LogicalPath, RawDevice };

    ScanMode    mode            = ScanMode::LogicalPath;
    QString     sourcePath;     // Directory (logical) or device / disk-image file (raw)
    QString     destPath;       // Output directory - must not live on the scanned source
    QStringList categories;     // Empty = all categories; otherwise filter by category name
    bool        rawModeConfirmed = false; // Must be true for raw device mode to proceed
};

// ---------------------------------------------------------------------------
// ForensicEngine — read-only carving engine
//
// SAFETY CONTRACT: This engine NEVER writes to sourcePath or any sub-path of
// sourcePath. All writes go exclusively to ForensicConfig::destPath. Sources
// are opened read-only; raw reads are sector-aligned and bad sectors are
// skipped rather than aborting the scan.
// ---------------------------------------------------------------------------
class ForensicEngine : public QObject {
    Q_OBJECT
    friend class ForensicWorker;

public:
    explicit ForensicEngine(QObject *parent = nullptr);
    ~ForensicEngine() override;

    // Start a scan in a dedicated thread. Returns false if the request is rejected;
    // the reason is delivered through warning().
    bool startScan(const ForensicConfig &config);

    // Request graceful cancellation
    void cancel();

    bool isRunning() const { return running; }

    static QString confidenceString(RecoveryConfidence c);
    static QString statusString(RecoveryStatus s);

signals:
    void progress(int percentage, const QString &status);
    void fileFound(const RecoveryResult &result);
    void finished(bool success, const QString &message, const QList<RecoveryResult> &results);
    void warning(const QString &message);

private:
    struct Length { qint64 bytes = -1; bool reliable = false; };

    void runLogicalScan(const ForensicConfig &config);
    void runRawScan(const ForensicConfig &config);
    void finishScan(bool success, const QString &message, const QList<RecoveryResult> &results);

    QList<FileSignature> activeSignatures(const ForensicConfig &config) const;

    // Work out where a file that starts at `start` ends.
    Length determineLength(RawReader &src, qint64 start, qint64 limit, const FileSignature &sig,
                           const QByteArray &head);

    // Copy [start, start+length) from the source into a new file under destDir.
    RecoveryResult carve(RawReader &src, qint64 start, qint64 length, bool reliable,
                         const FileSignature &sig, const QByteArray &head,
                         const QString &sourceLabel, const QString &destDir, int fileIndex);

    RecoveryResult recoverLogicalFile(const QString &filePath, const QList<FileSignature> &sigs,
                                      const QString &destDir, int fileIndex);

    static RecoveryConfidence confidenceFor(bool reliable, qint64 bytes);

    std::atomic<bool> running{false};
    std::atomic<bool> cancelled{false};
    std::atomic<bool> destinationFull{false};
    QPointer<ForensicWorker> worker;
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
