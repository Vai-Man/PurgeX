#ifndef PURGEX_WIPEENGINE_H
#define PURGEX_WIPEENGINE_H

#include <QObject>
#include <QString>
#include <QStringList>
#include <QByteArray>
#include <QHash>
#include <QMap>
#include <QMutex>
#include <QStorageInfo>
#include <QThread>
#include <QElapsedTimer>
#include <atomic>

enum class WipePattern {
    ZERO_FILL,
    ONE_FILL,
    RANDOM,
    ALTERNATING,
    NIST_800_88_1_PASS,
    NIST_800_88_3_PASS,
    NIST_800_88_7_PASS,
    GUTMANN_35_PASS
};

enum class WipeTarget {
    FILES,         // Files and/or folders (folders are expanded recursively)
    FOLDERS,       // Alias of FILES kept for API compatibility
    FREE_SPACE,
    FULL_DRIVE,
    SECURE_ERASE   // Hardware secure erase (ATA Security Erase / NVMe format)
};

struct DriveInfo {
    QString device;            // Volume path on Windows (\\.\C:), disk node on Linux (/dev/sda)
    QString physicalDevice;    // \\.\PhysicalDriveN / /dev/sdX that holds this volume
    QString mountPoint;
    QString fileSystem;
    qint64 totalSize = 0;
    qint64 freeSize = 0;
    bool isSSD = false;
    bool supportsSecureErase = false;
    QString model;
    QString serial;
};

struct WipeConfig {
    WipeTarget  target = WipeTarget::FILES;
    WipePattern pattern = WipePattern::NIST_800_88_3_PASS;
    QStringList paths;
    QString     drive;
    int         passes = 1;
    bool        verify = false;
    bool        generateCertificate = false;
};

// ---------------------------------------------------------------------------
// VerificationResult — result of a post-wipe verification pass
// ---------------------------------------------------------------------------
struct VerificationResult {
    bool    performed        = false;
    qint64  sectorsChecked   = 0;
    qint64  sectorsVerified  = 0;
    qint64  sectorsFailed    = 0;
    bool    isSSD            = false;
    bool    passed           = false;
    QString note; // Limitation note (e.g. SSD wear-leveling caveat)

    // Human-readable operation type for certificates
    // Possible values: "host-level-overwrite", "filesystem-wipe",
    //                  "free-space-wipe", "verified-host-level-overwrite"
    QString operationType;
};

Q_DECLARE_METATYPE(VerificationResult)

class WipeEngine : public QObject {
    Q_OBJECT

public:
    explicit WipeEngine(QObject *parent = nullptr);

    // Drive detection
    QList<DriveInfo> detectDrives();
    bool isSSD(const QString &device);
    bool supportsSecureErase(const QString &device);

    // Wiping operations. Each returns true only if the whole operation
    // completed; the reason for a false return is in lastMessage().
    bool wipeFiles(const QStringList &files, WipePattern pattern, int passes, bool verify = false);
    bool wipeFolder(const QString &folder, WipePattern pattern, int passes, bool verify = false);
    bool wipeFreeSpace(const QString &drive, WipePattern pattern, int passes = 0);
    bool wipeFullDrive(const QString &device, WipePattern pattern, int passes = 0);
    bool secureEraseSSD(const QString &device);

    // Pattern generation. `offset` is the position inside the written stream
    // so multi-byte patterns stay phase-aligned across chunk boundaries.
    QByteArray generatePattern(WipePattern pattern, qint64 size, int pass = 0, qint64 offset = 0);
    QByteArray generateNISTPattern(int pass, qint64 size, WipePattern variant = WipePattern::NIST_800_88_3_PASS);
    QByteArray generateGutmannPattern(int pass, qint64 size, qint64 offset = 0);

    // Number of overwrite passes a pattern really performs. Fixed-sequence
    // patterns (NIST, Gutmann) ignore the requested count.
    static int effectivePasses(WipePattern pattern, int requested);
    static QString patternName(WipePattern pattern);

    // Control
    void cancel();
    bool isRunning() const { return running; }
    QString lastMessage() const;

    // Platform helpers
    // Device passport: OS, CPU, memory (and host name) of this machine.
    static QMap<QString, QString> systemPassport();
    static bool isRunningAsAdministrator();
    static bool requestAdministratorPrivileges();
    // Physical disk number (PhysicalDriveN) that backs a volume such as "C:" or
    // "\\.\C:". Returns -1 if it cannot be determined (always -1 off Windows).
    static int  physicalDriveNumber(const QString &volume);
    // True when `device` (volume, \\.\PhysicalDriveN or /dev node) hosts the running OS.
    static bool isSystemDevice(const QString &device);
    // True when `folderPath` lives on the same physical disk as `deviceOrVolume`.
    static bool pathIsOnDisk(const QString &deviceOrVolume, const QString &folderPath);

signals:
    void progress(int percentage, const QString &status);
    void finished(bool success, const QString &message);
    void warning(const QString &message);
    void verificationComplete(const VerificationResult &result);

public:
    bool performWipe(const WipeConfig &config);
    bool overwriteFile(const QString &filePath, WipePattern pattern, int passes);

    // Post-wipe verification
    VerificationResult verifyFile(const QString &filePath, WipePattern pattern);
    VerificationResult verifyFreeSpace(const QString &drive, WipePattern pattern);
    // Verification summary of the most recent verified wipeFiles() run.
    VerificationResult lastFileVerification() const { return fileVerification; }
    void randomizeFileTimes(const QString &filePath);

    std::atomic<bool> running{false};
    std::atomic<bool> cancelled{false};

private:
    bool overwriteFileImpl(const QString &filePath, WipePattern pattern, int passes,
                           bool verify, bool *verifyOk, QString *error);
    void collectFiles(const QString &path, QStringList &files, QStringList &dirs, QStringList &skipped);
    void beginOperation();
    bool endOperation(bool ok, const QString &message);
    void reportBytes(qint64 delta, const QString &status);
    void resetProgress(qint64 totalBytes);
    void setMessage(const QString &msg);

    mutable QMutex  messageMutex;
    QString         message;
    QHash<QString, bool> secureEraseCache;
    QHash<QString, bool> ssdCache;

    std::atomic<qint64> progressDone{0};
    qint64              progressTotal = 0;
    QElapsedTimer       progressTimer;
    int                 lastPercent = -1;

    VerificationResult  fileVerification;
};

// ---------------------------------------------------------------------------
// WipeWorker — runs a complete WipeConfig (wipe + verify + certificate +
// audit-log entry) on a background thread. Used by both the GUI and the CLI.
// ---------------------------------------------------------------------------
class WipeWorker : public QThread {
    Q_OBJECT

public:
    explicit WipeWorker(const WipeConfig &config, WipeEngine *engine, QObject *parent = nullptr);

    QString certificatePdfPath() const { return certPdf; }
    QString certificateJsonPath() const { return certJson; }

protected:
    void run() override;

signals:
    void progress(int percentage, const QString &status);
    void finished(bool success, const QString &message);
    void warning(const QString &message);

private:
    WipeConfig config;
    WipeEngine *engine;
    QString certPdf;
    QString certJson;
};

#endif // PURGEX_WIPEENGINE_H
