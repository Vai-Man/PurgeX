#ifndef PURGEX_WIPEENGINE_H
#define PURGEX_WIPEENGINE_H

#include <QObject>
#include <QString>
#include <QStringList>
#include <QByteArray>
#include <QStorageInfo>
#include <QThread>
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
    FILES,
    FOLDERS,
    FREE_SPACE,
    FULL_DRIVE
};

struct DriveInfo {
    QString device;
    QString mountPoint;
    QString fileSystem;
    qint64 totalSize;
    qint64 freeSize;
    bool isSSD;
    bool supportsSecureErase;
    QString model;
    QString serial;
};

struct WipeConfig {
    WipeTarget target;
    WipePattern pattern;
    QStringList paths;
    QString drive;
    int passes;
    bool verify;
    bool generateCertificate;
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

class WipeEngine : public QObject {
    Q_OBJECT

public:
    explicit WipeEngine(QObject *parent = nullptr);
    
    // Drive detection
    QList<DriveInfo> detectDrives();
    bool isSSD(const QString &device);
    bool supportsSecureErase(const QString &device);
    
    // Wiping operations
    bool wipeFiles(const QStringList &files, WipePattern pattern, int passes);
    bool wipeFolder(const QString &folder, WipePattern pattern, int passes);
    bool wipeFreeSpace(const QString &drive, WipePattern pattern);
    bool wipeFullDrive(const QString &device, WipePattern pattern);
    bool secureEraseSSD(const QString &device);
    
    // Pattern generation
    QByteArray generatePattern(WipePattern pattern, qint64 size, int pass = 0);
    QByteArray generateNISTPattern(int pass, qint64 size);
    QByteArray generateGutmannPattern(int pass, qint64 size);
    
    // Control
    void cancel();
    bool isRunning() const { return running; }
    
    // Administrator privileges
    static bool isRunningAsAdministrator();
    static bool requestAdministratorPrivileges();

signals:
    void progress(int percentage, const QString &status);
    void finished(bool success, const QString &message);
    void warning(const QString &message);
    void verificationComplete(const VerificationResult &result);

private:
    
public:
    bool performWipe(const WipeConfig &config);
    bool overwriteFile(const QString &filePath, WipePattern pattern, int passes);
    bool overwriteWithPattern(QFile &file, WipePattern pattern, int pass);

    // Post-wipe verification
    VerificationResult verifyFile(const QString &filePath, WipePattern pattern);
    VerificationResult verifyFreeSpace(const QString &drive, WipePattern pattern);
    void randomizeFileTimes(const QString &filePath);
    
    std::atomic<bool> running{false};
    std::atomic<bool> cancelled{false};
};

class WipeWorker : public QThread {
    Q_OBJECT

public:
    explicit WipeWorker(const WipeConfig &config, WipeEngine *engine, QObject *parent = nullptr);
    
protected:
    void run() override;

signals:
    void progress(int percentage, const QString &status);
    void finished(bool success, const QString &message);
    void warning(const QString &message);

private:
    WipeConfig config;
    WipeEngine *engine;
};

#endif // PURGEX_WIPEENGINE_H
