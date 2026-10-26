#include "WipeEngine.h"
#include "AuditLog.h"
#include "../cert/CertManager.h"
#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QDirIterator>
#include <QProcess>
#include <QStorageInfo>
#include <QRandomGenerator>
#include <QCryptographicHash>
#include <QStandardPaths>
#include <QDateTime>
#include <QSysInfo>
#include <QVector>
#include <algorithm>
#include <cstring>

#ifdef Q_OS_WIN
#include <windows.h>
#include <winioctl.h>
#include <shellapi.h>
#include <io.h>
#else
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <cerrno>
#ifdef Q_OS_LINUX
#include <sys/ioctl.h>
#include <linux/fs.h>
#endif
#endif

namespace {

constexpr qint64 kChunk = 4LL * 1024 * 1024;

// ---------------------------------------------------------------------------
// Pattern tables
// ---------------------------------------------------------------------------
enum NistKind { NistZero = 0, NistOne = 1, NistRandom = 2 };

NistKind nistKind(WipePattern variant, int pass)
{
    static const NistKind three[3] = { NistZero, NistOne, NistRandom };
    static const NistKind seven[7] = { NistZero, NistOne, NistRandom, NistZero, NistOne, NistRandom, NistRandom };
    switch (variant) {
        case WipePattern::NIST_800_88_1_PASS: return NistZero;
        case WipePattern::NIST_800_88_3_PASS: return three[qBound(0, pass, 2)];
        case WipePattern::NIST_800_88_7_PASS: return seven[qBound(0, pass, 6)];
        default: return pass == 0 ? NistZero : (pass == 1 ? NistOne : NistRandom);
    }
}

struct GutmannPass { int len; unsigned char b[3]; }; // len == 0 -> random data

// Peter Gutmann's 35-pass sequence (passes 1-4 and 32-35 are random).
const GutmannPass kGutmann[35] = {
    {0,{0,0,0}}, {0,{0,0,0}}, {0,{0,0,0}}, {0,{0,0,0}},
    {1,{0x55,0,0}}, {1,{0xAA,0,0}},
    {3,{0x92,0x49,0x24}}, {3,{0x49,0x24,0x92}}, {3,{0x24,0x92,0x49}},
    {1,{0x00,0,0}}, {1,{0x11,0,0}}, {1,{0x22,0,0}}, {1,{0x33,0,0}},
    {1,{0x44,0,0}}, {1,{0x55,0,0}}, {1,{0x66,0,0}}, {1,{0x77,0,0}},
    {1,{0x88,0,0}}, {1,{0x99,0,0}}, {1,{0xAA,0,0}}, {1,{0xBB,0,0}},
    {1,{0xCC,0,0}}, {1,{0xDD,0,0}}, {1,{0xEE,0,0}}, {1,{0xFF,0,0}},
    {3,{0x92,0x49,0x24}}, {3,{0x49,0x24,0x92}}, {3,{0x24,0x92,0x49}},
    {3,{0x6D,0xB6,0xDB}}, {3,{0xB6,0xDB,0x6D}}, {3,{0xDB,0x6D,0xB6}},
    {0,{0,0,0}}, {0,{0,0,0}}, {0,{0,0,0}}, {0,{0,0,0}}
};

void fillRandom(char *ptr, qint64 size)
{
    // The operating-system CSPRNG, not the (deterministic) global generator.
    QRandomGenerator *rng = QRandomGenerator::system();
    const qint64 words = size / 4;
    if (words > 0)
        rng->fillRange(reinterpret_cast<quint32 *>(ptr), static_cast<qsizetype>(words));
    for (qint64 i = words * 4; i < size; ++i)
        ptr[i] = static_cast<char>(rng->bounded(256));
}

QString randomHex(int bytes)
{
    QByteArray b(bytes, 0);
    fillRandom(b.data(), bytes);
    return QString::fromLatin1(b.toHex());
}

// ---------------------------------------------------------------------------
// Small platform helpers
// ---------------------------------------------------------------------------
void syncFile(QFile &f)
{
    f.flush();
#ifdef Q_OS_WIN
    const intptr_t h = _get_osfhandle(f.handle());
    if (h != -1) FlushFileBuffers(reinterpret_cast<HANDLE>(h));
#else
    if (f.handle() >= 0) fsync(f.handle());
#endif
}

// True for symbolic links and (on Windows) junctions. These are removed, never
// followed - otherwise wiping a link would overwrite whatever it points at.
bool isLinkOrJunction(const QString &path)
{
#ifdef Q_OS_WIN
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(reinterpret_cast<LPCWSTR>(QDir::toNativeSeparators(path).utf16()), &fd);
    if (h == INVALID_HANDLE_VALUE) return false;
    FindClose(h);
    return (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
           (fd.dwReserved0 == IO_REPARSE_TAG_SYMLINK || fd.dwReserved0 == IO_REPARSE_TAG_MOUNT_POINT);
#else
    struct stat st;
    return ::lstat(path.toLocal8Bit().constData(), &st) == 0 && S_ISLNK(st.st_mode);
#endif
}

#ifdef Q_OS_WIN
QString volumeLetter(const QString &s)
{
    for (int i = 0; i + 1 < s.size(); ++i)
        if (s.at(i).isLetter() && s.at(i + 1) == ':') return QString(s.at(i).toUpper());
    return QString();
}

QString nativeVolumePath(const QString &volume)
{
    if (volume.startsWith("\\\\.\\")) return volume;
    const QString l = volumeLetter(volume);
    return l.isEmpty() ? QString() : QString("\\\\.\\%1:").arg(l);
}

HANDLE openForQuery(const QString &path)
{
    return CreateFileW(reinterpret_cast<LPCWSTR>(path.utf16()), 0,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
}

void queryDeviceStrings(const QString &path, QString *model, QString *serial)
{
    HANDLE h = openForQuery(path);
    if (h == INVALID_HANDLE_VALUE) return;
    STORAGE_PROPERTY_QUERY q = {};
    q.PropertyId = StorageDeviceProperty;
    q.QueryType  = PropertyStandardQuery;
    char buf[2048] = {};
    DWORD got = 0;
    if (DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &q, sizeof(q), buf, sizeof(buf), &got, nullptr)) {
        auto *d = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR *>(buf);
        auto str = [&](DWORD off) {
            return off ? QString::fromLatin1(buf + off).trimmed() : QString();
        };
        const QString vendor  = str(d->VendorIdOffset);
        const QString product = str(d->ProductIdOffset);
        if (model)  *model  = (vendor + " " + product).trimmed();
        if (serial) *serial = str(d->SerialNumberOffset);
    }
    CloseHandle(h);
}
#endif

#ifdef Q_OS_LINUX
QString readSysfs(const QString &path)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) return QString();
    return QString::fromLatin1(f.readAll()).trimmed();
}

// "sda1" -> "sda", "nvme0n1p2" -> "nvme0n1", "sda" -> "sda"
QString parentDiskName(const QString &name)
{
    const QString link = "/sys/class/block/" + name;
    if (QFile::exists(link + "/partition"))
        return QFileInfo(QFileInfo(link).canonicalFilePath()).dir().dirName();
    return name;
}

// Mount point of any partition of `device`, or an empty string if none is mounted.
QString mountedPartition(const QString &device)
{
    QFile mounts("/proc/mounts");
    if (!mounts.open(QIODevice::ReadOnly)) return QString();
    const QString name = QFileInfo(device).fileName();
    const QList<QByteArray> lines = mounts.readAll().split('\n');
    for (const QByteArray &line : lines) {
        const QList<QByteArray> cols = line.split(' ');
        if (cols.size() < 2) continue;
        const QString src = QString::fromLocal8Bit(cols.at(0));
        if (!src.startsWith("/dev/")) continue;
        const QString srcName = QFileInfo(src).fileName();
        if (srcName == name || parentDiskName(srcName) == name)
            return QString::fromLocal8Bit(cols.at(1));
    }
    return QString();
}
#endif

} // namespace

// ===========================================================================
// WipeEngine
// ===========================================================================
WipeEngine::WipeEngine(QObject *parent) : QObject(parent) {
    qRegisterMetaType<VerificationResult>("VerificationResult");
}

int WipeEngine::effectivePasses(WipePattern pattern, int requested)
{
    switch (pattern) {
        case WipePattern::NIST_800_88_1_PASS: return 1;
        case WipePattern::NIST_800_88_3_PASS: return 3;
        case WipePattern::NIST_800_88_7_PASS: return 7;
        case WipePattern::GUTMANN_35_PASS:    return 35;
        default:                              return qMax(1, requested);
    }
}

QString WipeEngine::patternName(WipePattern p)
{
    switch (p) {
        case WipePattern::ZERO_FILL:          return "Zero Fill";
        case WipePattern::ONE_FILL:           return "One Fill";
        case WipePattern::RANDOM:             return "Random";
        case WipePattern::ALTERNATING:        return "Alternating";
        case WipePattern::NIST_800_88_1_PASS: return "NIST SP 800-88 (1 pass)";
        case WipePattern::NIST_800_88_3_PASS: return "NIST SP 800-88 (3 passes)";
        case WipePattern::NIST_800_88_7_PASS: return "NIST SP 800-88 (7 passes)";
        case WipePattern::GUTMANN_35_PASS:    return "Gutmann (35 passes)";
    }
    return "Unknown";
}

QString WipeEngine::lastMessage() const
{
    QMutexLocker lock(&messageMutex);
    return message;
}

void WipeEngine::setMessage(const QString &msg)
{
    QMutexLocker lock(&messageMutex);
    message = msg;
}

bool WipeEngine::endOperation(bool ok, const QString &msg)
{
    setMessage(msg);
    running = false;
    emit finished(ok, msg);
    return ok;
}

void WipeEngine::resetProgress(qint64 totalBytes)
{
    progressDone = 0;
    progressTotal = qMax<qint64>(1, totalBytes);
    lastPercent = -1;
    progressTimer.start();
}

void WipeEngine::reportBytes(qint64 delta, const QString &status)
{
    const qint64 done = (progressDone += delta);
    const int percent = static_cast<int>(qMin<qint64>(100, (done * 100) / progressTotal));
    if (percent == lastPercent && progressTimer.elapsed() < 250) return;
    lastPercent = percent;
    progressTimer.restart();
    emit progress(percent, status);
}

void WipeEngine::cancel()
{
    cancelled = true;
}

// ---------------------------------------------------------------------------
// Drive detection
// ---------------------------------------------------------------------------
int WipeEngine::physicalDriveNumber(const QString &volume)
{
#ifdef Q_OS_WIN
    const int idx = volume.indexOf("PhysicalDrive", 0, Qt::CaseInsensitive);
    if (idx >= 0) {
        bool ok = false;
        const int n = volume.mid(idx + 13).toInt(&ok);
        return ok ? n : -1;
    }
    const QString path = nativeVolumePath(volume);
    if (path.isEmpty()) return -1;
    HANDLE h = openForQuery(path);
    if (h == INVALID_HANDLE_VALUE) return -1;
    STORAGE_DEVICE_NUMBER sdn = {};
    DWORD got = 0;
    int result = -1;
    if (DeviceIoControl(h, IOCTL_STORAGE_GET_DEVICE_NUMBER, nullptr, 0, &sdn, sizeof(sdn), &got, nullptr)
        && sdn.DeviceType == FILE_DEVICE_DISK)
        result = static_cast<int>(sdn.DeviceNumber);
    CloseHandle(h);
    return result;
#else
    Q_UNUSED(volume);
    return -1;
#endif
}

bool WipeEngine::isSystemDevice(const QString &device)
{
#ifdef Q_OS_WIN
    const int target = physicalDriveNumber(device);
    QString sysDrive = QString::fromLocal8Bit(qgetenv("SystemDrive"));
    if (sysDrive.isEmpty()) sysDrive = "C:";
    const int system = physicalDriveNumber(sysDrive);
    // If either side cannot be resolved, assume the worst.
    return target < 0 || system < 0 || target == system;
#elif defined(Q_OS_LINUX)
    const QString name = QFileInfo(device).fileName();
    for (const char *mp : { "/", "/boot", "/boot/efi" }) {
        const QStorageInfo s{QString::fromLatin1(mp)};
        if (!s.isValid()) continue;
        const QString src = QString::fromUtf8(s.device());
        if (!src.startsWith("/dev/")) continue;
        const QString srcName = QFileInfo(src).fileName();
        if (srcName == name || parentDiskName(srcName) == name) return true;
    }
    return false;
#else
    Q_UNUSED(device);
    return true;
#endif
}

bool WipeEngine::pathIsOnDisk(const QString &deviceOrVolume, const QString &folderPath)
{
#ifdef Q_OS_WIN
    const int a = physicalDriveNumber(deviceOrVolume);
    const int b = physicalDriveNumber(QStorageInfo(folderPath).rootPath());
    return a >= 0 && a == b;
#elif defined(Q_OS_LINUX)
    const QStorageInfo st(folderPath);
    if (!st.isValid()) return false;
    const QString dst = QFileInfo(QString::fromUtf8(st.device())).fileName();
    const QString src = QFileInfo(deviceOrVolume).fileName();
    return !dst.isEmpty() && parentDiskName(dst) == parentDiskName(src);
#else
    Q_UNUSED(deviceOrVolume); Q_UNUSED(folderPath);
    return false;
#endif
}

QList<DriveInfo> WipeEngine::detectDrives() {
    QList<DriveInfo> drives;

#ifdef Q_OS_WIN
    const QFileInfoList volumes = QDir::drives();
    for (const QFileInfo &volume : volumes) {
        const QString rootPath = volume.absoluteFilePath(); // "C:/"
        const UINT type = GetDriveTypeW(reinterpret_cast<LPCWSTR>(QDir::toNativeSeparators(rootPath).utf16()));
        if (type != DRIVE_FIXED && type != DRIVE_REMOVABLE) continue;

        QStorageInfo storage(rootPath);
        if (!storage.isValid() || !storage.isReady()) continue;

        DriveInfo info;
        info.mountPoint = rootPath;
        info.fileSystem = QString::fromLatin1(storage.fileSystemType());
        info.totalSize  = storage.bytesTotal();
        info.freeSize   = storage.bytesAvailable();
        info.device     = "\\\\.\\" + rootPath.left(2);                 // \\.\C:
        const int disk  = physicalDriveNumber(info.device);
        if (disk >= 0) info.physicalDevice = QString("\\\\.\\PhysicalDrive%1").arg(disk);
        info.isSSD      = isSSD(info.device);
        info.supportsSecureErase = supportsSecureErase(info.device);
        info.model  = "Unknown";
        info.serial = "Unknown";
        QString model, serial;
        queryDeviceStrings(info.device, &model, &serial);
        if (!model.isEmpty())  info.model  = model;
        if (!serial.isEmpty()) info.serial = serial;
        drives.append(info);
    }
#elif defined(Q_OS_LINUX)
    QStringList seen;
    const QList<QStorageInfo> volumes = QStorageInfo::mountedVolumes();
    for (const QStorageInfo &storage : volumes) {
        if (!storage.isValid() || !storage.isReady()) continue;
        const QString dev = QString::fromUtf8(storage.device());
        if (!dev.startsWith("/dev/")) continue;
        const QString name = QFileInfo(dev).fileName();
        if (name.startsWith("loop") || name.startsWith("ram") || name.startsWith("zram")) continue;
        if (seen.contains(storage.rootPath())) continue;
        seen << storage.rootPath();

        const QString parent = parentDiskName(name);
        DriveInfo info;
        info.device         = "/dev/" + parent;
        info.physicalDevice = info.device;
        info.mountPoint     = storage.rootPath();
        info.fileSystem     = QString::fromLatin1(storage.fileSystemType());
        info.totalSize      = storage.bytesTotal();
        info.freeSize       = storage.bytesAvailable();
        info.isSSD          = isSSD(info.device);
        info.supportsSecureErase = supportsSecureErase(info.device);
        info.model  = readSysfs("/sys/block/" + parent + "/device/model");
        info.serial = readSysfs("/sys/block/" + parent + "/device/serial");
        if (info.model.isEmpty())  info.model  = "Unknown";
        if (info.serial.isEmpty()) info.serial = "Unknown";
        drives.append(info);
    }
#else
    const QList<QStorageInfo> volumes = QStorageInfo::mountedVolumes();
    for (const QStorageInfo &storage : volumes) {
        if (!storage.isValid() || !storage.isReady()) continue;
        DriveInfo info;
        info.device     = QString::fromUtf8(storage.device());
        info.mountPoint = storage.rootPath();
        info.fileSystem = QString::fromLatin1(storage.fileSystemType());
        info.totalSize  = storage.bytesTotal();
        info.freeSize   = storage.bytesAvailable();
        info.model = info.serial = "Unknown";
        drives.append(info);
    }
#endif

    return drives;
}

bool WipeEngine::isSSD(const QString &device) {
    if (ssdCache.contains(device)) return ssdCache.value(device);
    bool result = false;

#ifdef Q_OS_WIN
    const QString path = nativeVolumePath(device);
    if (!path.isEmpty()) {
        HANDLE h = openForQuery(path);
        if (h != INVALID_HANDLE_VALUE) {
            STORAGE_PROPERTY_QUERY q = {};
            q.PropertyId = StorageDeviceSeekPenaltyProperty;
            q.QueryType  = PropertyStandardQuery;
            DEVICE_SEEK_PENALTY_DESCRIPTOR d = {};
            DWORD got = 0;
            if (DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &q, sizeof(q), &d, sizeof(d), &got, nullptr))
                result = !d.IncursSeekPenalty; // no seek penalty => flash storage
            CloseHandle(h);
        }
    }
#elif defined(Q_OS_LINUX)
    const QString name = QFileInfo(device).fileName();
    QString value = readSysfs(QString("/sys/block/%1/queue/rotational").arg(name));
    if (value.isEmpty())
        value = readSysfs(QString("/sys/class/block/%1/../queue/rotational").arg(name));
    result = (value == "0");
#endif

    ssdCache.insert(device, result);
    return result;
}

bool WipeEngine::supportsSecureErase(const QString &device) {
    if (secureEraseCache.contains(device)) return secureEraseCache.value(device);
    bool result = false;

#ifdef Q_OS_LINUX
    // Only a real, privileged probe is trustworthy; without root hdparm/nvme cannot read the drive.
    if (isRunningAsAdministrator()) {
        if (QFileInfo(device).fileName().startsWith("nvme")) {
            result = !QStandardPaths::findExecutable("nvme").isEmpty();
        } else if (!QStandardPaths::findExecutable("hdparm").isEmpty()) {
            QProcess hdparm;
            hdparm.start("hdparm", QStringList() << "-I" << device);
            if (hdparm.waitForFinished(5000) && hdparm.exitCode() == 0) {
                // Look inside the "Security:" block for "supported" and "not frozen".
                const QStringList lines = QString::fromLocal8Bit(hdparm.readAllStandardOutput()).split('\n');
                bool inSecurity = false, supported = false, notFrozen = false;
                for (const QString &raw : lines) {
                    const QString line = raw.simplified();
                    if (line.startsWith("Security:")) { inSecurity = true; continue; }
                    if (!inSecurity) continue;
                    if (!raw.startsWith('\t') && !raw.startsWith(' ')) break; // next section
                    if (line == "supported") supported = true;
                    if (line == "not frozen") notFrozen = true;
                }
                result = supported && notFrozen;
            }
        }
    }
#else
    Q_UNUSED(device);
    // Hardware secure erase is not implemented for Windows builds.
#endif

    secureEraseCache.insert(device, result);
    return result;
}

// ---------------------------------------------------------------------------
// File / folder wiping
// ---------------------------------------------------------------------------
void WipeEngine::collectFiles(const QString &path, QStringList &files, QStringList &dirs, QStringList &skipped)
{
    QFileInfo info(path);
    if (!info.exists() && !isLinkOrJunction(path)) {
        skipped << QString("Not found, skipped: %1").arg(path);
        return;
    }
    if (isLinkOrJunction(path) || info.isFile()) {
        files << info.absoluteFilePath();
        return;
    }
    if (!info.isDir()) {
        skipped << QString("Not a regular file or folder, skipped: %1").arg(path);
        return;
    }

    dirs << info.absoluteFilePath();
    QDirIterator it(info.absoluteFilePath(),
                    QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden | QDir::System,
                    QDirIterator::Subdirectories); // symlinked directories are NOT followed
    while (it.hasNext()) {
        const QString entry = it.next();
        const QFileInfo ei(entry);
        if (isLinkOrJunction(entry) || !ei.isDir())
            files << entry;
        else
            dirs << ei.absoluteFilePath();
    }
}

bool WipeEngine::wipeFiles(const QStringList &paths, WipePattern pattern, int passes, bool verify) {
    if (running.exchange(true)) return false;
    cancelled = false;
    setMessage(QString());
    fileVerification = VerificationResult();

    QStringList files, dirs, skipped;
    for (const QString &p : paths) collectFiles(p, files, dirs, skipped);
    for (const QString &s : skipped) emit warning(s);
    files.removeDuplicates();
    dirs.removeDuplicates();

    if (files.isEmpty() && dirs.isEmpty())
        return endOperation(false, "Nothing to wipe: none of the selected files or folders exist.");

    const int total = effectivePasses(pattern, passes);
    qint64 bytes = 0;
    for (const QString &f : files) {
        if (isLinkOrJunction(f)) continue;
        bytes += QFileInfo(f).size() * (total + (verify ? 1 : 0));
    }
    resetProgress(bytes);

    int failed = 0, verifyChecked = 0, verifyOk = 0, processed = 0;
    for (const QString &f : files) {
        if (cancelled) break;
        QString err;
        bool vOk = true;
        const bool isLink = isLinkOrJunction(f);
        if (!overwriteFileImpl(f, pattern, passes, verify, &vOk, &err)) {
            if (cancelled) break;
            ++failed;
            emit warning(err.isEmpty() ? QString("Failed to wipe file: %1").arg(f) : err);
        } else if (verify && !isLink) {
            ++verifyChecked;
            if (vOk) ++verifyOk;
            else emit warning(QString("Read-back verification FAILED for: %1").arg(f));
        }
        ++processed;
    }

    // Remove the (now empty) directories, deepest first.
    if (!cancelled) {
        std::sort(dirs.begin(), dirs.end(), [](const QString &a, const QString &b) { return a.size() > b.size(); });
        for (const QString &d : dirs) {
            if (!QDir().rmdir(d) && QDir(d).exists()) {
                ++failed;
                emit warning(QString("Could not remove folder (not empty?): %1").arg(d));
            }
        }
    }

    // Verification summary
    if (verify) {
        fileVerification.performed       = true;
        fileVerification.operationType   = "filesystem-wipe";
        fileVerification.sectorsChecked  = verifyChecked;
        fileVerification.sectorsVerified = verifyOk;
        fileVerification.sectorsFailed   = verifyChecked - verifyOk;
        fileVerification.passed          = (failed == 0 && !cancelled && verifyOk == verifyChecked);
        fileVerification.note = fileVerification.passed
            ? QString("%1 file(s) were read back after the final pass and matched the data written "
                      "(SHA-256); all targets were then removed from the filesystem. Read-back can be "
                      "served from the OS cache, so this confirms the write path, not the physical media.")
                  .arg(verifyChecked)
            : QString("Verification incomplete: %1 of %2 file(s) failed read-back or could not be wiped.")
                  .arg(verifyChecked - verifyOk + failed).arg(qMax(verifyChecked, processed));
    }

    if (cancelled) return endOperation(false, "Operation cancelled");
    if (failed > 0)
        return endOperation(false, QString("%1 item(s) could not be wiped. See the log for details.").arg(failed));
    return endOperation(true, QString("%1 file(s) wiped successfully").arg(files.size()));
}

bool WipeEngine::wipeFolder(const QString &folder, WipePattern pattern, int passes, bool verify) {
    return wipeFiles(QStringList(folder), pattern, passes, verify);
}

bool WipeEngine::overwriteFile(const QString &filePath, WipePattern pattern, int passes) {
    QString err;
    const bool ok = overwriteFileImpl(filePath, pattern, passes, false, nullptr, &err);
    if (!ok && !err.isEmpty()) emit warning(err);
    return ok;
}

bool WipeEngine::overwriteFileImpl(const QString &filePath, WipePattern pattern, int passes,
                                   bool verify, bool *verifyOk, QString *error)
{
    auto fail = [&](const QString &msg) { if (error) *error = msg; return false; };
    if (verifyOk) *verifyOk = true;

    if (isLinkOrJunction(filePath)) {
        // Links are removed, never followed.
        if (QFile::remove(filePath) || QDir().rmdir(filePath)) return true;
        return fail(QString("Could not remove link: %1").arg(filePath));
    }

    const QFileInfo fi(filePath);
    if (!fi.exists()) return fail(QString("File not found: %1").arg(filePath));
    if (!fi.isFile()) return fail(QString("Not a regular file: %1").arg(filePath));

    QFile::setPermissions(filePath, QFile::ReadOwner | QFile::WriteOwner | QFile::ReadUser | QFile::WriteUser);

    const int total = effectivePasses(pattern, passes);
    const qint64 size = fi.size();
    const QString name = fi.fileName();

    QFile file(filePath);
    if (!file.open(QIODevice::ReadWrite))
        return fail(QString("Cannot open for writing (%1): %2").arg(file.errorString(), filePath));

    QCryptographicHash written(QCryptographicHash::Sha256);

    for (int pass = 0; pass < total; ++pass) {
        if (!file.seek(0)) return fail(QString("Seek failed: %1").arg(filePath));
        qint64 done = 0;
        while (done < size) {
            if (cancelled) return false;
            const qint64 n = qMin(kChunk, size - done);
            const QByteArray buf = generatePattern(pattern, n, pass, done);
            if (verify && pass == total - 1) written.addData(buf);
            if (file.write(buf) != n)
                return fail(QString("Write error (%1): %2").arg(file.errorString(), filePath));
            done += n;
            reportBytes(n, QString("Wiping %1 (pass %2/%3)").arg(name).arg(pass + 1).arg(total));
        }
        syncFile(file);
    }

    if (verify && size > 0) {
        QCryptographicHash readBack(QCryptographicHash::Sha256);
        file.seek(0);
        qint64 done = 0;
        while (done < size && !cancelled) {
            const QByteArray buf = file.read(qMin(kChunk, size - done));
            if (buf.isEmpty()) break;
            readBack.addData(buf);
            done += buf.size();
            reportBytes(buf.size(), QString("Verifying %1").arg(name));
        }
        if (verifyOk) *verifyOk = (done == size && readBack.result() == written.result());
    }
    if (cancelled) return false;

    file.resize(0);
    syncFile(file);
    file.close();

    randomizeFileTimes(filePath);

    // Scrub the file name from the directory entry before deleting.
    QString finalPath = filePath;
    const QString renamed = QDir(fi.absolutePath()).filePath("purgex_" + randomHex(6) + ".tmp");
    if (QFile::rename(filePath, renamed)) finalPath = renamed;

    if (!QFile::remove(finalPath))
        return fail(QString("Could not delete after overwrite: %1").arg(finalPath));
    return true;
}

void WipeEngine::randomizeFileTimes(const QString &filePath) {
    QRandomGenerator *rng = QRandomGenerator::system();
    const qint64 now = QDateTime::currentSecsSinceEpoch();
    const qint64 floorTime = 946684800; // 2000-01-01
    auto randomTime = [&]() { return floorTime + static_cast<qint64>(rng->bounded(static_cast<quint32>(qMax<qint64>(1, now - floorTime)))); };

#ifdef Q_OS_WIN
    HANDLE h = CreateFileW(reinterpret_cast<LPCWSTR>(QDir::toNativeSeparators(filePath).utf16()),
                           FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    auto toFileTime = [](qint64 unixSecs) {
        const quint64 t = (static_cast<quint64>(unixSecs) + 11644473600ULL) * 10000000ULL;
        FILETIME ft;
        ft.dwLowDateTime  = static_cast<DWORD>(t & 0xFFFFFFFF);
        ft.dwHighDateTime = static_cast<DWORD>(t >> 32);
        return ft;
    };
    FILETIME created = toFileTime(randomTime());
    FILETIME accessed = toFileTime(randomTime());
    FILETIME modified = toFileTime(randomTime());
    SetFileTime(h, &created, &accessed, &modified);
    CloseHandle(h);
#else
    struct timeval tv[2];
    tv[0].tv_sec = static_cast<time_t>(randomTime()); tv[0].tv_usec = 0;
    tv[1].tv_sec = static_cast<time_t>(randomTime()); tv[1].tv_usec = 0;
    utimes(filePath.toLocal8Bit().constData(), tv);
#endif
}

// ---------------------------------------------------------------------------
// Free-space wiping
// ---------------------------------------------------------------------------
bool WipeEngine::wipeFreeSpace(const QString &drive, WipePattern pattern, int passes) {
    if (running.exchange(true)) return false;
    cancelled = false;
    setMessage(QString());

    QStorageInfo storage(drive);
    if (!storage.isValid() || !storage.isReady())
        return endOperation(false, QString("Invalid or unavailable drive: %1").arg(drive));
    if (storage.isReadOnly())
        return endOperation(false, QString("Drive is read-only: %1").arg(drive));

    const qint64 freeSpace = storage.bytesAvailable();
    const qint64 reserve = 16LL * 1024 * 1024; // keep a little headroom so the system stays usable
    if (freeSpace < 100LL * 1024 * 1024)
        return endOperation(false, "Insufficient free space for wiping (less than 100 MB).");

    const int total = effectivePasses(pattern, passes <= 0 ? 1 : passes);
    const QString tempDir = QDir(storage.rootPath()).filePath("PurgeX_Temp_" + randomHex(4));
    if (!QDir().mkpath(tempDir))
        return endOperation(false, QString("Cannot create temporary folder on %1 (is the drive writable?)").arg(drive));

    resetProgress((freeSpace - reserve) * total);
    const qint64 fileLimit = 256LL * 1024 * 1024;
    qint64 firstPassBytes = 0;
    bool ioError = false;
    QString ioMessage;

    for (int pass = 0; pass < total && !cancelled && !ioError; ++pass) {
        qint64 passBytes = 0;
        int fileCount = 0;
        bool full = false;

        while (!cancelled && !full) {
            storage.refresh();
            const qint64 avail = storage.bytesAvailable();
            if (avail <= reserve) break;

            const qint64 target = qMin(fileLimit, avail - reserve);
            QFile f(QDir(tempDir).filePath(QString("purgex_temp_%1.dat").arg(fileCount++)));
            if (!f.open(QIODevice::WriteOnly)) {
                ioError = true;
                ioMessage = QString("Cannot create temp file: %1").arg(f.errorString());
                break;
            }
            qint64 inFile = 0;
            while (inFile < target && !cancelled) {
                const qint64 n = qMin(kChunk, target - inFile);
                const QByteArray buf = generatePattern(pattern, n, pass, inFile);
                const qint64 w = f.write(buf);
                if (w != n) { full = true; break; } // volume is full - exactly what we want
                inFile += w;
                passBytes += w;
                reportBytes(w, QString("Wiping free space (pass %1/%2): %3 MB written")
                                   .arg(pass + 1).arg(total).arg(passBytes / (1024 * 1024)));
            }
            syncFile(f);
            f.close();
            if (inFile == 0) full = true;
        }

        if (pass == 0) firstPassBytes = passBytes;
        QDir(tempDir).removeRecursively();
        QDir().mkpath(tempDir);
    }

    QDir(tempDir).removeRecursively();

    if (cancelled) return endOperation(false, "Operation cancelled");
    if (ioError)   return endOperation(false, ioMessage);

    const double coverage = (freeSpace - reserve) > 0
        ? double(firstPassBytes) / double(freeSpace - reserve) : 1.0;
    if (coverage < 0.90) {
        return endOperation(false,
            QString("Only %1% of the free space could be overwritten. Another process may be using the drive.")
                .arg(int(coverage * 100)));
    }
    return endOperation(true, QString("Free space wiped successfully (%1 pass(es))").arg(total));
}

// ---------------------------------------------------------------------------
// Full-drive wiping
// ---------------------------------------------------------------------------
bool WipeEngine::wipeFullDrive(const QString &device, WipePattern pattern, int passes) {
    if (running.exchange(true)) return false;
    cancelled = false;
    setMessage(QString());

    const int total = effectivePasses(pattern, passes <= 0 ? 1 : passes);

    if (isSystemDevice(device))
        return endOperation(false, "Refusing to wipe: this disk hosts the running operating system "
                                   "(or its role could not be determined).");
    if (!isRunningAsAdministrator())
        return endOperation(false, "Administrator / root privileges are required for raw disk access.");

    emit warning("Full drive wipe is destructive and irreversible.");

#ifdef Q_OS_WIN
    const int disk = physicalDriveNumber(device);
    if (disk < 0)
        return endOperation(false, QString("Could not determine which physical disk backs %1.").arg(device));
    const QString diskPath = QString("\\\\.\\PhysicalDrive%1").arg(disk);

    // Lock and dismount every volume on the disk, otherwise Windows rejects writes to its sectors.
    QVector<HANDLE> lockedVolumes;
    auto releaseVolumes = [&]() {
        for (HANDLE h : lockedVolumes) CloseHandle(h);
        lockedVolumes.clear();
    };
    for (char letter = 'A'; letter <= 'Z'; ++letter) {
        const QString vol = QString("%1:").arg(QChar(letter));
        const UINT type = GetDriveTypeW(reinterpret_cast<LPCWSTR>((vol + "\\").utf16()));
        if (type != DRIVE_FIXED && type != DRIVE_REMOVABLE) continue;
        if (physicalDriveNumber(vol) != disk) continue;

        const QString volPath = "\\\\.\\" + vol;
        HANDLE h = CreateFileW(reinterpret_cast<LPCWSTR>(volPath.utf16()), GENERIC_READ | GENERIC_WRITE,
                               FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        DWORD br = 0;
        if (h == INVALID_HANDLE_VALUE) {
            releaseVolumes();
            return endOperation(false, QString("Cannot open volume %1 for exclusive access.").arg(vol));
        }
        if (!DeviceIoControl(h, FSCTL_LOCK_VOLUME, nullptr, 0, nullptr, 0, &br, nullptr)) {
            CloseHandle(h);
            releaseVolumes();
            return endOperation(false, QString("Volume %1 is in use. Close any program using it and try again.").arg(vol));
        }
        DeviceIoControl(h, FSCTL_DISMOUNT_VOLUME, nullptr, 0, nullptr, 0, &br, nullptr);
        lockedVolumes.push_back(h);
    }

    HANDLE hd = CreateFileW(reinterpret_cast<LPCWSTR>(diskPath.utf16()), GENERIC_READ | GENERIC_WRITE,
                            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                            FILE_FLAG_WRITE_THROUGH, nullptr);
    if (hd == INVALID_HANDLE_VALUE) {
        releaseVolumes();
        return endOperation(false, QString("Cannot open %1 for writing (error %2).").arg(diskPath).arg(GetLastError()));
    }

    GET_LENGTH_INFORMATION li = {};
    DWORD got = 0;
    if (!DeviceIoControl(hd, IOCTL_DISK_GET_LENGTH_INFO, nullptr, 0, &li, sizeof(li), &got, nullptr)
        || li.Length.QuadPart <= 0) {
        CloseHandle(hd);
        releaseVolumes();
        return endOperation(false, "Cannot determine the size of the disk.");
    }
    const qint64 diskSize = li.Length.QuadPart;
    const qint64 chunk = 1LL * 1024 * 1024;

    resetProgress(diskSize * total);
    emit progress(0, QString("Wiping %1 (%2 MB, %3 pass(es))").arg(diskPath).arg(diskSize / (1024 * 1024)).arg(total));

    QString failure;
    for (int pass = 0; pass < total && !cancelled && failure.isEmpty(); ++pass) {
        LARGE_INTEGER zero; zero.QuadPart = 0;
        SetFilePointerEx(hd, zero, nullptr, FILE_BEGIN);
        qint64 done = 0;
        while (done < diskSize && !cancelled) {
            const qint64 n = qMin(chunk, diskSize - done);
            const QByteArray buf = generatePattern(pattern, n, pass, done);
            DWORD wrote = 0;
            if (!WriteFile(hd, buf.constData(), static_cast<DWORD>(n), &wrote, nullptr) || wrote != n) {
                failure = QString("Write error at %1 MB (Windows error %2).")
                              .arg(done / (1024 * 1024)).arg(GetLastError());
                break;
            }
            done += n;
            reportBytes(n, QString("Wiping %1: pass %2/%3, %4 / %5 MB")
                               .arg(diskPath).arg(pass + 1).arg(total)
                               .arg(done / (1024 * 1024)).arg(diskSize / (1024 * 1024)));
        }
        FlushFileBuffers(hd);
    }
    CloseHandle(hd);
    releaseVolumes();

    if (!failure.isEmpty()) return endOperation(false, failure);
    if (cancelled) return endOperation(false, "Drive wipe cancelled - the disk is partially overwritten.");
    return endOperation(true, QString("Physical drive wipe completed successfully (%1 pass(es))").arg(total));

#elif defined(Q_OS_LINUX)
    const QString mounted = mountedPartition(device);
    if (!mounted.isEmpty())
        return endOperation(false, QString("%1 has a mounted partition (%2). Unmount it first.").arg(device, mounted));

    const int fd = ::open(device.toLocal8Bit().constData(), O_WRONLY | O_CLOEXEC);
    if (fd < 0)
        return endOperation(false, QString("Cannot open %1 for writing: %2").arg(device, QString::fromLocal8Bit(strerror(errno))));

    quint64 diskSize = 0;
    if (ioctl(fd, BLKGETSIZE64, &diskSize) != 0 || diskSize == 0) {
        ::close(fd);
        return endOperation(false, "Cannot determine the size of the device.");
    }

    const qint64 chunk = 1LL * 1024 * 1024;
    resetProgress(static_cast<qint64>(diskSize) * total);
    QString failure;
    for (int pass = 0; pass < total && !cancelled && failure.isEmpty(); ++pass) {
        if (lseek(fd, 0, SEEK_SET) < 0) { failure = "Seek failed."; break; }
        qint64 done = 0;
        while (done < static_cast<qint64>(diskSize) && !cancelled) {
            const qint64 n = qMin<qint64>(chunk, static_cast<qint64>(diskSize) - done);
            const QByteArray buf = generatePattern(pattern, n, pass, done);
            qint64 off = 0;
            while (off < n) {
                const ssize_t w = ::write(fd, buf.constData() + off, static_cast<size_t>(n - off));
                if (w < 0) {
                    if (errno == EINTR) continue;
                    failure = QString("Write error at %1 MB: %2").arg(done / (1024 * 1024)).arg(QString::fromLocal8Bit(strerror(errno)));
                    break;
                }
                off += w;
            }
            if (!failure.isEmpty()) break;
            done += n;
            reportBytes(n, QString("Wiping %1: pass %2/%3, %4 / %5 MB")
                               .arg(device).arg(pass + 1).arg(total)
                               .arg(done / (1024 * 1024)).arg(diskSize / (1024 * 1024)));
        }
        fsync(fd);
    }
    ::close(fd);

    if (!failure.isEmpty()) return endOperation(false, failure);
    if (cancelled) return endOperation(false, "Drive wipe cancelled - the device is partially overwritten.");
    return endOperation(true, QString("Physical drive wipe completed successfully (%1 pass(es))").arg(total));
#else
    Q_UNUSED(total);
    return endOperation(false, "Full drive wipe is not supported on this platform.");
#endif
}

// ---------------------------------------------------------------------------
// Hardware secure erase
// ---------------------------------------------------------------------------
bool WipeEngine::secureEraseSSD(const QString &device) {
    if (running.exchange(true)) return false;
    cancelled = false;
    setMessage(QString());

#ifdef Q_OS_LINUX
    if (isSystemDevice(device))
        return endOperation(false, "Refusing to erase the disk that hosts the running operating system.");
    if (!isRunningAsAdministrator())
        return endOperation(false, "Root privileges are required for hardware secure erase.");

    secureEraseCache.remove(device);
    if (!supportsSecureErase(device))
        return endOperation(false, "The device does not report support for secure erase, or its security "
                                   "state is frozen (suspend/resume the machine to unfreeze SATA drives).");

    const QString mounted = mountedPartition(device);
    if (!mounted.isEmpty())
        return endOperation(false, QString("%1 has a mounted partition (%2). Unmount it first.").arg(device, mounted));

    emit warning("Hardware secure erase destroys all data and cannot be interrupted once started.");
    emit progress(0, "Secure erase in progress - this can take a long time and cannot be cancelled");

    auto run = [](const QString &program, const QStringList &args, QString *out) {
        QProcess p;
        p.start(program, args);
        if (!p.waitForStarted(5000)) { if (out) *out = "could not start " + program; return false; }
        p.waitForFinished(-1);
        if (out) *out = QString::fromLocal8Bit(p.readAllStandardError() + p.readAllStandardOutput()).trimmed();
        return p.exitStatus() == QProcess::NormalExit && p.exitCode() == 0;
    };

    QString output;
    bool ok = false;
    if (QFileInfo(device).fileName().startsWith("nvme")) {
        ok = run("nvme", { "format", device, "--ses=1" }, &output);      // user-data erase
    } else {
        const QString pw = "PurgeX";
        if (!run("hdparm", { "--user-master", "u", "--security-set-pass", pw, device }, &output))
            return endOperation(false, "Could not set the temporary ATA security password: " + output);
        ok = run("hdparm", { "--user-master", "u", "--security-erase-enhanced", pw, device }, &output)
          || run("hdparm", { "--user-master", "u", "--security-erase", pw, device }, &output);
        if (!ok) // never leave the drive locked behind a password
            run("hdparm", { "--user-master", "u", "--security-disable", pw, device }, nullptr);
    }
    return endOperation(ok, ok ? "Hardware secure erase completed"
                               : "Hardware secure erase failed: " + output);
#else
    Q_UNUSED(device);
    return endOperation(false, "Hardware secure erase is not available on this platform build. "
                               "Use the drive vendor's sanitize utility, or run PurgeX on Linux.");
#endif
}

// ---------------------------------------------------------------------------
// Patterns
// ---------------------------------------------------------------------------
QByteArray WipeEngine::generatePattern(WipePattern pattern, qint64 size, int pass, qint64 offset) {
    switch (pattern) {
        case WipePattern::NIST_800_88_1_PASS:
        case WipePattern::NIST_800_88_3_PASS:
        case WipePattern::NIST_800_88_7_PASS:
            return generateNISTPattern(pass, size, pattern);
        case WipePattern::GUTMANN_35_PASS:
            return generateGutmannPattern(pass, size, offset);
        default:
            break;
    }

    QByteArray data;
    data.resize(size);
    char *ptr = data.data();

    switch (pattern) {
        case WipePattern::ZERO_FILL: std::memset(ptr, 0x00, size); break;
        case WipePattern::ONE_FILL:  std::memset(ptr, 0xFF, size); break;
        case WipePattern::RANDOM:    fillRandom(ptr, size);        break;
        case WipePattern::ALTERNATING: {
            // 0x55 / 0xAA, with the roles swapped on every other pass.
            const unsigned char even = (pass % 2 == 0) ? 0x55 : 0xAA;
            for (qint64 i = 0; i < size; ++i)
                ptr[i] = static_cast<char>(((offset + i) % 2 == 0) ? even : (even ^ 0xFF));
            break;
        }
        default: break;
    }
    return data;
}

QByteArray WipeEngine::generateNISTPattern(int pass, qint64 size, WipePattern variant) {
    QByteArray data;
    data.resize(size);
    switch (nistKind(variant, pass)) {
        case NistZero:   std::memset(data.data(), 0x00, size); break;
        case NistOne:    std::memset(data.data(), 0xFF, size); break;
        case NistRandom: fillRandom(data.data(), size);        break;
    }
    return data;
}

QByteArray WipeEngine::generateGutmannPattern(int pass, qint64 size, qint64 offset) {
    QByteArray data;
    data.resize(size);
    char *ptr = data.data();

    const GutmannPass &gp = kGutmann[qBound(0, pass, 34)];
    if (gp.len == 0) {
        fillRandom(ptr, size);
    } else {
        for (qint64 i = 0; i < size; ++i)
            ptr[i] = static_cast<char>(gp.b[(offset + i) % gp.len]);
    }
    return data;
}

bool WipeEngine::performWipe(const WipeConfig &config) {
    switch (config.target) {
        case WipeTarget::FILES:
        case WipeTarget::FOLDERS:
            return wipeFiles(config.paths, config.pattern, config.passes, config.verify);
        case WipeTarget::FREE_SPACE:
            return wipeFreeSpace(config.drive, config.pattern, config.passes);
        case WipeTarget::FULL_DRIVE:
            return wipeFullDrive(config.drive, config.pattern, config.passes);
        case WipeTarget::SECURE_ERASE:
            return secureEraseSSD(config.drive);
    }
    return false;
}

// ===========================================================================
// WipeWorker
// ===========================================================================
WipeWorker::WipeWorker(const WipeConfig &config, WipeEngine *engine, QObject *parent)
    : QThread(parent), config(config), engine(engine) {
    // The engine lives on the GUI thread but is driven from run(); relay its
    // signals through the worker so receivers are always notified on their own thread.
    connect(engine, &WipeEngine::progress, this, &WipeWorker::progress);
    connect(engine, &WipeEngine::warning,  this, &WipeWorker::warning);
}

void WipeWorker::run() {
    // ---- Describe the job BEFORE wiping so sizes in the certificate are accurate ----
    const int effPasses = WipeEngine::effectivePasses(config.pattern, config.passes);
    const bool isFileJob = (config.target == WipeTarget::FILES || config.target == WipeTarget::FOLDERS);

    auto targetNameOf = [](WipeTarget t) {
        switch (t) {
            case WipeTarget::FILES:        return QString("Files");
            case WipeTarget::FOLDERS:      return QString("Folders");
            case WipeTarget::FREE_SPACE:   return QString("Free Space");
            case WipeTarget::FULL_DRIVE:   return QString("Full Drive");
            case WipeTarget::SECURE_ERASE: return QString("Hardware Secure Erase");
        }
        return QString("Unknown");
    };

    CertDetails details;
    details.subject = "PurgeX User";

    // Device passport: this machine plus the drive that holds the target.
    details.device = WipeEngine::systemPassport();
    {
        QString probe = isFileJob ? config.paths.value(0) : config.drive;
        const QString root = QStorageInfo(probe).rootPath();
        for (const DriveInfo &d : engine->detectDrives()) {
            const bool hit = (!root.isEmpty() && QDir::cleanPath(d.mountPoint) == QDir::cleanPath(root))
                          || d.device == config.drive || d.physicalDevice == config.drive
                          || QDir::cleanPath(d.mountPoint) == QDir::cleanPath(config.drive);
            if (!hit) continue;
            details.device["driveModel"]  = d.model;
            details.device["driveSerial"] = d.serial;
            details.device["driveType"]   = d.isSSD ? "SSD / flash" : "HDD";
            details.device["driveSize"]   = QString("%1 GB").arg(d.totalSize / (1024 * 1024 * 1024));
            if (!d.physicalDevice.isEmpty()) details.device["physicalDisk"] = d.physicalDevice;
            break;
        }
    }
    if (config.target == WipeTarget::SECURE_ERASE) {
        details.method = QString("Target: %1 | Method: ATA Security Erase / NVMe format").arg(targetNameOf(config.target));
    } else {
        details.method = QString("Target: %1 | Pattern: %2 | Passes: %3 | Verify: %4")
                             .arg(targetNameOf(config.target), WipeEngine::patternName(config.pattern))
                             .arg(effPasses).arg(config.verify ? "Yes" : "No");
    }

    qint64 totalBytes = 0;
    qint64 itemCount  = 0;
    QStringList listing;
    const int kMaxListed = 200; // keep certificates readable for very large folders

    if (isFileJob) {
        details.targets = config.paths;
        for (const QString &path : config.paths) {
            const QFileInfo info(path);
            if (info.isDir()) {
                QDirIterator it(path, QDir::Files | QDir::Hidden | QDir::System, QDirIterator::Subdirectories);
                while (it.hasNext()) {
                    const QFileInfo fi(it.next());
                    totalBytes += fi.size();
                    if (++itemCount <= kMaxListed)
                        listing << QString("%1 (%2 bytes)").arg(QDir::toNativeSeparators(fi.filePath())).arg(fi.size());
                }
            } else if (info.exists()) {
                totalBytes += info.size();
                if (++itemCount <= kMaxListed)
                    listing << QString("%1 (%2 bytes)").arg(QDir::toNativeSeparators(info.filePath())).arg(info.size());
            }
        }
        if (itemCount > kMaxListed)
            listing << QString("... and %1 more file(s)").arg(itemCount - kMaxListed);
    } else if (config.target == WipeTarget::FREE_SPACE) {
        details.targets = QStringList(config.drive);
        const QStorageInfo storage(config.drive);
        if (storage.isValid()) totalBytes = storage.bytesAvailable();
        listing << QString("Free space on %1: ~%2 bytes").arg(config.drive).arg(totalBytes);
    } else {
        details.targets = QStringList(config.drive);
        listing << QString("Device %1").arg(config.drive);
    }
    details.bytesProcessed = static_cast<qulonglong>(qMax<qint64>(0, totalBytes));
    if (!listing.isEmpty()) {
        details.targets << "--- Processed Files ---";
        details.targets << listing;
    }

    // ---- Perform the wipe ----
    const bool success = engine->performWipe(config);
    const bool wasCancelled = engine->cancelled.load();
    QString message = engine->lastMessage();

    // ---- Verification ----
    VerificationResult vr;
    if (success && config.verify) {
        emit progress(100, "Finalising verification...");
        if (isFileJob) {
            vr = engine->lastFileVerification();
        } else if (config.target == WipeTarget::FREE_SPACE) {
            vr = engine->verifyFreeSpace(config.drive, config.pattern);
        }
        if (vr.performed) {
            emit engine->verificationComplete(vr);
            if (!vr.passed && !vr.note.isEmpty()) emit warning(vr.note);
        }
    }

    if (vr.performed) {
        details.method += QString("\nVerification: %1").arg(vr.passed ? "PASSED" : "FAILED");
        details.verificationStatus = vr.passed ? "verified" : "failed";
        details.verificationNote   = vr.note;
    } else if (config.target == WipeTarget::SECURE_ERASE) {
        details.verificationStatus = "unverified";
        details.verificationNote   = "The drive reported completion of the hardware erase command. "
                                     "No independent read-back verification was performed.";
    } else if (config.target == WipeTarget::FULL_DRIVE) {
        details.verificationStatus = "limitation";
        details.verificationNote   =
            "Full-drive host-level overwrite performed. Individual sectors were not read back. "
            "For SSDs, wear-leveling and over-provisioning may leave data in NAND cells the host "
            "cannot address; use hardware Secure Erase for certified SSD sanitization.";
    } else {
        details.verificationStatus = config.verify ? "not_performed" : "unverified";
        details.verificationNote   = config.verify
            ? "Verification was requested but could not be completed."
            : "Verification was not requested. Enable 'Verify' for a post-wipe read-back check.";
    }

    switch (config.target) {
        case WipeTarget::FILES:
        case WipeTarget::FOLDERS:
            details.operationType = "filesystem-wipe";
            break;
        case WipeTarget::FREE_SPACE:
            details.operationType = (vr.performed && vr.passed) ? "verified-host-level-overwrite"
                                                                : "host-level-overwrite";
            break;
        case WipeTarget::FULL_DRIVE:
            details.operationType = "host-level-overwrite";
            break;
        case WipeTarget::SECURE_ERASE:
            details.operationType = "hardware-secure-erase";
            break;
    }

    // ---- Certificate ----
    if (success && config.generateCertificate) {
        CertManager certManager;
        if (certManager.generateCertificates(details, nullptr, &certPdf, &certJson))
            message += QString("\nCertificate: %1").arg(certPdf);
        else
            emit warning("The wipe succeeded but the certificate could not be written.");
    }

    // ---- Audit trail (every operation, successful or not) ----
    AuditEntry entry;
    entry.id        = AuditLog::generateId();
    entry.type      = "wipe";
    entry.timestamp = QDateTime::currentDateTime();
    entry.target    = isFileJob
        ? QString("%1 item(s): %2").arg(config.paths.size()).arg(config.paths.value(0))
        : config.drive;
    entry.algorithm = details.method;
    entry.status    = success ? "success" : (wasCancelled ? "cancelled" : "failed");
    entry.verificationStatus = details.verificationStatus;
    entry.verificationNote   = details.verificationNote;
    entry.certPath       = certPdf;
    entry.bytesProcessed = totalBytes;
    entry.details        = message;
    AuditLog().append(entry);

    emit finished(success, success ? message
                                   : (message.isEmpty() ? QString("Operation failed") : message));
}

// ===========================================================================
// Privileges
// ===========================================================================
QMap<QString, QString> WipeEngine::systemPassport()
{
    QMap<QString, QString> p;
    p["hostname"] = QSysInfo::machineHostName();
    p["os"]       = QSysInfo::prettyProductName();
    p["arch"]     = QSysInfo::currentCpuArchitecture();

    QString cpu;
    qint64 ramBytes = 0;
#ifdef Q_OS_WIN
    wchar_t buf[256] = {};
    DWORD size = sizeof(buf);
    if (RegGetValueW(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
                     L"ProcessorNameString", RRF_RT_REG_SZ, nullptr, buf, &size) == ERROR_SUCCESS)
        cpu = QString::fromWCharArray(buf).trimmed();
    MEMORYSTATUSEX mem;
    mem.dwLength = sizeof(mem);
    if (GlobalMemoryStatusEx(&mem)) ramBytes = static_cast<qint64>(mem.ullTotalPhys);
#else
    QFile info("/proc/cpuinfo");
    if (info.open(QIODevice::ReadOnly)) {
        for (const QByteArray &line : info.readAll().split('\n'))
            if (line.startsWith("model name")) { cpu = QString::fromLocal8Bit(line.mid(line.indexOf(':') + 1)).trimmed(); break; }
    }
    QFile meminfo("/proc/meminfo");
    if (meminfo.open(QIODevice::ReadOnly)) {
        for (const QByteArray &line : meminfo.readAll().split('\n'))
            if (line.startsWith("MemTotal:")) { ramBytes = line.simplified().split(' ').value(1).toLongLong() * 1024; break; }
    }
#endif
    if (!cpu.isEmpty()) p["cpu"] = cpu;
    if (ramBytes > 0)   p["memory"] = QString("%1 GB").arg(QString::number(ramBytes / double(1024 * 1024 * 1024), 'f', 1));
    return p;
}

bool WipeEngine::isRunningAsAdministrator() {
#ifdef Q_OS_WIN
    BOOL isAdmin = FALSE;
    PSID adminGroup = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(nullptr, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin;
#else
    return geteuid() == 0;
#endif
}

bool WipeEngine::requestAdministratorPrivileges() {
#ifdef Q_OS_WIN
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);

    SHELLEXECUTEINFOW sei;
    ZeroMemory(&sei, sizeof(sei));
    sei.cbSize = sizeof(sei);
    sei.fMask  = SEE_MASK_FLAG_DDEWAIT | SEE_MASK_FLAG_NO_UI;
    sei.lpVerb = L"runas"; // triggers the UAC prompt
    sei.lpFile = exePath;
    sei.nShow  = SW_SHOW;
    return ShellExecuteExW(&sei);
#else
    return false; // re-run with sudo
#endif
}

// ===========================================================================
// Verification helpers
// ===========================================================================

// Read a file back and confirm it holds the expected pattern (pass 0).
VerificationResult WipeEngine::verifyFile(const QString &filePath, WipePattern pattern)
{
    VerificationResult vr;
    vr.performed     = true;
    vr.operationType = "host-level-overwrite";

    QFile f(filePath);
    if (!f.open(QIODevice::ReadOnly)) {
        vr.passed = false;
        vr.note   = QString("Cannot open file for verification (ReadOnly): %1").arg(f.errorString());
        return vr;
    }

    const qint64 chunkSize = 1 * 1024 * 1024;
    qint64 checked = 0, verified = 0, failed = 0, offset = 0;

    while (!cancelled) {
        const QByteArray actual = f.read(chunkSize);
        if (actual.isEmpty()) break;

        const QByteArray expected = generatePattern(pattern, actual.size(), 0, offset);
        offset += actual.size();
        ++checked;

        if (actual == expected) ++verified; else ++failed;
    }
    f.close();

    vr.sectorsChecked  = checked;
    vr.sectorsVerified = verified;
    vr.sectorsFailed   = failed;
    vr.passed          = (failed == 0 && checked > 0);

    vr.note = vr.passed
        ? QString("Read-back verification passed: %1 chunk(s) verified.").arg(verified)
        : QString("Read-back verification: %1/%2 chunk(s) mismatch.").arg(failed).arg(checked);
    return vr;
}

// Write a known probe file, read it back, delete it. This is the only free-space
// check possible without raw sector access; its limits are stated in the note.
VerificationResult WipeEngine::verifyFreeSpace(const QString &drive, WipePattern pattern)
{
    VerificationResult vr;
    vr.performed     = true;
    vr.operationType = "host-level-overwrite";
    vr.isSSD         = isSSD(drive);

    const QString probeDir  = QDir(drive).filePath("PurgeX_Verify");
    const QString probePath = QDir(probeDir).filePath("purgex_verify_probe.dat");
    QDir().mkpath(probeDir);

    const qint64 probeSize = 4 * 1024 * 1024;
    const QByteArray expected = generatePattern(pattern, probeSize, 0, 0);

    {
        QFile wf(probePath);
        if (!wf.open(QIODevice::WriteOnly)) {
            vr.passed = false;
            vr.note   = "Cannot create verification probe file.";
            QDir(probeDir).removeRecursively();
            return vr;
        }
        wf.write(expected);
        syncFile(wf);
        wf.close();
    }

    QByteArray actual;
    {
        QFile rf(probePath);
        if (!rf.open(QIODevice::ReadOnly)) {
            vr.passed = false;
            vr.note   = "Cannot read verification probe file.";
            QDir(probeDir).removeRecursively();
            return vr;
        }
        actual = rf.readAll();
    }
    QFile::remove(probePath);
    QDir(probeDir).removeRecursively();

    vr.sectorsChecked  = 1;
    vr.sectorsVerified = (actual == expected) ? 1 : 0;
    vr.sectorsFailed   = (actual == expected) ? 0 : 1;
    vr.passed          = (actual == expected);

    if (!vr.passed) {
        vr.note = "Free-space probe MISMATCH: read-back data does not match the written pattern. "
                  "The volume may be changing underneath PurgeX; retry without other programs running.";
    } else if (vr.isSSD) {
        vr.note = "Free space was overwritten at the host level and a probe file read back correctly. "
                  "NOTE: SSD wear-leveling, TRIM and over-provisioning can leave data in NAND cells "
                  "the host cannot address, so this does not prove physical erasure. "
                  "Use hardware Secure Erase for certified SSD sanitization.";
    } else {
        vr.note = "Free space was overwritten at the host level and a probe file read back correctly. "
                  "This checks the write path, not every sector.";
    }
    return vr;
}
