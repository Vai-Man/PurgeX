#include "ForensicEngine.h"
#include "../core/WipeEngine.h"

#include <QFile>
#include <QDir>
#include <QDirIterator>
#include <QFileInfo>
#include <QStorageInfo>
#include <QCryptographicHash>
#include <QDebug>
#include <algorithm>
#include <cerrno>
#include <cstring>

#ifdef Q_OS_WIN
#include <windows.h>
#include <winioctl.h>
#else
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifdef Q_OS_LINUX
#include <sys/ioctl.h>
#include <linux/fs.h>
#endif
#endif

// ===========================================================================
// RawReader — read-only random access to a file, volume or physical disk.
//
// Raw devices only accept sector-aligned offsets and lengths, so everything is
// fetched in aligned 1 MiB blocks and served from a one-block cache. Unreadable
// regions (bad sectors on damaged media) are zero-filled and counted instead of
// aborting the scan.
// ===========================================================================
class RawReader {
public:
    RawReader() = default;
    ~RawReader() { close(); }
    RawReader(const RawReader &) = delete;
    RawReader &operator=(const RawReader &) = delete;

    bool open(const QString &path, QString *err);
    void close();

    qint64 size() const { return total; }
    qint64 badBytes() const { return bad; }

    QByteArray read(qint64 offset, qint64 length);
    int byteAt(qint64 pos); // -1 past the end

private:
    static constexpr qint64 kBlock = 1024 * 1024;

    bool loadBlock(qint64 blockStart);
    bool rawRead(qint64 offset, char *dst, qint64 len);
    void readTolerant(qint64 offset, char *dst, qint64 len, qint64 grain);

#ifdef Q_OS_WIN
    HANDLE handle = INVALID_HANDLE_VALUE;
#else
    int fd = -1;
#endif
    qint64 total = 0;
    qint64 bad = 0;
    qint64 cacheStart = -1;
    QByteArray cache;
};

bool RawReader::open(const QString &path, QString *err)
{
    close();
#ifdef Q_OS_WIN
    const QString native = path.startsWith("\\\\.\\") ? path : QDir::toNativeSeparators(path);
    handle = CreateFileW(reinterpret_cast<LPCWSTR>(native.utf16()), GENERIC_READ,
                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                         nullptr, OPEN_EXISTING, 0, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        const DWORD code = GetLastError();
        if (err) *err = QString("Windows error %1%2").arg(code)
                            .arg(code == ERROR_ACCESS_DENIED ? " (access denied - run PurgeX as Administrator)" : "");
        return false;
    }
    GET_LENGTH_INFORMATION li = {};
    DWORD got = 0;
    if (DeviceIoControl(handle, IOCTL_DISK_GET_LENGTH_INFO, nullptr, 0, &li, sizeof(li), &got, nullptr)) {
        total = li.Length.QuadPart;
    } else {
        LARGE_INTEGER sz;
        if (GetFileSizeEx(handle, &sz)) total = sz.QuadPart;
    }
#else
    fd = ::open(path.toLocal8Bit().constData(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (err) *err = QString::fromLocal8Bit(strerror(errno));
        return false;
    }
    struct stat st;
    if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode)) {
        total = st.st_size;
    } else {
#ifdef Q_OS_LINUX
        quint64 sz = 0;
        if (ioctl(fd, BLKGETSIZE64, &sz) == 0) total = static_cast<qint64>(sz);
#endif
        if (total <= 0) total = lseek(fd, 0, SEEK_END);
    }
#endif
    bad = 0;
    cacheStart = -1;
    return true;
}

void RawReader::close()
{
#ifdef Q_OS_WIN
    if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
    handle = INVALID_HANDLE_VALUE;
#else
    if (fd >= 0) ::close(fd);
    fd = -1;
#endif
    cache.clear();
    cacheStart = -1;
}

bool RawReader::rawRead(qint64 offset, char *dst, qint64 len)
{
#ifdef Q_OS_WIN
    LARGE_INTEGER pos; pos.QuadPart = offset;
    if (!SetFilePointerEx(handle, pos, nullptr, FILE_BEGIN)) return false;
    qint64 done = 0;
    while (done < len) {
        DWORD got = 0;
        const DWORD want = static_cast<DWORD>(qMin<qint64>(len - done, 16 * 1024 * 1024));
        if (!ReadFile(handle, dst + done, want, &got, nullptr) || got == 0) return false;
        done += got;
    }
    return true;
#else
    qint64 done = 0;
    while (done < len) {
        const ssize_t got = pread(fd, dst + done, static_cast<size_t>(len - done), offset + done);
        if (got <= 0) return false;
        done += got;
    }
    return true;
#endif
}

void RawReader::readTolerant(qint64 offset, char *dst, qint64 len, qint64 grain)
{
    if (rawRead(offset, dst, len)) return;
    if (grain < 512 || len <= 512) {            // smallest unit - give up on it
        std::memset(dst, 0, static_cast<size_t>(len));
        bad += len;
        return;
    }
    // Retry in smaller aligned pieces so one bad sector does not hide a whole block.
    const qint64 piece = qMax<qint64>(512, grain);
    for (qint64 done = 0; done < len; done += piece)
        readTolerant(offset + done, dst + done, qMin(piece, len - done), piece / 8);
}

bool RawReader::loadBlock(qint64 blockStart)
{
    if (blockStart < 0 || blockStart >= total) return false;
    const qint64 len = qMin(kBlock, total - blockStart);
    QByteArray block(static_cast<int>(len), 0);
    readTolerant(blockStart, block.data(), len, 64 * 1024);
    cache = block;
    cacheStart = blockStart;
    return true;
}

QByteArray RawReader::read(qint64 offset, qint64 length)
{
    QByteArray out;
    if (offset < 0 || length <= 0 || offset >= total) return out;
    length = qMin(length, total - offset);
    out.reserve(static_cast<int>(length));
    while (length > 0) {
        const qint64 blockStart = offset - (offset % kBlock);
        if (blockStart != cacheStart && !loadBlock(blockStart)) break;
        const qint64 inBlock = offset - cacheStart;
        const qint64 n = qMin<qint64>(length, cache.size() - inBlock);
        if (n <= 0) break;
        out.append(cache.constData() + inBlock, static_cast<int>(n));
        offset += n;
        length -= n;
    }
    return out;
}

int RawReader::byteAt(qint64 pos)
{
    if (pos < 0 || pos >= total) return -1;
    const qint64 blockStart = pos - (pos % kBlock);
    if (blockStart != cacheStart && !loadBlock(blockStart)) return -1;
    const qint64 idx = pos - cacheStart;
    return idx < cache.size() ? static_cast<uint8_t>(cache[static_cast<int>(idx)]) : -1;
}

// ===========================================================================
// Length detection helpers
// ===========================================================================
namespace {

using namespace sigutil;

constexpr qint64 kFallbackCap = 8LL * 1024 * 1024; // used when a structure walk fails

// Footer search that works across block boundaries. Returns the exclusive end or -1.
qint64 findFooter(RawReader &src, qint64 from, qint64 end, const QByteArray &footer, int trailing)
{
    if (footer.isEmpty()) return -1;
    const qint64 block = 1024 * 1024;
    for (qint64 pos = from; pos < end; pos += block) {
        const QByteArray blk = src.read(pos, qMin(block + footer.size() - 1, end - pos));
        const int idx = blk.indexOf(footer);
        if (idx >= 0)
            return qMin(end, pos + idx + footer.size() + trailing);
        if (blk.size() < footer.size()) break;
    }
    return -1;
}

// Walk JPEG segments; the first FFD9 after the scan data is the real EOI, so
// thumbnails embedded in EXIF segments no longer truncate the file.
qint64 jpegEnd(RawReader &src, qint64 start, qint64 end)
{
    qint64 pos = start + 2; // after SOI
    while (pos + 2 <= end) {
        if (src.byteAt(pos) != 0xFF) return -1;
        const int marker = src.byteAt(pos + 1);
        if (marker < 0) return -1;
        if (marker == 0xFF) { ++pos; continue; }                       // fill byte
        if (marker == 0xD9) return pos + 2;                            // EOI
        if (marker == 0x01 || (marker >= 0xD0 && marker <= 0xD8)) { pos += 2; continue; }
        if (pos + 4 > end) return -1;
        const int hi = src.byteAt(pos + 2), lo = src.byteAt(pos + 3);
        if (hi < 0 || lo < 0) return -1;
        const int len = (hi << 8) | lo;
        if (len < 2) return -1;
        pos += 2 + len;
        if (marker == 0xDA) {                                          // entropy-coded data
            while (pos + 2 <= end) {
                const int c = src.byteAt(pos);
                if (c < 0) return -1;
                if (c != 0xFF) { ++pos; continue; }
                const int n = src.byteAt(pos + 1);
                if (n < 0) return -1;
                if (n == 0x00 || (n >= 0xD0 && n <= 0xD7)) { pos += 2; continue; }
                if (n == 0xFF) { ++pos; continue; }
                break; // a real marker follows
            }
        }
    }
    return -1;
}

qint64 pngEnd(RawReader &src, qint64 start, qint64 end)
{
    qint64 pos = start + 8;
    while (pos + 12 <= end) {
        const QByteArray hdr = src.read(pos, 8);
        if (hdr.size() < 8) return -1;
        const quint32 len = be32(hdr, 0);
        for (int i = 4; i < 8; ++i) {
            const char c = hdr[i];
            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))) return -1;
        }
        if (len > 0x7FFFFFFFu) return -1;
        const qint64 next = pos + 12 + len;
        if (hdr.mid(4, 4) == "IEND") return qMin(next, end);
        if (next > end) return -1;
        pos = next;
    }
    return -1;
}

qint64 skipGifSubBlocks(RawReader &src, qint64 pos, qint64 end)
{
    while (pos < end) {
        const int n = src.byteAt(pos);
        if (n < 0) return -1;
        ++pos;
        if (n == 0) return pos;
        pos += n;
    }
    return -1;
}

qint64 gifEnd(RawReader &src, qint64 start, qint64 end)
{
    qint64 pos = start + 6;
    const int packed = src.byteAt(pos + 4);
    if (packed < 0) return -1;
    pos += 7;
    if (packed & 0x80) pos += 3 * (1LL << ((packed & 7) + 1));
    while (pos < end) {
        const int c = src.byteAt(pos);
        if (c == 0x3B) return pos + 1;
        if (c == 0x21) {                                   // extension
            pos = skipGifSubBlocks(src, pos + 2, end);
        } else if (c == 0x2C) {                            // image descriptor
            const int ip = src.byteAt(pos + 9);
            if (ip < 0) return -1;
            pos += 10;
            if (ip & 0x80) pos += 3 * (1LL << ((ip & 7) + 1));
            pos = skipGifSubBlocks(src, pos + 1, end);     // LZW minimum code size + data
        } else {
            return -1;
        }
        if (pos < 0) return -1;
    }
    return -1;
}

// ZIP ends at an end-of-central-directory record whose directory offset/size
// agree with where the archive started - this skips EOCDs of zips stored inside.
qint64 zipEnd(RawReader &src, qint64 start, qint64 end, const QByteArray &footer)
{
    qint64 from = start + 4;
    while (from < end) {
        const qint64 hit = findFooter(src, from, end, footer, 0);
        if (hit < 0) return -1;
        const qint64 eocd = hit - footer.size();
        const QByteArray rec = src.read(eocd, 22);
        if (rec.size() == 22) {
            const quint32 cdSize = le32(rec, 12), cdOff = le32(rec, 16);
            const quint32 comment = le16(rec, 20);
            if (cdOff == 0xFFFFFFFFu || start + qint64(cdOff) + qint64(cdSize) == eocd)
                return qMin(end, eocd + 22 + qint64(comment));
        }
        from = eocd + 1;
    }
    return -1;
}

qint64 mp4End(RawReader &src, qint64 start, qint64 end)
{
    qint64 pos = start;
    int boxes = 0;
    bool haveMedia = false;
    while (pos + 8 <= end) {
        const QByteArray hdr = src.read(pos, 16);
        if (hdr.size() < 8) break;
        quint64 size = be32(hdr, 0);
        if (size == 1 && hdr.size() >= 16) size = (quint64(be32(hdr, 8)) << 32) | be32(hdr, 12);
        if (size < 8) break;
        bool printable = true;
        for (int i = 4; i < 8; ++i) if (hdr[i] < 0x20 || hdr[i] > 0x7E) printable = false;
        if (!printable) break;
        if (pos + qint64(size) > end) { pos = -1; break; }  // box runs past the available data
        if (hdr.mid(4, 4) == "moov" || hdr.mid(4, 4) == "mdat") haveMedia = true;
        pos += qint64(size);
        ++boxes;
    }
    return (pos > start && boxes >= 2 && haveMedia) ? pos : -1;
}

qint64 peEnd(const QByteArray &head)
{
    const quint32 e = le32(head, 0x3C);
    const quint32 sections = le16(head, e + 6);
    const quint32 optSize = le16(head, e + 20);
    const int optBase = int(e) + 24;
    qint64 end = 0;
    for (quint32 i = 0; i < sections && i < 96; ++i) {
        const int off = optBase + int(optSize) + int(i) * 40;
        if (off + 40 > head.size()) return -1;
        end = qMax<qint64>(end, qint64(le32(head, off + 20)) + qint64(le32(head, off + 16)));
    }
    // Authenticode signature lives after the last section.
    const quint32 magic = le16(head, optBase);
    const int dd = optBase + (magic == 0x20B ? 112 : 96) + 4 * 8;
    const quint32 certOff = le32(head, dd), certSize = le32(head, dd + 4);
    if (certOff && certSize) end = qMax<qint64>(end, qint64(certOff) + qint64(certSize));
    return end > 0 ? end : -1;
}

QString uniqueDestPath(const QString &destDir, const QString &ext, int index, qint64 offset)
{
    const QString base = QString("recovered_%1_off%2").arg(index, 6, 10, QChar('0')).arg(offset, 0, 16);
    QString path = QDir(destDir).filePath(base + "." + ext);
    for (int i = 1; QFile::exists(path); ++i)
        path = QDir(destDir).filePath(QString("%1_%2.%3").arg(base).arg(i).arg(ext));
    return path;
}

bool pathInside(const QString &child, const QString &parent)
{
    QString c = QDir::cleanPath(QFileInfo(child).absoluteFilePath());
    QString p = QDir::cleanPath(QFileInfo(parent).absoluteFilePath());
    if (!p.endsWith('/')) p += '/';
    if (!c.endsWith('/')) c += '/';
#ifdef Q_OS_WIN
    return c.startsWith(p, Qt::CaseInsensitive);
#else
    return c.startsWith(p);
#endif
}

} // namespace

// ===========================================================================
// ForensicEngine
// ===========================================================================
ForensicEngine::ForensicEngine(QObject *parent) : QObject(parent)
{
    // Required for the queued (cross-thread) delivery of these signals. Without it
    // Qt silently drops fileFound()/finished() and the UI never hears from the scan.
    qRegisterMetaType<RecoveryResult>("RecoveryResult");
    qRegisterMetaType<QList<RecoveryResult>>("QList<RecoveryResult>");
}

ForensicEngine::~ForensicEngine()
{
    cancelled = true;
    if (worker) worker->wait();
}

bool ForensicEngine::startScan(const ForensicConfig &config)
{
    if (running.exchange(true)) {
        emit warning("A scan is already running.");
        return false;
    }
    auto reject = [this](const QString &why) {
        running = false;
        emit warning(why);
        return false;
    };

    if (config.destPath.trimmed().isEmpty())
        return reject("Please choose a destination folder for the recovered files.");

    if (config.mode == ForensicConfig::ScanMode::RawDevice && !config.rawModeConfirmed)
        return reject("Raw device scan requires explicit user confirmation. Scan aborted.");

    if (config.mode == ForensicConfig::ScanMode::LogicalPath) {
        const QFileInfo src(config.sourcePath);
        if (!src.exists() || !src.isDir())
            return reject("The source folder does not exist.");
        if (pathInside(config.destPath, config.sourcePath))
            return reject("Destination must not be inside the source directory. Scan aborted.");
    } else {
        QString err;
        RawReader probe;
        if (!probe.open(config.sourcePath, &err))
            return reject(QString("Cannot open the source for reading: %1").arg(err));
        if (probe.size() <= 0)
            return reject("The source reports a size of zero bytes.");
        // Writing recovered files onto the disk being scanned can destroy the very data we are after.
        const bool isDevice = config.sourcePath.startsWith("\\\\.\\") || config.sourcePath.startsWith("/dev/");
        if (isDevice && WipeEngine::pathIsOnDisk(config.sourcePath, config.destPath))
            return reject("The destination is on the disk being scanned. Writing there could overwrite "
                          "the data you are trying to recover - choose a folder on a different disk.");
    }

    if (!QDir().mkpath(config.destPath))
        return reject("Cannot create the destination folder.");

    cancelled = false;
    destinationFull = false;

    worker = new ForensicWorker(config, this, this);
    connect(worker, &QThread::finished, worker, &QObject::deleteLater);
    worker->start();
    return true;
}

void ForensicEngine::cancel()
{
    cancelled = true;
}

void ForensicEngine::finishScan(bool success, const QString &message, const QList<RecoveryResult> &results)
{
    running = false; // clear first so a slot connected to finished() may start the next scan
    emit finished(success, message, results);
}

QList<FileSignature> ForensicEngine::activeSignatures(const ForensicConfig &config) const
{
    QList<FileSignature> active;
    for (const FileSignature &sig : builtinSignatures())
        if (config.categories.isEmpty() || config.categories.contains(sig.category))
            active.append(sig);
    return active;
}

RecoveryConfidence ForensicEngine::confidenceFor(bool reliable, qint64 bytes)
{
    if (reliable) return RecoveryConfidence::HIGH;
    return bytes > 4096 ? RecoveryConfidence::MEDIUM : RecoveryConfidence::LOW;
}

// ---------------------------------------------------------------------------
// Work out where a file ends
// ---------------------------------------------------------------------------
ForensicEngine::Length ForensicEngine::determineLength(RawReader &src, qint64 start, qint64 limit,
                                                       const FileSignature &sig, const QByteArray &head)
{
    Length L;
    const qint64 maxLen = qMin(sig.maxSize, limit - start);
    if (maxLen <= 0) return L;
    const qint64 end = start + maxLen;
    qint64 found = -1;

    switch (sig.rule) {
        case LengthRule::Jpeg:  found = jpegEnd(src, start, end); break;
        case LengthRule::Png:   found = pngEnd(src, start, end);  break;
        case LengthRule::Gif:   found = gifEnd(src, start, end);  break;
        case LengthRule::Zip:   found = zipEnd(src, start, end, sig.footer); break;
        case LengthRule::Mp4:   found = mp4End(src, start, end);  break;
        case LengthRule::Footer:
            found = findFooter(src, start + sig.headerOffset + sig.header.size(), end, sig.footer, sig.footerTrailing);
            break;
        case LengthRule::Riff: {
            const qint64 n = qint64(le32(head, 4)) + 8;
            if (n >= 12 && n <= maxLen) found = start + n;
            break;
        }
        case LengthRule::Bmp: {
            const qint64 n = le32(head, 2);
            if (n >= 26 && n <= maxLen) found = start + n;
            break;
        }
        case LengthRule::SevenZip: {
            const quint64 off = le64(head, 12), size = le64(head, 20);
            const quint64 n = 32 + off + size;
            if (off < (1ULL << 40) && size < (1ULL << 40) && qint64(n) <= maxLen) found = start + qint64(n);
            break;
        }
        case LengthRule::Sqlite: {
            quint64 ps = be16(head, 16);
            if (ps == 1) ps = 65536;
            const quint64 pages = be32(head, 28);
            if (pages > 0 && qint64(ps * pages) <= maxLen) found = start + qint64(ps * pages);
            break;
        }
        case LengthRule::PE: {
            const qint64 n = peEnd(head);
            if (n > 0 && n <= maxLen) found = start + n;
            break;
        }
        case LengthRule::None:
            break;
    }

    if (found > start) {
        L.bytes = found - start;
        L.reliable = true;
    } else {
        // The structure could not be followed (damaged or overwritten): take what is plausible.
        L.bytes = (sig.rule == LengthRule::None) ? maxLen : qMin(maxLen, kFallbackCap);
        L.reliable = false;
    }
    return L;
}

// ---------------------------------------------------------------------------
// Copy a region of the source into a recovered file
// ---------------------------------------------------------------------------
RecoveryResult ForensicEngine::carve(RawReader &src, qint64 start, qint64 length, bool reliable,
                                     const FileSignature &sig, const QByteArray &head,
                                     const QString &sourceLabel, const QString &destDir, int fileIndex)
{
    RecoveryResult r;
    r.sourcePath     = sourceLabel;
    r.originalOffset = start;
    r.fileType       = sig.name;
    r.extension      = sig.refineExtension ? sig.refineExtension(head) : sig.extension;
    if (r.extension.isEmpty()) r.extension = sig.extension;
    r.category       = sig.category;

    if (length <= 0) {
        r.notes = "No data could be read at this offset.";
        return r;
    }

    const QStorageInfo dest(destDir);
    if (dest.isValid() && dest.bytesAvailable() < length + 64LL * 1024 * 1024) {
        destinationFull = true;
        r.notes = "Destination folder does not have enough free space.";
        return r;
    }

    const QString outPath = uniqueDestPath(destDir, r.extension, fileIndex, start);
    QFile out(outPath);
    if (!out.open(QIODevice::WriteOnly)) {
        r.notes = QString("Cannot write to destination: %1").arg(out.errorString());
        return r;
    }

    QCryptographicHash hash(QCryptographicHash::Sha256);
    const qint64 block = 1024 * 1024;
    qint64 copied = 0;
    while (copied < length && !cancelled) {
        const QByteArray data = src.read(start + copied, qMin(block, length - copied));
        if (data.isEmpty()) break;
        if (out.write(data) != data.size()) {
            r.notes = QString("Write error: %1").arg(out.errorString());
            out.close();
            QFile::remove(outPath);
            return r;
        }
        hash.addData(data);
        copied += data.size();
    }
    out.close();

    if (cancelled || copied == 0) {
        QFile::remove(outPath);
        return r;
    }

    const bool complete = reliable && copied == length;
    r.destinationPath = outPath;
    r.recoveredBytes  = copied;
    r.sha256          = QString::fromLatin1(hash.result().toHex());
    r.confidence      = confidenceFor(complete, copied);
    r.status          = complete ? RecoveryStatus::Recovered : RecoveryStatus::PartiallyRecovered;
    if (!complete)
        r.notes = reliable ? "Source ended before the file's own structure did - the file is truncated."
                           : "The end of the file could not be proven from its structure; the output "
                             "may be truncated or carry trailing data.";
    return r;
}

// ---------------------------------------------------------------------------
// Logical scan - classify and copy the files of a mounted folder
// ---------------------------------------------------------------------------
RecoveryResult ForensicEngine::recoverLogicalFile(const QString &filePath, const QList<FileSignature> &sigs,
                                                  const QString &destDir, int fileIndex)
{
    RecoveryResult none;
    none.sourcePath = filePath;

    RawReader src;
    QString err;
    if (!src.open(filePath, &err)) {
        none.notes = QString("Cannot open source file (read-only): %1").arg(err);
        return none;
    }
    const qint64 size = src.size();
    const QByteArray head = src.read(0, 16384);

    for (const FileSignature &sig : sigs) {
        const int off = sig.headerOffset, hl = sig.header.size();
        if (head.size() < off + hl || head.mid(off, hl) != sig.header) continue;
        if (sig.validate && !sig.validate(head)) continue;

        const Length L = determineLength(src, 0, size, sig, head);
        const qint64 copyLen = qMin(size, sig.maxSize);
        // A real file on disk is copied whole; the structure only decides the confidence.
        RecoveryResult r = carve(src, 0, copyLen, L.reliable && L.bytes == copyLen, sig, head, filePath, destDir, fileIndex);
        if (r.status != RecoveryStatus::Unrecoverable) {
            if (L.reliable && L.bytes < copyLen) {
                r.confidence = RecoveryConfidence::MEDIUM;
                r.notes = QString("File structure ends at byte %1 but the file continues to %2 (trailing data).")
                              .arg(L.bytes).arg(copyLen);
            } else if (L.reliable && L.bytes > copyLen) {
                r.notes = QString("File is truncated: its structure ends at byte %1 but only %2 are present.")
                              .arg(L.bytes).arg(copyLen);
            }
        }
        return r;
    }
    return none; // no signature matched
}

void ForensicEngine::runLogicalScan(const ForensicConfig &config)
{
    const QList<FileSignature> sigs = activeSignatures(config);
    if (sigs.isEmpty()) {
        finishScan(false, "No file signatures match the selected categories.", {});
        return;
    }

    QStringList filePaths;
    QDirIterator it(config.sourcePath, QDir::Files | QDir::Hidden | QDir::System, QDirIterator::Subdirectories);
    while (it.hasNext() && !cancelled) {
        const QString p = it.next();
        if (!pathInside(p, config.destPath)) filePaths.append(p);
    }
    if (cancelled) { finishScan(false, "Scan cancelled.", {}); return; }

    QList<RecoveryResult> results;
    const int total = filePaths.size();
    int index = 0;

    for (const QString &path : filePaths) {
        if (cancelled || destinationFull) break;
        emit progress(total > 0 ? (index * 100) / total : 0,
                      QString("Scanning (%1/%2): %3").arg(index + 1).arg(total).arg(QFileInfo(path).fileName()));

        const RecoveryResult r = recoverLogicalFile(path, sigs, config.destPath, index);
        if (r.status != RecoveryStatus::Unrecoverable) {
            results.append(r);
            emit fileFound(r);
        }
        ++index;
    }

    if (destinationFull)
        finishScan(false, QString("Stopped: the destination ran out of space after %1 file(s).").arg(results.size()), results);
    else if (cancelled)
        finishScan(false, "Scan cancelled.", results);
    else
        finishScan(true, QString("Scan complete. %1 file(s) recovered from %2 scanned.")
                             .arg(results.size()).arg(total), results);
}

// ---------------------------------------------------------------------------
// Raw scan - sector-aligned signature carving of a device or disk image
// ---------------------------------------------------------------------------
void ForensicEngine::runRawScan(const ForensicConfig &config)
{
    RawReader src;
    QString err;
    if (!src.open(config.sourcePath, &err)) {
        finishScan(false, QString("Cannot open source device (read-only): %1 - %2").arg(config.sourcePath, err), {});
        return;
    }
    const qint64 total = src.size();
    const QList<FileSignature> sigs = activeSignatures(config);
    if (sigs.isEmpty()) {
        finishScan(false, "No file signatures match the selected categories.", {});
        return;
    }

    // Files start on sector boundaries; testing only those cuts false positives dramatically.
    const qint64 sector = 512;
    const qint64 chunk  = 4LL * 1024 * 1024;
    const qint64 headWindow = 16384;

    QList<RecoveryResult> results;
    qint64 skipUntil = 0;
    int index = 0;

    emit progress(0, "Starting raw scan...");

    for (qint64 pos = 0; pos < total && !cancelled && !destinationFull; pos += chunk) {
        const QByteArray buf = src.read(pos, qMin(chunk, total - pos));
        if (buf.isEmpty()) break;
        const char *base = buf.constData();

        for (qint64 s = 0; s < buf.size() && !cancelled && !destinationFull; s += sector) {
            const qint64 abs = pos + s;
            if (abs < skipUntil) continue;

            // Cheap pre-check against every header at this sector.
            bool candidate = false;
            for (const FileSignature &sig : sigs) {
                const qint64 off = sig.headerOffset, hl = sig.header.size();
                if (s + off + hl <= buf.size() &&
                    std::memcmp(base + s + off, sig.header.constData(), static_cast<size_t>(hl)) == 0) {
                    candidate = true;
                    break;
                }
            }
            if (!candidate) continue;

            const QByteArray head = (s + headWindow <= buf.size()) ? buf.mid(static_cast<int>(s), static_cast<int>(headWindow))
                                                                   : src.read(abs, headWindow);
            for (const FileSignature &sig : sigs) {
                const int off = sig.headerOffset, hl = sig.header.size();
                if (head.size() < off + hl || std::memcmp(head.constData() + off, sig.header.constData(), static_cast<size_t>(hl)) != 0)
                    continue;
                if (sig.validate && !sig.validate(head)) continue;

                const Length L = determineLength(src, abs, total, sig, head);
                const RecoveryResult r = carve(src, abs, L.bytes, L.reliable, sig, head,
                                               config.sourcePath, config.destPath, index);
                if (r.status != RecoveryStatus::Unrecoverable) {
                    results.append(r);
                    emit fileFound(r);
                    ++index;
                    // Skip the body of a file whose extent is proven so nested content isn't re-carved.
                    if (L.reliable) skipUntil = abs + ((r.recoveredBytes + sector - 1) / sector) * sector;
                }
                break; // one file per sector
            }
        }

        emit progress(static_cast<int>(((pos + buf.size()) * 100) / total),
                      QString("Raw scan: %1 of %2 MB, %3 file(s) found")
                          .arg((pos + buf.size()) / (1024 * 1024)).arg(total / (1024 * 1024)).arg(results.size()));
    }

    QString note;
    if (src.badBytes() > 0)
        note = QString(" %1 KB of unreadable (damaged) sectors were skipped.").arg(src.badBytes() / 1024);

    if (destinationFull)
        finishScan(false, QString("Stopped: the destination ran out of space after %1 file(s).").arg(results.size()) + note, results);
    else if (cancelled)
        finishScan(false, QString("Raw scan cancelled after %1 file(s).").arg(results.size()) + note, results);
    else
        finishScan(true, QString("Raw scan complete. %1 file(s) recovered.").arg(results.size()) + note, results);
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

// ===========================================================================
// ForensicWorker
// ===========================================================================
ForensicWorker::ForensicWorker(const ForensicConfig &cfg, ForensicEngine *eng, QObject *parent)
    : QThread(parent), config(cfg), engine(eng) {}

void ForensicWorker::run()
{
    if (config.mode == ForensicConfig::ScanMode::LogicalPath)
        engine->runLogicalScan(config);
    else
        engine->runRawScan(config);
}
