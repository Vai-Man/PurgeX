#ifndef PURGEX_FILESIGNATURES_H
#define PURGEX_FILESIGNATURES_H

#include <QString>
#include <QByteArray>
#include <QList>
#include <cstdint>

// ---------------------------------------------------------------------------
// How the end of a carved file is determined
// ---------------------------------------------------------------------------
enum class LengthRule {
    Footer,    // search for the footer marker (optionally followed by `footerTrailing` bytes)
    Jpeg,      // walk JPEG segments to the real EOI marker (ignores embedded thumbnails)
    Png,       // walk PNG chunks to IEND
    Gif,       // walk GIF blocks to the trailer
    Zip,       // locate an end-of-central-directory record consistent with the start offset
    Riff,      // size field in the RIFF header
    Bmp,       // size field in the BMP header
    Mp4,       // walk top-level ISO-BMFF boxes
    SevenZip,  // start-header fields
    Sqlite,    // page size * page count
    PE,        // section table
    None       // no way to know: carve up to maxSize and flag the result as unreliable
};

// ---------------------------------------------------------------------------
// FileSignature — describes a recognisable file type by its binary signature
// ---------------------------------------------------------------------------
struct FileSignature {
    QString name;           // Human-readable name, e.g. "JPEG Image"
    QString extension;      // e.g. "jpg"
    QString category;       // "Image", "Document", "Archive", "Media", "Database", "Executable", "Text"
    QByteArray header;      // Mandatory leading bytes (magic number)
    QByteArray footer;      // Optional trailing marker (Footer rule)
    int      headerOffset;  // Byte offset where the header appears (usually 0)
    qint64   maxSize;       // Safety cap on carved size in bytes
    int      footerTrailing = 0;                       // Bytes after the footer marker that belong to the file
    LengthRule rule = LengthRule::Footer;
    // Optional structural check on the first 16 KB of the candidate. Rejects false positives
    // and lets several signatures share one magic number (ZIP vs Office, RIFF flavours).
    bool (*validate)(const QByteArray &head) = nullptr;
    // Optional: pick the extension from the content (docx / xlsx / pptx).
    QString (*refineExtension)(const QByteArray &head) = nullptr;
};

namespace sigutil {

inline quint32 le32(const QByteArray &b, int off)
{
    if (off < 0 || off + 4 > b.size()) return 0;
    const auto *p = reinterpret_cast<const uint8_t *>(b.constData()) + off;
    return quint32(p[0]) | (quint32(p[1]) << 8) | (quint32(p[2]) << 16) | (quint32(p[3]) << 24);
}
inline quint64 le64(const QByteArray &b, int off)
{
    return quint64(le32(b, off)) | (quint64(le32(b, off + 4)) << 32);
}
inline quint32 le16(const QByteArray &b, int off)
{
    if (off < 0 || off + 2 > b.size()) return 0;
    const auto *p = reinterpret_cast<const uint8_t *>(b.constData()) + off;
    return quint32(p[0]) | (quint32(p[1]) << 8);
}
inline quint32 be32(const QByteArray &b, int off)
{
    if (off < 0 || off + 4 > b.size()) return 0;
    const auto *p = reinterpret_cast<const uint8_t *>(b.constData()) + off;
    return (quint32(p[0]) << 24) | (quint32(p[1]) << 16) | (quint32(p[2]) << 8) | quint32(p[3]);
}
inline quint32 be16(const QByteArray &b, int off)
{
    if (off < 0 || off + 2 > b.size()) return 0;
    const auto *p = reinterpret_cast<const uint8_t *>(b.constData()) + off;
    return (quint32(p[0]) << 8) | quint32(p[1]);
}

inline QString officeKind(const QByteArray &head)
{
    if (head.contains("word/")) return "docx";
    if (head.contains("xl/"))   return "xlsx";
    if (head.contains("ppt/"))  return "pptx";
    return QString();
}

inline bool isOffice(const QByteArray &head)    { return !officeKind(head).isEmpty(); }
inline bool isPlainZip(const QByteArray &head)  { return !isOffice(head); }
inline QString officeExtension(const QByteArray &head) { return officeKind(head); }

inline bool isJpeg(const QByteArray &head)
{
    return head.size() > 4 && static_cast<uint8_t>(head[3]) >= 0xC0;
}
inline bool isGif(const QByteArray &head)
{
    return head.size() > 6 && (head[4] == '7' || head[4] == '9') && head[5] == 'a';
}
inline bool isBmp(const QByteArray &head)
{
    if (head.size() < 30) return false;
    if (le32(head, 6) != 0) return false; // reserved fields are zero
    const quint32 dib = le32(head, 14);
    const bool knownDib = dib == 12 || dib == 40 || dib == 52 || dib == 56 || dib == 64 || dib == 108 || dib == 124;
    return knownDib && le32(head, 2) >= 26 && le32(head, 10) >= 26 && le32(head, 10) < le32(head, 2);
}
inline bool isWebp(const QByteArray &head) { return head.size() > 12 && head.mid(8, 4) == "WEBP"; }
inline bool isAvi(const QByteArray &head)  { return head.size() > 12 && head.mid(8, 4) == "AVI "; }
inline bool isWave(const QByteArray &head) { return head.size() > 12 && head.mid(8, 4) == "WAVE"; }
inline bool isMp4(const QByteArray &head)
{
    if (head.size() < 16) return false;
    const quint32 boxSize = be32(head, 0);
    if (boxSize < 8 || boxSize > 512) return false;           // ftyp box is small
    for (int i = 8; i < 12; ++i) {                              // brand is printable ASCII
        const char c = head[i];
        if (c < 0x20 || c > 0x7E) return false;
    }
    return true;
}
inline bool isSqlite(const QByteArray &head)
{
    const quint32 ps = be16(head, 16);
    return head.size() > 100 && (ps == 1 || (ps >= 512 && ps <= 32768 && (ps & (ps - 1)) == 0));
}
inline bool isPE(const QByteArray &head)
{
    if (head.size() < 0x40) return false;
    const quint32 e = le32(head, 0x3C);
    return e >= 0x40 && e <= 4096 && int(e) + 4 <= head.size() && head.mid(int(e), 4) == QByteArray("PE\0\0", 4);
}
inline bool isId3(const QByteArray &head)
{
    return head.size() > 10 && head[3] >= 2 && head[3] <= 4 && head[4] == 0 &&
           !(head[6] & 0x80) && !(head[7] & 0x80) && !(head[8] & 0x80) && !(head[9] & 0x80);
}
inline bool isGzip(const QByteArray &head)
{   // reserved flag bits clear, plausible XFL and OS bytes
    return head.size() > 10 && (static_cast<uint8_t>(head[3]) & 0xE0) == 0 &&
           (head[8] == 0 || head[8] == 2 || head[8] == 4) &&
           (static_cast<uint8_t>(head[9]) <= 13 || static_cast<uint8_t>(head[9]) == 255);
}
inline bool isRar(const QByteArray &head)   { return head.size() > 8 && (head[6] == 0 || head[6] == 1); }
inline bool isFlac(const QByteArray &head)
{   // the first metadata block must be STREAMINFO (type 0, length 34)
    return head.size() > 8 && (static_cast<uint8_t>(head[4]) & 0x7F) == 0 &&
           head[5] == 0 && head[6] == 0 && head[7] == 0x22;
}
inline bool isXml(const QByteArray &head)   { return head.size() > 6 && (head[5] == ' ' || head[5] == '\n' || head[5] == '\r'); }
inline bool isOle(const QByteArray &head)
{   // byte-order mark of a compound document
    return head.size() > 30 && static_cast<uint8_t>(head[28]) == 0xFE && static_cast<uint8_t>(head[29]) == 0xFF;
}

} // namespace sigutil

// ---------------------------------------------------------------------------
// Global signature registry — add new entries here to extend coverage.
// For a given offset the first matching entry (header + validate) wins.
// ---------------------------------------------------------------------------
inline QList<FileSignature> builtinSignatures()
{
    using namespace sigutil;
    constexpr qint64 MB = 1024 * 1024;
    constexpr qint64 GB = 1024 * MB;

    QList<FileSignature> sigs;

    // --- Images ---
    sigs.append({ "JPEG Image", "jpg", "Image",
                  QByteArray("\xFF\xD8\xFF", 3), QByteArray("\xFF\xD9", 2), 0, 64 * MB,
                  0, LengthRule::Jpeg, &isJpeg, nullptr });

    sigs.append({ "PNG Image", "png", "Image",
                  QByteArray("\x89PNG\r\n\x1A\n", 8), QByteArray("IEND\xAE\x42\x60\x82", 8), 0, 128 * MB,
                  0, LengthRule::Png, nullptr, nullptr });

    sigs.append({ "GIF Image", "gif", "Image",
                  QByteArray("GIF8", 4), QByteArray("\x00\x3B", 2), 0, 64 * MB,
                  0, LengthRule::Gif, &isGif, nullptr });

    sigs.append({ "BMP Image", "bmp", "Image",
                  QByteArray("BM", 2), QByteArray(), 0, 256 * MB,
                  0, LengthRule::Bmp, &isBmp, nullptr });

    sigs.append({ "WebP Image", "webp", "Image",
                  QByteArray("RIFF", 4), QByteArray(), 0, 128 * MB,
                  0, LengthRule::Riff, &isWebp, nullptr });

    // --- Documents ---
    sigs.append({ "PDF Document", "pdf", "Document",
                  QByteArray("%PDF-", 5), QByteArray("%%EOF", 5), 0, 512 * MB,
                  0, LengthRule::Footer, nullptr, nullptr });

    // DOCX / XLSX / PPTX are ZIP containers; telling them apart needs a look at the content.
    sigs.append({ "Office Open XML", "docx", "Document",
                  QByteArray("PK\x03\x04", 4), QByteArray("PK\x05\x06", 4), 0, 256 * MB,
                  18, LengthRule::Zip, &isOffice, &officeExtension });

    // Legacy DOC / XLS / PPT - OLE2 compound document; no cheap way to find the end.
    sigs.append({ "Legacy Office Document", "doc", "Document",
                  QByteArray("\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", 8), QByteArray(), 0, 64 * MB,
                  0, LengthRule::None, &isOle, nullptr });

    // --- Archives ---
    sigs.append({ "ZIP Archive", "zip", "Archive",
                  QByteArray("PK\x03\x04", 4), QByteArray("PK\x05\x06", 4), 0, 4 * GB,
                  18, LengthRule::Zip, &isPlainZip, nullptr });

    sigs.append({ "RAR Archive", "rar", "Archive",
                  QByteArray("Rar!\x1A\x07", 6), QByteArray(), 0, 64 * MB,
                  0, LengthRule::None, &isRar, nullptr });

    sigs.append({ "7-Zip Archive", "7z", "Archive",
                  QByteArray("7z\xBC\xAF\x27\x1C", 6), QByteArray(), 0, 4 * GB,
                  0, LengthRule::SevenZip, nullptr, nullptr });

    sigs.append({ "GZip Archive", "gz", "Archive",
                  QByteArray("\x1F\x8B\x08", 3), QByteArray(), 0, 64 * MB,
                  0, LengthRule::None, &isGzip, nullptr });

    // --- Media ---
    sigs.append({ "MP4 Video", "mp4", "Media",
                  QByteArray("ftyp", 4), QByteArray(), 4, 4 * GB,
                  0, LengthRule::Mp4, &isMp4, nullptr });

    sigs.append({ "AVI Video", "avi", "Media",
                  QByteArray("RIFF", 4), QByteArray(), 0, 4 * GB,
                  0, LengthRule::Riff, &isAvi, nullptr });

    sigs.append({ "WAV Audio", "wav", "Media",
                  QByteArray("RIFF", 4), QByteArray(), 0, 2 * GB,
                  0, LengthRule::Riff, &isWave, nullptr });

    sigs.append({ "MP3 Audio (ID3)", "mp3", "Media",
                  QByteArray("ID3", 3), QByteArray(), 0, 20 * MB,
                  0, LengthRule::None, &isId3, nullptr });

    sigs.append({ "FLAC Audio", "flac", "Media",
                  QByteArray("fLaC", 4), QByteArray(), 0, 100 * MB,
                  0, LengthRule::None, &isFlac, nullptr });

    // --- Database ---
    sigs.append({ "SQLite Database", "db", "Database",
                  QByteArray("SQLite format 3\x00", 16), QByteArray(), 0, 2 * GB,
                  0, LengthRule::Sqlite, &isSqlite, nullptr });

    // --- Executables ---
    sigs.append({ "Windows PE", "exe", "Executable",
                  QByteArray("MZ", 2), QByteArray(), 0, 256 * MB,
                  0, LengthRule::PE, &isPE, nullptr });

    // --- Text / Scripts ---
    sigs.append({ "XML Document", "xml", "Text",
                  QByteArray("<?xml", 5), QByteArray(), 0, 4 * MB,
                  0, LengthRule::None, &isXml, nullptr });

    return sigs;
}

#endif // PURGEX_FILESIGNATURES_H
