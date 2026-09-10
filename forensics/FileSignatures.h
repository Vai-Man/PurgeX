#ifndef PURGEX_FILESIGNATURES_H
#define PURGEX_FILESIGNATURES_H

#include <QString>
#include <QByteArray>
#include <QList>

// ---------------------------------------------------------------------------
// FileSignature — describes a recognisable file type by its binary signature
// ---------------------------------------------------------------------------
struct FileSignature {
    QString name;           // Human-readable name, e.g. "JPEG Image"
    QString extension;      // e.g. "jpg"
    QString category;       // e.g. "Image", "Document", "Archive", "Media"
    QByteArray header;      // Mandatory leading bytes (magic number)
    QByteArray footer;      // Optional trailing bytes (empty = no footer check)
    int      headerOffset;  // Byte offset where the header appears (usually 0)
    qint64   maxSize;       // Reasonable max file size in bytes (safety limit)
};

// ---------------------------------------------------------------------------
// Global signature registry — add new entries here to extend coverage.
// The list is ordered by priority; first match wins during scanning.
// ---------------------------------------------------------------------------
inline QList<FileSignature> builtinSignatures()
{
    QList<FileSignature> sigs;

    // --- Images ---
    sigs.append({ "JPEG Image",       "jpg",  "Image",
                  QByteArray("\xFF\xD8\xFF", 3),
                  QByteArray("\xFF\xD9",     2),
                  0,  50 * 1024 * 1024 });

    sigs.append({ "PNG Image",        "png",  "Image",
                  QByteArray("\x89PNG\r\n\x1A\n", 8),
                  QByteArray("IEND\xAE\x42\x60\x82", 8),
                  0,  100 * 1024 * 1024 });

    sigs.append({ "GIF Image",        "gif",  "Image",
                  QByteArray("GIF8", 4),
                  QByteArray("\x00\x3B", 2),
                  0,  20 * 1024 * 1024 });

    sigs.append({ "BMP Image",        "bmp",  "Image",
                  QByteArray("BM", 2),
                  QByteArray(),
                  0,  200 * 1024 * 1024 });

    sigs.append({ "WebP Image",       "webp", "Image",
                  QByteArray("RIFF", 4),
                  QByteArray(),
                  0,  50 * 1024 * 1024 });

    // --- Documents ---
    sigs.append({ "PDF Document",     "pdf",  "Document",
                  QByteArray("%PDF", 4),
                  QByteArray("%%EOF", 5),
                  0,  500 * 1024 * 1024 });

    // DOCX/XLSX/PPTX are all ZIP containers
    sigs.append({ "Office Open XML",  "docx", "Document",
                  QByteArray("PK\x03\x04", 4),
                  QByteArray("PK\x05\x06", 4),
                  0,  200 * 1024 * 1024 });

    // Legacy DOC — OLE2 compound document
    sigs.append({ "Word Document",    "doc",  "Document",
                  QByteArray("\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", 8),
                  QByteArray(),
                  0,  200 * 1024 * 1024 });

    // --- Archives ---
    sigs.append({ "ZIP Archive",      "zip",  "Archive",
                  QByteArray("PK\x03\x04", 4),
                  QByteArray("PK\x05\x06", 4),
                  0,  4LL * 1024 * 1024 * 1024 });

    sigs.append({ "RAR Archive",      "rar",  "Archive",
                  QByteArray("Rar!\x1A\x07", 6),
                  QByteArray(),
                  0,  4LL * 1024 * 1024 * 1024 });

    sigs.append({ "7-Zip Archive",    "7z",   "Archive",
                  QByteArray("7z\xBC\xAF\x27\x1C", 6),
                  QByteArray(),
                  0,  4LL * 1024 * 1024 * 1024 });

    sigs.append({ "GZip Archive",     "gz",   "Archive",
                  QByteArray("\x1F\x8B", 2),
                  QByteArray(),
                  0,  2LL * 1024 * 1024 * 1024 });

    // --- Media ---
    sigs.append({ "MP4 Video",        "mp4",  "Media",
                  QByteArray("ftyp", 4),
                  QByteArray(),
                  4,  4LL * 1024 * 1024 * 1024 });

    sigs.append({ "AVI Video",        "avi",  "Media",
                  QByteArray("RIFF", 4),
                  QByteArray(),
                  0,  4LL * 1024 * 1024 * 1024 });

    sigs.append({ "MP3 Audio",        "mp3",  "Media",
                  QByteArray("\xFF\xFB", 2),
                  QByteArray(),
                  0,  300 * 1024 * 1024 });

    sigs.append({ "WAV Audio",        "wav",  "Media",
                  QByteArray("RIFF", 4),
                  QByteArray(),
                  0,  2LL * 1024 * 1024 * 1024 });

    sigs.append({ "FLAC Audio",       "flac", "Media",
                  QByteArray("fLaC", 4),
                  QByteArray(),
                  0,  500 * 1024 * 1024 });

    // --- Database ---
    sigs.append({ "SQLite Database",  "db",   "Database",
                  QByteArray("SQLite format 3\x00", 16),
                  QByteArray(),
                  0,  2LL * 1024 * 1024 * 1024 });

    // --- Executables (detect only, not recovered by default) ---
    sigs.append({ "Windows PE",       "exe",  "Executable",
                  QByteArray("MZ", 2),
                  QByteArray(),
                  0,  500 * 1024 * 1024 });

    // --- Text / Scripts ---
    sigs.append({ "XML Document",     "xml",  "Text",
                  QByteArray("<?xml", 5),
                  QByteArray(),
                  0,  100 * 1024 * 1024 });

    return sigs;
}

#endif // PURGEX_FILESIGNATURES_H
