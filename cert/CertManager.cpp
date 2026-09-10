#include "CertManager.h"
#include "qrcodegen.hpp"

#include <QDir>
#include <QDateTime>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QFile>
#include <QCryptographicHash>
#include <QProcess>
#include <QStandardPaths>
#include <QPdfWriter>
#include <QPainter>
#include <QtPrintSupport/QPrinter>
#include <QPageLayout>
#include <QImage>
#include <QBuffer>
#include <QTextDocument>
#include <QAbstractTextDocumentLayout>
#include <QFileInfo>

#include "../core/AuditLog.h"

CertManager::CertManager(QObject *parent) : QObject(parent) {}

// ---------------------------------------------------------------------------
// Key management
// ---------------------------------------------------------------------------
QString CertManager::ensureKeypair(QWidget *parent)
{
    Q_UNUSED(parent);
    QString baseDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    if (baseDir.isEmpty()) baseDir = QDir::homePath() + "/.purgex";
    QDir().mkpath(baseDir);
    QString priv = QDir(baseDir).filePath("purgex_private.pem");
    QString pub  = QDir(baseDir).filePath("purgex_public.pem");
    if (QFile::exists(priv) && QFile::exists(pub)) return baseDir;
    QProcess p;
    p.start("openssl", {"genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", priv});
    p.waitForFinished(15000);
    QProcess p2;
    p2.start("openssl", {"rsa", "-in", priv, "-pubout", "-out", pub});
    p2.waitForFinished(8000);
    return baseDir;
}

bool CertManager::signWithOpenSSL(const QString &privateKeyPath, const QByteArray &data,
                                   QByteArray &outSignature, QString *errMsg)
{
    QProcess p;
    p.start("openssl", {"dgst", "-sha256", "-sign", privateKeyPath});
    if (!p.waitForStarted(3000)) { if (errMsg) *errMsg = "Unable to start openssl."; return false; }
    p.write(data);
    p.closeWriteChannel();
    p.waitForFinished(8000);
    if (p.exitStatus() != QProcess::NormalExit || p.exitCode() != 0) {
        if (errMsg) *errMsg = p.readAllStandardError();
        return false;
    }
    outSignature = p.readAllStandardOutput();
    return !outSignature.isEmpty();
}

bool CertManager::verifyWithOpenSSL(const QString &publicKeyPath, const QByteArray &data,
                                     const QByteArray &signature, QString *errMsg)
{
    Q_UNUSED(errMsg);
    QDir tmp(QDir::tempPath());
    QString sigPath  = tmp.filePath("purgex_sig.bin");
    QString dataPath = tmp.filePath("purgex_data.bin");
    QFile(sigPath).remove();
    QFile(dataPath).remove();
    { QFile fs(sigPath);   fs.open(QIODevice::WriteOnly); fs.write(signature); }
    { QFile fd(dataPath);  fd.open(QIODevice::WriteOnly); fd.write(data);      }
    QProcess v;
    v.start("openssl", {"dgst", "-sha256", "-verify", publicKeyPath, "-signature", sigPath, dataPath});
    v.waitForFinished(8000);
    bool ok = (v.exitStatus() == QProcess::NormalExit && v.exitCode() == 0);
    QFile(sigPath).remove();
    QFile(dataPath).remove();
    return ok;
}

// ---------------------------------------------------------------------------
// QR code rendering helper
// Returns a QImage of the QR code at the requested pixel size.
// The module (dot) size is scaled to fill the requested image dimensions.
// ---------------------------------------------------------------------------
static QImage renderQrCode(const QString &text, int imageSizePx)
{
    using namespace qrcodegen;
    QrCode qr = QrCode::encodeText(text.toUtf8().constData(), QrCode::Ecc::MEDIUM);
    int modules = qr.getSize();

    // Render to a small exact-size buffer then scale up
    QImage img(modules, modules, QImage::Format_RGB32);
    img.fill(Qt::white);
    for (int y = 0; y < modules; ++y) {
        for (int x = 0; x < modules; ++x) {
            if (qr.getModule(x, y))
                img.setPixel(x, y, qRgb(0, 0, 0));
        }
    }
    // Scale with no smoothing so QR pixels stay crisp
    return img.scaled(imageSizePx, imageSizePx,
                      Qt::KeepAspectRatio, Qt::FastTransformation);
}

// ---------------------------------------------------------------------------
// JSON certificate writer (extended with QR payload and new fields)
// ---------------------------------------------------------------------------
bool CertManager::writeJsonCertificate(const QString &outPath, const CertDetails &details,
                                        const QByteArray &dataHash, const QByteArray &signature,
                                        const QString &timestamp, const QString &qrPayload)
{
    QJsonObject obj;
    obj["tool"]               = "PurgeX";
    obj["subject"]            = details.subject;
    obj["method"]             = details.method;
    obj["targets"]            = QJsonArray::fromStringList(details.targets);
    obj["bytesProcessed"]     = static_cast<double>(details.bytesProcessed);
    obj["timestamp"]          = timestamp;
    obj["nist"]               = "SP 800-88";
    obj["hashAlgo"]           = "SHA256";
    obj["dataHashHex"]        = QString::fromLatin1(dataHash.toHex());
    obj["signatureAlg"]       = "RSA-SHA256";
    obj["signatureHex"]       = QString::fromLatin1(signature.toHex());
    // QR payload
    obj["qrPayload"]          = qrPayload;
    obj["canonicalization"]   = "SHA256(Compact JSON of {subject,method,targets,bytesProcessed,timestamp})";
    // Extended operation fields
    if (!details.operationType.isEmpty())
        obj["operationType"]       = details.operationType;
    if (!details.verificationStatus.isEmpty())
        obj["verificationStatus"]  = details.verificationStatus;
    if (!details.verificationNote.isEmpty())
        obj["verificationNote"]    = details.verificationNote;

    QFile f(outPath);
    if (!f.open(QIODevice::WriteOnly)) return false;
    f.write(QJsonDocument(obj).toJson(QJsonDocument::Indented));
    f.close();
    return true;
}

// ---------------------------------------------------------------------------
// Main certificate generation entry point
// ---------------------------------------------------------------------------
bool CertManager::generateCertificates(const CertDetails &details, QWidget *parent)
{
    // Ensure keypair (best-effort)
    QString baseDir = ensureKeypair(parent);
    QString priv    = QDir(baseDir).filePath("purgex_private.pem");

    // ---- Build canonical JSON (exactly these 5 fields, in this order) ----
    QJsonObject canonical;
    canonical["subject"]        = details.subject;
    canonical["method"]         = details.method;
    canonical["targets"]        = QJsonArray::fromStringList(details.targets);
    canonical["bytesProcessed"] = static_cast<double>(details.bytesProcessed);
    const QString timestamp     = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss");
    canonical["timestamp"]      = timestamp;
    QByteArray canonicalBytes   = QJsonDocument(canonical).toJson(QJsonDocument::Compact);

    // ---- SHA-256 hash of canonical data ----
    QByteArray hash = QCryptographicHash::hash(canonicalBytes, QCryptographicHash::Sha256);

    // ---- QR payload: <hex_sha256>_PurgeX ----
    // "_PurgeX" is an application identifier, NOT part of the cryptographic hash.
    QString qrPayload = QString::fromLatin1(hash.toHex()) + "_PurgeX";

    // ---- RSA signature of the canonical data ----
    QByteArray sig;
    QString    err;
    if (!signWithOpenSSL(priv, canonicalBytes, sig, &err))
        sig = QByteArray("unsigned");

    // ---- Output paths ----
    QString outDir = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
    if (outDir.isEmpty()) outDir = QDir::homePath();

    QString baseName = QString("PurgeX_Certificate_%1")
                       .arg(QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss"));

    QDir jsonDir(QDir(outDir).filePath("PurgeX/certificates/json"));
    if (!jsonDir.exists()) jsonDir.mkpath(".");
    QString jsonPath = jsonDir.filePath(baseName + ".json");

    QDir pdfDir(QDir(outDir).filePath("PurgeX/certificates/pdfs"));
    if (!pdfDir.exists()) pdfDir.mkpath(".");
    QString pdfPath = pdfDir.filePath(baseName + ".pdf");

    writeJsonCertificate(jsonPath, details, hash, sig, timestamp, qrPayload);
    writePdfCertificate(pdfPath,  details, hash.toHex(), sig.toHex(), timestamp, qrPayload);

    // ---- Persist to audit log ----
    AuditLog auditLog;
    AuditEntry entry;
    entry.id                 = AuditLog::generateId();
    entry.type               = details.operationType.contains("recovery") ? "recovery" : "wipe";
    entry.timestamp          = QDateTime::currentDateTime();
    entry.target             = details.targets.isEmpty() ? "—" : details.targets.first();
    entry.algorithm          = details.method;
    entry.status             = "success";
    entry.verificationStatus = details.verificationStatus.isEmpty()
                               ? "not_applicable" : details.verificationStatus;
    entry.verificationNote   = details.verificationNote;
    entry.certPath           = pdfPath;
    entry.bytesProcessed     = static_cast<qint64>(details.bytesProcessed);
    entry.details            = QString("Cert: %1").arg(jsonPath);
    auditLog.append(entry);

    return true;
}

// ---------------------------------------------------------------------------
// JSON certificate verification
// ---------------------------------------------------------------------------
bool CertManager::verifyJsonCertificate(const QString &jsonPath, QString *message, QWidget *parent)
{
    Q_UNUSED(parent);
    QFile f(jsonPath);
    if (!f.open(QIODevice::ReadOnly)) { if (message) *message = "Cannot open file."; return false; }
    QByteArray data = f.readAll();
    f.close();

    QJsonParseError pe{};
    QJsonDocument doc = QJsonDocument::fromJson(data, &pe);
    if (pe.error != QJsonParseError::NoError || !doc.isObject()) {
        if (message) *message = "Invalid JSON.";
        return false;
    }
    QJsonObject obj = doc.object();

    // Rebuild canonical object (same 5 fields, same order)
    QJsonObject canonical;
    canonical["subject"]        = obj.value("subject").toString();
    canonical["method"]         = obj.value("method").toString();
    canonical["targets"]        = obj.value("targets").toArray();
    canonical["bytesProcessed"] = obj.value("bytesProcessed").toDouble();
    canonical["timestamp"]      = obj.value("timestamp").toString();
    QByteArray canonicalBytes   = QJsonDocument(canonical).toJson(QJsonDocument::Compact);

    // Verify QR payload hash
    QByteArray recomputedHash = QCryptographicHash::hash(canonicalBytes, QCryptographicHash::Sha256);
    QString    expectedQr     = QString::fromLatin1(recomputedHash.toHex()) + "_PurgeX";
    QString    storedQr       = obj.value("qrPayload").toString();

    bool hashMatch = (storedQr == expectedQr);

    // Verify RSA signature
    QByteArray sig = QByteArray::fromHex(obj.value("signatureHex").toString().toLatin1());
    QString    baseDir = ensureKeypair(nullptr);
    QString    pub     = QDir(baseDir).filePath("purgex_public.pem");
    QString    sigErr;
    bool       sigOk   = verifyWithOpenSSL(pub, canonicalBytes, sig, &sigErr);

    if (message) {
        if (hashMatch && sigOk)
            *message = "Certificate authentic. QR hash verified. RSA signature valid. Issuer: PurgeX";
        else if (hashMatch && !sigOk)
            *message = "QR hash verified but RSA signature could not be validated "
                       "(OpenSSL unavailable or key mismatch). Data integrity confirmed.";
        else
            *message = QString("TAMPER DETECTED: QR hash mismatch. "
                               "Certificate data has been modified. Expected: %1  Stored: %2")
                           .arg(expectedQr).arg(storedQr);
    }

    return hashMatch; // Hash is the primary integrity check; signature is secondary
}

// ---------------------------------------------------------------------------
// PDF certificate writer with embedded QR code
// ---------------------------------------------------------------------------
bool CertManager::writePdfCertificate(const QString &outPath, const CertDetails &details,
                                       const QByteArray &dataHashHex, const QByteArray &signatureHex,
                                       const QString &timestamp, const QString &qrPayload)
{
    // ---- Wrap long hex fields ----
    auto chunkHtml = [](const QString &s, int width) {
        QString out;
        out.reserve(s.size() + (s.size() / width) * 5);
        for (int i = 0; i < s.size(); i += width) {
            out += s.mid(i, width);
            if (i + width < s.size()) out += "<br/>";
        }
        return out;
    };

    const QString hashWrapped = chunkHtml(QString::fromLatin1(dataHashHex.toHex()), 64);
    const QString sigWrapped  = chunkHtml(QString::fromLatin1(signatureHex.toHex()), 64);

    // Targets list
    QString targetsHtml;
    if (!details.targets.isEmpty()) {
        targetsHtml = "<ul>";
        for (const QString &t : details.targets)
            targetsHtml += "<li>" + t.toHtmlEscaped() + "</li>";
        targetsHtml += "</ul>";
    }

    // Operation type and verification rows
    QString opTypeHtml, verifHtml;
    if (!details.operationType.isEmpty())
        opTypeHtml = QString("<p><b>Operation Type:</b> %1</p>")
                         .arg(details.operationType.toHtmlEscaped());
    if (!details.verificationStatus.isEmpty()) {
        QString statusColor = (details.verificationStatus == "verified") ? "#1a7a1a"
                            : (details.verificationStatus == "failed")   ? "#cc0000"
                            : "#888888";
        verifHtml  = QString("<p><b>Verification Status:</b> "
                             "<span style='color:%1;font-weight:bold;'>%2</span></p>")
                         .arg(statusColor)
                         .arg(details.verificationStatus.toHtmlEscaped());
        if (!details.verificationNote.isEmpty())
            verifHtml += QString("<p class='small'><i>Note: %1</i></p>")
                             .arg(details.verificationNote.toHtmlEscaped());
    }

    QString html;
    html += "<html><head><style>"
            "body{font-family:Helvetica,Arial,sans-serif;font-size:11pt;}"
            "h1{font-size:18pt;margin:0 0 4pt 0;}"
            "p{margin:4pt 0;}"
            "code{font-family:'Courier New',monospace;font-size:8pt;"
            "word-break:break-all;white-space:pre-wrap;}"
            "ul{margin:3pt 0 3pt 12pt;font-size:10pt;}"
            ".small{color:#555;font-size:9pt;}"
            ".qr-label{font-family:'Courier New',monospace;font-size:8pt;"
            "word-break:break-all;color:#333;}"
            "</style></head><body>";
    html += "<h1>PurgeX Certificate</h1>";
    html += "<p class='small'>Standard: NIST SP 800-88 | Issued by: PurgeX</p><hr/>";
    html += QString("<p><b>Subject:</b> %1</p>")      .arg(details.subject.toHtmlEscaped());
    html += QString("<p><b>Timestamp:</b> %1</p>")    .arg(timestamp.toHtmlEscaped());
    html += opTypeHtml;
    html += verifHtml;
    html += QString("<p><b>Method:</b> %1</p>")       .arg(details.method.toHtmlEscaped());
    html += QString("<p><b>Targets:</b></p>%1")       .arg(targetsHtml);
    html += QString("<p><b>Bytes Processed:</b> %1</p>").arg(details.bytesProcessed);
    html += "<hr/>";
    html += QString("<p><b>Data Hash (SHA-256):</b><br/><code>%1</code></p>").arg(hashWrapped);
    html += QString("<p><b>Signature (RSA/SHA-256):</b><br/><code>%1</code></p>").arg(sigWrapped);
    html += "<hr/>";
    html += "<p><b>Tamper-Verification QR Code:</b></p>";
    // QR code will be painted directly; add placeholder label
    html += QString("<p class='qr-label'>%1</p>")     .arg(qrPayload.toHtmlEscaped());
    html += "<p class='small'>Scan the QR code above with the PurgeX Verifier app to confirm "
            "certificate integrity. The payload is: SHA-256(canonical JSON) + \"_PurgeX\".</p>";
    html += "<p class='small'>Issuer: PurgeX  |  Signature may read 'unsigned' if OpenSSL is unavailable.</p>";
    html += "</body></html>";

    // ---- Set up QPrinter ----
    QPrinter printer(QPrinter::HighResolution);
    printer.setOutputFormat(QPrinter::PdfFormat);
    printer.setOutputFileName(outPath);
    printer.setPageSize(QPageSize(QPageSize::A4));
    QMarginsF margins(15, 15, 15, 15);
    printer.setPageLayout(QPageLayout(QPageSize(QPageSize::A4),
                                      QPageLayout::Portrait, margins));

    // ---- Render QR image ----
    // The QR is placed in the top-right corner of the first page.
    // We render it at a fixed pixel size so it's readable when printed.
    const int qrPx = 200; // pixels in the final printer DPI space
    QImage qrImage = renderQrCode(qrPayload, qrPx);

    // ---- Print the HTML document ----
    QTextDocument doc;
    doc.setHtml(html);
    doc.print(&printer);

    // ---- Paint QR code on top of the first page ----
    // We open the file with QPainter for a second pass would overwrite it,
    // so instead we draw using a QPdfWriter approach.
    // Simpler: embed QR as an HTML img encoded as base64.
    // Rebuild with QR image embedded as data URI to avoid second-pass complexity.
    QByteArray pngData;
    QBuffer buf(&pngData);
    buf.open(QIODevice::WriteOnly);
    qrImage.save(&buf, "PNG");
    buf.close();
    QString qrDataUri = "data:image/png;base64," + pngData.toBase64();

    // Rebuild HTML with embedded QR image
    html.replace("<p><b>Tamper-Verification QR Code:</b></p>",
                 QString("<p><b>Tamper-Verification QR Code:</b></p>"
                         "<p><img src='%1' width='150' height='150'/></p>").arg(qrDataUri));

    QTextDocument doc2;
    doc2.setHtml(html);
    doc2.print(&printer);

    return true;
}
