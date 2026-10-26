#include "CertManager.h"
#include "qrcodegen.hpp"
#include "../core/AppPaths.h"

#include <QDir>
#include <QDateTime>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QFile>
#include <QSaveFile>
#include <QCryptographicHash>
#include <QPrinter>
#include <QPageLayout>
#include <QPageSize>
#include <QPainter>
#include <QImage>
#include <QTextDocument>
#include <QFileInfo>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include <memory>

#ifdef Q_OS_WIN
#include <windows.h>
#include <wincrypt.h>
#endif

namespace {

// ---------------------------------------------------------------------------
// Tiny RAII wrappers around the OpenSSL EVP API (works on OpenSSL 1.1.1 and 3.x)
// ---------------------------------------------------------------------------
struct PkeyFree { void operator()(EVP_PKEY *p) const { EVP_PKEY_free(p); } };
struct BioFree  { void operator()(BIO *b)      const { BIO_free(b); } };
struct CtxFree  { void operator()(EVP_PKEY_CTX *c) const { EVP_PKEY_CTX_free(c); } };
struct MdFree   { void operator()(EVP_MD_CTX *c)   const { EVP_MD_CTX_free(c); } };
using PkeyPtr = std::unique_ptr<EVP_PKEY, PkeyFree>;
using BioPtr  = std::unique_ptr<BIO, BioFree>;
using CtxPtr  = std::unique_ptr<EVP_PKEY_CTX, CtxFree>;
using MdPtr   = std::unique_ptr<EVP_MD_CTX, MdFree>;

QString opensslError()
{
    char buf[256] = {};
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    return QString::fromLatin1(buf);
}

QByteArray bioToBytes(BIO *bio)
{
    char *data = nullptr;
    const long len = BIO_get_mem_data(bio, &data);
    return len > 0 ? QByteArray(data, static_cast<int>(len)) : QByteArray();
}

bool generateRsaKeyPem(QByteArray *privPem, QByteArray *pubPem, QString *err)
{
    CtxPtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
    EVP_PKEY *raw = nullptr;
    if (!ctx || EVP_PKEY_keygen_init(ctx.get()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), 2048) <= 0 ||
        EVP_PKEY_keygen(ctx.get(), &raw) <= 0) {
        if (err) *err = opensslError();
        return false;
    }
    PkeyPtr key(raw);

    BioPtr priv(BIO_new(BIO_s_mem())), pub(BIO_new(BIO_s_mem()));
    if (!PEM_write_bio_PrivateKey(priv.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr) ||
        !PEM_write_bio_PUBKEY(pub.get(), key.get())) {
        if (err) *err = opensslError();
        return false;
    }
    *privPem = bioToBytes(priv.get());
    *pubPem  = bioToBytes(pub.get());
    return !privPem->isEmpty() && !pubPem->isEmpty();
}

bool rsaSign(const QByteArray &privPem, const QByteArray &data, QByteArray *sig, QString *err)
{
    BioPtr bio(BIO_new_mem_buf(privPem.constData(), privPem.size()));
    PkeyPtr key(bio ? PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr) : nullptr);
    MdPtr md(EVP_MD_CTX_new());
    size_t len = 0;
    if (!key || !md ||
        EVP_DigestSignInit(md.get(), nullptr, EVP_sha256(), nullptr, key.get()) <= 0 ||
        EVP_DigestSignUpdate(md.get(), data.constData(), data.size()) <= 0 ||
        EVP_DigestSignFinal(md.get(), nullptr, &len) <= 0) {
        if (err) *err = opensslError();
        return false;
    }
    sig->resize(static_cast<int>(len));
    if (EVP_DigestSignFinal(md.get(), reinterpret_cast<unsigned char *>(sig->data()), &len) <= 0) {
        if (err) *err = opensslError();
        return false;
    }
    sig->resize(static_cast<int>(len));
    return true;
}

bool rsaVerify(const QByteArray &pubPem, const QByteArray &data, const QByteArray &sig)
{
    if (pubPem.isEmpty() || sig.isEmpty()) return false;
    BioPtr bio(BIO_new_mem_buf(pubPem.constData(), pubPem.size()));
    PkeyPtr key(bio ? PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr) : nullptr);
    MdPtr md(EVP_MD_CTX_new());
    if (!key || !md ||
        EVP_DigestVerifyInit(md.get(), nullptr, EVP_sha256(), nullptr, key.get()) <= 0 ||
        EVP_DigestVerifyUpdate(md.get(), data.constData(), data.size()) <= 0)
        return false;
    return EVP_DigestVerifyFinal(md.get(),
                                 reinterpret_cast<const unsigned char *>(sig.constData()),
                                 static_cast<size_t>(sig.size())) == 1;
}

// The private key is encrypted at rest. On Windows it is sealed with DPAPI, so only the same
// Windows user on the same machine can open it; elsewhere it relies on owner-only file mode.
const QByteArray kSealedMagic("PURGEX-DPAPI1\n");

QByteArray sealSecret(const QByteArray &plain)
{
#ifdef Q_OS_WIN
    DATA_BLOB in = { static_cast<DWORD>(plain.size()),
                     reinterpret_cast<BYTE *>(const_cast<char *>(plain.constData())) };
    DATA_BLOB out = {};
    if (!CryptProtectData(&in, L"PurgeX signing key", nullptr, nullptr, nullptr,
                          CRYPTPROTECT_UI_FORBIDDEN, &out))
        return plain;
    const QByteArray sealed = kSealedMagic + QByteArray(reinterpret_cast<char *>(out.pbData), static_cast<int>(out.cbData));
    LocalFree(out.pbData);
    return sealed;
#else
    return plain;
#endif
}

QByteArray unsealSecret(const QByteArray &stored)
{
    if (!stored.startsWith(kSealedMagic)) return stored; // plain PEM (non-Windows or older key file)
#ifdef Q_OS_WIN
    const QByteArray blob = stored.mid(kSealedMagic.size());
    DATA_BLOB in = { static_cast<DWORD>(blob.size()),
                     reinterpret_cast<BYTE *>(const_cast<char *>(blob.constData())) };
    DATA_BLOB out = {};
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out))
        return QByteArray();
    const QByteArray plain(reinterpret_cast<char *>(out.pbData), static_cast<int>(out.cbData));
    SecureZeroMemory(out.pbData, out.cbData);
    LocalFree(out.pbData);
    return plain;
#else
    return QByteArray();
#endif
}

bool writeSecretFile(const QString &path, const QByteArray &content, bool ownerOnly)
{
    QSaveFile f(path);
    if (!f.open(QIODevice::WriteOnly)) return false;
    f.write(content);
    if (ownerOnly) f.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    return f.commit();
}

QByteArray readFile(const QString &path)
{
    QFile f(path);
    return f.open(QIODevice::ReadOnly) ? f.readAll() : QByteArray();
}

// Canonical document that is hashed and signed. See CertDetails in the header.
QJsonObject deviceToJson(const QMap<QString, QString> &device)
{
    QJsonObject o;
    for (auto it = device.constBegin(); it != device.constEnd(); ++it) o[it.key()] = it.value();
    return o;
}

QByteArray readPrivateKey(const QString &path)
{
    const QByteArray stored = readFile(path);
    const QByteArray pem = unsealSecret(stored);
    // Seal keys written by earlier versions the first time they are used.
    if (!pem.isEmpty() && !stored.startsWith(kSealedMagic)) {
        const QByteArray sealed = sealSecret(pem);
        if (sealed != pem) writeSecretFile(path, sealed, true);
    }
    return pem;
}

QByteArray canonicalBytes(const QString &subject, const QString &method, const QJsonArray &targets,
                          double bytesProcessed, const QString &timestamp,
                          const QJsonObject &device = QJsonObject())
{
    QJsonObject canonical;
    if (!device.isEmpty()) canonical["device"] = device;
    canonical["subject"]        = subject;
    canonical["method"]         = method;
    canonical["targets"]        = targets;
    canonical["bytesProcessed"] = bytesProcessed;
    canonical["timestamp"]      = timestamp;
    return QJsonDocument(canonical).toJson(QJsonDocument::Compact);
}

// Unique "<dir>/<base>.<ext>" so two certificates in the same second never collide.
QString uniquePath(const QDir &dir, const QString &base, const QString &ext)
{
    QString path = dir.filePath(base + "." + ext);
    for (int i = 1; QFile::exists(path); ++i)
        path = dir.filePath(QString("%1_%2.%3").arg(base).arg(i).arg(ext));
    return path;
}

// ---------------------------------------------------------------------------
// QR code rendering helper (includes the 4-module quiet zone scanners need)
// ---------------------------------------------------------------------------
QImage renderQrCode(const QString &text, int imageSizePx)
{
    using namespace qrcodegen;
    const QrCode qr = QrCode::encodeText(text.toUtf8().constData(), QrCode::Ecc::MEDIUM);
    const int modules = qr.getSize();
    const int border = 4;
    const int scale = qMax(1, imageSizePx / (modules + 2 * border));
    const int dim = (modules + 2 * border) * scale;

    QImage img(dim, dim, QImage::Format_RGB32);
    img.fill(Qt::white);
    for (int y = 0; y < modules; ++y)
        for (int x = 0; x < modules; ++x)
            if (qr.getModule(x, y))
                for (int dy = 0; dy < scale; ++dy)
                    for (int dx = 0; dx < scale; ++dx)
                        img.setPixel((x + border) * scale + dx, (y + border) * scale + dy, qRgb(0, 0, 0));
    return img;
}

} // namespace

CertManager::CertManager(QObject *parent) : QObject(parent) {}

// ---------------------------------------------------------------------------
// Key management
// ---------------------------------------------------------------------------
QString CertManager::ensureKeypair()
{
    const QString dir = AppPaths::ensureDir(AppPaths::keyDir());
    const QString priv = QDir(dir).filePath("purgex_private.pem");
    const QString pub  = QDir(dir).filePath("purgex_public.pem");
    if (QFile::exists(priv) && QFile::exists(pub)) return dir;

    QByteArray privPem, pubPem;
    QString err;
    if (!generateRsaKeyPem(&privPem, &pubPem, &err) ||
        !writeSecretFile(priv, sealSecret(privPem), true) || !writeSecretFile(pub, pubPem, false)) {
        qWarning("PurgeX: could not create signing key: %s", qPrintable(err));
        return QString();
    }
    return dir;
}

QString CertManager::publicKeyFingerprint(const QByteArray &publicKeyPem)
{
    // Hash the DER body of the PEM (SubjectPublicKeyInfo).
    QByteArray body;
    for (const QByteArray &line : publicKeyPem.split('\n')) {
        const QByteArray t = line.trimmed();
        if (!t.isEmpty() && !t.startsWith("-----")) body += t;
    }
    const QByteArray der = QByteArray::fromBase64(body);
    if (der.isEmpty()) return QString();
    return QString::fromLatin1(QCryptographicHash::hash(der, QCryptographicHash::Sha256).toHex());
}

// ---------------------------------------------------------------------------
// JSON certificate writer
// ---------------------------------------------------------------------------
bool CertManager::writeJsonCertificate(const QString &outPath, const CertDetails &details,
                                       const QByteArray &dataHash, const QByteArray &signature,
                                       const QString &timestamp, const QString &qrPayload,
                                       const QByteArray &publicKeyPem)
{
    QJsonObject obj;
    obj["tool"]             = "PurgeX";
    obj["subject"]          = details.subject;
    obj["method"]           = details.method;
    obj["targets"]          = QJsonArray::fromStringList(details.targets);
    obj["bytesProcessed"]   = static_cast<double>(details.bytesProcessed);
    obj["timestamp"]        = timestamp;
    if (!details.device.isEmpty()) obj["device"] = deviceToJson(details.device);
    obj["nist"]             = "SP 800-88";
    obj["hashAlgo"]         = "SHA256";
    obj["dataHashHex"]      = QString::fromLatin1(dataHash.toHex());
    obj["signatureAlg"]     = "RSA-SHA256";
    obj["signatureHex"]     = QString::fromLatin1(signature.toHex());
    obj["publicKeyPem"]     = QString::fromLatin1(publicKeyPem);
    obj["publicKeyFingerprint"] = publicKeyFingerprint(publicKeyPem);
    obj["qrPayload"]        = qrPayload;
    obj["canonicalization"] = "SHA256(compact JSON of {bytesProcessed,method,subject,targets,timestamp}, keys sorted)";
    if (!details.operationType.isEmpty())
        obj["operationType"] = details.operationType;
    if (!details.verificationStatus.isEmpty())
        obj["verificationStatus"] = details.verificationStatus;
    if (!details.verificationNote.isEmpty())
        obj["verificationNote"] = details.verificationNote;

    QSaveFile f(outPath);
    if (!f.open(QIODevice::WriteOnly)) return false;
    f.write(QJsonDocument(obj).toJson(QJsonDocument::Indented));
    return f.commit();
}

// ---------------------------------------------------------------------------
// Main certificate generation entry point
// ---------------------------------------------------------------------------
bool CertManager::generateCertificates(const CertDetails &details, QWidget *parent,
                                       QString *pdfPathOut, QString *jsonPathOut)
{
    Q_UNUSED(parent);

    const QString keyDir = ensureKeypair();
    const QByteArray privPem = keyDir.isEmpty() ? QByteArray() : readPrivateKey(QDir(keyDir).filePath("purgex_private.pem"));
    const QByteArray pubPem  = keyDir.isEmpty() ? QByteArray() : readFile(QDir(keyDir).filePath("purgex_public.pem"));

    const QString timestamp = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss");
    const QByteArray canonical = canonicalBytes(details.subject, details.method,
                                                QJsonArray::fromStringList(details.targets),
                                                static_cast<double>(details.bytesProcessed), timestamp,
                                                deviceToJson(details.device));

    const QByteArray hash = QCryptographicHash::hash(canonical, QCryptographicHash::Sha256);
    // "_PurgeX" is an application identifier, NOT part of the cryptographic hash.
    const QString qrPayload = QString::fromLatin1(hash.toHex()) + "_PurgeX";

    QByteArray sig;
    QString err;
    if (privPem.isEmpty() || !rsaSign(privPem, canonical, &sig, &err)) {
        qWarning("PurgeX: certificate left unsigned: %s", qPrintable(err));
        sig = QByteArray("unsigned");
    }
    const bool signed_ = (sig != "unsigned");
    const QString fingerprint = signed_ ? publicKeyFingerprint(pubPem) : QString();

    const QString root = AppPaths::certificatesDir();
    const QDir jsonDir(AppPaths::ensureDir(QDir(root).filePath("json")));
    const QDir pdfDir(AppPaths::ensureDir(QDir(root).filePath("pdfs")));
    const QString baseName = QString("PurgeX_Certificate_%1")
                                 .arg(QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss"));
    const QString jsonPath = uniquePath(jsonDir, baseName, "json");
    const QString pdfPath  = uniquePath(pdfDir,  QFileInfo(jsonPath).completeBaseName(), "pdf");

    const bool jsonOk = writeJsonCertificate(jsonPath, details, hash, sig, timestamp, qrPayload,
                                             signed_ ? pubPem : QByteArray());
    const bool pdfOk  = writePdfCertificate(pdfPath, details, QString::fromLatin1(hash.toHex()),
                                            QString::fromLatin1(sig.toHex()), timestamp, qrPayload,
                                            fingerprint);

    if (pdfPathOut)  *pdfPathOut  = pdfOk  ? pdfPath  : QString();
    if (jsonPathOut) *jsonPathOut = jsonOk ? jsonPath : QString();
    return jsonOk && pdfOk;
}

// ---------------------------------------------------------------------------
// JSON certificate verification
// ---------------------------------------------------------------------------
bool CertManager::verifyJsonCertificate(const QString &jsonPath, QString *message, QWidget *parent)
{
    Q_UNUSED(parent);
    auto say = [&](const QString &m) { if (message) *message = m; };

    QFile f(jsonPath);
    if (!f.open(QIODevice::ReadOnly)) { say("Cannot open file."); return false; }
    const QByteArray data = f.readAll();
    f.close();

    QJsonParseError pe{};
    const QJsonDocument doc = QJsonDocument::fromJson(data, &pe);
    if (pe.error != QJsonParseError::NoError || !doc.isObject()) { say("Invalid JSON."); return false; }
    const QJsonObject obj = doc.object();

    const QByteArray canonical = canonicalBytes(obj.value("subject").toString(),
                                                obj.value("method").toString(),
                                                obj.value("targets").toArray(),
                                                obj.value("bytesProcessed").toDouble(),
                                                obj.value("timestamp").toString(),
                                                obj.value("device").toObject());

    // 1. Content hash must match the stored hash and the QR payload.
    const QByteArray recomputed = QCryptographicHash::hash(canonical, QCryptographicHash::Sha256);
    const QString expectedQr = QString::fromLatin1(recomputed.toHex()) + "_PurgeX";
    const QString storedQr   = obj.value("qrPayload").toString();
    const QString storedHash = obj.value("dataHashHex").toString();
    const bool hashMatch = (storedQr == expectedQr) &&
                           (storedHash.isEmpty() || storedHash == QString::fromLatin1(recomputed.toHex()));
    if (!hashMatch) {
        say(QString("TAMPER DETECTED: the certificate contents no longer match their hash. "
                    "Expected: %1  Stored: %2").arg(expectedQr, storedQr));
        return false;
    }

    // 2. The RSA signature must verify. A bare hash proves nothing - anyone can recompute it.
    QByteArray pubPem = obj.value("publicKeyPem").toString().toLatin1();
    const bool embedded = !pubPem.isEmpty();
    QByteArray localPub = readFile(QDir(AppPaths::keyDir()).filePath("purgex_public.pem"));
    if (!embedded) pubPem = localPub; // certificates written by older versions
    const QByteArray sig = QByteArray::fromHex(obj.value("signatureHex").toString().toLatin1());

    if (sig.isEmpty() || sig == "unsigned" || QByteArray::fromHex("756e7369676e6564") == sig) {
        say("NOT AUTHENTIC: the certificate content is intact but it is unsigned, so its origin "
            "cannot be proven.");
        return false;
    }
    if (!rsaVerify(pubPem, canonical, sig)) {
        say("INVALID SIGNATURE: the contents are intact but the RSA signature does not verify "
            "against the signing key. Do not trust this certificate.");
        return false;
    }

    const QString fp = publicKeyFingerprint(pubPem);
    const bool localSigner = !localPub.isEmpty() && publicKeyFingerprint(localPub) == fp;
    say(QString("Certificate authentic: content hash and RSA-SHA256 signature are valid.\n"
                "Signer key fingerprint (SHA-256): %1\n%2")
            .arg(fp.left(32) + "...",
                 localSigner ? "The signing key belongs to this PurgeX installation."
                             : "Signed by a different key - confirm this fingerprint with the issuer "
                               "before relying on the certificate."));
    return true;
}

// ---------------------------------------------------------------------------
// PDF certificate writer with embedded QR code
// ---------------------------------------------------------------------------
bool CertManager::writePdfCertificate(const QString &outPath, const CertDetails &details,
                                      const QString &dataHashHex, const QString &signatureHex,
                                      const QString &timestamp, const QString &qrPayload,
                                      const QString &signerFingerprint)
{
    auto chunkHtml = [](const QString &s, int width) {
        QString out;
        out.reserve(s.size() + (s.size() / width) * 5);
        for (int i = 0; i < s.size(); i += width) {
            out += s.mid(i, width).toHtmlEscaped();
            if (i + width < s.size()) out += "<br/>";
        }
        return out;
    };

    QString targetsHtml;
    if (!details.targets.isEmpty()) {
        targetsHtml = "<ul>";
        for (const QString &t : details.targets)
            targetsHtml += "<li>" + t.toHtmlEscaped() + "</li>";
        targetsHtml += "</ul>";
    }

    QString opTypeHtml, verifHtml;
    if (!details.operationType.isEmpty())
        opTypeHtml = QString("<p><b>Operation Type:</b> %1</p>").arg(details.operationType.toHtmlEscaped());
    if (!details.verificationStatus.isEmpty()) {
        const QString color = (details.verificationStatus == "verified") ? "#1a7a1a"
                            : (details.verificationStatus == "failed")   ? "#cc0000" : "#888888";
        verifHtml = QString("<p><b>Verification Status:</b> <span style='color:%1;font-weight:bold;'>%2</span></p>")
                        .arg(color, details.verificationStatus.toHtmlEscaped());
        if (!details.verificationNote.isEmpty())
            verifHtml += QString("<p class='small'><i>Note: %1</i></p>")
                             .arg(details.verificationNote.toHtmlEscaped());
    }

    QString html;
    html += "<html><head><style>"
            "body{font-family:Helvetica,Arial,sans-serif;font-size:11pt;}"
            "h1{font-size:18pt;margin:0 0 4pt 0;}"
            "p{margin:4pt 0;}"
            "code{font-family:'Courier New',monospace;font-size:8pt;}"
            "ul{margin:3pt 0 3pt 12pt;font-size:10pt;}"
            ".small{color:#555;font-size:9pt;}"
            "</style></head><body>";
    html += "<h1>PurgeX Certificate</h1>";
    html += "<p class='small'>Standard: NIST SP 800-88 | Issued by: PurgeX</p><hr/>";
    html += QString("<p><b>Subject:</b> %1</p>").arg(details.subject.toHtmlEscaped());
    html += QString("<p><b>Timestamp:</b> %1</p>").arg(timestamp.toHtmlEscaped());
    html += opTypeHtml;
    html += verifHtml;
    html += QString("<p><b>Method:</b> %1</p>").arg(details.method.toHtmlEscaped().replace("\n", "<br/>"));
    html += QString("<p><b>Targets:</b></p>%1").arg(targetsHtml);
    html += QString("<p><b>Bytes Processed:</b> %1</p>").arg(details.bytesProcessed);
    if (!details.device.isEmpty()) {
        html += "<p><b>Device Passport:</b></p><ul>";
        for (auto it = details.device.constBegin(); it != details.device.constEnd(); ++it)
            html += QString("<li>%1: %2</li>").arg(it.key().toHtmlEscaped(), it.value().toHtmlEscaped());
        html += "</ul>";
    }
    html += "<hr/>";
    html += QString("<p><b>Data Hash (SHA-256):</b><br/><code>%1</code></p>").arg(chunkHtml(dataHashHex, 64));
    html += QString("<p><b>Signature (RSA/SHA-256):</b><br/><code>%1</code></p>").arg(chunkHtml(signatureHex, 64));
    if (!signerFingerprint.isEmpty())
        html += QString("<p><b>Signer key fingerprint (SHA-256):</b><br/><code>%1</code></p>")
                    .arg(chunkHtml(signerFingerprint, 64));
    html += "<hr/>";
    html += "<p><b>Tamper-Verification QR Code:</b></p>";
    html += "<p><img src='qr://payload' width='150' height='150'/></p>";
    html += QString("<p class='small'>%1</p>").arg(qrPayload.toHtmlEscaped());
    html += "<p class='small'>The QR payload is SHA-256(canonical JSON) + \"_PurgeX\". Verify the "
            "companion .json file with PurgeX (Certificates tab or --verify-cert).</p>";
    if (signerFingerprint.isEmpty())
        html += "<p class='small'><b>This certificate is UNSIGNED</b> (no signing key was available).</p>";
    html += "</body></html>";

    QPrinter printer(QPrinter::HighResolution);
    printer.setOutputFormat(QPrinter::PdfFormat);
    printer.setOutputFileName(outPath);
    printer.setPageLayout(QPageLayout(QPageSize(QPageSize::A4), QPageLayout::Portrait, QMarginsF(15, 15, 15, 15)));

    QTextDocument doc;
    doc.addResource(QTextDocument::ImageResource, QUrl("qr://payload"), renderQrCode(qrPayload, 300));
    doc.setHtml(html);
    doc.print(&printer);

    return QFileInfo(outPath).size() > 0;
}

// ---------------------------------------------------------------------------
// Verify a scanned QR payload against a certificate
// ---------------------------------------------------------------------------
bool CertManager::verifyQrPayload(const QString &jsonPath, const QString &scannedPayload, QString *message)
{
    QString certMessage;
    const bool certOk = verifyJsonCertificate(jsonPath, &certMessage, nullptr);

    QFile f(jsonPath);
    QString stored;
    if (f.open(QIODevice::ReadOnly))
        stored = QJsonDocument::fromJson(f.readAll()).object().value("qrPayload").toString();

    const bool match = !stored.isEmpty() && scannedPayload.trimmed() == stored;
    if (message) {
        *message = match ? QString("The scanned QR code matches this certificate.\n%1").arg(certMessage)
                         : QString("QR MISMATCH: the scanned code does not belong to this certificate.\n%1").arg(certMessage);
    }
    return certOk && match;
}
