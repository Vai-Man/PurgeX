#include "CertManager.h"
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
#include <QTextDocument>
#include <QAbstractTextDocumentLayout>
#include <QFileInfo>
#include <cmath> // for std::ceil

/// @brief 
/// @param parent 
CertManager::CertManager(QObject *parent):QObject(parent){}

QString CertManager::ensureKeypair(QWidget *parent){
	Q_UNUSED(parent);
	QString baseDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
	if(baseDir.isEmpty()) baseDir = QDir::homePath()+"/.purgex";
	QDir().mkpath(baseDir);
	QString priv = QDir(baseDir).filePath("purgex_private.pem");
	QString pub  = QDir(baseDir).filePath("purgex_public.pem");
	if(QFile::exists(priv) && QFile::exists(pub)) return baseDir;
	// Generate RSA keypair via openssl if available
	QProcess p;
	p.start("openssl", {"genpkey","-algorithm","RSA","-pkeyopt","rsa_keygen_bits:2048","-out",priv});
	p.waitForFinished(15000);
	QProcess p2;
	p2.start("openssl", {"rsa","-in",priv,"-pubout","-out",pub});
	p2.waitForFinished(8000);
	return baseDir;
}

bool CertManager::signWithOpenSSL(const QString &privateKeyPath, const QByteArray &data, QByteArray &outSignature, QString *errMsg){
	QProcess p;
	p.start("openssl", {"dgst","-sha256","-sign",privateKeyPath});
	if(!p.waitForStarted(3000)) { if(errMsg) *errMsg="Unable to start openssl."; return false; }
	p.write(data);
	p.closeWriteChannel();
	p.waitForFinished(8000);
	if(p.exitStatus()!=QProcess::NormalExit || p.exitCode()!=0){ if(errMsg) *errMsg=p.readAllStandardError(); return false; }
	outSignature = p.readAllStandardOutput();
	return !outSignature.isEmpty();
}

bool CertManager::verifyWithOpenSSL(const QString &publicKeyPath, const QByteArray &data, const QByteArray &signature, QString *errMsg){
	QProcess p;
	p.start("openssl", {"dgst","-sha256","-verify",publicKeyPath,"-signature","/proc/self/fd/0"});
	if(!p.waitForStarted(3000)) { if(errMsg) *errMsg="Unable to start openssl."; return false; }
	// Pipe signature on stdin first, then the data via a second process is tricky on Windows; use temp files instead.
	p.kill();
	Q_UNUSED(errMsg);
	// Fallback: write temp files
	QDir tmp(QDir::tempPath());
	QString sigPath = tmp.filePath("purgex_sig.bin");
	QString dataPath = tmp.filePath("purgex_data.bin");
	QFile(sigPath).remove(); QFile(dataPath).remove();
	QFile fs(sigPath); fs.open(QIODevice::WriteOnly); fs.write(signature); fs.close();
	QFile fd(dataPath); fd.open(QIODevice::WriteOnly); fd.write(data); fd.close();
	QProcess v;
	v.start("openssl", {"dgst","-sha256","-verify",publicKeyPath,"-signature",sigPath,dataPath});
	v.waitForFinished(8000);
	bool ok = (v.exitStatus()==QProcess::NormalExit && v.exitCode()==0);
	QFile(sigPath).remove(); QFile(dataPath).remove();
	return ok;
}

bool CertManager::writeJsonCertificate(const QString &outPath, const CertDetails &details, const QByteArray &dataHash, const QByteArray &signature, const QString &timestamp){
	QJsonObject obj;
	obj["tool"] = "PurgeX";
	obj["subject"] = details.subject;
	obj["method"] = details.method;
	obj["targets"] = QJsonArray::fromStringList(details.targets);
	obj["bytesProcessed"] = static_cast<double>(details.bytesProcessed);
    obj["timestamp"] = timestamp;
	obj["nist"] = "SP 800-88";
	obj["hashAlgo"] = "SHA256";
	obj["dataHashHex"] = QString::fromLatin1(dataHash.toHex());
	obj["signatureAlg"] = "RSA-SHA256";
	obj["signatureHex"] = QString::fromLatin1(signature.toHex());
	QFile f(outPath);
	if(!f.open(QIODevice::WriteOnly)) return false;
	QJsonDocument doc(obj);
	f.write(doc.toJson(QJsonDocument::Indented));
	f.close();
	return true;
}

bool CertManager::generateCertificates(const CertDetails &details, QWidget *parent){
    // Ensure keypair exists (best-effort)
    QString baseDir = ensureKeypair(parent);
    QString priv = QDir(baseDir).filePath("purgex_private.pem");
    
    // Canonical data for signing
    QJsonObject canonical;
    canonical["subject"] = details.subject;
    canonical["method"] = details.method;
    canonical["targets"] = QJsonArray::fromStringList(details.targets);
    canonical["bytesProcessed"] = static_cast<double>(details.bytesProcessed);
    // Use one consistent timestamp for both signing and outputs to avoid false tamper flags
    const QString timestamp = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss");
    canonical["timestamp"] = timestamp;
    QByteArray canonicalBytes = QJsonDocument(canonical).toJson(QJsonDocument::Compact);
    
    QByteArray hash = QCryptographicHash::hash(canonicalBytes, QCryptographicHash::Sha256);
    QByteArray sig;
    QString err;
    if (!signWithOpenSSL(priv, canonicalBytes, sig, &err)){
        sig = QByteArray("unsigned");
    }
    
    // Output paths (Documents/PurgeX/certificates)
    QString outDir = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
    if (outDir.isEmpty()) outDir = QDir::homePath();
    
    QString baseName = QString("PurgeX_Certificate_%1").arg(QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss"));
    
    QDir jsonDir(QDir(outDir).filePath("PurgeX/certificates/json"));
    if (!jsonDir.exists()) jsonDir.mkpath(".");
    QString jsonPath = jsonDir.filePath(baseName + ".json");
    
    QDir pdfDir(QDir(outDir).filePath("PurgeX/certificates/pdfs"));
    if (!pdfDir.exists()) pdfDir.mkpath(".");
    QString pdfPath  = pdfDir.filePath(baseName + ".pdf");
    
    // Write JSON/PDF with the exact same timestamp
    writeJsonCertificate(jsonPath, details, hash, sig, timestamp);
    writePdfCertificate(pdfPath, details, hash.toHex(), sig.toHex(), timestamp);
    return true;
}

bool CertManager::verifyJsonCertificate(const QString &jsonPath, QString *message, QWidget *parent){
    Q_UNUSED(parent);
    QFile f(jsonPath);
    if (!f.open(QIODevice::ReadOnly)) { if (message) *message = "Cannot open file."; return false; }
    QByteArray data = f.readAll(); f.close();
    
    QJsonParseError pe{}; QJsonDocument doc = QJsonDocument::fromJson(data, &pe);
    if (pe.error != QJsonParseError::NoError || !doc.isObject()) { if (message) *message = "Invalid JSON."; return false; }
    QJsonObject obj = doc.object();
    
    // Extract signature and rebuild canonical
    QByteArray sig = QByteArray::fromHex(obj.value("signatureHex").toString().toLatin1());
    QJsonObject canonical;
    canonical["subject"] = obj.value("subject").toString();
    canonical["method"] = obj.value("method").toString();
    canonical["targets"] = obj.value("targets").toArray();
    canonical["bytesProcessed"] = obj.value("bytesProcessed").toDouble();
    canonical["timestamp"] = obj.value("timestamp").toString();
    QByteArray canonicalBytes = QJsonDocument(canonical).toJson(QJsonDocument::Compact);
    
    QString baseDir = ensureKeypair(nullptr);
    QString pub = QDir(baseDir).filePath("purgex_public.pem");
    QString err;
    bool ok = verifyWithOpenSSL(pub, canonicalBytes, sig, &err);
    if (message) *message = ok ? QString("Certificate authentic. Issuer: PurgeX")
                               : QString("Verification failed. %1").arg(err);
    return ok;
}

// Legacy/alternate implementations (disabled)
#if 0
bool CertManager::writePdfCertificate(const QString &outPath,
    const CertDetails &details,
    const QByteArray &dataHashHex,
    const QByteArray &signatureHex,
    const QString &timestamp)
{
QPdfWriter pdf(outPath);
pdf.setCreator("PurgeX");
pdf.setTitle("PurgeX Wipe Certificate");
pdf.setResolution(300);                      // keep high DPI if you want crisp output
pdf.setPageSize(QPageSize(QPageSize::A4));   // A4

QPainter painter(&pdf);
if (!painter.isActive()) return false;

// Device-space margins (pixels at the PDF resolution)
const double margin = 150.0;
const QRectF deviceContentRect(margin,
 margin,
 pdf.width()  - 2.0 * margin,
 pdf.height() - 2.0 * margin);

// Build HTML (keep using escaped fields)
auto chunkHtml = [](const QString &s, int width){
QString out; out.reserve(s.size()+s.size()/width*5);
for (int i=0;i<s.size();i+=width){
out += s.mid(i, width);
if (i+width < s.size()) out += "<br/>";
}
return out;
};
const QString hashWrapped = chunkHtml(QString::fromLatin1(dataHashHex.toHex()), 64);
const QString sigWrapped  = chunkHtml(QString::fromLatin1(signatureHex.toHex()), 64);

QString html;
html += "<html><head><style>"
"body{font-family:Helvetica,Arial,sans-serif;}"
"h1{font-size:28pt;margin:0 0 8pt 0;}"
"p{margin:6pt 0;font-size:12pt;}"
"code{font-family:'Courier New',monospace;font-size:10pt;white-space:pre-wrap;word-break:break-all;}"
".small{color:#555;font-size:10pt;}"
"</style></head><body>";
html += "<h1>PurgeX Wipe Certificate</h1>";
html += "<p class='small'>Built by PurgeX<br/>Standard: NIST SP 800-88</p>";
html += QString("<p><b>Subject:</b> %1</p>").arg(details.subject.toHtmlEscaped());
html += QString("<p><b>Method:</b> %1</p>").arg(details.method.toHtmlEscaped());
html += QString("<p><b>Targets:</b> %1</p>").arg(details.targets.join(", ").toHtmlEscaped());
html += QString("<p><b>Bytes Processed:</b> %1</p>").arg(details.bytesProcessed);
html += QString("<p><b>Timestamp (UTC):</b> %1</p>").arg(QDateTime::currentDateTimeUtc().toString(Qt::ISODate).toHtmlEscaped());
html += QString("<p><b>Data Hash (SHA256):</b><br/><code>%1</code></p>").arg(hashWrapped);
html += QString("<p><b>Signature (RSA/SHA256):</b><br/><code>%1</code></p>").arg(sigWrapped);
html += "<p class='small'>Issuer: PurgeX • Signature may be 'unsigned' if OpenSSL is unavailable.</p>";
html += "</body></html>";

// --- KEY IDEA: map between "document points" (72pt/in) and PDF device pixels ---
const double pdfDpi = pdf.resolution();           // e.g. 300
const double pointToDevice = pdfDpi / 72.0;       // scale factor

// Document width in *points* that corresponds to device content width
const double docContentWidthPoints = deviceContentRect.width() / pointToDevice;
const double docPageHeightPoints   = deviceContentRect.height() / pointToDevice;

// Setup QTextDocument in document points coordinates
QTextDocument doc;
doc.setDefaultStyleSheet(
"body{font-family:Helvetica,Arial,sans-serif;font-size:12pt;}"
"h1{font-size:28pt;}"
"code{font-size:10pt;}"
);
doc.setHtml(html);
doc.setTextWidth(docContentWidthPoints);   // layout width in points

// doc.size() is in document points
const QSizeF docSizePoints = doc.size();
const double docHeightPoints = docSizePoints.height();
const int totalPages = static_cast<int>(std::ceil(docHeightPoints / docPageHeightPoints));

// Render each page: translate to device content origin, scale points -> device, then draw the doc slice
for (int pageIndex = 0; pageIndex < totalPages; ++pageIndex) {
// For pages after the first, start a new PDF page
if (pageIndex > 0)
pdf.newPage();

painter.save();

// Move painter to top-left of the device content rectangle
painter.translate(deviceContentRect.left(), deviceContentRect.top());

// Scale so that 1 document point = pointToDevice device pixels
painter.scale(pointToDevice, pointToDevice);

// Calculate which slice of the document (in *points*) to draw for this page
const double yOffsetPoints = pageIndex * docPageHeightPoints;
QRectF docSlice(0, yOffsetPoints, docContentWidthPoints, docPageHeightPoints);

// Draw that part of the QTextDocument (doc coordinates = points)
doc.drawContents(&painter, docSlice);

painter.restore();
}

painter.end();
return true;
}

}


#endif

// DPI-aware, single implementation
bool CertManager::writePdfCertificate(const QString &outPath,
	const CertDetails &details,
	const QByteArray &dataHashHex,
	const QByteArray &signatureHex,
	const QString &timestamp)
{
    // Build HTML first

	// Wrap long fields
	auto chunkHtml = [](const QString &s, int width){
		QString out; out.reserve(s.size()+s.size()/width*5);
		for (int i=0;i<s.size();i+=width){ out += s.mid(i,width); if(i+width<s.size()) out += "<br/>"; }
		return out;
	};
	const QString hashWrapped = chunkHtml(QString::fromLatin1(dataHashHex.toHex()), 64);
	const QString sigWrapped  = chunkHtml(QString::fromLatin1(signatureHex.toHex()), 64);

	QString targetsHtml;
	if (!details.targets.isEmpty()) {
		targetsHtml = "<ul>";
		for (const QString &t : details.targets) targetsHtml += "<li>" + t.toHtmlEscaped() + "</li>";
		targetsHtml += "</ul>";
	}

	QString html;
	html += "<html><head><style>"
		"body{font-family:Helvetica,Arial,sans-serif;font-size:11pt;}"
		"h1{font-size:18pt;margin:0 0 8pt 0;}"
		"p{margin:5pt 0;}"
		"code{font-family:'Courier New',monospace;font-size:9pt;word-break:break-all;white-space:pre-wrap;}"
		"ul{margin:3pt 0 3pt 12pt;}"
		".small{color:#555;font-size:9pt;}"
		"</style></head><body>";
	html += "<h1>PurgeX Wipe Certificate</h1>";
	html += "<p class='small'>Built by PurgeX • Standard: NIST SP 800-88</p>";
	html += QString("<p><b>Subject:</b> %1</p>").arg(details.subject.toHtmlEscaped());
	html += QString("<p><b>Method:</b> %1</p>").arg(details.method.toHtmlEscaped());
	html += QString("<p><b>Targets:</b></p>%1").arg(targetsHtml);
	html += QString("<p><b>Bytes Processed:</b> %1</p>").arg(details.bytesProcessed);
    html += QString("<p><b>Timestamp (IST):</b> %1</p>").arg(timestamp.toHtmlEscaped());
	html += QString("<p><b>Data Hash (SHA256):</b><br/><code>%1</code></p>").arg(hashWrapped);
	html += QString("<p><b>Signature (RSA/SHA256):</b><br/><code>%1</code></p>").arg(sigWrapped);
	html += "</body></html>";

    QTextDocument doc;
    doc.setHtml(html);

    // Use QPrinter to handle pagination and margins automatically
    QPrinter printer(QPrinter::HighResolution);
    printer.setOutputFormat(QPrinter::PdfFormat);
    printer.setOutputFileName(outPath);
    printer.setPageSize(QPageSize(QPageSize::A4));
    // Set decent margins ~15mm
    QMarginsF marginsMM(15, 15, 15, 15);
    QPageLayout layout(QPageSize(QPageSize::A4), QPageLayout::Portrait, marginsMM);
    printer.setPageLayout(layout);

    doc.print(&printer);
    return true;
}





