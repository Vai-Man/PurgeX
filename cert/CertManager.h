#ifndef PURGEX_CERTMANAGER_H
#define PURGEX_CERTMANAGER_H

#include <QObject>
#include <QString>
#include <QStringList>

struct CertDetails{
	QString subject;
	QString method;
	QStringList targets;
	qulonglong bytesProcessed{0};
};

class CertManager : public QObject{
	Q_OBJECT
public:
	explicit CertManager(QObject *parent=nullptr);
	bool generateCertificates(const CertDetails &details, QWidget *parent);
	bool verifyJsonCertificate(const QString &jsonPath, QString *message, QWidget *parent);

private:
	QString ensureKeypair(QWidget *parent);
	bool signWithOpenSSL(const QString &privateKeyPath, const QByteArray &data, QByteArray &outSignature, QString *errMsg);
	bool verifyWithOpenSSL(const QString &publicKeyPath, const QByteArray &data, const QByteArray &signature, QString *errMsg);
    bool writeJsonCertificate(const QString &outPath, const CertDetails &details, const QByteArray &dataHash, const QByteArray &signature, const QString &timestamp);
    bool writePdfCertificate(const QString &outPath, const CertDetails &details, const QByteArray &dataHashHex, const QByteArray &signatureHex, const QString &timestamp);
};

#endif


