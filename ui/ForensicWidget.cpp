#include "ForensicWidget.h"

#include <QFileDialog>
#include <QInputDialog>
#include <QMessageBox>
#include <QHeaderView>
#include <QDesktopServices>
#include <QUrl>
#include <QDateTime>
#include <QApplication>
#include <QDir>
#include <QLabel>
#include <QSplitter>
#include <QFrame>
#include <QFont>

#include "../cert/CertManager.h"
#include "../core/AuditLog.h"
#include "../core/WipeEngine.h"
#include <QFileInfo>

// ---------------------------------------------------------------------------
// ForensicWidget
// ---------------------------------------------------------------------------
ForensicWidget::ForensicWidget(QWidget *parent)
    : QWidget(parent), engine(new ForensicEngine(this)), scanning(false)
{
    setupUI();

    connect(engine, &ForensicEngine::progress,  this, &ForensicWidget::onScanProgress);
    connect(engine, &ForensicEngine::fileFound, this, &ForensicWidget::onFileFound);
    connect(engine, &ForensicEngine::finished,  this, &ForensicWidget::onScanFinished);
    connect(engine, &ForensicEngine::warning,   this, &ForensicWidget::onScanWarning);
}

// ---------------------------------------------------------------------------
// UI setup
// ---------------------------------------------------------------------------
void ForensicWidget::setupUI()
{
    auto *rootLayout = new QVBoxLayout(this);
    rootLayout->setSpacing(8);

    // ---- Safety banner ----
    auto *banner = new QLabel(
        "  READ-ONLY SOURCE  |  The scanned device or folder is never modified. "
        "Recovered files are written only to the destination you choose.", this);
    banner->setObjectName("forensicBanner");
    banner->setStyleSheet("background:#1a3a5c;color:#7ec8e3;font-weight:bold;"
                          "padding:6px 10px;border-radius:4px;font-size:11px;");
    rootLayout->addWidget(banner);

    // ---- Source / Destination ----
    auto *pathGroup = new QGroupBox("Scan Source and Recovery Destination", this);
    auto *pathLayout = new QVBoxLayout(pathGroup);

    auto *srcRow = new QHBoxLayout();
    srcRow->addWidget(new QLabel("Source (read-only):", this));
    sourceEdit = new QLineEdit(this);
    sourceEdit->setPlaceholderText("Select a folder/drive to scan for recoverable files...");
    sourceEdit->setReadOnly(false);
    sourceButton = new QPushButton("Browse...", this);
    srcRow->addWidget(sourceEdit);
    srcRow->addWidget(sourceButton);
    pathLayout->addLayout(srcRow);

    auto *dstRow = new QHBoxLayout();
    dstRow->addWidget(new QLabel("Recovery destination:", this));
    destEdit = new QLineEdit(this);
    destEdit->setPlaceholderText("Select a folder where recovered files will be saved...");
    destEdit->setReadOnly(true);
    destButton = new QPushButton("Browse...", this);
    dstRow->addWidget(destEdit);
    dstRow->addWidget(destButton);
    pathLayout->addLayout(dstRow);

    auto *modeRow = new QHBoxLayout();
    modeRow->addWidget(new QLabel("Scan mode:", this));
    modeCombo = new QComboBox(this);
    modeCombo->addItem("Logical Path (identify and copy files in a folder)", 0);
    modeCombo->addItem("Raw Device / Disk Image (carve deleted files from raw sectors)", 1);
    modeRow->addWidget(modeCombo);
    modeRow->addStretch();
    pathLayout->addLayout(modeRow);

    rootLayout->addWidget(pathGroup);

    // ---- File type filters ----
    auto *filterGroup = new QGroupBox("File Types to Scan For", this);
    auto *filterLayout = new QHBoxLayout(filterGroup);
    chkImages    = new QCheckBox("Images",    this); chkImages->setChecked(true);
    chkDocuments = new QCheckBox("Documents", this); chkDocuments->setChecked(true);
    chkArchives  = new QCheckBox("Archives",  this); chkArchives->setChecked(true);
    chkMedia     = new QCheckBox("Media",     this); chkMedia->setChecked(true);
    chkDatabases = new QCheckBox("Databases", this); chkDatabases->setChecked(true);
    chkOther     = new QCheckBox("Other",     this); chkOther->setChecked(false);
    filterLayout->addWidget(chkImages);
    filterLayout->addWidget(chkDocuments);
    filterLayout->addWidget(chkArchives);
    filterLayout->addWidget(chkMedia);
    filterLayout->addWidget(chkDatabases);
    filterLayout->addWidget(chkOther);
    filterLayout->addStretch();
    rootLayout->addWidget(filterGroup);

    // ---- Controls ----
    auto *ctrlRow = new QHBoxLayout();
    startButton  = new QPushButton("Start Scan",           this);
    cancelButton = new QPushButton("Cancel",               this);
    openDestButton = new QPushButton("Open Recovery Folder", this);
    exportButton = new QPushButton("Export Forensic Report", this);

    cancelButton->setEnabled(false);
    openDestButton->setEnabled(false);
    exportButton->setEnabled(false);

    ctrlRow->addWidget(startButton);
    ctrlRow->addWidget(cancelButton);
    ctrlRow->addStretch();
    ctrlRow->addWidget(openDestButton);
    ctrlRow->addWidget(exportButton);
    rootLayout->addLayout(ctrlRow);

    // ---- Progress ----
    progressBar   = new QProgressBar(this);
    progressLabel = new QLabel("Ready.", this);
    progressLabel->setStyleSheet("font-size:10px;color:#888;");
    progressBar->setVisible(false);
    rootLayout->addWidget(progressBar);
    rootLayout->addWidget(progressLabel);

    // ---- Splitter: results table / log ----
    auto *splitter = new QSplitter(Qt::Vertical, this);

    // Results table
    resultsTable = new QTableWidget(0, 6, this);
    resultsTable->setHorizontalHeaderLabels(
        {"Filename", "Type", "Category", "Size (bytes)", "Confidence", "Status"});
    resultsTable->horizontalHeader()->setStretchLastSection(true);
    resultsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    resultsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    resultsTable->setAlternatingRowColors(true);
    resultsTable->setSortingEnabled(true);
    splitter->addWidget(resultsTable);

    // Log
    logText = new QTextEdit(this);
    logText->setReadOnly(true);
    logText->setMaximumHeight(120);
    logText->setPlaceholderText("Scan log will appear here...");
    logText->setStyleSheet("font-family: 'Courier New'; font-size: 10px;");
    splitter->addWidget(logText);

    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 1);
    rootLayout->addWidget(splitter);

    // ---- Connections ----
    connect(sourceButton,  &QPushButton::clicked, this, &ForensicWidget::onSelectSource);
    connect(destButton,    &QPushButton::clicked, this, &ForensicWidget::onSelectDestination);
    connect(startButton,   &QPushButton::clicked, this, &ForensicWidget::onStartScan);
    connect(cancelButton,  &QPushButton::clicked, this, &ForensicWidget::onCancelScan);
    connect(openDestButton,&QPushButton::clicked, this, &ForensicWidget::onOpenDestination);
    connect(exportButton,  &QPushButton::clicked, this, &ForensicWidget::onExportReport);
    connect(modeCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &ForensicWidget::onModeChanged);
    connect(resultsTable, &QTableWidget::cellDoubleClicked,
            this, &ForensicWidget::onResultDoubleClicked);
}

// ---------------------------------------------------------------------------
// Slot: browse for source
// ---------------------------------------------------------------------------
void ForensicWidget::onSelectSource()
{
    if (modeCombo->currentIndex() == 0) {
        const QString path = QFileDialog::getExistingDirectory(
            this, "Select Source Directory to Scan", QDir::rootPath());
        if (!path.isEmpty()) sourceEdit->setText(path);
        return;
    }

    // Raw mode: offer detected disks, a disk-image file, or a hand-typed device path.
    const QString browse = "Browse for a disk image file (.img, .dd, .raw, .iso)...";
    QStringList items;
    items << browse;
    WipeEngine probe;
    QStringList seen;
    for (const DriveInfo &d : probe.detectDrives()) {
        if (!d.physicalDevice.isEmpty() && !seen.contains(d.physicalDevice)) {
            seen << d.physicalDevice;
            items << QString("%1   -   whole disk (%2, %3 GB)")
                         .arg(d.physicalDevice, d.model).arg(d.totalSize / (1024 * 1024 * 1024));
        }
#ifdef Q_OS_WIN
        items << QString("%1   -   volume %2").arg(d.device, d.mountPoint);
#endif
    }

    bool ok = false;
    const QString choice = QInputDialog::getItem(this, "Select Raw Source",
        "Choose a device, or type a path (Windows: \\\\.\\PhysicalDrive1 or \\\\.\\D: / Linux: /dev/sdb).\n"
        "Raw device access needs Administrator / root. The source is opened read-only.",
        items, 0, true, &ok);
    if (!ok || choice.trimmed().isEmpty()) return;

    if (choice == browse) {
        const QString file = QFileDialog::getOpenFileName(this, "Select Disk Image", QDir::homePath(),
            "Disk images (*.img *.dd *.raw *.bin *.iso *.vhd *.001);;All files (*)");
        if (!file.isEmpty()) sourceEdit->setText(file);
        return;
    }
    const int sep = choice.indexOf("   -   ");
    sourceEdit->setText((sep > 0 ? choice.left(sep) : choice).trimmed());
}

// ---------------------------------------------------------------------------
// Slot: browse for destination
// ---------------------------------------------------------------------------
void ForensicWidget::onSelectDestination()
{
    QString path = QFileDialog::getExistingDirectory(
        this, "Select Recovery Destination Folder", QDir::homePath());
    if (!path.isEmpty()) destEdit->setText(path);
}

// ---------------------------------------------------------------------------
// Slot: start scan
// ---------------------------------------------------------------------------
void ForensicWidget::onStartScan()
{
    const QString src = sourceEdit->text().trimmed();
    const QString dst = destEdit->text().trimmed();

    if (src.isEmpty() || dst.isEmpty()) {
        QMessageBox::warning(this, "Missing Paths",
            "Please select both a source (folder, device or disk image) and a destination folder.");
        return;
    }

    QStringList categories;
    if (chkImages->isChecked())    categories << "Image";
    if (chkDocuments->isChecked()) categories << "Document";
    if (chkArchives->isChecked())  categories << "Archive";
    if (chkMedia->isChecked())     categories << "Media";
    if (chkDatabases->isChecked()) categories << "Database";
    if (chkOther->isChecked())     categories << "Executable" << "Text";

    if (categories.isEmpty()) {
        QMessageBox::warning(this, "No File Types Selected",
            "Please select at least one file type category to scan for.");
        return;
    }

    ForensicConfig config;
    config.destPath   = dst;
    config.categories = categories;
    config.sourcePath = src;

    const bool rawMode = (modeCombo->currentIndex() == 1);
    if (rawMode) {
        const bool isDevice = src.startsWith("\\\\.\\") || src.startsWith("/dev/");
        QString text = QString("You are about to run a raw, read-only scan of:\n\n  %1\n\n"
                               "Recovered files are written to:\n\n  %2\n\n"
                               "Make sure the destination is on a DIFFERENT disk than the source.").arg(src, dst);
        if (isDevice && !WipeEngine::isRunningAsAdministrator())
            text += "\n\nNote: PurgeX is not running as Administrator / root, so opening the device will probably fail.";
        if (QMessageBox::warning(this, "Raw Scan", text + "\n\nProceed?",
                                 QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes)
            return;
        config.mode = ForensicConfig::ScanMode::RawDevice;
        config.rawModeConfirmed = true;
    } else {
        config.mode = ForensicConfig::ScanMode::LogicalPath;
    }

    results.clear();
    resultsTable->setRowCount(0);
    logText->clear();
    scanSource = src;
    scanMode = rawMode ? "Raw carving" : "Logical scan";

    // startScan() explains a refusal through the warning() signal (shown in the log); also tell the user.
    QString refusal;
    const QMetaObject::Connection c = connect(engine, &ForensicEngine::warning, this,
                                              [&refusal](const QString &m) { refusal = m; });
    const bool started = engine->startScan(config);
    disconnect(c);
    if (!started) {
        QMessageBox::warning(this, "Scan Not Started",
            refusal.isEmpty() ? QString("Could not start the scan. Check the source path and permissions.") : refusal);
        return;
    }

    setRunning(true);
    appendLog(QString("[%1] %2 started: %3")
        .arg(QDateTime::currentDateTime().toString("hh:mm:ss"), scanMode, src));
}

// ---------------------------------------------------------------------------
// Slot: cancel scan
// ---------------------------------------------------------------------------
void ForensicWidget::onCancelScan()
{
    engine->cancel();
    appendLog("[INFO] Cancellation requested...");
}

// ---------------------------------------------------------------------------
// Slot: file found during scan
// ---------------------------------------------------------------------------
void ForensicWidget::onFileFound(const RecoveryResult &r)
{
    results.append(r);
    addResultRow(r);
}

// ---------------------------------------------------------------------------
// Slot: progress update
// ---------------------------------------------------------------------------
void ForensicWidget::onScanProgress(int pct, const QString &status)
{
    progressBar->setValue(pct);
    progressLabel->setText(status);
}

// ---------------------------------------------------------------------------
// Slot: scan finished
// ---------------------------------------------------------------------------
void ForensicWidget::onScanFinished(bool success, const QString &message,
                                    const QList<RecoveryResult> &res)
{
    Q_UNUSED(res);
    setRunning(false);
    appendLog(QString("[%1] %2")
        .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
        .arg(message));
    progressLabel->setText(message);

    const bool wasCancelled = message.contains("cancelled", Qt::CaseInsensitive);
    qint64 bytes = 0;
    for (const RecoveryResult &r : results) bytes += r.recoveredBytes;

    // Every scan is part of the audit trail, whatever its outcome.
    AuditEntry entry;
    entry.id        = AuditLog::generateId();
    entry.type      = "recovery";
    entry.timestamp = QDateTime::currentDateTime();
    entry.target    = scanSource;
    entry.algorithm = scanMode;
    entry.status    = success ? "success" : (wasCancelled ? "cancelled" : (results.isEmpty() ? "failed" : "partial"));
    entry.verificationStatus = "not_applicable";
    entry.verificationNote   = "Source was opened read-only. Each recovered file carries a SHA-256 in the report.";
    entry.bytesProcessed = bytes;
    entry.details = QString("%1 | destination: %2").arg(message, destEdit->text());
    AuditLog().append(entry);

    if (!results.isEmpty()) {
        openDestButton->setEnabled(true);
        exportButton->setEnabled(true);
    }
    emit recoveryComplete(results, scanSource);

    if (success) {
        QMessageBox::information(this, "Scan Complete",
            QString("%1\n\n%2 file(s) written to:\n%3").arg(message).arg(results.size()).arg(destEdit->text()));
    } else if (!wasCancelled) {
        QMessageBox::warning(this, "Scan Stopped", message);
    }
}

// ---------------------------------------------------------------------------
// Slot: warning from engine
// ---------------------------------------------------------------------------
void ForensicWidget::onScanWarning(const QString &msg)
{
    appendLog("[WARNING] " + msg);
}

// ---------------------------------------------------------------------------
// Slot: open destination folder
// ---------------------------------------------------------------------------
void ForensicWidget::onOpenDestination()
{
    QString dst = destEdit->text();
    if (!dst.isEmpty())
        QDesktopServices::openUrl(QUrl::fromLocalFile(dst));
}

// ---------------------------------------------------------------------------
// Slot: export forensic report
// ---------------------------------------------------------------------------
void ForensicWidget::onExportReport()
{
    if (results.isEmpty()) return;

    CertDetails d;
    d.subject       = "Forensic Recovery Operation";
    d.operationType = "forensic-recovery";

    QStringList targetList;
    int recovered = 0, partial = 0, unrecoverable = 0;
    for (const RecoveryResult &r : results) {
        targetList << QString("%1 | %2 | offset %3 | %4 bytes | %5 | SHA-256 %6")
            .arg(QFileInfo(r.destinationPath).fileName(), r.fileType)
            .arg(r.originalOffset).arg(r.recoveredBytes).arg(statusText(r.status), r.sha256);
        if (r.status == RecoveryStatus::Recovered)               ++recovered;
        else if (r.status == RecoveryStatus::PartiallyRecovered) ++partial;
        else ++unrecoverable;
    }

    d.method = QString("%1 of %2 | Recovered: %3 | Partial: %4 | Unrecoverable: %5")
                   .arg(scanMode, scanSource).arg(recovered).arg(partial).arg(unrecoverable);
    d.targets        = targetList;
    d.bytesProcessed = 0;
    for (const RecoveryResult &r : results) d.bytesProcessed += static_cast<qulonglong>(r.recoveredBytes);
    d.device = WipeEngine::systemPassport();
    d.verificationStatus = "not_applicable";
    d.verificationNote   = "Forensic recovery. The source was opened read-only; recovered files are listed "
                           "with their SHA-256 so their integrity can be checked later.";

    CertManager cm;
    QString pdfPath;
    if (!cm.generateCertificates(d, this, &pdfPath)) {
        QMessageBox::warning(this, "Report", "The report could not be written.");
        return;
    }

    AuditEntry entry;
    entry.id        = AuditLog::generateId();
    entry.type      = "recovery";
    entry.timestamp = QDateTime::currentDateTime();
    entry.target    = scanSource;
    entry.algorithm = QString("%1 report (%2 file(s))").arg(scanMode).arg(results.size());
    entry.status    = "success";
    entry.verificationStatus = "not_applicable";
    entry.certPath  = pdfPath;
    entry.bytesProcessed = static_cast<qint64>(d.bytesProcessed);
    entry.details   = "Forensic report exported";
    AuditLog().append(entry);
    emit recoveryComplete(results, scanSource);

    QMessageBox::information(this, "Report Generated",
        QString("Forensic report written to:\n%1").arg(pdfPath));
}

// ---------------------------------------------------------------------------
// Slot: mode changed
// ---------------------------------------------------------------------------
void ForensicWidget::onModeChanged(int index)
{
    if (index == 1) {
        QMessageBox::information(this, "Raw Device Mode",
            "Raw device mode scans the device at the byte level.\n\n"
            "This requires Administrator privileges.\n"
            "The device will be opened READ-ONLY — no data will be modified.\n\n"
            "Make absolutely sure you select the CORRECT device, not your system drive.");
    }
    // Clear source when mode changes to prevent stale path mismatches
    sourceEdit->clear();
}

// ---------------------------------------------------------------------------
// Slot: double-click result to open the recovered file
// ---------------------------------------------------------------------------
void ForensicWidget::onResultDoubleClicked(int row, int /*column*/)
{
    // Rows can be re-sorted, so the path travels with the row instead of being looked up by index.
    const QTableWidgetItem *item = resultsTable->item(row, 0);
    if (!item) return;
    const QString path = item->data(Qt::UserRole).toString();
    if (!path.isEmpty() && QFile::exists(path))
        QDesktopServices::openUrl(QUrl::fromLocalFile(path));
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
void ForensicWidget::setRunning(bool run)
{
    scanning = run;
    startButton->setEnabled(!run);
    cancelButton->setEnabled(run);
    sourceButton->setEnabled(!run);
    destButton->setEnabled(!run);
    modeCombo->setEnabled(!run);
    progressBar->setVisible(run);
    if (run) progressBar->setValue(0);
}

void ForensicWidget::appendLog(const QString &line)
{
    logText->append(line);
}

void ForensicWidget::addResultRow(const RecoveryResult &r)
{
    // Inserting cell by cell while sorting is on makes the row jump around mid-insert.
    resultsTable->setSortingEnabled(false);
    const int row = resultsTable->rowCount();
    resultsTable->insertRow(row);

    const QString fname = r.destinationPath.isEmpty()
        ? QFileInfo(r.sourcePath).fileName()
        : QFileInfo(r.destinationPath).fileName();

    auto *nameItem = new QTableWidgetItem(fname);
    nameItem->setData(Qt::UserRole, r.destinationPath);
    nameItem->setToolTip(QString("Source: %1\nOffset: %2\nSHA-256: %3\n%4")
                             .arg(r.sourcePath).arg(r.originalOffset).arg(r.sha256, r.notes));
    resultsTable->setItem(row, 0, nameItem);
    resultsTable->setItem(row, 1, new QTableWidgetItem(r.fileType));
    resultsTable->setItem(row, 2, new QTableWidgetItem(r.category));
    auto *sizeItem = new QTableWidgetItem;
    sizeItem->setData(Qt::DisplayRole, r.recoveredBytes); // numeric so it sorts numerically
    resultsTable->setItem(row, 3, sizeItem);
    resultsTable->setItem(row, 4, new QTableWidgetItem(confidenceText(r.confidence)));
    resultsTable->setItem(row, 5, new QTableWidgetItem(statusText(r.status)));

    QColor rowColor("#fce8e6");
    if (r.status == RecoveryStatus::Recovered)               rowColor = QColor("#e6f4ea");
    else if (r.status == RecoveryStatus::PartiallyRecovered) rowColor = QColor("#fff3e0");
    for (int c = 0; c < 6; ++c)
        if (resultsTable->item(row, c)) {
            resultsTable->item(row, c)->setBackground(rowColor);
            resultsTable->item(row, c)->setForeground(QColor("#202124")); // readable in dark themes
        }
    resultsTable->setSortingEnabled(true);
}

QString ForensicWidget::confidenceText(RecoveryConfidence c) const
{
    switch (c) {
        case RecoveryConfidence::HIGH:   return "High";
        case RecoveryConfidence::MEDIUM: return "Medium";
        case RecoveryConfidence::LOW:    return "Low";
    }
    return "—";
}

QString ForensicWidget::statusText(RecoveryStatus s) const
{
    switch (s) {
        case RecoveryStatus::Recovered:          return "Recovered";
        case RecoveryStatus::PartiallyRecovered: return "Partial";
        case RecoveryStatus::Unrecoverable:      return "Unrecoverable";
    }
    return "—";
}
