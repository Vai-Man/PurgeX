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
        "  READ-ONLY FORENSIC SCAN  |  No changes will be made to the source device or directory.", this);
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
    sourceEdit->setReadOnly(true);
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
    modeCombo->addItem("Logical Path (reads files in directory — no admin required)", 0);
    modeCombo->addItem("Raw Device (byte-level scan — requires Administrator)", 1);
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
        // Logical path — folder picker
        QString path = QFileDialog::getExistingDirectory(
            this, "Select Source Directory to Scan", QDir::rootPath());
        if (!path.isEmpty()) sourceEdit->setText(path);
    } else {
        // Raw device — warn user explicitly
        QMessageBox::information(this, "Raw Device Scan",
            "For raw device scanning, enter the device path directly in the source field.\n\n"
            "Windows examples:  \\\\.\\PhysicalDrive1  or  \\\\.\\D:\n"
            "Linux examples:    /dev/sdb   or   /dev/sdb1\n\n"
            "WARNING: Raw device scanning requires Administrator/root privileges.\n"
            "The source will be opened in READ-ONLY mode. No data will be modified.");
        bool ok;
        QString device = QInputDialog::getText(
            this, "Enter Device Path",
            "Device path (e.g. \\\\.\\PhysicalDrive1):", QLineEdit::Normal, "", &ok);
        if (ok && !device.isEmpty())
            sourceEdit->setText(device);
    }
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
    QString src = sourceEdit->text().trimmed();
    QString dst = destEdit->text().trimmed();

    if (src.isEmpty() || dst.isEmpty()) {
        QMessageBox::warning(this, "Missing Paths",
            "Please select both a source directory/device and a destination folder.");
        return;
    }

    // Safety: source and destination must differ
    if (QDir(src) == QDir(dst)) {
        QMessageBox::critical(this, "Safety Check Failed",
            "Source and destination must be different directories.\n"
            "Writing recovered files back to the source could overwrite data.");
        return;
    }

    // Collect selected categories
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

    bool rawMode = (modeCombo->currentIndex() == 1);
    if (rawMode) {
        // Raw mode: explicit confirmation required
        auto ans = QMessageBox::warning(this, "Raw Device Scan",
            QString("You are about to perform a raw byte-level scan of:\n\n  %1\n\n"
                    "This will open the device in READ-ONLY mode.\n"
                    "No data on this device will be modified.\n\n"
                    "Confirm that you have selected the CORRECT device and not your system drive.\n\n"
                    "Proceed?").arg(src),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
        if (ans != QMessageBox::Yes) return;

        config.mode = ForensicConfig::ScanMode::RawDevice;
        config.sourcePath = src;
        config.rawModeConfirmed = true;
    } else {
        config.mode = ForensicConfig::ScanMode::LogicalPath;
        config.sourcePath = src;
        config.rawModeConfirmed = false;
    }

    // Clear previous results
    results.clear();
    resultsTable->setRowCount(0);
    logText->clear();

    if (!engine->startScan(config)) {
        QMessageBox::warning(this, "Scan Error",
            "Could not start the scan. Check source path and permissions.");
        return;
    }

    setRunning(true);
    appendLog(QString("[%1] Scan started: %2")
        .arg(QDateTime::currentDateTime().toString("hh:mm:ss")).arg(src));
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

    if (!results.isEmpty()) {
        openDestButton->setEnabled(true);
        exportButton->setEnabled(true);
        emit recoveryComplete(results, sourceEdit->text());
    }

    if (!success && !message.contains("cancelled", Qt::CaseInsensitive)) {
        QMessageBox::warning(this, "Scan Warning", message);
    } else if (success) {
        QMessageBox::information(this, "Scan Complete",
            QString("Scan complete.\n%1 file(s) identified.\nRecovered files saved to:\n%2")
                .arg(results.size()).arg(destEdit->text()));
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
        targetList << QString("%1  [%2] {%3}")
            .arg(QFileInfo(r.sourcePath).fileName())
            .arg(r.fileType)
            .arg(statusText(r.status));
        if (r.status == RecoveryStatus::Recovered)          ++recovered;
        else if (r.status == RecoveryStatus::PartiallyRecovered) ++partial;
        else ++unrecoverable;
    }

    d.method         = QString("Source: %1 | Recovered: %2 | Partial: %3 | Unrecoverable: %4")
                           .arg(sourceEdit->text()).arg(recovered).arg(partial).arg(unrecoverable);
    d.targets        = targetList;
    d.bytesProcessed = 0;
    for (const RecoveryResult &r : results) d.bytesProcessed += static_cast<qulonglong>(r.recoveredBytes);
    d.verificationStatus = "not_applicable";
    d.verificationNote   = "Forensic recovery operation. No data was modified on the source device.";

    CertManager cm;
    cm.generateCertificates(d, this);

    QMessageBox::information(this, "Report Generated",
        "Forensic recovery certificate generated in Documents/PurgeX/certificates/");
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
    if (row < 0 || row >= results.size()) return;
    const RecoveryResult &r = results[row];
    if (!r.destinationPath.isEmpty() && QFile::exists(r.destinationPath))
        QDesktopServices::openUrl(QUrl::fromLocalFile(r.destinationPath));
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
    int row = resultsTable->rowCount();
    resultsTable->insertRow(row);

    QString fname = r.destinationPath.isEmpty()
        ? QFileInfo(r.sourcePath).fileName()
        : QFileInfo(r.destinationPath).fileName();

    resultsTable->setItem(row, 0, new QTableWidgetItem(fname));
    resultsTable->setItem(row, 1, new QTableWidgetItem(r.fileType));
    resultsTable->setItem(row, 2, new QTableWidgetItem(r.category));
    resultsTable->setItem(row, 3, new QTableWidgetItem(QString::number(r.recoveredBytes)));
    resultsTable->setItem(row, 4, new QTableWidgetItem(confidenceText(r.confidence)));
    resultsTable->setItem(row, 5, new QTableWidgetItem(statusText(r.status)));

    // Color-code by status
    QColor rowColor = Qt::transparent;
    if (r.status == RecoveryStatus::Recovered)
        rowColor = QColor("#e6f4ea");
    else if (r.status == RecoveryStatus::PartiallyRecovered)
        rowColor = QColor("#fff3e0");
    else
        rowColor = QColor("#fce8e6");

    for (int c = 0; c < 6; ++c) {
        if (resultsTable->item(row, c))
            resultsTable->item(row, c)->setBackground(rowColor);
    }
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
