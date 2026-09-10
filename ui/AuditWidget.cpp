#include "AuditWidget.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QMessageBox>
#include <QDesktopServices>
#include <QUrl>
#include <QDialog>
#include <QDialogButtonBox>
#include <QTextBrowser>
#include <QFileInfo>
#include <QFont>
#include <QScrollArea>

// ---------------------------------------------------------------------------
// AuditWidget
// ---------------------------------------------------------------------------
AuditWidget::AuditWidget(QWidget *parent)
    : QWidget(parent), auditLog(new AuditLog(this))
{
    setupUI();
    refresh();
}

// ---------------------------------------------------------------------------
// UI setup
// ---------------------------------------------------------------------------
void AuditWidget::setupUI()
{
    auto *root = new QVBoxLayout(this);
    root->setSpacing(6);

    // ---- Header ----
    auto *header = new QLabel("Audit History — All past PurgeX operations", this);
    header->setStyleSheet("font-size:13px;font-weight:bold;padding:4px 0;");
    root->addWidget(header);

    // ---- Filter bar ----
    auto *filterGroup = new QGroupBox("Filter", this);
    auto *fLayout = new QHBoxLayout(filterGroup);

    fLayout->addWidget(new QLabel("Type:", this));
    typeFilter = new QComboBox(this);
    typeFilter->addItems({"All", "wipe", "recovery"});
    fLayout->addWidget(typeFilter);

    fLayout->addWidget(new QLabel("Status:", this));
    statusFilter = new QComboBox(this);
    statusFilter->addItems({"All", "success", "failed", "cancelled", "partial"});
    fLayout->addWidget(statusFilter);

    fLayout->addWidget(new QLabel("Search:", this));
    searchEdit = new QLineEdit(this);
    searchEdit->setPlaceholderText("Filter by target, algorithm...");
    searchEdit->setMinimumWidth(180);
    fLayout->addWidget(searchEdit);

    useDateFilter = new QCheckBox("Date range:", this);
    fLayout->addWidget(useDateFilter);
    fromDate = new QDateEdit(QDate::currentDate().addMonths(-1), this);
    fromDate->setEnabled(false);
    fromDate->setCalendarPopup(true);
    toDate   = new QDateEdit(QDate::currentDate(), this);
    toDate->setEnabled(false);
    toDate->setCalendarPopup(true);
    fLayout->addWidget(fromDate);
    fLayout->addWidget(new QLabel("to", this));
    fLayout->addWidget(toDate);

    filterButton      = new QPushButton("Apply", this);
    clearFilterButton = new QPushButton("Clear",  this);
    refreshButton     = new QPushButton("Refresh", this);
    fLayout->addWidget(filterButton);
    fLayout->addWidget(clearFilterButton);
    fLayout->addStretch();
    fLayout->addWidget(refreshButton);

    root->addWidget(filterGroup);

    connect(useDateFilter, &QCheckBox::toggled, fromDate, &QDateEdit::setEnabled);
    connect(useDateFilter, &QCheckBox::toggled, toDate,   &QDateEdit::setEnabled);
    connect(filterButton,      &QPushButton::clicked, this, &AuditWidget::onFilter);
    connect(clearFilterButton, &QPushButton::clicked, this, &AuditWidget::onClearFilter);
    connect(refreshButton,     &QPushButton::clicked, this, &AuditWidget::onRefresh);
    connect(searchEdit,        &QLineEdit::returnPressed, this, &AuditWidget::onFilter);

    // ---- Table ----
    table = new QTableWidget(0, 7, this);
    table->setHorizontalHeaderLabels(
        {"Timestamp", "Type", "Target", "Algorithm", "Status", "Verification", "Certificate"});
    table->horizontalHeader()->setStretchLastSection(true);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setAlternatingRowColors(true);
    table->setSortingEnabled(true);
    table->verticalHeader()->setVisible(false);
    table->setColumnWidth(0, 140);
    table->setColumnWidth(1, 70);
    table->setColumnWidth(2, 200);
    table->setColumnWidth(4, 80);
    table->setColumnWidth(5, 110);

    connect(table->selectionModel(), &QItemSelectionModel::selectionChanged,
            this, &AuditWidget::onTableSelectionChanged);

    root->addWidget(table);

    // ---- Bottom bar ----
    auto *btmRow = new QHBoxLayout();
    countLabel       = new QLabel("0 record(s)", this);
    countLabel->setStyleSheet("color:#888;font-size:10px;");
    openCertButton   = new QPushButton("Open Certificate", this);
    viewDetailsButton= new QPushButton("View Details",     this);
    openCertButton->setEnabled(false);
    viewDetailsButton->setEnabled(false);

    btmRow->addWidget(countLabel);
    btmRow->addStretch();
    btmRow->addWidget(viewDetailsButton);
    btmRow->addWidget(openCertButton);
    root->addLayout(btmRow);

    connect(openCertButton,    &QPushButton::clicked, this, &AuditWidget::onOpenCertificate);
    connect(viewDetailsButton, &QPushButton::clicked, this, &AuditWidget::onViewDetails);
}

// ---------------------------------------------------------------------------
// Public: reload from disk and repopulate
// ---------------------------------------------------------------------------
void AuditWidget::refresh()
{
    auditLog->load();
    populateTable(auditLog->entries());
}

// ---------------------------------------------------------------------------
// Slots
// ---------------------------------------------------------------------------
void AuditWidget::onRefresh()
{
    refresh();
}

void AuditWidget::onFilter()
{
    QString type   = typeFilter->currentText()   == "All" ? "" : typeFilter->currentText();
    QString status = statusFilter->currentText() == "All" ? "" : statusFilter->currentText();
    QDateTime from, to;
    if (useDateFilter->isChecked()) {
        from = QDateTime(fromDate->date(), QTime(0, 0));
        to   = QDateTime(toDate->date(),   QTime(23, 59, 59));
    }

    QList<AuditEntry> filtered = auditLog->filter(type, status, from, to);

    // Text search
    QString search = searchEdit->text().trimmed().toLower();
    if (!search.isEmpty()) {
        QList<AuditEntry> searched;
        for (const AuditEntry &e : filtered) {
            if (e.target.toLower().contains(search) ||
                e.algorithm.toLower().contains(search) ||
                e.details.toLower().contains(search))
                searched.append(e);
        }
        filtered = searched;
    }

    populateTable(filtered);
}

void AuditWidget::onClearFilter()
{
    typeFilter->setCurrentIndex(0);
    statusFilter->setCurrentIndex(0);
    searchEdit->clear();
    useDateFilter->setChecked(false);
    populateTable(auditLog->entries());
}

void AuditWidget::onOpenCertificate()
{
    int row = table->currentRow();
    if (row < 0 || row >= currentEntries.size()) return;
    const AuditEntry &e = currentEntries[row];

    if (e.certPath.isEmpty()) {
        QMessageBox::information(this, "No Certificate", "No certificate was generated for this operation.");
        return;
    }
    if (!QFileInfo::exists(e.certPath)) {
        QMessageBox::warning(this, "Certificate Not Found",
            QString("The certificate file no longer exists at:\n%1\n\n"
                    "It may have been moved or deleted.").arg(e.certPath));
        return;
    }
    QDesktopServices::openUrl(QUrl::fromLocalFile(e.certPath));
}

void AuditWidget::onViewDetails()
{
    int row = table->currentRow();
    if (row < 0 || row >= currentEntries.size()) return;
    showDetailDialog(currentEntries[row]);
}

void AuditWidget::onTableSelectionChanged()
{
    bool hasSelection = !table->selectedItems().isEmpty();
    openCertButton->setEnabled(hasSelection);
    viewDetailsButton->setEnabled(hasSelection);
}

// ---------------------------------------------------------------------------
// Populate table from entry list
// ---------------------------------------------------------------------------
void AuditWidget::populateTable(const QList<AuditEntry> &entries)
{
    currentEntries = entries;
    table->setSortingEnabled(false);
    table->setRowCount(0);

    for (const AuditEntry &e : entries) {
        int row = table->rowCount();
        table->insertRow(row);

        table->setItem(row, 0, new QTableWidgetItem(e.timestamp.toString("yyyy-MM-dd hh:mm")));
        table->setItem(row, 1, new QTableWidgetItem(e.type));
        table->setItem(row, 2, new QTableWidgetItem(
            e.target.length() > 60 ? e.target.left(57) + "..." : e.target));
        table->setItem(row, 3, new QTableWidgetItem(
            e.algorithm.length() > 40 ? e.algorithm.left(37) + "..." : e.algorithm));
        table->setItem(row, 4, new QTableWidgetItem(statusIcon(e.status) + " " + e.status));
        table->setItem(row, 5, new QTableWidgetItem(e.verificationStatus));
        table->setItem(row, 6, new QTableWidgetItem(
            e.certPath.isEmpty() ? "—" : QFileInfo(e.certPath).fileName()));

        // Row color by status
        QColor c = statusColor(e.status);
        for (int col = 0; col < 7; ++col)
            if (table->item(row, col))
                table->item(row, col)->setBackground(c);
    }

    table->setSortingEnabled(true);
    countLabel->setText(QString("%1 record(s)").arg(entries.size()));
}

// ---------------------------------------------------------------------------
// Detail dialog
// ---------------------------------------------------------------------------
void AuditWidget::showDetailDialog(const AuditEntry &e)
{
    auto *dlg = new QDialog(this);
    dlg->setWindowTitle("Operation Details — " + e.id);
    dlg->setMinimumWidth(600);
    dlg->setMinimumHeight(400);
    auto *layout = new QVBoxLayout(dlg);

    QString html;
    html += QString("<b>ID:</b> %1<br/>").arg(e.id);
    html += QString("<b>Timestamp:</b> %1<br/>").arg(e.timestamp.toString(Qt::ISODate));
    html += QString("<b>Type:</b> %1<br/>").arg(e.type);
    html += QString("<b>Status:</b> %1<br/>").arg(e.status);
    html += QString("<b>Verification:</b> %1<br/>").arg(e.verificationStatus);
    if (!e.verificationNote.isEmpty())
        html += QString("<b>Verification Note:</b> %1<br/>").arg(e.verificationNote.toHtmlEscaped());
    html += QString("<b>Bytes Processed:</b> %1<br/>").arg(e.bytesProcessed);
    html += QString("<b>Target:</b> %1<br/>").arg(e.target.toHtmlEscaped());
    html += QString("<b>Algorithm:</b><pre>%1</pre>").arg(e.algorithm.toHtmlEscaped());
    html += QString("<b>Certificate:</b> %1<br/>").arg(
        e.certPath.isEmpty() ? "None" : e.certPath.toHtmlEscaped());
    html += QString("<b>Details:</b> %1<br/>").arg(e.details.toHtmlEscaped());

    auto *browser = new QTextBrowser(dlg);
    browser->setHtml(html);
    layout->addWidget(browser);

    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Close, dlg);
    if (!e.certPath.isEmpty() && QFileInfo::exists(e.certPath)) {
        auto *openBtn = new QPushButton("Open Certificate PDF", dlg);
        connect(openBtn, &QPushButton::clicked, [&e] {
            QDesktopServices::openUrl(QUrl::fromLocalFile(e.certPath));
        });
        buttons->addButton(openBtn, QDialogButtonBox::ActionRole);
    }
    connect(buttons, &QDialogButtonBox::rejected, dlg, &QDialog::accept);
    layout->addWidget(buttons);

    dlg->exec();
    dlg->deleteLater();
}

// ---------------------------------------------------------------------------
// Status display helpers
// ---------------------------------------------------------------------------
QString AuditWidget::statusIcon(const QString &status) const
{
    if (status == "success")   return "[OK]";
    if (status == "failed")    return "[FAIL]";
    if (status == "cancelled") return "[CANCELLED]";
    if (status == "partial")   return "[PARTIAL]";
    return "";
}

QColor AuditWidget::statusColor(const QString &status) const
{
    if (status == "success")   return QColor("#e6f4ea");
    if (status == "failed")    return QColor("#fce8e6");
    if (status == "cancelled") return QColor("#fff8e1");
    if (status == "partial")   return QColor("#fff3e0");
    return Qt::transparent;
}
