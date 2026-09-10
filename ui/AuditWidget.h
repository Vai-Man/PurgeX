#ifndef PURGEX_AUDITWIDGET_H
#define PURGEX_AUDITWIDGET_H

#include <QWidget>
#include <QTableWidget>
#include <QLineEdit>
#include <QComboBox>
#include <QPushButton>
#include <QLabel>
#include <QGroupBox>
#include <QTextEdit>
#include <QDateEdit>
#include <QCheckBox>

#include "../core/AuditLog.h"

// ---------------------------------------------------------------------------
// AuditWidget — Audit History tab
// Displays all past wipe/recovery operations from the persistent AuditLog.
// ---------------------------------------------------------------------------
class AuditWidget : public QWidget {
    Q_OBJECT

public:
    explicit AuditWidget(QWidget *parent = nullptr);

    // Reload audit entries from disk (call after a new operation completes)
    void refresh();

private slots:
    void onRefresh();
    void onFilter();
    void onClearFilter();
    void onOpenCertificate();
    void onViewDetails();
    void onTableSelectionChanged();

private:
    void setupUI();
    void populateTable(const QList<AuditEntry> &entries);
    void showDetailDialog(const AuditEntry &entry);
    QString statusIcon(const QString &status) const;
    QColor  statusColor(const QString &status) const;

    AuditLog     *auditLog;

    // Filter controls
    QComboBox    *typeFilter;
    QComboBox    *statusFilter;
    QLineEdit    *searchEdit;
    QCheckBox    *useDateFilter;
    QDateEdit    *fromDate;
    QDateEdit    *toDate;
    QPushButton  *filterButton;
    QPushButton  *clearFilterButton;
    QPushButton  *refreshButton;

    // Table
    QTableWidget *table;
    QLabel       *countLabel;

    // Detail/action buttons
    QPushButton  *openCertButton;
    QPushButton  *viewDetailsButton;

    QList<AuditEntry> currentEntries; // Entries currently shown in table
};

#endif // PURGEX_AUDITWIDGET_H
