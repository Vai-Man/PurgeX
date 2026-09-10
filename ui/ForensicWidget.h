#ifndef PURGEX_FORENSICWIDGET_H
#define PURGEX_FORENSICWIDGET_H

#include <QWidget>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QComboBox>
#include <QCheckBox>
#include <QProgressBar>
#include <QTextEdit>
#include <QTableWidget>
#include <QGroupBox>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QSplitter>
#include <QList>

#include "../forensics/ForensicEngine.h"

// ---------------------------------------------------------------------------
// ForensicWidget — File Recovery / Forensics tab
//
// Safety guarantees enforced by this widget:
//  - Source path and destination path are validated to be different before scan
//  - Raw device mode requires admin check AND a separate explicit confirmation
//  - No destructive method (wipe/delete/format/rename) is callable from this widget
//  - ForensicEngine is constructed in read-only mode by design
// ---------------------------------------------------------------------------
class ForensicWidget : public QWidget {
    Q_OBJECT

public:
    explicit ForensicWidget(QWidget *parent = nullptr);

signals:
    void recoveryComplete(const QList<RecoveryResult> &results, const QString &sourcePath);

private slots:
    void onSelectSource();
    void onSelectDestination();
    void onStartScan();
    void onCancelScan();
    void onFileFound(const RecoveryResult &result);
    void onScanProgress(int pct, const QString &status);
    void onScanFinished(bool success, const QString &message, const QList<RecoveryResult> &results);
    void onScanWarning(const QString &msg);
    void onOpenDestination();
    void onExportReport();
    void onModeChanged(int index);
    void onResultDoubleClicked(int row, int column);

private:
    void setupUI();
    void setRunning(bool running);
    void appendLog(const QString &line);
    void addResultRow(const RecoveryResult &r);
    QString confidenceText(RecoveryConfidence c) const;
    QString statusText(RecoveryStatus s) const;

    // Source / destination
    QLineEdit   *sourceEdit;
    QPushButton *sourceButton;
    QLineEdit   *destEdit;
    QPushButton *destButton;

    // Options
    QComboBox   *modeCombo;     // Logical Path | Raw Device
    QCheckBox   *chkImages;
    QCheckBox   *chkDocuments;
    QCheckBox   *chkArchives;
    QCheckBox   *chkMedia;
    QCheckBox   *chkDatabases;
    QCheckBox   *chkOther;

    // Controls
    QPushButton *startButton;
    QPushButton *cancelButton;
    QPushButton *openDestButton;
    QPushButton *exportButton;

    // Results
    QTableWidget *resultsTable;
    QProgressBar *progressBar;
    QLabel       *progressLabel;
    QTextEdit    *logText;

    // State
    ForensicEngine         *engine;
    QList<RecoveryResult>   results;
    bool                    scanning;
};

#endif // PURGEX_FORENSICWIDGET_H
