#ifndef PURGEX_MAINWINDOW_H
#define PURGEX_MAINWINDOW_H

#include <QWidget>
#include <QTabWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLabel>
#include <QProgressBar>
#include <QTextEdit>
#include <QGroupBox>
#include <QComboBox>
#include <QSpinBox>
#include <QCheckBox>
#include <QListWidget>
#include <QFileDialog>
#include <QMessageBox>
#include <QTimer>
#include <QStackedWidget>
#include <QFile>
#include <QTextStream>

#include "../core/WipeEngine.h"
#include "../cert/CertManager.h"

class OneClickWidget;
class AdvancedWidget;
class DriveWidget;
class CertificateWidget;
class ForensicWidget;
class AuditWidget;

class MainWindow : public QWidget {
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);

protected:
    void closeEvent(QCloseEvent *event) override;

private slots:
    void onWipeProgress(int percentage, const QString &status);
    void onWipeFinished(bool success, const QString &message);
    void onWipeWarning(const QString &message);
    void onCancelWipe();
    void showAbout();
    void onRefreshAuditLog();

private:
    void setupUI();
    void setupMenuBar();
    void setupStatusBar();
    void updateDriveList();
    void log(const QString &line);
    void showSettings();
    void applyLightTheme();
    void toggleDarkTheme(bool enabled);
    void togglePitchBlackTheme(bool enabled);
    
    QTabWidget *tabWidget;
    OneClickWidget *oneClickWidget;
    AdvancedWidget *advancedWidget;
    DriveWidget *driveWidget;
    CertificateWidget *certificateWidget;
    ForensicWidget *forensicWidget;
    AuditWidget *auditWidget;
    
    WipeEngine *wipeEngine;
    CertManager *certManager;
    
    QLabel *statusLabel;
    QProgressBar *statusProgress;
    QPushButton *cancelButton;
    QTextEdit *logText;
    
    QTimer *driveUpdateTimer;
    WipeWorker *currentWorker;
    QFile *logFile;
    QTextStream *logStream;
    QString logsDirPath;
    bool isDarkTheme;
    bool isPitchBlackTheme;
};

class OneClickWidget : public QWidget {
    Q_OBJECT

public:
    explicit OneClickWidget(QWidget *parent = nullptr);
    void clearSelection();

signals:
    void startWipe(const WipeConfig &config);

private slots:
    void onStartWipe();
    void onSelectTarget();

private:
    void setupUI();
    
    QPushButton *selectButton;
    QLabel *targetLabel;
    QPushButton *startButton;
    QLabel *infoLabel;
    
    QString selectedTarget; // For single folder selection
    QStringList selectedTargets; // For multiple file selection
    WipeTarget targetType;
};

class AdvancedWidget : public QWidget {
    Q_OBJECT

public:
    explicit AdvancedWidget(QWidget *parent = nullptr);
    void clearFiles();

signals:
    void startWipe(const WipeConfig &config);

private slots:
    void onAddFiles();
    void onAddFolder();
    void onRemoveSelected();
    void onClearAll();
    void onStartWipe();
    void onPatternChanged();

private:
    void setupUI();
    void updateUI();
    
    QListWidget *fileList;
    QComboBox *patternCombo;
    QSpinBox *passesSpin;
    QCheckBox *verifyCheck;
    QCheckBox *certificateCheck;
    QPushButton *addFilesButton;
    QPushButton *addFolderButton;
    QPushButton *removeButton;
    QPushButton *clearButton;
    QPushButton *startButton;
    
    QStringList files;
};

class DriveWidget : public QWidget {
    Q_OBJECT

public:
    explicit DriveWidget(QWidget *parent = nullptr, WipeEngine *wipeEngine = nullptr);
    void updateDriveList();

signals:
    void startWipe(const WipeConfig &config);

private slots:
    void onRefreshDrives();
    void onDriveSelected();
    void onWipeFreeSpace();
    void onWipeFullDrive();
    void onSecureEraseSSD();

private:
    void setupUI();
    
    QListWidget *driveList;
    QComboBox *patternCombo;
    QPushButton *refreshButton;
    QPushButton *wipeFreeSpaceButton;
    QPushButton *wipeFullDriveButton;
    QPushButton *secureEraseButton;
    QLabel *driveInfoLabel;
    
    QList<DriveInfo> drives;
    DriveInfo selectedDrive;
    WipeEngine *wipeEngine;
};

class CertificateWidget : public QWidget {
    Q_OBJECT

public:
    explicit CertificateWidget(QWidget *parent = nullptr);

private slots:
    void onVerifyCertificate();
    void onOpenCertificateFolder();
    void onOpenLogsFolder();

private:
    void setupUI();
    
    QPushButton *verifyButton;
    QPushButton *openFolderButton;
    QPushButton *openLogsFolderButton;
    QTextEdit *resultText;
};

#endif // PURGEX_MAINWINDOW_H
