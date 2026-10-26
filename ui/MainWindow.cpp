#include "MainWindow.h"
#include "ForensicWidget.h"
#include "AuditWidget.h"
#include "../core/AppPaths.h"
#include <QApplication>
#include <QMenuBar>
#include <QStatusBar>
#include <QMessageBox>
#include <QInputDialog>
#include <QDialog>
#include <QGroupBox>
#include <QCheckBox>
#include <QDialogButtonBox>
#include <QDir>
#include <QStandardPaths>
#include <QDesktopServices>
#include <QUrl>
#include <QDateTime>
#include <QCloseEvent>
#include <QDir>
#include <QDirIterator>
#include <QFileInfo>
#include <QFile>
#include <QTextStream>
#include <QJsonDocument>
#include <QSizePolicy>
#include <QJsonObject>
#include <QJsonParseError>

MainWindow::MainWindow(QWidget *parent) : QWidget(parent) {
    wipeEngine = new WipeEngine(this);
    certManager = new CertManager(this);
    
    setupUI();
    setupMenuBar();
    setupStatusBar();
    
    // Note: We connect to worker signals per operation to avoid duplicate messages
    
    driveUpdateTimer = new QTimer(this);
    connect(driveUpdateTimer, &QTimer::timeout, this, &MainWindow::updateDriveList);
    driveUpdateTimer->start(5000); // Update every 5 seconds
    
    updateDriveList();

    // Initialize persistent log file with robust fallbacks
    QStringList logDirs;
    logDirs << AppPaths::logsDir()
            << QDir(QDir::homePath()).filePath("PurgeX/logs")
            << QDir(QDir::currentPath()).filePath("PurgeX/logs");
    for (const QString &dir : logDirs) {
        QDir candidate(dir);
        if (!candidate.exists()) candidate.mkpath(".");
        if (candidate.exists()) {
            logsDirPath = candidate.absolutePath();
            break;
        }
    }
    if (!logsDirPath.isEmpty()) {
        const QString logPath = QDir(logsDirPath).filePath(QString("PurgeX_%1.log")
            .arg(QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss")));
        logFile = new QFile(logPath, this);
        if (logFile->open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text)) {
            logStream = new QTextStream(logFile);
            *logStream << "=== PurgeX session started "
                       << QDateTime::currentDateTime().toString(Qt::ISODate) << " ===\n";
            *logStream << "Log file: " << logFile->fileName() << "\n";
            logStream->flush();
            // Also announce in UI
            log(QString("[INFO] Logging to %1").arg(logFile->fileName()));
        } else {
            log("[WARNING] Failed to open log file for writing.");
        }
    }
    if (logsDirPath.isEmpty()) {
        log("[WARNING] Could not create PurgeX/logs directory. Logging only to UI.");
    }
}

void MainWindow::closeEvent(QCloseEvent *event) {
    if (currentWorker && currentWorker->isRunning()) {
        const auto answer = QMessageBox::question(this, "Operation in progress",
            "A wipe is still running. Closing now cancels it and can leave data partially overwritten.\n\n"
            "Cancel the operation and exit?", QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
        if (answer != QMessageBox::Yes) {
            event->ignore();
            return;
        }
        wipeEngine->cancel();
        currentWorker->wait(30000);
    }
    if (driveUpdateTimer) {
        driveUpdateTimer->stop();
    }
    if (logStream) {
        *logStream << "=== PurgeX session ended "
                   << QDateTime::currentDateTime().toString(Qt::ISODate) << " ===\n";
        logStream->flush();
    }
    // Ensure any child workers are cleaned up by QObject hierarchy
    event->accept();
}

void MainWindow::setupUI() {
    setWindowTitle("PurgeX");
    setMinimumSize(1000, 700);
    
    auto *mainLayout = new QVBoxLayout(this);
    
    // Add menu bar
    auto *menuLayout = new QHBoxLayout();
    auto *titleLabel = new QLabel("PurgeX - Secure Erasure and Recovery", this);
    titleLabel->setObjectName("mainTitle");
    titleLabel->setStyleSheet("font-size: 16px; font-weight: bold; margin: 5px;");
    menuLayout->addWidget(titleLabel);
    menuLayout->addStretch();
    
    auto *aboutButton = new QPushButton("About", this);
    aboutButton->setStyleSheet("padding: 5px 15px; border: none; background: transparent;");
    connect(aboutButton, &QPushButton::clicked, this, &MainWindow::showAbout);
    menuLayout->addWidget(aboutButton);
    
    auto *settingsButton = new QPushButton("Settings", this);
    settingsButton->setStyleSheet("padding: 5px 15px; border: none; background: transparent;");
    connect(settingsButton, &QPushButton::clicked, this, &MainWindow::showSettings);
    menuLayout->addWidget(settingsButton);
    
    mainLayout->addLayout(menuLayout);
    
    // Create tab widget
    tabWidget = new QTabWidget(this);
    
    oneClickWidget = new OneClickWidget(this);
    advancedWidget = new AdvancedWidget(this);
    driveWidget = new DriveWidget(this, wipeEngine);
    certificateWidget = new CertificateWidget(this);
    forensicWidget = new ForensicWidget(this);
    auditWidget    = new AuditWidget(this);
    
    tabWidget->addTab(oneClickWidget,    "One-Click Wipe");
    tabWidget->addTab(advancedWidget,    "Advanced Mode");
    tabWidget->addTab(driveWidget,       "Drive Wiping");
    tabWidget->addTab(forensicWidget,    "File Recovery");
    tabWidget->addTab(certificateWidget, "Certificates");
    tabWidget->addTab(auditWidget,       "Audit History");
    
    mainLayout->addWidget(tabWidget);
    
    // Connect signals
    connect(oneClickWidget, &OneClickWidget::startWipe, this, [this](WipeConfig config) {
        startWorker(config, "One-Click wipe");
    });
    connect(advancedWidget, &AdvancedWidget::startWipe, this, [this](WipeConfig config) {
        startWorker(config, "Advanced wipe");
    });
    connect(driveWidget, &DriveWidget::startWipe, this, [this](const WipeConfig &config) {
        startWorker(config, "Drive operation");
    });
    connect(forensicWidget, &ForensicWidget::recoveryComplete, this, [this]() {
        if (auditWidget) auditWidget->refresh();
    });
}

bool MainWindow::confirmWipe(const WipeConfig &config) {
    QString what;
    switch (config.target) {
        case WipeTarget::FILES:
        case WipeTarget::FOLDERS:
            what = QString("%1 selected item(s) will be overwritten with %2 and then deleted.")
                       .arg(config.paths.size()).arg(WipeEngine::patternName(config.pattern));
            break;
        case WipeTarget::FREE_SPACE:
            what = QString("The free space on %1 will be overwritten with %2. Existing files are not touched, "
                           "but the drive will be nearly full for the duration.")
                       .arg(config.drive).arg(WipeEngine::patternName(config.pattern));
            break;
        default:
            return true; // drive-level operations are confirmed in the Drive tab
    }
    return QMessageBox::warning(this, "Confirm secure wipe",
               what + "\n\nThis cannot be undone. Continue?",
               QMessageBox::Yes | QMessageBox::No, QMessageBox::No) == QMessageBox::Yes;
}

void MainWindow::startWorker(const WipeConfig &config, const QString &label) {
    if (currentWorker) {
        QMessageBox::information(this, "PurgeX", "Another operation is still running. Please wait for it to finish.");
        return;
    }
    if ((config.target == WipeTarget::FILES || config.target == WipeTarget::FOLDERS) && config.paths.isEmpty()) {
        QMessageBox::warning(this, "PurgeX", "No valid targets to wipe.");
        return;
    }
    if (!confirmWipe(config)) return;

    statusProgress->setVisible(true);
    statusProgress->setValue(0);
    cancelButton->setVisible(true);
    cancelButton->setEnabled(true);
    cancelButton->setText("Cancel");
    statusLabel->setText("Initializing...");
    log(QString("[INFO] Starting %1 (%2, %3 target(s))")
            .arg(label, WipeEngine::patternName(config.pattern))
            .arg(config.paths.isEmpty() ? 1 : config.paths.size()));

    currentWorker = new WipeWorker(config, wipeEngine, this);
    connect(currentWorker, &WipeWorker::progress, this, &MainWindow::onWipeProgress);
    connect(currentWorker, &WipeWorker::finished, this, &MainWindow::onWipeFinished);
    connect(currentWorker, &WipeWorker::warning, this, &MainWindow::onWipeWarning);
    // Delete only once the thread has really stopped (QThread::finished, not our result signal).
    connect(currentWorker, &QThread::finished, currentWorker, &QObject::deleteLater);
    currentWorker->start();
}

void MainWindow::setupMenuBar() {
    // Menu bar is now integrated into setupUI method
}

void MainWindow::setupStatusBar() {
    auto *statusLayout = new QHBoxLayout();
    
    statusLabel = new QLabel("Ready", this);
    statusProgress = new QProgressBar(this);
    statusProgress->setVisible(false);
    statusProgress->setRange(0, 100);
    
    cancelButton = new QPushButton("Cancel", this);
    cancelButton->setVisible(false);
    cancelButton->setStyleSheet("padding: 5px 15px; background: #d32f2f; color: white; border-radius: 3px;");
    
    statusLayout->addWidget(statusLabel);
    statusLayout->addWidget(statusProgress);
    statusLayout->addWidget(cancelButton);
    statusLayout->addStretch();
    
    // Add log area
    logText = new QTextEdit(this);
    logText->setMaximumHeight(100);
    logText->setPlaceholderText("Operation log will appear here...");
    
    auto *mainLayout = static_cast<QVBoxLayout*>(layout());
    mainLayout->addLayout(statusLayout);
    mainLayout->addWidget(logText);
    
    // Connect cancel button
    connect(cancelButton, &QPushButton::clicked, this, &MainWindow::onCancelWipe);
}

void MainWindow::updateDriveList() {
    // Probing drives while a wipe holds them open only adds contention.
    if (driveWidget && !currentWorker) {
        driveWidget->updateDriveList();
    }
}

void MainWindow::onWipeProgress(int percentage, const QString &status) {
    statusProgress->setVisible(true);
    cancelButton->setVisible(true);
    statusProgress->setValue(percentage);
    statusLabel->setText(status);
    log(QString("[%1%] %2").arg(percentage).arg(status));
}

void MainWindow::onWipeFinished(bool success, const QString &message) {
    statusProgress->setVisible(false);
    cancelButton->setVisible(false);
    
    // Check if operation was cancelled
    bool wasCancelled = message.contains("cancelled", Qt::CaseInsensitive);
    
    if (wasCancelled) {
        statusLabel->setText("Cancelled");
        log(QString("[CANCELLED] %1").arg(message));
        QMessageBox::information(this, "PurgeX", message);
    } else if (success) {
        statusLabel->setText("Ready");
        log(QString("[SUCCESS] %1").arg(message));
        QMessageBox::information(this, "PurgeX", message);
        // Clear selections so user cannot re-trigger the same wipe
        if (oneClickWidget) oneClickWidget->clearSelection();
        if (advancedWidget) advancedWidget->clearFiles();
    } else {
        statusLabel->setText("Error");
        log(QString("[ERROR] %1").arg(message));
        QMessageBox::warning(this, "PurgeX", message);
    }
    
    // Refresh Audit History tab so the new record appears immediately
    if (auditWidget) auditWidget->refresh();
    
    currentWorker = nullptr;
    cancelButton->setEnabled(true);
    cancelButton->setText("Cancel");
    updateDriveList(); // free space has changed
}


void MainWindow::onWipeWarning(const QString &message) {
    // Warnings can arrive once per file; log them instead of blocking the UI with a dialog each time.
    log(QString("[WARNING] %1").arg(message));
}

void MainWindow::onCancelWipe() {
    if (!currentWorker) return;
    log("[INFO] Cancelling wipe operation...");
    // Never terminate the thread: that would leave the engine locked and files half-written.
    // The engine checks the flag between chunks and the worker reports back via onWipeFinished.
    wipeEngine->cancel();
    cancelButton->setEnabled(false);
    cancelButton->setText("Cancelling...");
    statusLabel->setText("Cancelling...");
}

void MainWindow::log(const QString &line) {
    const QString ts = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss");
    const QString full = QString("[%1] %2").arg(ts, line);
    if (logText) logText->append(full);
    if (logStream) {
        *logStream << full << "\n";
        logStream->flush();
    }
}

void MainWindow::onRefreshAuditLog() {
    if (auditWidget) auditWidget->refresh();
}

void MainWindow::showAbout() {
    QMessageBox::about(this, "About PurgeX",
        "PurgeX - secure data erasure and file recovery\n\n"
        "Version 1.0.0\n"
        "Wiping aligned with NIST SP 800-88 Rev. 1 (Clear / Purge)\n\n"
        "Features:\n"
        "• Secure file, folder, free-space and full-disk wiping\n"
        "• Hardware secure erase (Linux, ATA / NVMe)\n"
        "• Read-only file recovery with signature carving\n"
        "• Signed PDF + JSON certificates with QR verification\n"
        "• Persistent audit history");
}

void MainWindow::showSettings() {
    QDialog settingsDialog(this);
    settingsDialog.setWindowTitle("PurgeX Settings");
    settingsDialog.setFixedSize(400, 300);
    
    auto *layout = new QVBoxLayout(&settingsDialog);
    
    // Theme settings
    auto *themeGroup = new QGroupBox("Theme Settings", &settingsDialog);
    auto *themeLayout = new QVBoxLayout(themeGroup);
    
    auto *darkThemeCheck = new QCheckBox("Enable Dark Theme", themeGroup);
    darkThemeCheck->setChecked(isDarkTheme);
    connect(darkThemeCheck, &QCheckBox::toggled, this, &MainWindow::toggleDarkTheme);
    themeLayout->addWidget(darkThemeCheck);
    
    auto *pitchBlackThemeCheck = new QCheckBox("Enable Pitch Black Theme", themeGroup);
    pitchBlackThemeCheck->setChecked(isPitchBlackTheme);
    connect(pitchBlackThemeCheck, &QCheckBox::toggled, this, &MainWindow::togglePitchBlackTheme);
    themeLayout->addWidget(pitchBlackThemeCheck);
    
    layout->addWidget(themeGroup);
    
    // Other settings (future expansion)
    auto *generalGroup = new QGroupBox("General Settings", &settingsDialog);
    auto *generalLayout = new QVBoxLayout(generalGroup);
    
    auto *enableSoundsCheck = new QCheckBox("Enable Sound Effects", generalGroup);
    enableSoundsCheck->setChecked(true);
    enableSoundsCheck->setEnabled(false); // Placeholder for future feature
    generalLayout->addWidget(enableSoundsCheck);
    
    auto *autoUpdateDrivesCheck = new QCheckBox("Auto-refresh Drive List", generalGroup);
    autoUpdateDrivesCheck->setChecked(true);
    autoUpdateDrivesCheck->setEnabled(false); // Placeholder for future feature
    generalLayout->addWidget(autoUpdateDrivesCheck);
    
    layout->addWidget(generalGroup);
    
    // Dialog buttons
    auto *buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &settingsDialog);
    connect(buttonBox, &QDialogButtonBox::accepted, &settingsDialog, &QDialog::accept);
    connect(buttonBox, &QDialogButtonBox::rejected, &settingsDialog, &QDialog::reject);
    layout->addWidget(buttonBox);
    
    settingsDialog.exec();
}

void MainWindow::applyLightTheme() {
    this->setStyleSheet(
        "QWidget { background-color: #ffffff; color: #000000; }"
        "QMainWindow { background-color: #ffffff; }"
        "QTabWidget::pane { border: 1px solid #c0c0c0; background-color: #ffffff; }"
        "QTabBar::tab { background: #e0e0e0; padding: 8px; margin: 2px; border-radius: 4px; }"
        "QTabBar::tab:selected { background: #ffffff; }"
        "QPushButton { background: #f0f0f0; border: 1px solid #c0c0c0; padding: 8px; border-radius: 4px; }"
        "QPushButton:hover { background: #e0e0e0; }"
        "QPushButton:pressed { background: #d0d0d0; }"
        "QPushButton:disabled { background: #f5f5f5; color: #999999; }"
        "QGroupBox { font-weight: bold; border: 2px solid #c0c0c0; margin: 5px; padding-top: 10px; border-radius: 5px; background-color: #ffffff; }"
        "QGroupBox::title { subcontrol-origin: margin; padding: 0 5px; }"
        "QListWidget { border: 1px solid #c0c0c0; background-color: #ffffff; }"
        "QListWidget::item { background-color: #ffffff; padding: 4px; }"
        "QListWidget::item:selected { background-color: #3daee9; color: #ffffff; }"
        "QListWidget::item:hover { background-color: #e6f3ff; }"
        "QTextEdit { border: 1px solid #c0c0c0; background-color: #ffffff; }"
        "QLineEdit { background-color: #ffffff; border: 1px solid #c0c0c0; padding: 4px; }"
        "QComboBox { background: #ffffff; border: 1px solid #c0c0c0; padding: 4px; }"
        "QComboBox::drop-down { background: #f0f0f0; }"
        "QComboBox QAbstractItemView { background-color: #ffffff; border: 1px solid #c0c0c0; }"
        "QScrollBar:vertical { background: #f0f0f0; width: 16px; }"
        "QScrollBar::handle:vertical { background: #c0c0c0; border-radius: 8px; }"
        "QScrollBar::handle:vertical:hover { background: #a0a0a0; }"
        "QScrollBar:horizontal { background: #f0f0f0; height: 16px; }"
        "QScrollBar::handle:horizontal { background: #c0c0c0; border-radius: 8px; }"
        "QScrollBar::handle:horizontal:hover { background: #a0a0a0; }"
        "QProgressBar { border: 1px solid #c0c0c0; text-align: center; background-color: #ffffff; }"
        "QProgressBar::chunk { background-color: #4CAF50; }"
        "QMenuBar { background-color: #ffffff; }"
        "QMenuBar::item { background-color: transparent; padding: 4px 8px; }"
        "QMenuBar::item:selected { background-color: #e6f3ff; }"
        "QMenu { background-color: #ffffff; border: 1px solid #c0c0c0; }"
        "QMenu::item { padding: 6px 20px; }"
        "QMenu::item:selected { background-color: #e6f3ff; }"
        "QLabel#targetLabel { background-color: #f8f8f8; border: 1px solid #e0e0e0; }"
        "QLabel#driveInfoLabel { background-color: #f8f8f8; border: 1px solid #e0e0e0; }"
    );
    log("[INFO] Light theme enabled");
}

void MainWindow::toggleDarkTheme(bool enabled) {
    isDarkTheme = enabled;
    if (enabled) {
        isPitchBlackTheme = false;
        this->setStyleSheet(
            "QWidget { background-color: #2b2b2b; color: #ffffff; }"
            "QMainWindow { background-color: #2b2b2b; }"
            "QTabWidget::pane { border: 1px solid #404040; background-color: #2b2b2b; }"
            "QTabBar::tab { background: #404040; padding: 8px; margin: 2px; border-radius: 4px; color: #ffffff; }"
            "QTabBar::tab:selected { background: #555555; }"
            "QPushButton { background: #404040; border: 1px solid #555555; padding: 8px; border-radius: 4px; color: #ffffff; }"
            "QPushButton:hover { background: #505050; }"
            "QPushButton:pressed { background: #606060; }"
            "QPushButton:disabled { background: #333333; color: #666666; }"
            "QGroupBox { font-weight: bold; border: 2px solid #555555; margin: 5px; padding-top: 10px; border-radius: 5px; color: #ffffff; background-color: #2b2b2b; }"
            "QGroupBox::title { subcontrol-origin: margin; padding: 0 5px; color: #ffffff; }"
            "QListWidget { border: 1px solid #555555; background-color: #404040; color: #ffffff; }"
            "QListWidget::item { background-color: #404040; color: #ffffff; padding: 4px; }"
            "QListWidget::item:selected { background-color: #606060; color: #ffffff; }"
            "QListWidget::item:hover { background-color: #505050; }"
            "QTextEdit { border: 1px solid #555555; background-color: #404040; color: #ffffff; }"
            "QLineEdit { background-color: #404040; border: 1px solid #555555; color: #ffffff; padding: 4px; }"
            "QComboBox { background: #404040; border: 1px solid #555555; color: #ffffff; padding: 4px; }"
            "QComboBox::drop-down { background: #404040; border: none; }"
            "QComboBox::down-arrow { border: none; }"
            "QComboBox QAbstractItemView { background-color: #404040; color: #ffffff; border: 1px solid #555555; }"
            "QSpinBox { background: #404040; border: 1px solid #555555; color: #ffffff; }"
            "QCheckBox { color: #ffffff; }"
            "QCheckBox::indicator { border: 1px solid #555555; background-color: #404040; }"
            "QCheckBox::indicator:checked { background-color: #4CAF50; }"
            "QRadioButton { color: #ffffff; }"
            "QRadioButton::indicator { border: 1px solid #555555; background-color: #404040; }"
            "QRadioButton::indicator:checked { background-color: #4CAF50; }"
            "QLabel { color: #ffffff; background-color: transparent; }"
            "QFrame { background-color: #2b2b2b; }"
            "QScrollBar:vertical { background: #404040; width: 16px; }"
            "QScrollBar::handle:vertical { background: #606060; border-radius: 8px; }"
            "QScrollBar::handle:vertical:hover { background: #707070; }"
            "QScrollBar:horizontal { background: #404040; height: 16px; }"
            "QScrollBar::handle:horizontal { background: #606060; border-radius: 8px; }"
            "QScrollBar::handle:horizontal:hover { background: #707070; }"
            "QProgressBar { border: 1px solid #555555; text-align: center; background-color: #404040; color: #ffffff; }"
            "QProgressBar::chunk { background-color: #4CAF50; }"
            "QMenuBar { background-color: #2b2b2b; color: #ffffff; }"
            "QMenuBar::item { background-color: transparent; padding: 4px 8px; }"
            "QMenuBar::item:selected { background-color: #404040; }"
            "QMenu { background-color: #404040; color: #ffffff; border: 1px solid #555555; }"
            "QMenu::item { padding: 6px 20px; }"
            "QMenu::item:selected { background-color: #606060; }"
            "QLabel#targetLabel { background-color: #353535; border: 1px solid #555555; color: #ffffff; }"
            "QLabel#driveInfoLabel { background-color: #353535; border: 1px solid #555555; color: #ffffff; }"
        );
        log("[INFO] Dark theme enabled");
    } else {
        applyLightTheme();
    }
}

void MainWindow::togglePitchBlackTheme(bool enabled) {
    isPitchBlackTheme = enabled;
    if (enabled) {
        isDarkTheme = false;
        this->setStyleSheet(
            "QWidget { background-color: #000000; color: #ffffff; }"
            "QMainWindow { background-color: #000000; }"
            "QTabWidget::pane { border: 1px solid #404040; background-color: #000000; }"
            "QTabBar::tab { background: #1F1F1F; padding: 8px; margin: 2px; border-radius: 4px; color: #ffffff; }"
            "QTabBar::tab:selected { background: #2A2A2A; }"
            "QPushButton { background: #8B5CF6; border: none; padding: 12px 24px; border-radius: 8px; color: #ffffff; font-weight: bold; }"
            "QPushButton:hover { background: #7C3AED; }"
            "QPushButton:pressed { background: #6D28D9; }"
            "QPushButton:disabled { background: #525252; color: #A3A3A3; }"
            "QGroupBox { font-weight: bold; border: 2px solid #404040; margin: 5px; padding-top: 10px; border-radius: 8px; color: #10B981; background-color: #1F1F1F; }"
            "QGroupBox::title { subcontrol-origin: margin; padding: 0 8px; color: #10B981; }"
            "QListWidget { border: 1px solid #404040; background-color: #1F1F1F; color: #ffffff; }"
            "QListWidget::item { background-color: #1F1F1F; color: #ffffff; padding: 4px; }"
            "QListWidget::item:selected { background-color: #8B5CF6; color: #ffffff; }"
            "QListWidget::item:hover { background-color: #2A2A2A; }"
            "QTextEdit { border: 1px solid #404040; background-color: #1F1F1F; color: #ffffff; }"
            "QLineEdit { background-color: #1F1F1F; border: 1px solid #404040; color: #ffffff; padding: 8px; border-radius: 6px; }"
            "QComboBox { background: #1F1F1F; border: 1px solid #404040; color: #ffffff; padding: 8px; border-radius: 6px; }"
            "QComboBox::drop-down { background: #1F1F1F; border: none; }"
            "QComboBox QAbstractItemView { background-color: #1F1F1F; color: #ffffff; border: 1px solid #404040; }"
            "QSpinBox { background: #1F1F1F; border: 1px solid #404040; color: #ffffff; padding: 4px; border-radius: 6px; }"
            "QCheckBox { color: #ffffff; }"
            "QCheckBox::indicator { border: 1px solid #404040; background-color: #1F1F1F; }"
            "QCheckBox::indicator:checked { background-color: #10B981; }"
            "QLabel { color: #ffffff; background-color: transparent; }"
            "QFrame { background-color: #000000; }"
            "QScrollBar:vertical { background: #1F1F1F; width: 12px; border-radius: 6px; }"
            "QScrollBar::handle:vertical { background: #404040; border-radius: 6px; }"
            "QScrollBar::handle:vertical:hover { background: #8B5CF6; }"
            "QScrollBar:horizontal { background: #1F1F1F; height: 12px; border-radius: 6px; }"
            "QScrollBar::handle:horizontal { background: #404040; border-radius: 6px; }"
            "QScrollBar::handle:horizontal:hover { background: #8B5CF6; }"
            "QProgressBar { border: 1px solid #404040; text-align: center; background-color: #1F1F1F; color: #ffffff; border-radius: 8px; }"
            "QProgressBar::chunk { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #8B5CF6, stop:1 #10B981); border-radius: 6px; }"
            "QMenuBar { background-color: #000000; color: #ffffff; }"
            "QMenuBar::item { background-color: transparent; padding: 4px 8px; }"
            "QMenuBar::item:selected { background-color: #1F1F1F; }"
            "QMenu { background-color: #1F1F1F; color: #ffffff; border: 1px solid #404040; border-radius: 8px; }"
            "QMenu::item { padding: 8px 16px; border-radius: 4px; }"
            "QMenu::item:selected { background-color: #8B5CF6; }"
            "QLabel#targetLabel { background-color: #1F1F1F; border: 1px solid #404040; color: #ffffff; }"
            "QLabel#driveInfoLabel { background-color: #1F1F1F; border: 1px solid #404040; color: #ffffff; }"
            "QLabel#mainTitle { color: #10B981; font-size: 16px; font-weight: bold; }"
            "QLabel { color: #ffffff; }"
            "QTabWidget::tab-bar { color: #10B981; }"
            "QTabBar::tab { color: #10B981; }"
            "QTabBar::tab:selected { color: #10B981; }"
        );
        log("[INFO] Pitch Black theme enabled");
    } else {
        applyLightTheme();
    }
}

// OneClickWidget Implementation
OneClickWidget::OneClickWidget(QWidget *parent) : QWidget(parent) {
    setupUI();
}

void OneClickWidget::clearSelection() {
    selectedTargets.clear();
    selectedTarget.clear();
    targetType = WipeTarget::FILES;
    targetLabel->setText("No target selected");
    startButton->setEnabled(false);
}

void OneClickWidget::setupUI() {
    auto *layout = new QVBoxLayout(this);
    
    auto *titleLabel = new QLabel("One-Click Secure Wipe", this);
    titleLabel->setStyleSheet("font-size: 18px; font-weight: bold; margin: 10px;");
    layout->addWidget(titleLabel);
    
    auto *infoLabel = new QLabel("Select files, folders, or drives for secure wiping with default settings.", this);
    infoLabel->setWordWrap(true);
    infoLabel->setStyleSheet("margin: 10px; color: #666;");
    layout->addWidget(infoLabel);
    
    auto *buttonLayout = new QHBoxLayout();
    selectButton = new QPushButton("Select Target", this);
    selectButton->setStyleSheet("padding: 15px; font-size: 14px;");
    buttonLayout->addWidget(selectButton);
    buttonLayout->addStretch();
    
    layout->addLayout(buttonLayout);
    
    targetLabel = new QLabel("No target selected", this);
    targetLabel->setObjectName("targetLabel");
    targetLabel->setStyleSheet("margin: 10px; padding: 10px; border-radius: 5px;");
    layout->addWidget(targetLabel);
    
    startButton = new QPushButton("Start Secure Wipe", this);
    startButton->setEnabled(false);
    startButton->setStyleSheet("padding: 15px; font-size: 14px; background: #d32f2f; color: white; border-radius: 5px;");
    layout->addWidget(startButton);
    
    infoLabel = new QLabel("This will permanently delete the selected items using NIST SP 800-88 compliant methods.", this);
    infoLabel->setWordWrap(true);
    infoLabel->setStyleSheet("margin: 10px; color: #d32f2f; font-weight: bold;");
    layout->addWidget(infoLabel);
    
    layout->addStretch();
    
    connect(selectButton, &QPushButton::clicked, this, &OneClickWidget::onSelectTarget);
    connect(startButton, &QPushButton::clicked, this, &OneClickWidget::onStartWipe);

    // Haptic-like feedback: beep and quick visual flash on click for main buttons
    auto addClickFeedback = [](QPushButton *btn){
        if (!btn) return;
        QObject::connect(btn, &QPushButton::pressed, btn, [btn](){ QApplication::beep(); btn->setDown(true); });
        QObject::connect(btn, &QPushButton::released, btn, [btn](){ btn->setDown(false); });
    };
    addClickFeedback(selectButton);
    addClickFeedback(startButton);
}

void OneClickWidget::onSelectTarget() {
    QMessageBox msg(this);
    msg.setWindowTitle("Select Target Type");
    msg.setText("What do you want to wipe?");
    QPushButton *fileBtn = msg.addButton("Files", QMessageBox::AcceptRole);
    QPushButton *folderBtn = msg.addButton("Folders", QMessageBox::DestructiveRole);
    msg.addButton(QMessageBox::Cancel);
    msg.exec();

    if (msg.clickedButton() == fileBtn) {
        QStringList files = QFileDialog::getOpenFileNames(this, "Select Files to Wipe");
        if (!files.isEmpty()) {
            selectedTargets = files;
            targetType = WipeTarget::FILES;
            targetLabel->setText(QString("%1 file(s) selected").arg(files.size()));
            startButton->setEnabled(true);
        }
    } else if (msg.clickedButton() == folderBtn) {
        QString folder = QFileDialog::getExistingDirectory(this, "Select Folder to Wipe");
        if (!folder.isEmpty()) {
            selectedTarget = folder;
            targetType = WipeTarget::FOLDERS;
            targetLabel->setText(QString("Folder: %1").arg(QFileInfo(folder).fileName()));
            startButton->setEnabled(true);
        }
    }
}

void OneClickWidget::onStartWipe() {
    // Ensure a valid selection exists for the chosen target type
    if (targetType == WipeTarget::FILES) {
        if (selectedTargets.isEmpty()) {
            QMessageBox::warning(this, "PurgeX", "Please select at least one file.");
            return;
        }
    } else if (targetType == WipeTarget::FOLDERS) {
        if (selectedTarget.isEmpty()) {
            QMessageBox::warning(this, "PurgeX", "Please select a folder.");
            return;
        }
    } else {
        // Default to files if not set (fixes case where first action is files)
        if (!selectedTargets.isEmpty()) {
            targetType = WipeTarget::FILES;
        }
    }
    
    WipeConfig config;
    config.target = targetType;
    config.pattern = WipePattern::NIST_800_88_3_PASS;
    config.passes = 3;
    config.verify = true;
    config.generateCertificate = true;
    
    if (targetType == WipeTarget::FILES) {
        config.paths = selectedTargets;
    } else {
        config.paths = QStringList(selectedTarget);
    }
    
    emit startWipe(config);
}

// AdvancedWidget Implementation
AdvancedWidget::AdvancedWidget(QWidget *parent) : QWidget(parent) {
    setupUI();
}

void AdvancedWidget::clearFiles() {
    files.clear();
    fileList->clear();
    updateUI();
}

void AdvancedWidget::setupUI() {
    auto *layout = new QVBoxLayout(this);
    
    auto *titleLabel = new QLabel("Advanced Wiping Mode", this);
    titleLabel->setStyleSheet("font-size: 18px; font-weight: bold; margin: 10px;");
    layout->addWidget(titleLabel);
    
    // File list
    auto *listGroup = new QGroupBox("Files and Folders", this);
    auto *listLayout = new QVBoxLayout(listGroup);
    
    fileList = new QListWidget(this);
    fileList->setSelectionMode(QAbstractItemView::ExtendedSelection);
    listLayout->addWidget(fileList);
    
    auto *buttonLayout = new QHBoxLayout();
    addFilesButton = new QPushButton("Add Files", this);
    addFolderButton = new QPushButton("Add Folder", this);
    removeButton = new QPushButton("Remove Selected", this);
    clearButton = new QPushButton("Clear All", this);
    
    buttonLayout->addWidget(addFilesButton);
    buttonLayout->addWidget(addFolderButton);
    buttonLayout->addWidget(removeButton);
    buttonLayout->addWidget(clearButton);
    buttonLayout->addStretch();
    
    listLayout->addLayout(buttonLayout);
    layout->addWidget(listGroup);
    
    // Wipe settings
    auto *settingsGroup = new QGroupBox("Wipe Settings", this);
    auto *settingsLayout = new QGridLayout(settingsGroup);
    
    settingsLayout->addWidget(new QLabel("Pattern:"), 0, 0);
    patternCombo = new QComboBox(this);
    patternCombo->addItem("Zero Fill", static_cast<int>(WipePattern::ZERO_FILL));
    patternCombo->addItem("One Fill", static_cast<int>(WipePattern::ONE_FILL));
    patternCombo->addItem("Random", static_cast<int>(WipePattern::RANDOM));
    patternCombo->addItem("Alternating", static_cast<int>(WipePattern::ALTERNATING));
    patternCombo->addItem("NIST 800-88 (1 pass)", static_cast<int>(WipePattern::NIST_800_88_1_PASS));
    patternCombo->addItem("NIST 800-88 (3 passes)", static_cast<int>(WipePattern::NIST_800_88_3_PASS));
    patternCombo->addItem("NIST 800-88 (7 passes)", static_cast<int>(WipePattern::NIST_800_88_7_PASS));
    patternCombo->addItem("Gutmann (35 passes)", static_cast<int>(WipePattern::GUTMANN_35_PASS));
    patternCombo->setCurrentIndex(5); // Default to NIST 3 passes
    settingsLayout->addWidget(patternCombo, 0, 1);
    
    settingsLayout->addWidget(new QLabel("Passes:"), 1, 0);
    passesSpin = new QSpinBox(this);
    passesSpin->setRange(1, 50);
    passesSpin->setValue(3);
    settingsLayout->addWidget(passesSpin, 1, 1);
    
    verifyCheck = new QCheckBox("Verify wipe", this);
    verifyCheck->setChecked(true);
    settingsLayout->addWidget(verifyCheck, 2, 0);
    
    certificateCheck = new QCheckBox("Generate certificate", this);
    certificateCheck->setChecked(true);
    settingsLayout->addWidget(certificateCheck, 2, 1);
    
    layout->addWidget(settingsGroup);
    
    // Start button
    startButton = new QPushButton("Start Advanced Wipe", this);
    startButton->setStyleSheet("padding: 15px; font-size: 14px; background: #d32f2f; color: white; border-radius: 5px;");
    layout->addWidget(startButton);
    
    layout->addStretch();
    
    connect(addFilesButton, &QPushButton::clicked, this, &AdvancedWidget::onAddFiles);
    connect(addFolderButton, &QPushButton::clicked, this, &AdvancedWidget::onAddFolder);
    connect(removeButton, &QPushButton::clicked, this, &AdvancedWidget::onRemoveSelected);
    connect(clearButton, &QPushButton::clicked, this, &AdvancedWidget::onClearAll);
    connect(startButton, &QPushButton::clicked, this, &AdvancedWidget::onStartWipe);

    // Haptic-like feedback for important buttons
    auto addClickFeedback = [](QPushButton *btn){
        if (!btn) return;
        QObject::connect(btn, &QPushButton::pressed, btn, [btn](){ QApplication::beep(); btn->setDown(true); });
        QObject::connect(btn, &QPushButton::released, btn, [btn](){ btn->setDown(false); });
    };
    addClickFeedback(addFilesButton);
    addClickFeedback(addFolderButton);
    addClickFeedback(removeButton);
    addClickFeedback(clearButton);
    addClickFeedback(startButton);
    connect(patternCombo, static_cast<void (QComboBox::*)(int)>(&QComboBox::currentIndexChanged), this, &AdvancedWidget::onPatternChanged);
    connect(fileList, &QListWidget::itemSelectionChanged, this, &AdvancedWidget::updateUI);
    
    updateUI();
}

void AdvancedWidget::onAddFiles() {
    QStringList fileNames = QFileDialog::getOpenFileNames(this, "Select Files to Wipe");
    for (const QString &fileName : fileNames) {
        if (!files.contains(fileName)) {
            files.append(fileName);
            fileList->addItem(fileName);
        }
    }
    updateUI();
}

void AdvancedWidget::onAddFolder() {
    QString folderName = QFileDialog::getExistingDirectory(this, "Select Folder to Wipe");
    if (!folderName.isEmpty() && !files.contains(folderName)) {
        files.append(folderName);
        fileList->addItem(folderName);
    }
    updateUI();
}

void AdvancedWidget::onRemoveSelected() {
    for (auto *item : fileList->selectedItems()) {
        files.removeAll(item->text());
        delete fileList->takeItem(fileList->row(item));
    }
    updateUI();
}

void AdvancedWidget::onClearAll() {
    files.clear();
    fileList->clear();
    updateUI();
}

void AdvancedWidget::onStartWipe() {
    if (files.isEmpty()) {
        QMessageBox::warning(this, "PurgeX", "Please add files or folders to wipe.");
        return;
    }
    
    WipeConfig config;
    config.target = WipeTarget::FILES;
    config.pattern = static_cast<WipePattern>(patternCombo->currentData().toInt());
    config.passes = passesSpin->value();
    config.verify = verifyCheck->isChecked();
    config.generateCertificate = certificateCheck->isChecked();
    config.paths = files;
    
    emit startWipe(config);
}

void AdvancedWidget::onPatternChanged() {
    WipePattern pattern = static_cast<WipePattern>(patternCombo->currentData().toInt());
    switch (pattern) {
        case WipePattern::NIST_800_88_1_PASS:
            passesSpin->setValue(1);
            break;
        case WipePattern::NIST_800_88_3_PASS:
            passesSpin->setValue(3);
            break;
        case WipePattern::NIST_800_88_7_PASS:
            passesSpin->setValue(7);
            break;
        case WipePattern::GUTMANN_35_PASS:
            passesSpin->setValue(35);
            break;
        default:
            break;
    }
}

void AdvancedWidget::updateUI() {
    bool hasFiles = !files.isEmpty();
    removeButton->setEnabled(hasFiles && !fileList->selectedItems().isEmpty());
    clearButton->setEnabled(hasFiles);
    startButton->setEnabled(hasFiles);
}

// DriveWidget Implementation
DriveWidget::DriveWidget(QWidget *parent, WipeEngine *wipeEngine) : QWidget(parent), wipeEngine(wipeEngine) {
    setupUI();
}

void DriveWidget::setupUI() {
    auto *layout = new QVBoxLayout(this);
    
    auto *titleLabel = new QLabel("Drive Wiping", this);
    titleLabel->setStyleSheet("font-size: 18px; font-weight: bold; margin: 10px;");
    layout->addWidget(titleLabel);
    
    // Drive list
    auto *driveGroup = new QGroupBox("Available Drives", this);
    auto *driveLayout = new QVBoxLayout(driveGroup);
    
    driveList = new QListWidget(this);
    driveList->setSelectionMode(QAbstractItemView::SingleSelection);
    driveLayout->addWidget(driveList);
    
    refreshButton = new QPushButton("Refresh Drives", this);
    driveLayout->addWidget(refreshButton);
    
    layout->addWidget(driveGroup);
    
    // Drive info
    driveInfoLabel = new QLabel("Select a drive to view details", this);
    driveInfoLabel->setObjectName("driveInfoLabel");
    driveInfoLabel->setStyleSheet("margin: 10px; padding: 10px; border-radius: 5px;");
    layout->addWidget(driveInfoLabel);
    
    // Wipe options
    auto *wipeGroup = new QGroupBox("Wipe Options", this);
    auto *wipeLayout = new QVBoxLayout(wipeGroup);
    
    auto *patternLayout = new QHBoxLayout();
    patternLayout->addWidget(new QLabel("Pattern:"));
    patternCombo = new QComboBox(this);
    patternCombo->addItem("Zero Fill", static_cast<int>(WipePattern::ZERO_FILL));
    patternCombo->addItem("One Fill", static_cast<int>(WipePattern::ONE_FILL));
    patternCombo->addItem("Random", static_cast<int>(WipePattern::RANDOM));
    patternCombo->addItem("NIST 800-88 (3 passes)", static_cast<int>(WipePattern::NIST_800_88_3_PASS));
    patternCombo->addItem("Gutmann (35 passes)", static_cast<int>(WipePattern::GUTMANN_35_PASS));
    patternCombo->setCurrentIndex(3);
    patternLayout->addWidget(patternCombo);
    patternLayout->addStretch();
    wipeLayout->addLayout(patternLayout);
    
    // Create horizontal layout for the wipe buttons
    QHBoxLayout *buttonsLayout = new QHBoxLayout();
    
    wipeFreeSpaceButton = new QPushButton("Wipe Free Space", this);
    wipeFreeSpaceButton->setStyleSheet("padding: 10px; background: #ff9800; color: white; border-radius: 5px;");
    wipeFreeSpaceButton->setMinimumHeight(40);
    wipeFreeSpaceButton->setMinimumWidth(150);
    wipeFreeSpaceButton->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    buttonsLayout->addWidget(wipeFreeSpaceButton);
    
    wipeFullDriveButton = new QPushButton("Wipe Full Drive (DANGEROUS)", this);
    wipeFullDriveButton->setStyleSheet("padding: 10px; background: #d32f2f; color: white; border-radius: 5px;");
    wipeFullDriveButton->setMinimumHeight(40);
    wipeFullDriveButton->setMinimumWidth(150);
    wipeFullDriveButton->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    buttonsLayout->addWidget(wipeFullDriveButton);
    
    secureEraseButton = new QPushButton("SSD Secure Erase", this);
    secureEraseButton->setStyleSheet("padding: 10px; background: #9c27b0; color: white; border-radius: 5px;");
    secureEraseButton->setMinimumHeight(40);
    secureEraseButton->setMinimumWidth(150);
    secureEraseButton->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    buttonsLayout->addWidget(secureEraseButton);
    
    // Add the horizontal buttons layout to the main wipe layout
    wipeLayout->addLayout(buttonsLayout);
    
    // Initially disable the buttons until a drive is selected
    wipeFreeSpaceButton->setEnabled(false);
    wipeFullDriveButton->setEnabled(false);
    secureEraseButton->setEnabled(false);
    
    layout->addWidget(wipeGroup);
    layout->addStretch();
    
    connect(refreshButton, &QPushButton::clicked, this, &DriveWidget::onRefreshDrives);
    connect(driveList, &QListWidget::itemSelectionChanged, this, &DriveWidget::onDriveSelected);
    connect(wipeFreeSpaceButton, &QPushButton::clicked, this, &DriveWidget::onWipeFreeSpace);
    connect(wipeFullDriveButton, &QPushButton::clicked, this, &DriveWidget::onWipeFullDrive);
    connect(secureEraseButton, &QPushButton::clicked, this, &DriveWidget::onSecureEraseSSD);

    // Haptic-like feedback for drive actions
    auto addClickFeedback2 = [](QPushButton *btn){
        if (!btn) return;
        QObject::connect(btn, &QPushButton::pressed, btn, [btn](){ QApplication::beep(); btn->setDown(true); });
        QObject::connect(btn, &QPushButton::released, btn, [btn](){ btn->setDown(false); });
    };
    addClickFeedback2(refreshButton);
    addClickFeedback2(wipeFreeSpaceButton);
    addClickFeedback2(wipeFullDriveButton);
    addClickFeedback2(secureEraseButton);
    
    updateDriveList();
}

void DriveWidget::updateDriveList() {
    if (!wipeEngine) return;

    const QList<DriveInfo> fresh = wipeEngine->detectDrives();

    // The list is refreshed on a timer; rebuild only when something changed so the
    // user's selection is not wiped out from under them every few seconds.
    bool same = (fresh.size() == drives.size());
    for (int i = 0; same && i < fresh.size(); ++i)
        same = fresh[i].mountPoint == drives[i].mountPoint
            && fresh[i].freeSize / (1024 * 1024) == drives[i].freeSize / (1024 * 1024)
            && fresh[i].totalSize == drives[i].totalSize;
    if (same && driveList->count() == fresh.size()) return;

    const QString previous = selectedDrive.mountPoint;
    driveList->blockSignals(true);
    driveList->clear();
    drives = fresh;

    int reselect = -1;
    for (int i = 0; i < drives.size(); ++i) {
        const DriveInfo &drive = drives[i];
        QString itemText = QString("%1 (%2) - %3 GB free of %4 GB")
                          .arg(drive.mountPoint, drive.fileSystem)
                          .arg(drive.freeSize / (1024 * 1024 * 1024))
                          .arg(drive.totalSize / (1024 * 1024 * 1024));
        if (drive.isSSD) itemText += " [SSD]";
        if (drive.supportsSecureErase) itemText += " [Secure Erase]";
        driveList->addItem(itemText);
        if (drive.mountPoint == previous) reselect = i;
    }
    if (reselect >= 0) driveList->setCurrentRow(reselect);
    driveList->blockSignals(false);

    if (reselect >= 0) {
        selectedDrive = drives[reselect];
    } else {
        selectedDrive = DriveInfo();
        driveInfoLabel->setText("Select a drive to view details");
    }
    refreshButtons();
}

void DriveWidget::onRefreshDrives() {
    drives.clear();          // force a rebuild
    updateDriveList();
}

void DriveWidget::refreshButtons() {
    const bool have = !selectedDrive.mountPoint.isEmpty();
    wipeFreeSpaceButton->setEnabled(have);
    wipeFullDriveButton->setEnabled(have && !selectedDrive.physicalDevice.isEmpty());
    secureEraseButton->setEnabled(have && selectedDrive.supportsSecureErase);

    if (selectedDrive.isSSD) {
        wipeFreeSpaceButton->setToolTip("Overwrites free space at the host level. On SSDs, wear-leveling and "
                                        "TRIM mean this cannot reach every NAND cell - prefer Secure Erase.");
        wipeFullDriveButton->setToolTip("Overwrites the whole disk at the host level. On SSDs, hardware Secure "
                                        "Erase is the certified method.");
    } else {
        wipeFreeSpaceButton->setToolTip("Overwrite free space with secure patterns");
        wipeFullDriveButton->setToolTip("Overwrite the entire physical disk with secure patterns");
    }
    secureEraseButton->setToolTip(selectedDrive.supportsSecureErase
        ? "Hardware-level secure erase (ATA Security Erase / NVMe format)"
        : "Not available: unsupported by the drive, frozen, or PurgeX lacks root privileges (Linux only)");
}

void DriveWidget::onDriveSelected() {
    const int row = driveList->currentRow();
    if (row < 0 || row >= drives.size()) return;
    selectedDrive = drives[row];

    const QString info = QString("Drive: %1\n"
                                 "Physical disk: %2\n"
                                 "Model: %3   Serial: %4\n"
                                 "File System: %5\n"
                                 "Total Size: %6 GB   Free Space: %7 GB\n"
                                 "Type: %8\n"
                                 "Secure Erase: %9")
                         .arg(selectedDrive.mountPoint,
                              selectedDrive.physicalDevice.isEmpty() ? "unknown" : selectedDrive.physicalDevice,
                              selectedDrive.model, selectedDrive.serial, selectedDrive.fileSystem)
                         .arg(selectedDrive.totalSize / (1024 * 1024 * 1024))
                         .arg(selectedDrive.freeSize / (1024 * 1024 * 1024))
                         .arg(selectedDrive.isSSD ? "SSD / flash" : "HDD",
                              selectedDrive.supportsSecureErase ? "Supported" : "Not available");
    driveInfoLabel->setText(info);
    refreshButtons();
}

void DriveWidget::onWipeFreeSpace() {
    if (selectedDrive.mountPoint.isEmpty()) return;

    WipeConfig config;
    config.target = WipeTarget::FREE_SPACE;
    config.pattern = static_cast<WipePattern>(patternCombo->currentData().toInt());
    config.passes = 1;
    config.verify = true;
    config.drive = selectedDrive.mountPoint;
    config.generateCertificate = true;

    emit startWipe(config);
}

void DriveWidget::onWipeFullDrive() {
    if (selectedDrive.mountPoint.isEmpty() || selectedDrive.physicalDevice.isEmpty()) return;

    if (WipeEngine::isSystemDevice(selectedDrive.device)) {
        QMessageBox::critical(this, "PurgeX",
            QString("%1 is on the disk that runs this operating system (%2).\n\n"
                    "PurgeX will not wipe it. Boot from separate media to erase a system disk.")
                .arg(selectedDrive.mountPoint, selectedDrive.physicalDevice));
        return;
    }

    // Check if running as administrator for physical drive access
    if (!WipeEngine::isRunningAsAdministrator()) {
        int ret = QMessageBox::question(this, "Administrator Required",
            "Physical drive wiping requires Administrator privileges for low-level disk access.\n\n"
            "Would you like to restart PurgeX as Administrator?",
            QMessageBox::Yes | QMessageBox::No, QMessageBox::Yes);

        if (ret == QMessageBox::Yes) {
            if (WipeEngine::requestAdministratorPrivileges()) {
                QApplication::quit();
            } else {
                QMessageBox::warning(this, "PurgeX",
                    "Failed to request Administrator privileges.\n\n"
                    "Please run PurgeX as Administrator (right-click -> Run as administrator) or use sudo.");
            }
        }
        return;
    }

    QString text = QString("You are about to PERMANENTLY DESTROY ALL DATA on the entire disk:\n\n"
                           "    %1  (%2)\n"
                           "    Model: %3   Serial: %4\n"
                           "    Selected volume: %5\n\n"
                           "Every partition on this disk will be erased, not just %5.")
                       .arg(selectedDrive.physicalDevice,
                            QString("%1 GB").arg(selectedDrive.totalSize / (1024 * 1024 * 1024)),
                            selectedDrive.model, selectedDrive.serial, selectedDrive.mountPoint);
    if (selectedDrive.isSSD)
        text += "\n\nThis is an SSD: host-level overwriting cannot guarantee that every NAND cell is erased. "
                "Use Secure Erase for certified sanitization.";
    text += "\n\nThis cannot be undone. Continue?";

    if (QMessageBox::warning(this, "Confirm full-disk wipe", text,
                             QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes)
        return;

    // Second, deliberate confirmation: type the disk name.
    bool ok = false;
    const QString expected = QFileInfo(selectedDrive.physicalDevice).fileName();
    const QString typed = QInputDialog::getText(this, "Final confirmation",
        QString("Type  %1  to confirm:").arg(expected), QLineEdit::Normal, QString(), &ok);
    if (!ok || typed.trimmed().compare(expected, Qt::CaseInsensitive) != 0) {
        QMessageBox::information(this, "PurgeX", "Confirmation did not match. Nothing was changed.");
        return;
    }

    WipeConfig config;
    config.target = WipeTarget::FULL_DRIVE;
    config.pattern = static_cast<WipePattern>(patternCombo->currentData().toInt());
    config.passes = 1;
    config.drive = selectedDrive.device;
    config.generateCertificate = true;

    emit startWipe(config);
}

void DriveWidget::onSecureEraseSSD() {
    if (selectedDrive.physicalDevice.isEmpty() || !selectedDrive.supportsSecureErase) return;

    const int ret = QMessageBox::warning(this, "PurgeX",
        QString("WARNING: hardware secure erase will permanently destroy ALL data on %1\n"
                "(%2, serial %3).\n\n"
                "The drive firmware performs the erase; it cannot be interrupted once started.\n"
                "This cannot be undone. Continue?")
            .arg(selectedDrive.physicalDevice, selectedDrive.model, selectedDrive.serial),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    if (ret != QMessageBox::Yes) return;

    WipeConfig config;
    config.target = WipeTarget::SECURE_ERASE;
    config.drive = selectedDrive.physicalDevice;
    config.generateCertificate = true;

    emit startWipe(config);
}

// CertificateWidget Implementation
CertificateWidget::CertificateWidget(QWidget *parent) : QWidget(parent) {
    setupUI();
}

void CertificateWidget::setupUI() {
    auto *layout = new QVBoxLayout(this);
    
    auto *titleLabel = new QLabel("Certificate Management", this);
    titleLabel->setStyleSheet("font-size: 18px; font-weight: bold; margin: 10px;");
    layout->addWidget(titleLabel);
    
    auto *infoLabel = new QLabel("Verify wipe certificates and manage digital signatures.", this);
    infoLabel->setWordWrap(true);
    infoLabel->setStyleSheet("margin: 10px; color: #666;");
    layout->addWidget(infoLabel);
    
    auto *buttonLayout = new QHBoxLayout();
    verifyButton = new QPushButton("Verify Certificate", this);
    verifyButton->setStyleSheet("padding: 15px; font-size: 14px;");
    openFolderButton = new QPushButton("Open Certificate Folder", this);
    openFolderButton->setStyleSheet("padding: 15px; font-size: 14px;");
    openLogsFolderButton = new QPushButton("Open Logs Folder", this);
    openLogsFolderButton->setStyleSheet("padding: 15px; font-size: 14px;");
    
    buttonLayout->addWidget(verifyButton);
    buttonLayout->addWidget(openFolderButton);
    buttonLayout->addWidget(openLogsFolderButton);
    buttonLayout->addStretch();
    
    layout->addLayout(buttonLayout);
    
    auto *qrRow = new QHBoxLayout();
    qrEdit = new QLineEdit(this);
    qrEdit->setPlaceholderText("Paste the text of a scanned certificate QR code (<hash>_PurgeX)...");
    verifyQrButton = new QPushButton("Verify Scanned QR", this);
    qrRow->addWidget(qrEdit);
    qrRow->addWidget(verifyQrButton);
    layout->addLayout(qrRow);
    connect(verifyQrButton, &QPushButton::clicked, this, &CertificateWidget::onVerifyQr);

    resultText = new QTextEdit(this);
    resultText->setPlaceholderText("Certificate verification results will appear here...");
    resultText->setReadOnly(true);
    layout->addWidget(resultText);
    
    connect(verifyButton, &QPushButton::clicked, this, &CertificateWidget::onVerifyCertificate);
    connect(openFolderButton, &QPushButton::clicked, this, &CertificateWidget::onOpenCertificateFolder);
    connect(openLogsFolderButton, &QPushButton::clicked, this, &CertificateWidget::onOpenLogsFolder);

    // Haptic-like feedback for certificate buttons
    auto addClickFeedback3 = [](QPushButton *btn){
        if (!btn) return;
        QObject::connect(btn, &QPushButton::pressed, btn, [btn](){ QApplication::beep(); btn->setDown(true); });
        QObject::connect(btn, &QPushButton::released, btn, [btn](){ btn->setDown(false); });
    };
    addClickFeedback3(verifyButton);
    addClickFeedback3(openFolderButton);
    addClickFeedback3(openLogsFolderButton);
}

void CertificateWidget::onVerifyCertificate() {
    const QString fileName = QFileDialog::getOpenFileName(this, "Select Certificate to Verify",
                                                          AppPaths::certificatesDir(), "JSON Files (*.json)");
    if (fileName.isEmpty()) return;

    CertManager certManager;
    QString message;
    const bool isValid = certManager.verifyJsonCertificate(fileName, &message, this);

    QString certTimestamp;
    QFile f(fileName);
    if (f.open(QIODevice::ReadOnly)) {
        QJsonParseError pe{};
        const QJsonDocument doc = QJsonDocument::fromJson(f.readAll(), &pe);
        if (pe.error == QJsonParseError::NoError && doc.isObject())
            certTimestamp = doc.object().value("timestamp").toString();
    }
    if (certTimestamp.isEmpty()) certTimestamp = "Unknown";

    resultText->setText(QString("Certificate Verification Result\n\n"
                                "File: %1\n"
                                "Status: %2\n"
                                "Issued: %3\n\n"
                                "%4")
                            .arg(QFileInfo(fileName).fileName(),
                                 isValid ? "AUTHENTIC" : "NOT AUTHENTIC",
                                 certTimestamp, message));
}

void CertificateWidget::onVerifyQr() {
    const QString payload = qrEdit->text().trimmed();
    if (payload.isEmpty()) {
        QMessageBox::information(this, "PurgeX", "Paste the scanned QR text first.");
        return;
    }
    const QString fileName = QFileDialog::getOpenFileName(this, "Select the certificate (.json) to check against",
                                                          AppPaths::certificatesDir(), "JSON Files (*.json)");
    if (fileName.isEmpty()) return;
    CertManager certManager;
    QString message;
    const bool ok = certManager.verifyQrPayload(fileName, payload, &message);
    resultText->setText(QString("QR verification: %1\n\n%2").arg(ok ? "MATCH" : "FAILED", message));
}

void CertificateWidget::onOpenCertificateFolder() {
    const QString certPath = AppPaths::ensureDir(AppPaths::certificatesDir());
    QDesktopServices::openUrl(QUrl::fromLocalFile(certPath));
}

void CertificateWidget::onOpenLogsFolder() {
    const QString logsPath = AppPaths::ensureDir(AppPaths::logsDir());
    QDesktopServices::openUrl(QUrl::fromLocalFile(logsPath));
}
