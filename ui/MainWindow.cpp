#include "MainWindow.h"
#include "ForensicWidget.h"
#include "AuditWidget.h"
#include <QApplication>
#include <QMenuBar>
#include <QStatusBar>
#include <QMessageBox>
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
    logFile = nullptr;
    logStream = nullptr;
    logsDirPath.clear();
    isDarkTheme = false;
    isPitchBlackTheme = false;
    
    setupUI();
    setupMenuBar();
    setupStatusBar();
    
    // Note: We connect to worker signals per operation to avoid duplicate messages
    
    driveUpdateTimer = new QTimer(this);
    connect(driveUpdateTimer, &QTimer::timeout, this, &MainWindow::updateDriveList);
    driveUpdateTimer->start(5000); // Update every 5 seconds
    
    updateDriveList();

    // Initialize persistent log file with robust fallbacks
    QStringList baseDirs;
    baseDirs << QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation)
             << QDir::homePath()
             << QDir::currentPath();
    for (const QString &base : baseDirs) {
        if (base.isEmpty()) continue;
        QDir candidate(QDir(base).filePath("PurgeX/logs"));
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
    auto *titleLabel = new QLabel("PurgeX - Secure Data Wiping Tool", this);
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
        // Expand folder target to individual files for actual wiping
        if (config.target == WipeTarget::FOLDERS && !config.paths.isEmpty()) {
            QString folder = config.paths.first();
            QStringList expanded;
            QDirIterator it(folder, QDir::Files, QDirIterator::Subdirectories);
            while (it.hasNext()) expanded.append(it.next());
            config.target = WipeTarget::FILES;
            config.paths = expanded;
        }

        // Guard: nothing to wipe
        if ((config.target == WipeTarget::FILES && config.paths.isEmpty()) ||
            (config.target == WipeTarget::FREE_SPACE && config.drive.isEmpty()) ||
            (config.target == WipeTarget::FULL_DRIVE && config.drive.isEmpty())) {
            log("[ERROR] No valid targets provided for One-Click wipe.");
            QMessageBox::warning(this, "PurgeX", "No valid targets to wipe.");
            return;
        }

        // Immediate UI feedback
        statusProgress->setVisible(true);
        statusProgress->setValue(0);
        cancelButton->setVisible(true);
        statusLabel->setText("Initializing wipe...");
        // Log initiation
        log(QString("[INFO] Starting One-Click wipe. Targets: %1")
            .arg(config.target == WipeTarget::FILES ? QString::number(config.paths.size()) : config.drive));

        currentWorker = new WipeWorker(config, wipeEngine, this);
        connect(currentWorker, &WipeWorker::progress, this, &MainWindow::onWipeProgress);
        connect(currentWorker, &WipeWorker::finished, this, &MainWindow::onWipeFinished);
        connect(currentWorker, &WipeWorker::warning, this, &MainWindow::onWipeWarning);
        connect(currentWorker, &WipeWorker::finished, currentWorker, &QObject::deleteLater);
        currentWorker->start();
    });
    
        connect(advancedWidget, &AdvancedWidget::startWipe, this, [this](WipeConfig config) {
        // Expand folders to file list to ensure actual wiping occurs
        if (config.target == WipeTarget::FOLDERS || (config.target == WipeTarget::FILES && !config.paths.isEmpty())) {
            QStringList expanded;
            for (const QString &path : config.paths) {
                QFileInfo info(path);
                if (info.isFile()) {
                    expanded.append(path);
                } else if (info.isDir()) {
                    QDirIterator it(path, QDir::Files, QDirIterator::Subdirectories);
                    while (it.hasNext()) expanded.append(it.next());
                }
            }
            config.target = WipeTarget::FILES;
            config.paths = expanded;
        }
        
        // Immediate UI feedback
        statusProgress->setVisible(true);
        statusProgress->setValue(0);
        cancelButton->setVisible(true);
        statusLabel->setText("Initializing advanced wipe...");
        
        // Log initiation  
        log(QString("[INFO] Starting advanced wipe. Files: %1, Pattern: %2")
            .arg(config.paths.size()).arg((int)config.pattern));
        
        currentWorker = new WipeWorker(config, wipeEngine, this);
        connect(currentWorker, &WipeWorker::progress, this, &MainWindow::onWipeProgress);
        connect(currentWorker, &WipeWorker::finished, this, &MainWindow::onWipeFinished);
        connect(currentWorker, &WipeWorker::warning, this, &MainWindow::onWipeWarning);
        connect(currentWorker, &WipeWorker::finished, currentWorker, &QObject::deleteLater);
        currentWorker->start();
    });
    
    connect(driveWidget, &DriveWidget::startWipe, this, [this](const WipeConfig &config) {
        // Immediate UI feedback
        statusProgress->setVisible(true);
        statusProgress->setValue(0);
        cancelButton->setVisible(true);
        statusLabel->setText("Initializing wipe...");
        
        // Log initiation
        log(QString("[INFO] Starting drive wipe. Target: %1, Pattern: %2")
            .arg(config.drive).arg((int)config.pattern));

        currentWorker = new WipeWorker(config, wipeEngine, this);
        connect(currentWorker, &WipeWorker::progress, this, &MainWindow::onWipeProgress);
        connect(currentWorker, &WipeWorker::finished, this, &MainWindow::onWipeFinished);
        connect(currentWorker, &WipeWorker::warning, this, &MainWindow::onWipeWarning);
        connect(currentWorker, &WipeWorker::finished, currentWorker, &QObject::deleteLater);
        currentWorker->start();
    });
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
    if (driveWidget) {
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
    
    // Clear current worker reference
    currentWorker = nullptr;
}


void MainWindow::onWipeWarning(const QString &message) {
    log(QString("[WARNING] %1").arg(message));
    QMessageBox::warning(this, "PurgeX Warning", message);
}

void MainWindow::onCancelWipe() {
    if (currentWorker) {
        log("[INFO] Cancelling wipe operation...");
        wipeEngine->cancel();
        
        // Disable cancel button to prevent multiple clicks
        cancelButton->setEnabled(false);
        cancelButton->setText("Cancelling...");
        
        currentWorker->quit();
        currentWorker->wait(5000); // Wait up to 5 seconds for graceful shutdown
        
        if (currentWorker->isRunning()) {
            // Force terminate if still running
            currentWorker->terminate();
            currentWorker->wait(1000);
        }
        
        currentWorker->deleteLater();
        currentWorker = nullptr;
        
        statusProgress->setVisible(false);
        cancelButton->setVisible(false);
        cancelButton->setEnabled(true);
        cancelButton->setText("Cancel");
        statusLabel->setText("Operation cancelled");
    }
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
        "PurgeX — Secure Data Wiping Tool\n\n"
        "Built by PurgeX\n\n"
        "Compliant with NIST SP 800-88 standards\n"
        "Cross-platform support for Windows, Linux, and Android\n\n"
        "Features:\n"
        "• Secure file and folder wiping\n"
        "• Drive wiping and free space cleaning\n"
        "• SSD secure erase support\n"
        "• Digital wipe certificates\n"
        "• Multiple overwrite patterns");
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
    patternCombo->setCurrentIndex(4); // Default to NIST 3 passes
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
    driveList->clear();
    drives.clear();
    
    if (!wipeEngine) return;
    
    drives = wipeEngine->detectDrives();
    
    for (const DriveInfo &drive : drives) {
        QString itemText = QString("%1 (%2) - %3 free of %4")
                          .arg(drive.mountPoint)
                          .arg(drive.fileSystem)
                          .arg(QString::number(drive.freeSize / (1024*1024*1024)) + " GB")
                          .arg(QString::number(drive.totalSize / (1024*1024*1024)) + " GB");
        
        if (drive.isSSD) itemText += " [SSD]";
        if (drive.supportsSecureErase) itemText += " [Secure Erase]";
        
        driveList->addItem(itemText);
    }
}

void DriveWidget::onRefreshDrives() {
    updateDriveList();
}

void DriveWidget::onDriveSelected() {
    int row = driveList->currentRow();
    if (row >= 0 && row < drives.size()) {
        selectedDrive = drives[row];
        
        QString info = QString("Drive: %1\n"
                              "File System: %2\n"
                              "Total Size: %3 GB\n"
                              "Free Space: %4 GB\n"
                              "Type: %5\n"
                              "Secure Erase: %6")
                      .arg(selectedDrive.mountPoint)
                      .arg(selectedDrive.fileSystem)
                      .arg(selectedDrive.totalSize / (1024*1024*1024))
                      .arg(selectedDrive.freeSize / (1024*1024*1024))
                      .arg(selectedDrive.isSSD ? "SSD" : "HDD")
                      .arg(selectedDrive.supportsSecureErase ? "Supported" : "Not Supported");
        
        driveInfoLabel->setText(info);
        
        // Enable/disable buttons based on drive type
        if (selectedDrive.isSSD) {
            // For SSD: Only enable secure erase, disable overwriting methods
            wipeFreeSpaceButton->setEnabled(false);
            wipeFullDriveButton->setEnabled(false);
            secureEraseButton->setEnabled(selectedDrive.supportsSecureErase);
            
            // Update button text to explain why disabled
            wipeFreeSpaceButton->setToolTip("Not recommended for SSDs - use SSD Secure Erase instead");
            wipeFullDriveButton->setToolTip("Not recommended for SSDs - use SSD Secure Erase instead");
            secureEraseButton->setToolTip("Hardware-level secure erase for SSDs");
        } else {
            // For HDD: Enable overwriting methods, disable secure erase
            wipeFreeSpaceButton->setEnabled(true);
            wipeFullDriveButton->setEnabled(true);
            secureEraseButton->setEnabled(false);
            
            // Update tooltips
            wipeFreeSpaceButton->setToolTip("Overwrite free space with secure patterns");
            wipeFullDriveButton->setToolTip("Overwrite entire drive with secure patterns");
            secureEraseButton->setToolTip("Not available for traditional hard drives");
        }
    }
}

void DriveWidget::onWipeFreeSpace() {
    if (selectedDrive.mountPoint.isEmpty()) return;
    
    WipeConfig config;
    config.target = WipeTarget::FREE_SPACE;
    config.pattern = static_cast<WipePattern>(patternCombo->currentData().toInt());
    config.drive = selectedDrive.mountPoint;
    config.generateCertificate = true;
    
    emit startWipe(config);
}

void DriveWidget::onWipeFullDrive() {
    if (selectedDrive.mountPoint.isEmpty()) return;
    
    // Check if running as administrator for physical drive access
    if (!WipeEngine::isRunningAsAdministrator()) {
        int ret = QMessageBox::question(this, "Administrator Required", 
            "Physical drive wiping requires Administrator privileges for low-level disk access.\n\n"
            "Would you like to restart PurgeX as Administrator?\n\n"
            "Click 'Yes' to restart with elevated privileges, or 'No' to cancel.",
            QMessageBox::Yes | QMessageBox::No, QMessageBox::Yes);
        
        if (ret == QMessageBox::Yes) {
            if (WipeEngine::requestAdministratorPrivileges()) {
                // Successfully requested elevation, the app will restart
                QApplication::quit();
            } else {
                QMessageBox::warning(this, "PurgeX", 
                    "Failed to request Administrator privileges.\n\n"
                    "Please manually run PurgeX as Administrator:\n"
                    "1. Close PurgeX\n"
                    "2. Right-click on PurgeX.exe\n"
                    "3. Select 'Run as administrator'");
            }
        }
        return;
    }
    
    int ret = QMessageBox::warning(this, "PurgeX", 
        "WARNING: This will permanently destroy ALL data on the selected drive!\n\n"
        "This operation will perform low-level physical drive wiping.\n"
        "This action cannot be undone. Are you absolutely sure?",
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    
    if (ret == QMessageBox::Yes) {
        WipeConfig config;
        config.target = WipeTarget::FULL_DRIVE;
        config.pattern = static_cast<WipePattern>(patternCombo->currentData().toInt());
        config.drive = selectedDrive.device;
        config.generateCertificate = true;
        
        emit startWipe(config);
    }
}

void DriveWidget::onSecureEraseSSD() {
    if (selectedDrive.device.isEmpty() || !selectedDrive.supportsSecureErase) return;
    
    int ret = QMessageBox::warning(this, "PurgeX", 
        "WARNING: SSD Secure Erase will permanently destroy ALL data!\n\n"
        "This uses the drive's built-in secure erase command and cannot be undone.",
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    
    if (ret == QMessageBox::Yes) {
        WipeConfig config;
        config.target = WipeTarget::FULL_DRIVE;
        config.pattern = WipePattern::RANDOM; // Not used for secure erase
        config.drive = selectedDrive.device;
        config.generateCertificate = true;
        
        emit startWipe(config);
    }
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
    QString fileName = QFileDialog::getOpenFileName(this, "Select Certificate to Verify", 
                                                   QDir::homePath(), "JSON Files (*.json)");
    if (fileName.isEmpty()) return;
    
    CertManager certManager;
    QString message;
    bool isValid = certManager.verifyJsonCertificate(fileName, &message, this);

    // Read embedded certificate timestamp from JSON for display
    QString certTimestamp;
    QFile f(fileName);
    if (f.open(QIODevice::ReadOnly)) {
        QJsonParseError pe{}; QJsonDocument doc = QJsonDocument::fromJson(f.readAll(), &pe);
        if (pe.error == QJsonParseError::NoError && doc.isObject()) {
            certTimestamp = doc.object().value("timestamp").toString();
        }
        f.close();
    }
    if (certTimestamp.isEmpty()) certTimestamp = "Unknown";
    // Also show where logs are being written
    QString documentsPath = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
    if (documentsPath.isEmpty()) documentsPath = QDir::homePath();
    QString logsPath = QDir(documentsPath).filePath("PurgeX/logs");
    resultText->append(QString("\nLogs Folder: %1").arg(logsPath));

    QString result = QString("Certificate Verification Result:\n\n"
                           "File: %1\n"
                           "Status: %2\n"
                           "Message: %3\n\n"
                           "Timestamp: %4")
                    .arg(QFileInfo(fileName).fileName())
                    .arg(isValid ? "AUTHENTIC" : "TAMPERED")
                    .arg(message)
                    .arg(certTimestamp);

    resultText->setText(result);
}

void CertificateWidget::onOpenCertificateFolder() {
    QString documentsPath = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
    if (documentsPath.isEmpty()) documentsPath = QDir::homePath();
    QString certPath = QDir(documentsPath).filePath("PurgeX/certificates");
    QDir().mkpath(certPath);
    QDesktopServices::openUrl(QUrl::fromLocalFile(certPath));
}

void CertificateWidget::onOpenLogsFolder() {
    QString documentsPath = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
    if (documentsPath.isEmpty()) documentsPath = QDir::homePath();
    QString logsPath = QDir(documentsPath).filePath("PurgeX/logs");
    QDir().mkpath(logsPath);
    QDesktopServices::openUrl(QUrl::fromLocalFile(logsPath));
}
