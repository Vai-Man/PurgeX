#include "CLIManager.h"
#include <QFileInfo>
#include <QDir>
#include <QTimer>
#include <QEventLoop>
#include <QSocketNotifier>
#include <csignal>
#include <QDebug>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#else
#include <unistd.h>
#endif

CLIManager::CLIManager(QCoreApplication *app, QObject *parent)
    : QObject(parent), app(app), out(stdout), err(stderr), interrupted(false), eventLoop(nullptr) {
    wipeEngine = new WipeEngine(this);
    certManager = new CertManager(this);
    
    connect(wipeEngine, &WipeEngine::progress, this, &CLIManager::onProgress);
    connect(wipeEngine, &WipeEngine::finished, this, &CLIManager::onFinished);
    connect(wipeEngine, &WipeEngine::warning, this, &CLIManager::onWarning);
    
    setupParser();
    setupSignalHandling();
}

void CLIManager::setupParser() {
    parser.setApplicationDescription("PurgeX — Secure Data Wiping Tool\n"
                                   "Built by PurgeX\n"
                                   "Compliant with NIST SP 800-88 standards");
    
    parser.addHelpOption();
    parser.addVersionOption();
    
    // Global options
    parser.addOption(QCommandLineOption("verbose", "Verbose output"));
    parser.addOption(QCommandLineOption("pattern", "Wipe pattern (zero, one, random, alternating, nist1, nist3, nist7)", "pattern", "nist3"));
    parser.addOption(QCommandLineOption("passes", "Number of passes", "passes", "3"));
    parser.addOption(QCommandLineOption("verify", "Verify wipe"));
    parser.addOption(QCommandLineOption("certificate", "Generate certificate"));
    
    // Commands
    parser.addOption(QCommandLineOption("files", "Wipe files", "files"));
    parser.addOption(QCommandLineOption("folder", "Wipe folder", "folder"));
    parser.addOption(QCommandLineOption("drive", "Wipe drive", "drive"));
    parser.addOption(QCommandLineOption("free-space", "Wipe free space only"));
    parser.addOption(QCommandLineOption("full-drive", "Wipe full drive (DANGEROUS)"));
    parser.addOption(QCommandLineOption("secure-erase", "SSD secure erase", "device"));
    parser.addOption(QCommandLineOption("list-drives", "List available drives"));
    parser.addOption(QCommandLineOption("verify-cert", "Verify certificate", "certificate"));
}

void CLIManager::setupSignalHandling() {
    // Set up signal handling for Ctrl+C
#ifdef _WIN32
    // Windows signal handling
    SetConsoleCtrlHandler([](DWORD ctrlType) -> BOOL {
        if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_BREAK_EVENT) {
            QCoreApplication::quit();
            return TRUE;
        }
        return FALSE;
    }, TRUE);
#else
    // Unix signal handling
    signal(SIGINT, [](int) {
        QCoreApplication::quit();
    });
#endif
}

int CLIManager::run() {
    parser.process(*app);
    
    verbose = parser.isSet("verbose");
    
    if (parser.isSet("list-drives")) {
        printDrives();
        return 0;
    }
    
    if (parser.isSet("verify-cert")) {
        return verifyCertificate(parser.value("verify-cert"));
    }
    
    QString pattern = parser.value("pattern");
    int passes = parser.value("passes").toInt();
    bool verify = parser.isSet("verify");
    bool certificate = parser.isSet("certificate");
    
    if (parser.isSet("files")) {
        QStringList files = parser.values("files");
        return wipeFiles(files, pattern, passes, verify, certificate);
    }
    
    if (parser.isSet("folder")) {
        QString folder = parser.value("folder");
        return wipeFolder(folder, pattern, passes, verify, certificate);
    }
    
    if (parser.isSet("drive")) {
        QString drive = parser.value("drive");
        bool fullDrive = parser.isSet("full-drive");
        return wipeDrive(drive, pattern, fullDrive, certificate);
    }
    
    if (parser.isSet("free-space")) {
        QString drive = parser.value("free-space");
        return wipeDrive(drive, pattern, false, certificate);
    }
    
    if (parser.isSet("secure-erase")) {
        QString device = parser.value("secure-erase");
        return secureEraseSSD(device);
    }
    
    // No command specified, show GUI
    return -1;
}

void CLIManager::printUsage() {
    out << "PurgeX — Secure Data Wiping Tool\n\n";
    out << "Usage: purgex [options] [command]\n\n";
    out << "Commands:\n";
    out << "  --files <file1> [file2] ...    Wipe specific files\n";
    out << "  --folder <path>                Wipe entire folder\n";
    out << "  --drive <drive>                Wipe drive (use --full-drive for complete wipe)\n";
    out << "  --free-space <drive>           Wipe only free space on drive\n";
    out << "  --secure-erase <device>        SSD secure erase\n";
    out << "  --list-drives                  List available drives\n";
    out << "  --verify-cert <file>           Verify certificate\n\n";
    out << "Options:\n";
    out << "  --pattern <pattern>            Wipe pattern (zero, one, random, alternating, nist1, nist3, nist7)\n";
    out << "  --passes <number>              Number of passes (default: 3)\n";
    out << "  --verify                       Verify wipe\n";
    out << "  --certificate                  Generate certificate\n";
    out << "  --verbose                      Verbose output\n";
    out << "  --help                         Show this help\n";
    out << "  --version                      Show version\n\n";
    out << "Examples:\n";
    out << "  purgex --files file1.txt file2.txt\n";
    out << "  purgex --folder /path/to/folder --pattern nist7 --passes 7\n";
    out << "  purgex --drive C: --free-space\n";
    out << "  purgex --secure-erase /dev/sda\n";
    out << "  purgex --verify-cert certificate.json\n";
}

void CLIManager::printVersion() {
    out << "PurgeX — Secure Data Wiping Tool\n";
    out << "Built by PurgeX\n";
    out << "Compliant with NIST SP 800-88 standards\n";
}

void CLIManager::printDrives() {
    out << "Available Drives:\n\n";
    
    QList<DriveInfo> drives = wipeEngine->detectDrives();
    if (drives.isEmpty()) {
        out << "No drives detected.\n";
        return;
    }
    
    for (const DriveInfo &drive : drives) {
        out << QString("Drive: %1\n").arg(drive.mountPoint);
        out << QString("  Device: %1\n").arg(drive.device);
        out << QString("  File System: %1\n").arg(drive.fileSystem);
        out << QString("  Total Size: %1 GB\n").arg(drive.totalSize / (1024*1024*1024));
        out << QString("  Free Space: %1 GB\n").arg(drive.freeSize / (1024*1024*1024));
        out << QString("  Type: %1\n").arg(drive.isSSD ? "SSD" : "HDD");
        out << QString("  Secure Erase: %1\n").arg(drive.supportsSecureErase ? "Supported" : "Not Supported");
        out << QString("  Model: %1\n").arg(drive.model);
        out << QString("  Serial: %1\n\n").arg(drive.serial);
    }
}

int CLIManager::wipeFiles(const QStringList &files, const QString &pattern, int passes, bool verify, bool certificate) {
    if (files.isEmpty()) {
        err << "Error: No files specified\n";
        return 1;
    }
    
    // Convert pattern string to enum
    WipePattern wipePattern = WipePattern::NIST_800_88_3_PASS;
    if (pattern == "zero") wipePattern = WipePattern::ZERO_FILL;
    else if (pattern == "one") wipePattern = WipePattern::ONE_FILL;
    else if (pattern == "random") wipePattern = WipePattern::RANDOM;
    else if (pattern == "alternating") wipePattern = WipePattern::ALTERNATING;
    else if (pattern == "nist1") wipePattern = WipePattern::NIST_800_88_1_PASS;
    else if (pattern == "nist3") wipePattern = WipePattern::NIST_800_88_3_PASS;
    else if (pattern == "nist7") wipePattern = WipePattern::NIST_800_88_7_PASS;
    
    out << "Starting file wipe operation...\n";
    out << QString("Files: %1\n").arg(files.join(", "));
    out << QString("Pattern: %1\n").arg(pattern);
    out << QString("Passes: %1\n").arg(passes);
    out << QString("Verify: %1\n").arg(verify ? "Yes" : "No");
    out << QString("Certificate: %1\n\n").arg(certificate ? "Yes" : "No");
    
    eventLoop = new QEventLoop(this);
    connect(wipeEngine, &WipeEngine::finished, eventLoop, &QEventLoop::quit);
    
    bool success = wipeEngine->wipeFiles(files, wipePattern, passes);
    if (success) {
        eventLoop->exec();
    }
    
    return (success && !interrupted) ? 0 : 1;
}

int CLIManager::wipeFolder(const QString &folder, const QString &pattern, int passes, bool verify, bool certificate) {
    if (folder.isEmpty()) {
        err << "Error: No folder specified\n";
        return 1;
    }
    
    QFileInfo folderInfo(folder);
    if (!folderInfo.exists() || !folderInfo.isDir()) {
        err << QString("Error: Folder does not exist: %1\n").arg(folder);
        return 1;
    }
    
    // Convert pattern string to enum
    WipePattern wipePattern = WipePattern::NIST_800_88_3_PASS;
    if (pattern == "zero") wipePattern = WipePattern::ZERO_FILL;
    else if (pattern == "one") wipePattern = WipePattern::ONE_FILL;
    else if (pattern == "random") wipePattern = WipePattern::RANDOM;
    else if (pattern == "alternating") wipePattern = WipePattern::ALTERNATING;
    else if (pattern == "nist1") wipePattern = WipePattern::NIST_800_88_1_PASS;
    else if (pattern == "nist3") wipePattern = WipePattern::NIST_800_88_3_PASS;
    else if (pattern == "nist7") wipePattern = WipePattern::NIST_800_88_7_PASS;
    
    out << "Starting folder wipe operation...\n";
    out << QString("Folder: %1\n").arg(folder);
    out << QString("Pattern: %1\n").arg(pattern);
    out << QString("Passes: %1\n").arg(passes);
    out << QString("Verify: %1\n").arg(verify ? "Yes" : "No");
    out << QString("Certificate: %1\n\n").arg(certificate ? "Yes" : "No");
    
    eventLoop = new QEventLoop(this);
    connect(wipeEngine, &WipeEngine::finished, eventLoop, &QEventLoop::quit);
    
    bool success = wipeEngine->wipeFolder(folder, wipePattern, passes);
    if (success) {
        eventLoop->exec();
    }
    
    return (success && !interrupted) ? 0 : 1;
}

int CLIManager::wipeDrive(const QString &drive, const QString &pattern, bool fullDrive, bool certificate) {
    if (drive.isEmpty()) {
        err << "Error: No drive specified\n";
        return 1;
    }
    
    // Convert pattern string to enum
    WipePattern wipePattern = WipePattern::NIST_800_88_3_PASS;
    if (pattern == "zero") wipePattern = WipePattern::ZERO_FILL;
    else if (pattern == "one") wipePattern = WipePattern::ONE_FILL;
    else if (pattern == "random") wipePattern = WipePattern::RANDOM;
    else if (pattern == "alternating") wipePattern = WipePattern::ALTERNATING;
    else if (pattern == "nist1") wipePattern = WipePattern::NIST_800_88_1_PASS;
    else if (pattern == "nist3") wipePattern = WipePattern::NIST_800_88_3_PASS;
    else if (pattern == "nist7") wipePattern = WipePattern::NIST_800_88_7_PASS;
    
    out << QString("Starting %1 wipe operation...\n").arg(fullDrive ? "full drive" : "free space");
    out << QString("Drive: %1\n").arg(drive);
    out << QString("Pattern: %1\n").arg(pattern);
    out << QString("Certificate: %1\n\n").arg(certificate ? "Yes" : "No");
    
    if (fullDrive) {
        out << "WARNING: This will permanently destroy ALL data on the drive!\n";
        out << "This action cannot be undone. Press Ctrl+C to cancel.\n\n";
    }
    
    eventLoop = new QEventLoop(this);
    connect(wipeEngine, &WipeEngine::finished, eventLoop, &QEventLoop::quit);
    
    bool success;
    if (fullDrive) {
        success = wipeEngine->wipeFullDrive(drive, wipePattern);
    } else {
        success = wipeEngine->wipeFreeSpace(drive, wipePattern);
    }
    
    if (success) {
        eventLoop->exec();
    }
    
    return (success && !interrupted) ? 0 : 1;
}

int CLIManager::secureEraseSSD(const QString &device) {
    if (device.isEmpty()) {
        err << "Error: No device specified\n";
        return 1;
    }
    
    out << "Starting SSD secure erase operation...\n";
    out << QString("Device: %1\n").arg(device);
    out << "WARNING: This will permanently destroy ALL data on the SSD!\n";
    out << "This action cannot be undone. Press Ctrl+C to cancel.\n\n";
    
    eventLoop = new QEventLoop(this);
    connect(wipeEngine, &WipeEngine::finished, eventLoop, &QEventLoop::quit);
    
    bool success = wipeEngine->secureEraseSSD(device);
    if (success) {
        eventLoop->exec();
    }
    
    return (success && !interrupted) ? 0 : 1;
}

int CLIManager::verifyCertificate(const QString &certificateFile) {
    if (certificateFile.isEmpty()) {
        err << "Error: No certificate file specified\n";
        return 1;
    }
    
    QFileInfo certInfo(certificateFile);
    if (!certInfo.exists()) {
        err << QString("Error: Certificate file does not exist: %1\n").arg(certificateFile);
        return 1;
    }
    
    out << "Verifying certificate...\n";
    out << QString("File: %1\n\n").arg(certificateFile);
    
    QString message;
    bool isValid = certManager->verifyJsonCertificate(certificateFile, &message, nullptr);
    
    out << QString("Status: %1\n").arg(isValid ? "AUTHENTIC" : "TAMPERED");
    out << QString("Message: %1\n").arg(message);
    
    return isValid ? 0 : 1;
}

void CLIManager::onProgress(int percentage, const QString &status) {
    if (verbose) {
        out << QString("[%1%] %2\n").arg(percentage).arg(status);
    } else {
        out << QString("\r[%1%] %2").arg(percentage).arg(status);
        out.flush();
    }
}

void CLIManager::onFinished(bool success, const QString &message) {
    out << "\n";
    out << QString("Result: %1\n").arg(success ? "SUCCESS" : "FAILED");
    out << QString("Message: %1\n").arg(message);
}

void CLIManager::onWarning(const QString &message) {
    err << QString("WARNING: %1\n").arg(message);
}

void CLIManager::handleInterrupt() {
    if (interrupted) return; // Already handling interrupt
    
    interrupted = true;
    out << "\n\nInterrupt received (Ctrl+C). Stopping wipe operation...\n";
    out.flush();
    
    // Stop the wipe engine
    if (wipeEngine) {
        wipeEngine->cancel();
    }
    
    // Quit the event loop
    if (eventLoop) {
        eventLoop->quit();
    }
    
    out << "Wipe operation cancelled.\n";
}
