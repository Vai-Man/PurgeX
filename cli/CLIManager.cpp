#include "CLIManager.h"
#include <QFileInfo>
#include <QDir>
#include <QTimer>
#include <QEventLoop>
#include <atomic>
#include <csignal>

#ifdef _WIN32
#include <windows.h>
#endif

namespace {
std::atomic<bool> g_interrupted{false};

#ifdef _WIN32
BOOL WINAPI consoleHandler(DWORD ctrlType)
{
    if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_BREAK_EVENT) {
        g_interrupted = true;
        return TRUE; // handled: let the event loop cancel gracefully
    }
    return FALSE;
}
#else
void signalHandler(int) { g_interrupted = true; }
#endif
} // namespace

CLIManager::CLIManager(QCoreApplication *app, const CliStreams &streams, QObject *parent)
    : QObject(parent), app(app), inFile(streams.in), out(streams.out), err(streams.err) {
    wipeEngine = new WipeEngine(this);
    certManager = new CertManager(this);
    setupParser();

#ifdef _WIN32
    SetConsoleCtrlHandler(consoleHandler, TRUE);
#else
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);
#endif
}

void CLIManager::setupParser() {
    parser.setApplicationDescription(
        "PurgeX - secure data erasure and file recovery.\n"
        "Wiping follows the NIST SP 800-88 Rev. 1 Clear/Purge approach.");
    helpOption = parser.addHelpOption();
    versionOption = parser.addVersionOption();

    parser.addOption({"verbose", "Print every progress update on its own line."});
    parser.addOption({"pattern", "Wipe pattern: zero, one, random, alternating, nist1, nist3, nist7, dod3, dod7, gutmann (default: nist3).", "pattern", "nist3"});
    parser.addOption({"passes", "Number of passes for zero/one/random/alternating (NIST and Gutmann fix their own count).", "passes", "1"});
    parser.addOption({"verify", "Read back and verify the wipe."});
    parser.addOption({"certificate", "Generate a signed PDF + JSON certificate."});
    parser.addOption({"yes", "Do not ask for confirmation before destructive drive operations."});

    parser.addOption({"files", "Wipe a file (repeat the option or add more files as extra arguments).", "file"});
    parser.addOption({"folder", "Wipe a folder and everything in it.", "folder"});
    parser.addOption({"drive", "Target drive / mount point (used with --free-space or --full-drive).", "drive"});
    parser.addOption({"free-space", "Overwrite the free space of --drive."});
    parser.addOption({"full-drive", "Overwrite the entire physical disk behind --drive (DESTRUCTIVE)."});
    parser.addOption({"secure-erase", "Hardware secure erase of a device (Linux; ATA Security Erase / NVMe format).", "device"});
    parser.addOption({"list-drives", "List detected drives."});
    parser.addOption({"verify-cert", "Verify a JSON certificate.", "certificate"});
    parser.addOption({"qr", "With --verify-cert: also check a scanned QR payload against the certificate.", "payload"});

    parser.addOption({"recover", "Recover files from a folder, device or disk image (read-only).", "source"});
    parser.addOption({"output", "Destination folder for recovered files (--recover).", "folder"});
    parser.addOption({"raw", "Treat the --recover source as a raw device / disk image (signature carving)."});
    parser.addOption({"types", "Comma-separated categories for --recover: image,document,archive,media,database,executable,text (default: all but executable/text).", "list"});
    parser.addPositionalArgument("extra", "Additional files for --files.", "[extra-file...]");
}

int CLIManager::usageError(const QString &message) {
    err << "Error: " << message << "\n";
    err << "Run with --help for usage.\n";
    err.flush();
    return 2;
}

bool CLIManager::parsePattern(const QString &name, WipePattern *out) const {
    static const QHash<QString, WipePattern> table = {
        {"zero", WipePattern::ZERO_FILL}, {"one", WipePattern::ONE_FILL},
        {"random", WipePattern::RANDOM}, {"alternating", WipePattern::ALTERNATING},
        {"nist1", WipePattern::NIST_800_88_1_PASS}, {"nist3", WipePattern::NIST_800_88_3_PASS},
        {"nist7", WipePattern::NIST_800_88_7_PASS},
        {"dod3", WipePattern::NIST_800_88_3_PASS}, {"dod7", WipePattern::NIST_800_88_7_PASS}, {"gutmann", WipePattern::GUTMANN_35_PASS}
    };
    const auto it = table.constFind(name.toLower());
    if (it == table.constEnd()) return false;
    *out = it.value();
    return true;
}

bool CLIManager::confirmDestructive(const QString &what) {
    if (parser.isSet("yes")) return true;
    out << "WARNING: " << what << "\nThis permanently destroys data and cannot be undone.\n"
        << "Type YES to continue: ";
    out.flush();
    QTextStream in(inFile);
    return in.readLine().trimmed() == "YES";
}

int CLIManager::run() {
    // parse() instead of process(): on Windows process() would pop up message boxes for
    // --help and for errors, which blocks scripts.
    if (!parser.parse(app->arguments()))
        return usageError(parser.errorText());
    if (parser.isSet(helpOption)) {
        out << parser.helpText() << '\n';
        out.flush();
        return 0;
    }
    if (parser.isSet(versionOption)) {
        out << "PurgeX " << app->applicationVersion() << '\n';
        out.flush();
        return 0;
    }
    verbose = parser.isSet("verbose");

    if (parser.isSet("list-drives")) {
        printDrives();
        return 0;
    }
    if (parser.isSet("verify-cert"))
        return verifyCertificate(parser.value("verify-cert"), parser.value("qr"));
    if (parser.isSet("recover"))
        return runRecovery();

    WipeConfig config;
    config.verify = parser.isSet("verify");
    config.generateCertificate = parser.isSet("certificate");

    if (!parsePattern(parser.value("pattern"), &config.pattern))
        return usageError(QString("Unknown pattern '%1'.").arg(parser.value("pattern")));
    bool ok = false;
    config.passes = parser.value("passes").toInt(&ok);
    if (!ok || config.passes < 1 || config.passes > 99)
        return usageError("--passes must be a number between 1 and 99.");

    if (parser.isSet("files")) {
        config.target = WipeTarget::FILES;
        config.paths = parser.values("files") + parser.positionalArguments();
        return runWipe(config);
    }

    if (parser.isSet("folder")) {
        const QString folder = parser.value("folder");
        if (!QFileInfo(folder).isDir()) return usageError(QString("Folder does not exist: %1").arg(folder));
        config.target = WipeTarget::FOLDERS;
        config.paths = QStringList(folder);
        return runWipe(config);
    }

    if (parser.isSet("secure-erase")) {
        config.target = WipeTarget::SECURE_ERASE;
        config.drive = parser.value("secure-erase");
        if (!confirmDestructive(QString("Hardware secure erase of %1").arg(config.drive))) {
            err << "Aborted.\n";
            return 1;
        }
        return runWipe(config);
    }

    if (parser.isSet("drive")) {
        config.drive = parser.value("drive");
        const bool full = parser.isSet("full-drive");
        if (!full && !parser.isSet("free-space"))
            return usageError("--drive needs --free-space or --full-drive.");
        if (full) {
            config.target = WipeTarget::FULL_DRIVE;
            if (!confirmDestructive(QString("Overwrite the ENTIRE physical disk behind %1").arg(config.drive))) {
                err << "Aborted.\n";
                return 1;
            }
        } else {
            config.target = WipeTarget::FREE_SPACE;
        }
        return runWipe(config);
    }

    return usageError("No command given.");
}

void CLIManager::printDrives() {
    out << "Available drives:\n\n";
    const QList<DriveInfo> drives = wipeEngine->detectDrives();
    if (drives.isEmpty()) {
        out << "No drives detected.\n";
        return;
    }
    for (const DriveInfo &d : drives) {
        out << "Drive:          " << d.mountPoint << "\n"
            << "  Volume:       " << d.device << "\n"
            << "  Physical disk:" << " " << (d.physicalDevice.isEmpty() ? "unknown" : d.physicalDevice) << "\n"
            << "  File system:  " << d.fileSystem << "\n"
            << "  Size:         " << d.totalSize / (1024 * 1024 * 1024) << " GB ("
            << d.freeSize / (1024 * 1024 * 1024) << " GB free)\n"
            << "  Type:         " << (d.isSSD ? "SSD / flash" : "HDD") << "\n"
            << "  Secure erase: " << (d.supportsSecureErase ? "supported" : "not available") << "\n"
            << "  Model:        " << d.model << "\n"
            << "  Serial:       " << d.serial << "\n\n";
    }
}

void CLIManager::onProgress(int percentage, const QString &status) {
    if (verbose) {
        out << QString("[%1%] %2\n").arg(percentage).arg(status);
    } else {
        const QString line = QString("[%1%] %2").arg(percentage).arg(status);
        out << '\r' << line << QString(qMax(0, lastLineLength - line.size()), ' ');
        lastLineLength = line.size();
    }
    out.flush();
}

void CLIManager::onWarning(const QString &message) {
    if (!verbose && lastLineLength > 0) { out << "\n"; out.flush(); lastLineLength = 0; }
    err << "WARNING: " << message << "\n";
    err.flush();
}

int CLIManager::runWipe(const WipeConfig &config) {
    out << "Starting " << (config.target == WipeTarget::SECURE_ERASE ? "hardware secure erase"
                                                                      : WipeEngine::patternName(config.pattern)) << "...\n";
    out.flush();

    WipeWorker worker(config, wipeEngine);
    connect(&worker, &WipeWorker::progress, this, &CLIManager::onProgress);
    connect(&worker, &WipeWorker::warning, this, &CLIManager::onWarning);

    bool success = false;
    QString message;
    QEventLoop loop;
    connect(&worker, &WipeWorker::finished, &loop, [&](bool ok, const QString &msg) {
        success = ok;
        message = msg;
        loop.quit();
    });

    // Ctrl+C only raises a flag; the event loop turns it into a graceful cancel.
    bool cancelAnnounced = false;
    QTimer watchdog;
    watchdog.setInterval(150);
    connect(&watchdog, &QTimer::timeout, &loop, [&] {
        if (g_interrupted && !cancelAnnounced) {
            cancelAnnounced = true;
            out << "\nInterrupt received - cancelling safely...\n";
            out.flush();
            wipeEngine->cancel();
        }
    });
    watchdog.start();

    worker.start();
    loop.exec();
    worker.wait();

    if (lastLineLength > 0) { out << "\n"; lastLineLength = 0; }
    out << "Result: " << (success ? "SUCCESS" : "FAILED") << "\n" << message << "\n";
    out.flush();
    return success ? 0 : 1;
}

int CLIManager::runRecovery() {
    const QString source = parser.value("recover");
    const QString dest = parser.value("output");
    if (dest.isEmpty()) return usageError("--recover needs --output <folder>.");

    ForensicConfig config;
    config.sourcePath = source;
    config.destPath = dest;
    config.mode = parser.isSet("raw") ? ForensicConfig::ScanMode::RawDevice : ForensicConfig::ScanMode::LogicalPath;
    config.rawModeConfirmed = parser.isSet("raw");

    QStringList categories;
    const QStringList wanted = parser.isSet("types")
        ? parser.value("types").split(',', Qt::SkipEmptyParts)
        : QStringList{"image", "document", "archive", "media", "database"};
    for (QString t : wanted) {
        t = t.trimmed();
        if (t.isEmpty()) continue;
        categories << (t.left(1).toUpper() + t.mid(1).toLower());
    }
    config.categories = categories;

    ForensicEngine engine;
    int found = 0;
    bool success = false;
    QString message;
    QEventLoop loop;
    connect(&engine, &ForensicEngine::warning, this, &CLIManager::onWarning);
    connect(&engine, &ForensicEngine::progress, this, &CLIManager::onProgress);
    connect(&engine, &ForensicEngine::fileFound, &loop, [&](const RecoveryResult &r) {
        ++found;
        if (verbose)
            out << QString("  + %1 [%2] %3 bytes, confidence %4\n")
                       .arg(QFileInfo(r.destinationPath).fileName(), r.fileType)
                       .arg(r.recoveredBytes).arg(ForensicEngine::confidenceString(r.confidence));
    });
    connect(&engine, &ForensicEngine::finished, &loop, [&](bool ok, const QString &msg, const QList<RecoveryResult> &) {
        success = ok;
        message = msg;
        loop.quit();
    });

    if (!engine.startScan(config)) return 1; // reason already printed through warning()

    QTimer watchdog;
    watchdog.setInterval(150);
    connect(&watchdog, &QTimer::timeout, &loop, [&] {
        if (g_interrupted) engine.cancel();
    });
    watchdog.start();
    loop.exec();

    if (lastLineLength > 0) { out << "\n"; lastLineLength = 0; }
    out << (success ? "Done: " : "Stopped: ") << message << "\n" << "Recovered files: " << found
        << " -> " << QDir::toNativeSeparators(dest) << "\n";
    out.flush();
    return success ? 0 : 1;
}

int CLIManager::verifyCertificate(const QString &certificateFile, const QString &qrPayload) {
    if (!QFileInfo::exists(certificateFile))
        return usageError(QString("Certificate file does not exist: %1").arg(certificateFile));

    QString message;
    const bool isValid = qrPayload.isEmpty()
        ? certManager->verifyJsonCertificate(certificateFile, &message, nullptr)
        : certManager->verifyQrPayload(certificateFile, qrPayload, &message);
    out << "Status:  " << (isValid ? "AUTHENTIC" : "NOT AUTHENTIC") << "\n" << message << "\n";
    out.flush();
    return isValid ? 0 : 1;
}
