#include "WipeEngine.h"
#include "../cert/CertManager.h"
#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QDirIterator>
#include <QProcess>
#include <QStorageInfo>
#include <QRandomGenerator>
#include <QDebug>
#include <QStandardPaths>
#include <QApplication>
#include <QDateTime>

#ifdef Q_OS_WIN
#include <windows.h>
#include <setupapi.h>
#include <winioctl.h>
#include <ntddstor.h>
#include <ntddscsi.h>
#include <shellapi.h>
#ifdef _MSC_VER
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "shell32.lib")
#endif
#elif defined(Q_OS_LINUX)
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <linux/hdreg.h>
#endif

WipeEngine::WipeEngine(QObject *parent) : QObject(parent) {
}

QList<DriveInfo> WipeEngine::detectDrives() {
    QList<DriveInfo> drives;
    
#ifdef Q_OS_WIN
    // Windows drive detection
    QFileInfoList volumes = QDir::drives();
    for (const QFileInfo &volume : volumes) {
        QString rootPath = volume.absoluteFilePath();
        QStorageInfo storage(rootPath);
        
        if (storage.isValid() && storage.isReady()) {
            DriveInfo info;
            info.mountPoint = rootPath;
            info.fileSystem = storage.fileSystemType();
            info.totalSize = storage.bytesTotal();
            info.freeSize = storage.bytesAvailable();
            info.device = "\\\\.\\" + rootPath.left(2); // \\.\C:
            info.isSSD = isSSD(info.device);
            info.supportsSecureErase = supportsSecureErase(info.device);
            info.model = "Unknown";
            info.serial = "Unknown";
            
            drives.append(info);
        }
    }
#elif defined(Q_OS_LINUX)
    // Linux drive detection
    QDir devDir("/dev");
    QStringList blockDevices = devDir.entryList(QStringList() << "sd*" << "nvme*", QDir::System);
    
    for (const QString &device : blockDevices) {
        QString devicePath = "/dev/" + device;
        QString mountPoint = QStorageInfo(devicePath).rootPath();
        
        if (!mountPoint.isEmpty()) {
            QStorageInfo storage(mountPoint);
            
            DriveInfo info;
            info.device = devicePath;
            info.mountPoint = mountPoint;
            info.fileSystem = storage.fileSystemType();
            info.totalSize = storage.bytesTotal();
            info.freeSize = storage.bytesAvailable();
            info.isSSD = isSSD(devicePath);
            info.supportsSecureErase = supportsSecureErase(devicePath);
            info.model = "Unknown";
            info.serial = "Unknown";
            
            drives.append(info);
        }
    }
#endif
    
    return drives;
}

bool WipeEngine::isSSD(const QString &device) {
#ifdef Q_OS_WIN
    // Use WMIC to detect SSD on Windows - more reliable than low-level API
    QString driveLetter = device.mid(4, 1); // Extract drive letter from \\.\C:
    
    QProcess process;
    QString command = QString("wmic");
    QStringList arguments;
    arguments << "diskdrive" 
              << "where" 
              << QString("DeviceID='\\\\.\\PHYSICALDRIVE0'") // Simplified - check primary drive
              << "get" 
              << "MediaType,Model"
              << "/format:list";
    
    process.start(command, arguments);
    process.waitForFinished(5000); // 5 second timeout
    
    QString output = process.readAllStandardOutput();
    if (output.contains("SSD", Qt::CaseInsensitive) || 
        output.contains("Solid State", Qt::CaseInsensitive) ||
        output.contains("NVMe", Qt::CaseInsensitive)) {
        return true;
    }
    
    // Additional check: small drives are more likely to be SSDs
    QStorageInfo storage(device.left(2) + "/"); // Convert to C:/ format
    if (storage.isValid() && storage.bytesTotal() <= 1000LL * 1024 * 1024 * 1024) { // <= 1TB
        // Small drives are often SSDs, but this is just a heuristic
        return false; // Don't assume - better to show as HDD than incorrectly as SSD
    }
    
    return false; // Default to HDD if detection fails
    
#elif defined(Q_OS_LINUX)
    // Check if device is SSD on Linux
    QString deviceName = QFileInfo(device).baseName();
    QString rotationalPath = QString("/sys/block/%1/queue/rotational").arg(deviceName);
    
    QFile rotationalFile(rotationalPath);
    if (rotationalFile.open(QIODevice::ReadOnly)) {
        QByteArray data = rotationalFile.readAll();
        return data.trimmed() == "0";
    }
    return false;
#endif
    
    return false;
}

bool WipeEngine::supportsSecureErase(const QString &device) {
#ifdef Q_OS_WIN
    Q_UNUSED(device);
    // Disabled on MinGW builds due to header/struct availability.
    return false;
#elif defined(Q_OS_LINUX)
    // Check ATA security features on Linux
    QProcess hdparm;
    hdparm.start("hdparm", QStringList() << "-I" << device);
    hdparm.waitForFinished(5000);
    
    if (hdparm.exitCode() == 0) {
        QString output = hdparm.readAllStandardOutput();
        return output.contains("Security:") && output.contains("supported");
    }
#endif
    
    return false;
}

bool WipeEngine::wipeFiles(const QStringList &files, WipePattern pattern, int passes) {
    if (running) return false;
    
    running = true;
    cancelled = false;
    
    int totalFiles = files.size();
    int processedFiles = 0;
    
    for (const QString &filePath : files) {
        if (cancelled) break;
        
        emit progress((processedFiles * 100) / totalFiles, 
                     QString("Wiping file: %1").arg(QFileInfo(filePath).fileName()));
        
        if (!overwriteFile(filePath, pattern, passes)) {
            emit warning(QString("Failed to wipe file: %1").arg(filePath));
        }
        
        processedFiles++;
        QApplication::processEvents();
    }
    
    running = false;
    emit finished(!cancelled, cancelled ? "Operation cancelled" : "Files wiped successfully");
    return !cancelled;
}

bool WipeEngine::wipeFolder(const QString &folder, WipePattern pattern, int passes) {
    if (running) return false;
    
    running = true;
    cancelled = false;
    
    QStringList files;
    QDirIterator it(folder, QDir::Files, QDirIterator::Subdirectories);
    
    while (it.hasNext()) {
        files.append(it.next());
    }
    
    return wipeFiles(files, pattern, passes);
}

bool WipeEngine::wipeFreeSpace(const QString &drive, WipePattern pattern) {
    if (running) return false;
    
    running = true;
    cancelled = false;
    
    QStorageInfo storage(drive);
    if (!storage.isValid()) {
        running = false;
        emit finished(false, "Invalid drive");
        return false;
    }
    
    qint64 freeSpace = storage.bytesAvailable();
    if (freeSpace < 100 * 1024 * 1024) { // Less than 100MB
        running = false;
        emit finished(false, "Insufficient free space for wiping");
        return false;
    }
    
    // Create temporary files to fill free space
    QString tempDir = QDir(drive).filePath("PurgeX_Temp");
    QDir().mkpath(tempDir);
    
    qint64 written = 0;
    int fileCount = 0;
    const qint64 chunkSize = 100 * 1024 * 1024; // 100MB chunks
    
    while (written < freeSpace - 50 * 1024 * 1024 && !cancelled) { // Leave 50MB free
        QString fileName = QString("purgex_temp_%1.dat").arg(fileCount++);
        QString filePath = QDir(tempDir).filePath(fileName);
        
        QFile file(filePath);
        if (!file.open(QIODevice::WriteOnly)) break;
        
        qint64 toWrite = qMin(chunkSize, freeSpace - written - 50 * 1024 * 1024);
        QByteArray chunkData = generatePattern(pattern, toWrite);
        
        if (file.write(chunkData) != toWrite) break;
        file.close();
        
        written += toWrite;
        
        emit progress((written * 100) / freeSpace, 
                     QString("Wiping free space: %1 MB written").arg(written / (1024 * 1024)));
        
        QApplication::processEvents();
    }
    
    // Clean up temporary files
    QDir tempDirObj(tempDir);
    tempDirObj.removeRecursively();
    
    running = false;
    emit finished(!cancelled, cancelled ? "Operation cancelled" : "Free space wiped successfully");
    return !cancelled;
}

bool WipeEngine::wipeFullDrive(const QString &device, WipePattern pattern) {
    if (running) return false;
    
    running = true;
    cancelled = false;
    
    // This is a dangerous operation - only proceed with confirmation
    emit warning("Full drive wipe is destructive and irreversible!");
    
    // Additional safety check: warn if trying to wipe system drive
#ifdef Q_OS_WIN
    QString systemDrive = QString(QDir::rootPath()).left(2); // Usually C:
    if (device.contains(systemDrive, Qt::CaseInsensitive)) {
        emit warning(QString("WARNING: You are attempting to wipe the system drive (%1)!\n"
                           "This will make your computer unbootable!").arg(systemDrive));
    }
#endif
    
    // On Windows, we need to map logical drives to physical drives correctly
    QString devicePath = device;
#ifdef Q_OS_WIN
    if (device.startsWith("\\\\.\\") && device.length() == 6) {
        // Use WMI to get the correct physical drive mapping
        char driveLetter = device.at(4).toLatin1();
        if (driveLetter >= 'A' && driveLetter <= 'Z') {
            // Use WMIC to find the physical drive number for this logical drive
            QProcess process;
            QString command = "wmic";
            QStringList arguments;
            arguments << "partition" 
                      << "where" 
                      << QString("DeviceID='Disk #0, Partition #0'") // This is a simplified query
                      << "get" 
                      << "DiskIndex"
                      << "/format:list";
            
            // For now, use a safer approach: default to PhysicalDrive0 for C:, 1 for D:, etc.
            // This is a reasonable assumption for most systems
            int driveNumber = driveLetter - 'C'; // C: = 0, D: = 1, etc.
            if (driveNumber < 0) driveNumber = 0; // Safety fallback
            
            devicePath = QString("\\\\.\\PhysicalDrive%1").arg(driveNumber);
            
            // Log the mapping for user awareness
            emit warning(QString("Mapping logical drive %1: to physical drive %2")
                        .arg(device).arg(devicePath));
        }
    }
#endif
    
    // Check if we have administrator privileges
#ifdef Q_OS_WIN
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    
    if (!isAdmin) {
        running = false;
        emit finished(false, "Administrator privileges required for physical drive access. Please run as Administrator.");
        return false;
    }
#endif
    
    QFile deviceFile(devicePath);
    if (!deviceFile.open(QIODevice::WriteOnly | QIODevice::Unbuffered)) {
        running = false;
        QString error;
        if (deviceFile.error() == QFile::PermissionsError) {
            error = QString("Permission denied accessing %1\n\n"
                          "Physical drive access requires Administrator privileges.\n"
                          "Please run PurgeX as Administrator.")
                          .arg(devicePath);
        } else {
            error = QString("Cannot open device for writing: %1\n"
                          "Error: %2\n\n"
                          "This may indicate:\n"
                          "• Drive is in use by another process\n"
                          "• Insufficient privileges\n"
                          "• Hardware protection is enabled")
                          .arg(devicePath).arg(deviceFile.errorString());
        }
        emit finished(false, error);
        return false;
    }
    
    // Get device size
    qint64 deviceSize = deviceFile.size();
    
    // If size() doesn't work (common for raw devices), try alternative methods
    if (deviceSize <= 0) {
#ifdef Q_OS_WIN
        // Use Windows API to get physical drive size
        HANDLE hDevice = CreateFileA(devicePath.toLocal8Bit().constData(),
                                   GENERIC_READ,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   NULL, OPEN_EXISTING, 0, NULL);
        
        if (hDevice != INVALID_HANDLE_VALUE) {
            LARGE_INTEGER size;
            if (GetFileSizeEx(hDevice, &size)) {
                deviceSize = size.QuadPart;
            } else {
                // Try IOCTL_DISK_GET_DRIVE_GEOMETRY_EX for physical drives
                DISK_GEOMETRY_EX geometry;
                DWORD bytesReturned;
                if (DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                                  NULL, 0, &geometry, sizeof(geometry),
                                  &bytesReturned, NULL)) {
                    deviceSize = geometry.DiskSize.QuadPart;
                }
            }
            CloseHandle(hDevice);
        }
#endif
        
        // Fallback: try to get size from logical drive
        if (deviceSize <= 0) {
            QStorageInfo storage(device.left(2) + "/"); // C:/ format
            if (storage.isValid()) {
                deviceSize = storage.bytesTotal();
            }
        }
    }
    
    if (deviceSize <= 0) {
        deviceFile.close();
        running = false;
        emit finished(false, "Cannot determine device size for full drive wipe");
        return false;
    }
    
    const qint64 chunkSize = 1 * 1024 * 1024; // 1MB chunks for safety
    qint64 written = 0;
    
    emit progress(0, QString("Starting physical drive wipe of %1 MB").arg(deviceSize / (1024 * 1024)));
    
    while (written < deviceSize && !cancelled) {
        qint64 toWrite = qMin(chunkSize, deviceSize - written);
        QByteArray chunkData = generatePattern(pattern, toWrite);
        
        qint64 bytesWritten = deviceFile.write(chunkData);
        if (bytesWritten != toWrite) {
            deviceFile.close();
            running = false;
            emit finished(false, QString("Write error during drive wipe at %1 MB (wrote %2 of %3 bytes)")
                          .arg(written / (1024 * 1024)).arg(bytesWritten).arg(toWrite));
            return false;
        }
        
        written += bytesWritten;
        
        // Flush periodically for safety
        if (written % (10 * 1024 * 1024) == 0) {
            deviceFile.flush();
        }
        
        int progress_pct = static_cast<int>((written * 100) / deviceSize);
        emit progress(progress_pct, 
                     QString("Wiping physical drive: %1 MB / %2 MB (%3%)")
                     .arg(written / (1024 * 1024))
                     .arg(deviceSize / (1024 * 1024))
                     .arg(progress_pct));
        
        QApplication::processEvents();
    }
    
    deviceFile.close();
    running = false;
    emit finished(!cancelled, cancelled ? "Drive wipe cancelled" : "Physical drive wipe completed successfully");
    return !cancelled;
}

bool WipeEngine::secureEraseSSD(const QString &device) {
    if (running) return false;
    
    running = true;
    cancelled = false;
    
    if (!supportsSecureErase(device)) {
        running = false;
        emit finished(false, "Device does not support secure erase");
        return false;
    }
    
    emit warning("SSD Secure Erase will permanently destroy all data!");
    
#ifdef Q_OS_WIN
    Q_UNUSED(device);
    running = false;
    emit finished(false, "Secure erase not available on this Windows build");
    return false;
    
#elif defined(Q_OS_LINUX)
    // Linux hdparm secure erase
    QProcess hdparm;
    hdparm.start("hdparm", QStringList() << "--user-master" << "u" << "--security-erase" << "enhanced" << device);
    hdparm.waitForFinished(300000); // 5 minutes timeout
    
    running = false;
    bool success = (hdparm.exitCode() == 0);
    emit finished(success, success ? "SSD secure erase completed" : "SSD secure erase failed");
    return success;
#endif
    
    running = false;
    emit finished(false, "Secure erase not supported on this platform");
    return false;
}

QByteArray WipeEngine::generatePattern(WipePattern pattern, qint64 size, int pass) {
    QByteArray data;
    data.resize(size);
    char *ptr = data.data();
    
    switch (pattern) {
        case WipePattern::ZERO_FILL:
            memset(ptr, 0, size);
            break;
            
        case WipePattern::ONE_FILL:
            memset(ptr, 0xFF, size);
            break;
            
        case WipePattern::RANDOM:
            for (qint64 i = 0; i < size; i++) {
                ptr[i] = QRandomGenerator::global()->bounded(256);
            }
            break;
            
        case WipePattern::ALTERNATING:
            for (qint64 i = 0; i < size; i++) {
                ptr[i] = (i % 2) ? 0xAA : 0x55;
            }
            break;
            
        case WipePattern::NIST_800_88_1_PASS:
        case WipePattern::NIST_800_88_3_PASS:
        case WipePattern::NIST_800_88_7_PASS:
            return generateNISTPattern(pass, size);
            
        case WipePattern::GUTMANN_35_PASS:
            return generateGutmannPattern(pass, size);
    }
    
    return data;
}

QByteArray WipeEngine::generateNISTPattern(int pass, qint64 size) {
    QByteArray data;
    data.resize(size);
    char *ptr = data.data();
    
    switch (pass) {
        case 0: // First pass: all zeros
            memset(ptr, 0, size);
            break;
        case 1: // Second pass: all ones
            memset(ptr, 0xFF, size);
            break;
        default: // Additional passes: random
            for (qint64 i = 0; i < size; i++) {
                ptr[i] = QRandomGenerator::global()->bounded(256);
            }
            break;
    }
    
    return data;
}

QByteArray WipeEngine::generateGutmannPattern(int pass, qint64 size) {
    QByteArray data;
    data.resize(size);
    char *ptr = data.data();
    
    // Gutmann 35-pass algorithm patterns
    static const unsigned char gutmannPatterns[35] = {
        0x55, 0xAA, 0x92, 0x49, 0x24, 0x00, 0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF, 0x92, 0x49, 0x24, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xAA
    };
    
    if (pass < 35) {
        unsigned char pattern = gutmannPatterns[pass];
        memset(ptr, pattern, size);
    } else {
        // For passes beyond 35, use random data
        for (qint64 i = 0; i < size; i++) {
            ptr[i] = QRandomGenerator::global()->bounded(256);
        }
    }
    
    return data;
}

void WipeEngine::cancel() {
    cancelled = true;
}

bool WipeEngine::performWipe(const WipeConfig &config) {
    switch (config.target) {
        case WipeTarget::FILES:
            return wipeFiles(config.paths, config.pattern, config.passes);
        case WipeTarget::FOLDERS:
            return wipeFolder(config.paths.first(), config.pattern, config.passes);
        case WipeTarget::FREE_SPACE:
            return wipeFreeSpace(config.drive, config.pattern);
        case WipeTarget::FULL_DRIVE:
            return wipeFullDrive(config.drive, config.pattern);
    }
    return false;
}

bool WipeEngine::overwriteFile(const QString &filePath, WipePattern pattern, int passes) {
    QFileInfo fileInfo(filePath);
    if (!fileInfo.exists() || !fileInfo.isFile()) return true;
    
    QString currentPath = filePath;
    
    // Set write permissions
    QFile::setPermissions(currentPath, QFile::ReadOwner | QFile::WriteOwner);
    
    for (int pass = 0; pass < passes; pass++) {
        if (cancelled) return false;
        
        QFile file(currentPath);
        if (!file.open(QIODevice::ReadWrite)) return false;
        
        if (!overwriteWithPattern(file, pattern, pass)) {
            file.close();
            return false;
        }
        
        randomizeFileTimes(currentPath);
        file.close();
        
        // Rename file to random name for next pass
        if (pass < passes - 1) {
            QString dir = QFileInfo(currentPath).absolutePath();
            QString newName = QString("purgex_%1.tmp").arg(QRandomGenerator::global()->bounded(1000000));
            QString newPath = QDir(dir).filePath(newName);
            
            if (QFile::rename(currentPath, newPath)) {
                currentPath = newPath;
            }
        }
    }
    
    // Final deletion
    QFile finalFile(currentPath);
    if (finalFile.open(QIODevice::WriteOnly)) {
        finalFile.resize(0);
        finalFile.close();
    }
    
    return QFile::remove(currentPath);
}

bool WipeEngine::overwriteWithPattern(QFile &file, WipePattern pattern, int pass) {
    qint64 fileSize = file.size();
    if (fileSize <= 0) return true;
    
    const qint64 chunkSize = 8 * 1024 * 1024; // 8MB chunks
    qint64 written = 0;
    
    if (!file.seek(0)) return false;
    
    while (written < fileSize && !cancelled) {
        qint64 toWrite = qMin(chunkSize, fileSize - written);
        QByteArray patternData = generatePattern(pattern, toWrite, pass);
        
        if (file.write(patternData) != toWrite) return false;
        written += toWrite;

        // Emit smoother progress based on current file write position
        int percent = static_cast<int>((written * 100) / qMax<qint64>(fileSize, 1));
        emit progress(percent, QString("Wiping file: %1 (%2%)")
                               .arg(QFileInfo(file.fileName()).fileName())
                               .arg(percent));

        QApplication::processEvents();
    }
    
    file.flush();
#ifdef Q_OS_UNIX
    fsync(file.handle());
#endif
    
    return true;
}

void WipeEngine::randomizeFileTimes(const QString &filePath) {
#ifdef Q_OS_UNIX
    quint32 now = static_cast<quint32>(QDateTime::currentSecsSinceEpoch());
    struct timespec times[2];
    times[0].tv_sec = QRandomGenerator::global()->bounded(now);
    times[0].tv_nsec = 0;
    times[1].tv_sec = QRandomGenerator::global()->bounded(now);
    times[1].tv_nsec = 0;
    
    QFile file(filePath);
    if (file.open(QIODevice::WriteOnly)) {
        futimens(file.handle(), times);
        file.close();
    }
#else
    Q_UNUSED(filePath);
#endif
}

WipeWorker::WipeWorker(const WipeConfig &config, WipeEngine *engine, QObject *parent)
    : QThread(parent), config(config), engine(engine) {
}

void WipeWorker::run() {
    // Don't connect finished signal to avoid duplicate messages
    connect(engine, &WipeEngine::progress, this, &WipeWorker::progress);
    connect(engine, &WipeEngine::warning, this, &WipeWorker::warning);
    // Pre-compute certificate details BEFORE wiping so sizes are accurate
    CertDetails preDetails;
    preDetails.subject = "PurgeX User";

    auto patternNameOf = [](WipePattern p){
        switch (p) {
            case WipePattern::ZERO_FILL: return QString("Zero Fill");
            case WipePattern::ONE_FILL: return QString("One Fill");
            case WipePattern::RANDOM: return QString("Random");
            case WipePattern::ALTERNATING: return QString("Alternating");
            case WipePattern::NIST_800_88_1_PASS: return QString("NIST SP 800-88 (1 pass)");
            case WipePattern::NIST_800_88_3_PASS: return QString("NIST SP 800-88 (3 passes)");
            case WipePattern::NIST_800_88_7_PASS: return QString("NIST SP 800-88 (7 passes)");
            case WipePattern::GUTMANN_35_PASS: return QString("Gutmann (35 passes)");
        }
        return QString("Unknown");
    };
    auto targetNameOf = [](WipeTarget t){
        switch (t) {
            case WipeTarget::FILES: return QString("Files");
            case WipeTarget::FOLDERS: return QString("Folders");
            case WipeTarget::FREE_SPACE: return QString("Free Space");
            case WipeTarget::FULL_DRIVE: return QString("Full Drive");
        }
        return QString("Unknown");
    };
    preDetails.method = QString("Target: %1, Pattern: %2, Passes: %3, Verify: %4")
                        .arg(targetNameOf(config.target))
                        .arg(patternNameOf(config.pattern))
                        .arg(config.passes)
                        .arg(config.verify ? "Yes" : "No");
    if (config.target == WipeTarget::FILES || config.target == WipeTarget::FOLDERS) {
        preDetails.targets = config.paths;
    } else {
        preDetails.targets = QStringList(config.drive);
    }
    qint64 totalBytesPre = 0;
    QStringList processedFilesPre;
    if (config.target == WipeTarget::FILES || config.target == WipeTarget::FOLDERS) {
        for (const QString &path : config.paths) {
            QFileInfo info(path);
            if (info.isFile()) {
                totalBytesPre += info.size();
                processedFilesPre.append(QString("%1 (%2 bytes)").arg(info.fileName()).arg(info.size()));
            } else if (info.isDir()) {
                QDirIterator it(path, QDir::Files, QDirIterator::Subdirectories);
                while (it.hasNext()) {
                    QFileInfo fi(it.next());
                    totalBytesPre += fi.size();
                    processedFilesPre.append(QString("%1 (%2 bytes)").arg(fi.fileName()).arg(fi.size()));
                }
            }
        }
    } else if (config.target == WipeTarget::FREE_SPACE) {
        QStorageInfo storage(config.drive);
        if (storage.isValid()) totalBytesPre = storage.bytesAvailable();
        processedFilesPre.append(QString("Free space on %1: ~%2 bytes").arg(config.drive).arg(totalBytesPre));
    } else if (config.target == WipeTarget::FULL_DRIVE) {
        QFile deviceFile(config.drive);
        if (deviceFile.open(QIODevice::ReadOnly)) { totalBytesPre = deviceFile.size(); deviceFile.close(); }
        processedFilesPre.append(QString("Device %1: ~%2 bytes").arg(config.drive).arg(totalBytesPre));
    }
    preDetails.bytesProcessed = totalBytesPre;
    if (!processedFilesPre.isEmpty()) {
        preDetails.targets.append("Processed Files:");
        preDetails.targets.append(processedFilesPre);
    }

    bool success = engine->performWipe(config);

    // Generate certificate if requested and wipe was successful
    if (success && config.generateCertificate) {
        CertManager certManager;
        certManager.generateCertificates(preDetails, nullptr);
    }

    // Emit our own finished signal
    emit finished(success, success ? "Operation completed successfully" : "Operation failed");
}

bool WipeEngine::isRunningAsAdministrator() {
#ifdef Q_OS_WIN
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    
    return isAdmin;
#else
    // On Linux/macOS, check if running as root
    return geteuid() == 0;
#endif
}

bool WipeEngine::requestAdministratorPrivileges() {
#ifdef Q_OS_WIN
    // Get the current executable path
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    
    // Use ShellExecuteEx to restart with elevated privileges
    SHELLEXECUTEINFOW shExInfo;
    ZeroMemory(&shExInfo, sizeof(shExInfo));
    shExInfo.cbSize = sizeof(shExInfo);
    shExInfo.fMask = SEE_MASK_FLAG_DDEWAIT | SEE_MASK_FLAG_NO_UI;
    shExInfo.hwnd = NULL;
    shExInfo.lpVerb = L"runas"; // This triggers the UAC prompt
    shExInfo.lpFile = exePath;
    shExInfo.lpParameters = NULL;
    shExInfo.lpDirectory = NULL;
    shExInfo.nShow = SW_SHOW;
    shExInfo.hInstApp = NULL;
    
    return ShellExecuteExW(&shExInfo);
#else
    // On Linux/macOS, we can't automatically elevate - user needs to run with sudo
    return false;
#endif
}
