# PurgeX

PurgeX is a cross-platform data sanitization solution designed to address e-waste challenges by providing users with trustworthy, verifiable, and easy-to-use data wiping capabilities. PurgeX offers a comprehensive solution that builds user confidence in device recycling and sanitization, ensuring no sensitive data is left behind.

### Key Features
- **Cross-platform compatibility** (Windows, Linux, macOS)
- **NIST SP 800-88 compliant** data sanitization
- **One-click interface** for easy operation
- **Tamper-proof digital certificates** (PDF + JSON)
- **Offline operation** with no network dependencies
- **Third-party verification** capabilities
- **SSD-aware** secure erase functionality

---

## Architecture

PurgeX uses a multi-layered approach to secure your data:
- **WipeEngine (Core Engine):** Implements multi-pattern wiping algorithms, cross-platform drive detection, and secure erase functionalities.
- **CertManager:** Generates tamper-proof digital certificates and provides cryptographic verification using RSA/SHA256 signatures.
- **Multi-Interface Design:** Offers a One-Click GUI for general users, an Advanced GUI for technical users, and a comprehensive CLI for automation.

---

## Security

### Compliance
PurgeX algorithms align with government and industry standards:
- **NIST SP 800-88** Rev. 1 Guidelines for Media Sanitization
- **DoD 5220.22-M** Department of Defense standard
- **FIPS 140-2** Cryptographic module validation
- **Common Criteria** Security evaluation standard

### Multi-Pass Algorithms
PurgeX implements multiple secure wiping passes:
- **Clear (1 Pass):** Zero fill, One fill, or Cryptographically secure random data.
- **Purge (3-Pass):** Zero fill, followed by One fill, and ending with Cryptographically secure random data.
- **Advanced (7-Pass + Gutmann 35-Pass):** Extended pattern sequences for maximum security on magnetic drives.

---

## Installation and Deployment

### Build Instructions

PurgeX is built using C++ and Qt. 

**Prerequisites:**
- Qt 5.15+ or Qt 6.x
- OpenSSL development libraries
- Platform-specific build tools

**Building from Source:**

**Windows:**
The repository includes an all-in-one batch script that automatically compiles the executable and bundles all required DLL dependencies. Simply double-click it or run it from the terminal:
```cmd
.\build.bat
```
The final standalone executable will be generated inside the `release` folder.

**Linux / macOS:**
```bash
# Clone repository
git clone https://github.com/Vai-Man/PurgeX.git
cd PurgeX

# Build with qmake
qmake PurgeX.pro
make
```

### Command-Line Interface (CLI) Examples

PurgeX includes a powerful command-line interface for advanced operations and automation:

```bash
# Basic file wiping
PurgeX --files file1.txt file2.txt --pattern nist3 --certificate

# Advanced folder wiping  
PurgeX --folder /sensitive/data --pattern gutmann --passes 35 --verify

# Drive operations
PurgeX --drive C: --free-space --pattern random
PurgeX --drive /dev/sda --full-drive --pattern nist7

# SSD secure erase
PurgeX --secure-erase /dev/nvme0n1

# Certificate verification
PurgeX --verify-cert certificate.json
```

---

## Technical Specifications

### System Requirements
| Component | Minimum | Recommended |
|-----------|---------|-------------|
| OS | Windows 10, Ubuntu 18.04, macOS 10.14 | Latest versions |
| RAM | 2 GB | 4 GB and above |
| Storage | 100 MB free space | 1 GB and above |
| CPU | Dual-core 1.5 GHz | Quad-core 2.0 GHz and above |
