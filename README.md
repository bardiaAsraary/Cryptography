# 🔒 Secure File Checksum & Encryption Tool

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A Python utility for cryptographic file operations with checksum verification and AES-256 encryption.

## 📌 Table of Contents
- [Features](#-features)
- [Installation](#-installation)
- [Usage](#-usage)
- [File Structure](#-file-structure)
- [Technical Details](#-technical-details)
- [Example Workflow](#-example-workflow)
- [Security Notes](#⚠️-security-notes)
- [License](#-license)

## 🌟 Features

### 🔍 Checksum Operations
- **SHA-256** (recommended for security)
- **MD5** (legacy, faster but cryptographically broken)

### 🔐 Encryption/Decryption
- AES-256 symmetric encryption
- Password-based key derivation (PBKDF2HMAC)
- Random salt generation for each operation
- Automatic directory creation (`encrypted/`, `decrypted/`)

## 🛠️ Installation

1. **Clone the repository**:
   ```
   git clone https://github.com/yourusername/secure-file-tool.git
   cd secure-file-tool
   ```

2. **Install dependencies**:
```
pip install -r requirements.txt
```
 **Usage**:
Run the interactive menu:
```
python main.py
```

## 📂 File Structure
```
├── main.py                 # Main application entry point
├── utils/
│   ├── __init__.py         # Package initialization
│   ├── crypto.py           # AES encryption/decryption
│   ├── hashing.py          # SHA256/MD5 implementatis
│   └── helpers.py          # Password validation utilities
├── tests/                  # Test files directory
│   └── sample.txt          # Example test file
├── encrypted/              # Auto-generated encrypted files
├── decrypted/              # Auto-generated decrypted files
└── requirements.txt        # Dependency specifications
```
## ⚙️ Technical Details
**Cryptography Specifications**
| Component          | Implementation           | Security Level          |
|--------------------|--------------------------|-------------------------|
| Hash Algorithm     | SHA-256                  | Military-grade          |
| Encryption         | AES-256-CBC              | NSA-approved            |
| Key Derivation     | PBKDF2HMAC-SHA256        | 100,000 iterations      |
| Salt Generation    | `os.urandom(16)`         | Cryptographically secure|

## Performance Characteristics
### Benchmark results (1MB file)
| Operation       | Time (s) |
|----------------|----------|
| SHA-256 hash   | 0.023    |
| AES-256 encrypt| 0.142    |
| AES-256 decrypt| 0.138    |

## 🔄 Example Workflow
Generate baseline checksum:

```
python main.py
> Option 1
> tests/financial.xlsx
> sha256
```

Output:
```
SHA-256: 9f86d081...a00a08
```

Encrypt the file:
```
> Option 3
> tests/financial.xlsx
> Enter password: ********
```

Decrypt and verify:
```
> Option 4
> encrypted/financial.xlsx.enc
> Enter password: ********
```

Output:
```
✅ Decrypted to decrypted/financial.xlsx
Verification: Match with original checksum
```

## ⚠️ Security Notes
Critical Warnings

🔥 Passwords cannot be recovered - No backdoor exists!

🕵️ Checksums reveal file changes - Even 1-bit flip changes hash completely

🗑️ Securely delete decrypted files after use:
```
shred -u decrypted/secret_file.txt  # Linux
cipher /w:decrypted\file.txt       # Windows
```

## Best Practices
Use passwords with:

12+ characters

Mixed case + numbers + symbols

No dictionary words

Store checksums separately from encrypted files