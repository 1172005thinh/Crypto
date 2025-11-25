# Java Cryptography Architecture - Lab Implementation

## Overview

This project implements Java Cryptography Architecture (JCA) with three main programs for educational purposes:

- **Lab05_1.java** - DES file encryption/decryption with multiple modes
- **Lab05_2.java** - RSA file encryption/decryption with key management
- **Lab05_3.java** - Digital signatures with SHA1withRSA

**WARNING**: These implementations use DES and SHA-1 for educational purposes only. These algorithms are deprecated and should not be used in production systems.

---

## Quick Start

### Prerequisites

- JDK 1.6 or higher (tested with JDK 24)
- Windows, Linux, or Mac OS
- No external dependencies required (uses built-in JCA)

### Installation

1. Navigate to the code directory:

   ```bash
   cd code
   ```

2. Compile all programs:

   ```bash
   javac Lab05_1.java Lab05_2.java Lab05_3.java
   ```

---

## Running Tests

### Automated Tests

Run all tests automatically:

**Windows:**

```bash
run_tests.bat
```

**PowerShell/Linux:**

```bash
# Test HMAC
java testMAC

# Test RSA
echo "Hello RSA" | java testRSA

# Test Digital Signatures (auto demo)
echo "6" | java Lab05_3
```

### Manual Tests

Run individual test programs:

```bash
# Test 1: HMAC Message Authentication
java testMAC

# Test 2: RSA String Encryption
java testRSA
# (Enter a message when prompted)

# Test 3: DES File Encryption (legacy)
java EncryptFile test.txt
java DecryptFile
```

---

## Program Usage

### Lab05_1: DES File Encryption

**Description**: Encrypts/decrypts files using DES with 4 different modes.

**Run:**

```bash
java Lab05_1
```

**Interactive Menu:**

1. Choose action: Encrypt (1) or Decrypt (2)
2. Enter input file name
3. Enter key (8 characters) or key file path
4. Select encryption mode:
   - Mode 1: DES/ECB/PKCS5Padding
   - Mode 2: DES/ECB/NoPadding
   - Mode 3: DES/CBC/PKCS5Padding
   - Mode 4: DES/CBC/NoPadding

**Example:**

```plaintext
Choose action (1-Encrypt, 2-Decrypt): 1
Enter input file name: test.txt
Enter key (8 characters): mykey123
Choose mode (1-4): 3
```

**Output:** Creates `output.enc` (encrypted) or `output.dec` (decrypted)

---

### Lab05_2: RSA File Encryption

**Description**: Encrypts/decrypts files using RSA with key generation and management.

**Run:**

```bash
java Lab05_2
```

**Menu Options:**

1. **Generate new key pair**
   - Creates RSA keys (default 2048-bit)
   - Saves as `[name].key` (private) and `[name].pub` (public)

2. **Encrypt file**
   - Requires public key file
   - Processes file in blocks
   - Creates encrypted output file

3. **Decrypt file**
   - Requires private key file
   - Decrypts block-by-block
   - Restores original file

4. **Performance test**
   - Compares RSA vs DES speed
   - Uses 10MB test file
   - Shows timing statistics

**Example Session:**

```plaintext
Choice (1-4): 1
Enter key size (default 2048): [Enter]
Enter base name for key files: mykey

Choice (1-4): 2
Enter public key file name: mykey.pub
Enter file to encrypt: test.txt
Enter output file name: [Enter]
```

---

### Lab05_3: Digital Signatures

**Description**: Implements digital signatures with sign/verify and sign-and-encrypt operations.

**Run:**

```bash
java Lab05_3
```

**Menu Options:**

1. **Generate RSA key pair** - Create signing keys
2. **Sign message** - Create digital signature
3. **Verify signature** - Verify message authenticity
4. **Sign and encrypt** - Sign then encrypt with DES
5. **Decrypt and verify** - Decrypt then verify signature
6. **Demo basic sign/verify** - Automatic demonstration
7. **Demo sign-and-encrypt** - Complete workflow demo

**Quick Demo:**

```bash
# Run automatic demonstration
echo "6" | java Lab05_3
```

**Manual Example:**

```plaintext
Choice (1-7): 1
Enter key size (default 2048): [Enter]
Enter base name for key files: sig_key

Choice (1-7): 2
Enter private key file: sig_key.key
Enter message to sign: Hello World
Enter file to save signature: sig.bin
```

---

## Quick Demos

### Demo 1: DES Encryption/Decryption

```bash
# Create test file
echo "This is a test message" > test_message.txt

# Run Lab05_1 and follow prompts:
# 1 (encrypt) -> test_message.txt -> [Enter] -> mykey123 -> 3
java Lab05_1

# Decrypt the file:
# 2 (decrypt) -> output.enc -> [Enter] -> mykey123 -> 3
java Lab05_1

# Verify files match
cat test_message.txt
cat output.dec
```

### Demo 2: RSA Key Generation and File Encryption

```bash
java Lab05_2
# 1 -> [Enter] -> mykey -> [Enter]
# 2 -> mykey.pub -> test_message.txt -> [Enter]
# 3 -> mykey.key -> output.enc -> [Enter]
```

### Demo 3: Digital Signature Workflow

```bash
# Automatic demo (no input required)
echo "6" | java Lab05_3

# Or run full workflow demo
echo "7" | java Lab05_3
```

---

## File Descriptions

### Lab Programs

- `Lab05_1.java` - DES file encryption with 4 modes
- `Lab05_2.java` - RSA file encryption with key management
- `Lab05_3.java` - Digital signatures with SHA1withRSA

### Test Programs

- `testMAC.java` - HMAC-MD5 message authentication test
- `testRSA.java` - RSA string encryption test
- `EncryptFile.java` - Legacy DES encryption example
- `DecryptFile.java` - Legacy DES decryption example

### Helper Files

- `run_tests.bat` - Automated test runner (Windows)
- `HOW_TO_RUN_TESTS.md` - Detailed testing guide
- `REPORT.md` - Python code analysis report

---

## Performance Notes

### DES Performance

- Fast for large files (100+ MB/s)
- All 4 modes have similar speed
- CBC slightly slower than ECB due to IV

### RSA Performance

- Very slow for large files (< 1 MB/s)
- Block-based processing required
- ~100x slower than DES
- Use hybrid encryption for large files in production

### Timing Measurements

All programs use nanosecond precision timing (`System.nanoTime()`) for accurate performance measurements.

---

## Security Warnings

### Educational Use Only

This implementation uses deprecated algorithms:

- **DES**: 56-bit key (broken by modern standards)
- **ECB Mode**: Does not hide data patterns
- **SHA-1**: Vulnerable to collision attacks

### Production Recommendations

- Use **AES-256** instead of DES
- Use **CBC** or **GCM** mode instead of ECB
- Use **SHA-256** or **SHA-512** instead of SHA-1
- Implement proper key exchange mechanisms
- Add message authentication codes (MAC)

---

## Troubleshooting

### Common Issues

#### Error: "Could not find or load main class"

```bash
# Ensure you're in the code directory
cd code
# Recompile
javac Lab05_1.java Lab05_2.java Lab05_3.java
```

#### Error: "File does not exist"

```bash
# Create test file
echo "Test content" > test_message.txt
```

#### Error: "Invalid key length"

```bash
# DES key must be exactly 8 characters
# Example: "mykey123" or "abcdEFGH"
```

#### Error: "With NoPadding, data length must be multiple of 8 bytes"

```bash
# Use PKCS5Padding mode instead
# Or ensure file size is multiple of 8 bytes
```

---

## Additional Resources

- **Detailed Testing Guide**: See `HOW_TO_RUN_TESTS.md` in the code directory
- **Python Analysis**: See `REPORT.md` for original Python code issues
- **Java Cryptography**: [Oracle JCA Documentation](http://download.oracle.com/javase/6/docs/technotes/guides/security/crypto/CryptoSpec.html)

---

## Assignment Submission

Required files:

- `Lab05_1.java`
- `Lab05_2.java`
- `Lab05_3.java`

Package as: `<StudentID>_lab05.zip`

Submission deadline: As announced on Bkel platform
