# Quick Start Guide - Java Cryptography Labs

## 🚀 Easiest Way to Test

### Option 1: Run the batch file (RECOMMENDED)

Simply double-click `run_tests.bat` or run in terminal:

```cmd
.\run_tests.bat
```

### Option 2: Run tests manually

```powershell
# Test 1: HMAC
java testMAC

# Test 2: RSA
"Hello" | java testRSA

# Test 3: Digital Signatures Demo
echo 6 | java Lab05_3
```

---

## 📚 Your Lab Programs (Interactive)

### Lab05_1 - DES File Encryption

```cmd
java Lab05_1
```

- Choose encrypt/decrypt
- Select mode (ECB/CBC with padding options)
- Encrypts/decrypts files

### Lab05_2 - RSA File Encryption

```cmd
java Lab05_2
```

- Generate RSA keys
- Encrypt/decrypt files
- Performance comparison

### Lab05_3 - Digital Signatures

```cmd
java Lab05_3
```

- Sign/verify messages
- Sign-and-encrypt workflow
- Interactive demos

---

## 📖 Need More Help?

See **`HOW_TO_RUN_TESTS.md`** for:

- Detailed explanations
- Step-by-step examples
- Troubleshooting guide
- All command options

---

## ✅ Quick Verification

Run these commands to verify everything works:

```powershell
# 1. Check you have Java
java -version

# 2. Check files are compiled
dir *.class

# 3. Run a simple test
java testMAC
```

If you see output without errors, you're all set! 🎉
