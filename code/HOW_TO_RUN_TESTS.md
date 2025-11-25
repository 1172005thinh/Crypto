# How to Run Java Cryptography Tests

## Quick Start Guide for Java Beginners

### Prerequisites

✅ You have JDK 24 installed  
✅ You are in the `code` directory

---

## 1️⃣ Basic Java Commands

### Compile a Java file

```powershell
javac FileName.java
```

### Run a compiled Java program

```powershell
java ClassName
```

### Run with arguments

```powershell
java ClassName argument1 argument2
```

---

## 2️⃣ Running Existing Test Files

### Test 1: HMAC (Message Authentication Code)

Tests HMAC-MD5 for message integrity.

```powershell
# Compile
javac testMAC.java

# Run
java testMAC
```

**Expected output:** Two HMAC digests of the same message

---

### Test 2: RSA Encryption/Decryption

Tests basic RSA string encryption.

```powershell
# Compile
javac testRSA.java

# Run
java testRSA
```

**Expected output:** Original message and encrypted/decrypted versions

---

### Test 3: DES File Encryption (Old Example)

Encrypts a file with DES using the original example.

```powershell
# Compile
javac EncryptFile.java DecryptFile.java

# Encrypt test.txt
java EncryptFile test.txt

# This creates encrypt.des
# To decrypt:
java DecryptFile
```

**Expected output:** Creates `encrypt.des` and `decrypt.txt`

---

## 3️⃣ Running Your New Lab Programs

### Lab05_1: DES File Encryption (Interactive)

```powershell
# Run the program
java Lab05_1
```

**What it does:**

- Prompts you to choose encrypt (1) or decrypt (2)
- Asks for input file name (use: `test_message.txt`)
- Asks for key (type 8 characters like: `mykey123`)
- Lets you choose encryption mode (1-4)
- Creates `output.enc` (encrypted) or `output.dec` (decrypted)

**Example session:**

```plaintext
Choose action (1-Encrypt, 2-Decrypt): 1
Enter input file name: test_message.txt
Enter key file name (or press Enter to type key directly): [press Enter]
Enter key (8 characters): mykey123
Choose mode (1-4): 3
```

---

### Lab05_2: RSA File Encryption (Interactive)

```powershell
# Run the program
java Lab05_2
```

**What it does:**

1. **Generate keys (Option 1):**

   ```plaintext
   Choice (1-4): 1
   Enter key size (default 2048): [press Enter]
   Enter base name for key files: mykey
   ```

   Creates: `mykey.key` and `mykey.pub`

2. **Encrypt file (Option 2):**

   ```plaintext
   Choice (1-4): 2
   Enter public key file name: mykey.pub
   Enter file to encrypt: test_message.txt
   Enter output file name: [press Enter for default]
   ```

3. **Decrypt file (Option 3):**

   ```plaintext
   Choice (1-4): 3
   Enter private key file name: mykey.key
   Enter file to decrypt: output.enc
   ```

4. **Performance test (Option 4):**
   - Automatically creates 10MB test file
   - Compares RSA vs DES speed

---

### Lab05_3: Digital Signatures (Interactive)

```powershell
# Run the program
java Lab05_3
```

**What it does:**

1. **Generate keys (Option 1):**

   ```plaintext
   Choice (1-7): 1
   Enter key size: [press Enter]
   Enter base name: sig_key
   ```

2. **Sign a message (Option 2):**

   ```plaintext
   Choice (1-7): 2
   Enter private key file: sig_key.key
   Enter message to sign: Hello World
   Enter file to save signature: sig.bin
   ```

3. **Verify signature (Option 3):**

   ```plaintext
   Choice (1-7): 3
   Enter public key file: sig_key.pub
   Enter original message: Hello World
   Enter signature file: sig.bin
   ```

4. **Demo basic sign/verify (Option 6):**
   - Runs automatic demo
   - Shows successful and failed verification

5. **Demo sign-and-encrypt (Option 7):**
   - Shows complete workflow
   - Signs message, encrypts with DES, decrypts, verifies

---

## 4️⃣ Quick Test Commands

### Test Everything at Once

```powershell
# 1. Test HMAC
java testMAC

# 2. Test RSA
java testRSA

# 3. Run Lab05_3 demo (automatic, no input needed)
echo "6" | java Lab05_3
```

### Create a test file if needed

```powershell
echo "This is a test message for encryption" > test_message.txt
```

---

## 5️⃣ Common Issues & Solutions

### ❌ Error: "Could not find or load main class"

**Solution:** Make sure you're in the `code` directory:

```powershell
cd d:\Users\HungThinh\Applications\VSCode\MyProject\crypto\code
```

### ❌ Error: "File does not exist"

**Solution:** Create test file first:

```powershell
echo "Test content" > test_message.txt
```

### ❌ Error: "Invalid key length"

**Solution:** Make sure DES key is exactly 8 characters

### ❌ Error: Class not found

**Solution:** Compile first:

```powershell
javac Lab05_1.java Lab05_2.java Lab05_3.java
```

---

## 6️⃣ Step-by-Step Complete Test

Here's a complete test sequence you can run:

```powershell
# Navigate to code directory
cd d:\Users\HungThinh\Applications\VSCode\MyProject\crypto\code

# Make sure everything is compiled
javac Lab05_1.java Lab05_2.java Lab05_3.java testRSA.java testMAC.java

# Test 1: Run HMAC test
Write-Host "`n=== Testing HMAC ===" -ForegroundColor Green
java testMAC

# Test 2: Run RSA test
Write-Host "`n=== Testing RSA ===" -ForegroundColor Green
java testRSA

# Test 3: Lab05_3 demo (automatic)
Write-Host "`n=== Testing Digital Signatures (Demo) ===" -ForegroundColor Green
echo "6" | java Lab05_3

# Done!
Write-Host "`n=== All Tests Completed! ===" -ForegroundColor Green
```

---

## 7️⃣ Testing with File I/O

### Test DES encryption/decryption

```powershell
# Create test file
"Hello World from DES encryption!" | Out-File -FilePath test_message.txt -Encoding UTF8

# Run Lab05_1 with these inputs:
# 1 (encrypt)
# test_message.txt
# [press Enter]
# mykey123
# 3 (CBC/PKCS5)
java Lab05_1

# Then decrypt:
# 2 (decrypt)
# output.enc
# [press Enter]
# mykey123
# 3 (CBC/PKCS5)
java Lab05_1

# Compare files
Get-Content test_message.txt
Get-Content output.dec
```

---

## 8️⃣ Understanding the Output

### DES Encryption Output

```plaintext
Encryption successful!
Mode: DES/CBC/PKCS5Padding
File size: 0.00 MB
Encryption time: 0.0023 seconds
Speed: 0.15 MB/s
```

### RSA Encryption Output

```plaintext
Generating 2048-bit RSA key pair...
Key generation completed in 0.45 seconds
Max block size for encryption: 245 bytes
Encrypted 1 blocks...
Encryption successful!
```

### Digital Signature Output

```plaintext
Signed message (length: 50 bytes)
Signature (length: 256 bytes)
✓ Signature is valid!
```

---

## 🎯 Summary

**To test everything quickly:**

1. Open PowerShell in VS Code (Ctrl + `)
2. Navigate to code directory
3. Run: `java testMAC`
4. Run: `java testRSA`
5. Run: `echo "6" | java Lab05_3` (automatic demo)

**For interactive testing:**

- `java Lab05_1` - Test DES encryption
- `java Lab05_2` - Test RSA encryption
- `java Lab05_3` - Test digital signatures

All programs have interactive menus that guide you through the process!
