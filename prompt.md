# AI PROMPT

This is a prompt designed to help AI understand and generate code snippets effectively. It provides clear instructions and context for the AI to follow when responding to coding-related queries. I am human, the only one who can modify this prompt file. Do not modify it without my permission.

## Target & Requirements

We are going to implement JAVA Cryptography Architecture and test the created code with existing unit tests.
Although it is required to build on JDK 1.6 or higher, I do not recommend using as low as JDK 1.6, they are too old with many defects and security issues.
I already have JDK 24 installed on my system.
The machine I am working on is running Windows 11 24H2.
I have my old codebase in Python language, but I want to migrate it to Java language.
Check if my Python code has any issues, report them to REPORT.md file (you have full permission to create/modify/delete REPORT.md file).
You have permission to create/modify any other files as needed. Do not delete any existing files unless I specifically ask you to do so.

## Instructions

The instruction is a PDF file `docs.pdf` in the root directory of this project. Unfortunately, the file is in Vietnamese language, and it is a PDF, which might make it difficult for you to read. I have created a TXT version of the PDF file named `docs.txt` in the root directory of this project. Please read the TXT file carefully to understand the requirements and instructions for implementing the JAVA Cryptography Architecture.

All the code are in the `code` directory. The existing unit tests are also in the `code` directory.

The old Python codebase is in the `exmples` directory.

## Fix

Nothing pending.

## What fixed

### Completed (2025-11-25)

1. **Created REPORT.md** - Comprehensive analysis of Python codebase identifying security issues, code quality problems, and compatibility concerns
2. **Implemented Lab05_1.java** - Complete DES file encryption/decryption with:
   - All 4 modes: DES/ECB/PKCS5Padding, DES/ECB/NoPadding, DES/CBC/PKCS5Padding, DES/CBC/NoPadding
   - Interactive menu for mode selection
   - Performance timing with nano-precision
   - Proper resource management with try-with-resources
   - Clear security warnings about ECB and DES
3. **Implemented Lab05_2.java** - Complete RSA file encryption/decryption with:
   - Key generation (2048-bit default)
   - Key saving/loading in DER format
   - Block-based file encryption for large files
   - Performance comparison with DES
   - Proper error handling
4. **Implemented Lab05_3.java** - Complete digital signatures with:
   - SHA1withRSA signing and verification
   - signAndEncrypt method (sign then encrypt with DES)
   - decryptAndVerify method (decrypt then verify)
   - Binary format for efficiency (no JSON overhead)
   - Demo functions for testing
   - Security warnings about SHA-1 deprecation
5. **All files compiled successfully** - No compilation errors with JDK 24
