@echo off
REM Quick Test Script for Java Cryptography Labs
REM This runs all basic tests automatically

echo.
echo ============================================================
echo JAVA CRYPTOGRAPHY LABS - AUTOMATED TEST SUITE
echo ============================================================
echo.

cd /d d:\Users\HungThinh\Applications\VSCode\MyProject\crypto\code

echo [Test 1/3] Testing HMAC (Message Authentication Code)...
echo -----------------------------------------------------------
java testMAC
echo.
if %ERRORLEVEL% EQU 0 (
    echo [SUCCESS] HMAC test passed
) else (
    echo [FAILED] HMAC test failed
)

echo.
echo [Test 2/3] Testing RSA Encryption/Decryption...
echo -----------------------------------------------------------
echo Hello RSA Test | java testRSA
echo.
if %ERRORLEVEL% EQU 0 (
    echo [SUCCESS] RSA test passed
) else (
    echo [FAILED] RSA test failed
)

echo.
echo [Test 3/3] Testing Digital Signatures (Auto Demo)...
echo -----------------------------------------------------------
echo 6 | java Lab05_3
echo.
if %ERRORLEVEL% EQU 0 (
    echo [SUCCESS] Digital signature test passed
) else (
    echo [FAILED] Digital signature test failed
)

echo.
echo ============================================================
echo ALL AUTOMATED TESTS COMPLETED!
echo ============================================================
echo.
echo Next steps:
echo   - For interactive DES testing: java Lab05_1
echo   - For interactive RSA testing: java Lab05_2
echo   - For interactive signature testing: java Lab05_3
echo.
echo See HOW_TO_RUN_TESTS.md for detailed instructions.
echo.
pause
