import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Scanner;

/**
 * Lab05_1: DES File Encryption/Decryption
 * 
 * WARNING: This implementation uses DES and ECB mode for EDUCATIONAL PURPOSES ONLY.
 * 
 * Security issues:
 * - DES has 56-bit key size (broken by modern standards)
 * - ECB mode does not hide data patterns (cryptographically weak)
 * 
 * For production use:
 * - Use AES-256 instead of DES
 * - Use CBC or GCM mode instead of ECB
 * 
 * Implements 4 encryption modes:
 * 1. DES/ECB/PKCS5Padding
 * 2. DES/ECB/NoPadding
 * 3. DES/CBC/PKCS5Padding
 * 4. DES/CBC/NoPadding
 */
public class Lab05_1 {
    
    /**
     * Encrypts a file using DES with specified mode and padding
     */
    public static double encryptFile(String inputFile, String outputFile, 
                                     byte[] key, String mode, String padding) 
            throws Exception {
        
        long startTime = System.nanoTime();
        
        // Validate key length
        if (key.length != 8) {
            throw new IllegalArgumentException("DES key must be 8 bytes");
        }
        
        // Create secret key
        SecretKeySpec secretKey = new SecretKeySpec(key, "DES");
        
        // Create cipher
        String transformation = "DES/" + mode + "/" + padding;
        Cipher cipher = Cipher.getInstance(transformation);
        
        // Initialize cipher
        if (mode.equals("CBC")) {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        }
        
        // Read input file
        byte[] inputBytes = Files.readAllBytes(Paths.get(inputFile));
        
        // Check alignment for NoPadding
        if (padding.equals("NoPadding") && inputBytes.length % 8 != 0) {
            throw new IllegalArgumentException(
                "With NoPadding, data length must be multiple of 8 bytes. " +
                "Current length: " + inputBytes.length);
        }
        
        // Encrypt
        byte[] outputBytes = cipher.doFinal(inputBytes);
        
        // Write output file
        try (FileOutputStream fos = new FileOutputStream(outputFile)) {
            // Write IV for CBC mode
            if (mode.equals("CBC")) {
                byte[] iv = cipher.getIV();
                fos.write(iv);
            }
            fos.write(outputBytes);
        }
        
        long endTime = System.nanoTime();
        double elapsed = (endTime - startTime) / 1_000_000_000.0;
        
        // Print statistics
        File inFile = new File(inputFile);
        double fileSizeMB = inFile.length() / (1024.0 * 1024.0);
        System.out.println("Encryption successful!");
        System.out.println("Mode: " + transformation);
        System.out.println(String.format("File size: %.2f MB", fileSizeMB));
        System.out.println(String.format("Encryption time: %.4f seconds", elapsed));
        if (elapsed > 0) {
            System.out.println(String.format("Speed: %.2f MB/s", fileSizeMB / elapsed));
        }
        
        return elapsed;
    }
    
    /**
     * Decrypts a file using DES with specified mode and padding
     */
    public static double decryptFile(String inputFile, String outputFile, 
                                     byte[] key, String mode, String padding) 
            throws Exception {
        
        long startTime = System.nanoTime();
        
        // Validate key length
        if (key.length != 8) {
            throw new IllegalArgumentException("DES key must be 8 bytes");
        }
        
        // Create secret key
        SecretKeySpec secretKey = new SecretKeySpec(key, "DES");
        
        // Create cipher
        String transformation = "DES/" + mode + "/" + padding;
        Cipher cipher = Cipher.getInstance(transformation);
        
        // Read input file
        byte[] inputBytes = Files.readAllBytes(Paths.get(inputFile));
        
        // Extract IV for CBC mode
        byte[] ciphertext;
        if (mode.equals("CBC")) {
            byte[] iv = new byte[8];
            System.arraycopy(inputBytes, 0, iv, 0, 8);
            ciphertext = new byte[inputBytes.length - 8];
            System.arraycopy(inputBytes, 8, ciphertext, 0, ciphertext.length);
            
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        } else {
            ciphertext = inputBytes;
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
        }
        
        // Decrypt
        byte[] outputBytes = cipher.doFinal(ciphertext);
        
        // Write output file
        Files.write(Paths.get(outputFile), outputBytes);
        
        long endTime = System.nanoTime();
        double elapsed = (endTime - startTime) / 1_000_000_000.0;
        
        // Print statistics
        double fileSizeMB = outputBytes.length / (1024.0 * 1024.0);
        System.out.println("Decryption successful!");
        System.out.println("Mode: " + transformation);
        System.out.println(String.format("File size: %.2f MB", fileSizeMB));
        System.out.println(String.format("Decryption time: %.4f seconds", elapsed));
        if (elapsed > 0) {
            System.out.println(String.format("Speed: %.2f MB/s", fileSizeMB / elapsed));
        }
        
        return elapsed;
    }
    
    /**
     * Interactive main menu
     */
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        
        System.out.println("============================================================");
        System.out.println("DES FILE ENCRYPTION/DECRYPTION PROGRAM");
        System.out.println("============================================================");
        
        try {
            // Choose action
            System.out.print("\nChoose action (1-Encrypt, 2-Decrypt): ");
            String action = scanner.nextLine().trim();
            
            if (!action.equals("1") && !action.equals("2")) {
                System.out.println("Invalid choice!");
                return;
            }
            
            // Input file
            System.out.print("Enter input file name: ");
            String inputFile = scanner.nextLine().trim();
            
            File inFile = new File(inputFile);
            if (!inFile.exists()) {
                System.out.println("File " + inputFile + " does not exist!");
                return;
            }
            
            // Key
            System.out.print("Enter key file name (or press Enter to type key directly): ");
            String keyFile = scanner.nextLine().trim();
            
            byte[] key;
            if (!keyFile.isEmpty() && new File(keyFile).exists()) {
                key = Files.readAllBytes(Paths.get(keyFile));
                if (key.length < 8) {
                    System.out.println("Key file too short! Need 8 bytes.");
                    return;
                }
                // Take first 8 bytes
                byte[] keyBytes = new byte[8];
                System.arraycopy(key, 0, keyBytes, 0, 8);
                key = keyBytes;
            } else {
                System.out.print("Enter key (8 characters): ");
                String keyStr = scanner.nextLine().trim();
                if (keyStr.length() != 8) {
                    System.out.println("Key must be 8 characters!");
                    return;
                }
                key = keyStr.getBytes(StandardCharsets.UTF_8);
            }
            
            // Mode selection
            System.out.println("\nEncryption mode:");
            System.out.println("1. DES/ECB/PKCS5Padding");
            System.out.println("2. DES/ECB/NoPadding");
            System.out.println("3. DES/CBC/PKCS5Padding");
            System.out.println("4. DES/CBC/NoPadding");
            System.out.print("Choose mode (1-4): ");
            String modeChoice = scanner.nextLine().trim();
            
            String mode, padding;
            switch (modeChoice) {
                case "1":
                    mode = "ECB";
                    padding = "PKCS5Padding";
                    break;
                case "2":
                    mode = "ECB";
                    padding = "NoPadding";
                    break;
                case "3":
                    mode = "CBC";
                    padding = "PKCS5Padding";
                    break;
                case "4":
                    mode = "CBC";
                    padding = "NoPadding";
                    break;
                default:
                    System.out.println("Invalid choice!");
                    return;
            }
            
            // Perform encryption/decryption
            String outputFile;
            if (action.equals("1")) {
                outputFile = "output.enc";
                encryptFile(inputFile, outputFile, key, mode, padding);
                System.out.println("\nFile encrypted and saved to: " + outputFile);
            } else {
                outputFile = "output.dec";
                decryptFile(inputFile, outputFile, key, mode, padding);
                System.out.println("\nFile decrypted and saved to: " + outputFile);
            }
            
        } catch (Exception e) {
            System.out.println("\nError: " + e.getMessage());
            e.printStackTrace();
        } finally {
            scanner.close();
        }
    }
}
