import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import java.util.Scanner;

/**
 * Lab05_2: RSA File Encryption/Decryption
 * 
 * Implements RSA encryption with:
 * - Key generation (2048-bit)
 * - Key saving/loading (DER format)
 * - File encryption/decryption with block processing
 * - Performance comparison with DES
 * 
 * Note: RSA is much slower than symmetric encryption (DES/AES).
 * For large files, consider hybrid encryption (RSA + AES).
 */
public class Lab05_2 {
    
    private KeyPair keyPair;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    
    /**
     * Generates RSA key pair
     */
    public void generateKeys(int keySize) throws NoSuchAlgorithmException {
        System.out.println("Generating " + keySize + "-bit RSA key pair...");
        long startTime = System.currentTimeMillis();
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(keySize);
        keyPair = keyGen.generateKeyPair();
        
        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();
        
        long elapsed = System.currentTimeMillis() - startTime;
        System.out.println("Key generation completed in " + (elapsed / 1000.0) + " seconds");
    }
    
    /**
     * Saves keys to files in DER format
     */
    public void saveKeys(String baseFilename) throws IOException {
        // Save private key
        try (FileOutputStream fos = new FileOutputStream(baseFilename + ".key")) {
            fos.write(privateKey.getEncoded());
        }
        
        // Save public key
        try (FileOutputStream fos = new FileOutputStream(baseFilename + ".pub")) {
            fos.write(publicKey.getEncoded());
        }
        
        System.out.println("Keys saved:");
        System.out.println("  Private key: " + baseFilename + ".key");
        System.out.println("  Public key: " + baseFilename + ".pub");
    }
    
    /**
     * Loads public key from file
     */
    public void loadPublicKey(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        publicKey = keyFactory.generatePublic(spec);
        System.out.println("Loaded public key from " + filename);
    }
    
    /**
     * Loads private key from file
     */
    public void loadPrivateKey(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        privateKey = keyFactory.generatePrivate(spec);
        System.out.println("Loaded private key from " + filename);
    }
    
    /**
     * Encrypts a file using RSA with block processing
     * 
     * RSA can only encrypt data smaller than key size, so we process in blocks.
     * Each encrypted block is prefixed with its size (2 bytes).
     */
    public double encryptFile(String inputFile, String outputFile) throws Exception {
        if (publicKey == null) {
            throw new IllegalStateException("No public key loaded. Generate or load a key first.");
        }
        
        long startTime = System.nanoTime();
        
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        
        // Calculate max block size for RSA encryption
        int keySizeBytes = ((java.security.interfaces.RSAPublicKey) publicKey).getModulus().bitLength() / 8;
        int maxBlockSize = keySizeBytes - 11;  // PKCS1Padding overhead is 11 bytes
        
        System.out.println("Max block size for encryption: " + maxBlockSize + " bytes");
        
        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile)) {
            
            byte[] buffer = new byte[maxBlockSize];
            int blockCount = 0;
            int bytesRead;
            
            while ((bytesRead = fis.read(buffer)) != -1) {
                // Encrypt block
                byte[] inputBlock = new byte[bytesRead];
                System.arraycopy(buffer, 0, inputBlock, 0, bytesRead);
                byte[] encryptedBlock = cipher.doFinal(inputBlock);
                
                // Write block size (2 bytes) then encrypted block
                int blockSize = encryptedBlock.length;
                fos.write((blockSize >> 8) & 0xFF);
                fos.write(blockSize & 0xFF);
                fos.write(encryptedBlock);
                
                blockCount++;
                if (blockCount % 100 == 0) {
                    System.out.println("Encrypted " + blockCount + " blocks...");
                }
            }
            
            long endTime = System.nanoTime();
            double elapsed = (endTime - startTime) / 1_000_000_000.0;
            
            // Print statistics
            File inFile = new File(inputFile);
            File outFile = new File(outputFile);
            double inSizeMB = inFile.length() / (1024.0 * 1024.0);
            double outSizeMB = outFile.length() / (1024.0 * 1024.0);
            
            System.out.println("\nEncryption successful!");
            System.out.println("Blocks processed: " + blockCount);
            System.out.println(String.format("Original file size: %.2f MB", inSizeMB));
            System.out.println(String.format("Encrypted file size: %.2f MB", outSizeMB));
            System.out.println(String.format("Encryption time: %.4f seconds", elapsed));
            if (elapsed > 0) {
                System.out.println(String.format("Speed: %.2f MB/s", inSizeMB / elapsed));
            }
            
            return elapsed;
        }
    }
    
    /**
     * Decrypts a file using RSA with block processing
     */
    public double decryptFile(String inputFile, String outputFile) throws Exception {
        if (privateKey == null) {
            throw new IllegalStateException("No private key loaded. Generate or load a key first.");
        }
        
        long startTime = System.nanoTime();
        
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        
        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile)) {
            
            int blockCount = 0;
            
            while (true) {
                // Read block size (2 bytes)
                int byte1 = fis.read();
                int byte2 = fis.read();
                
                if (byte1 == -1 || byte2 == -1) {
                    break;  // End of file
                }
                
                int blockSize = ((byte1 & 0xFF) << 8) | (byte2 & 0xFF);
                
                // Read encrypted block
                byte[] encryptedBlock = new byte[blockSize];
                int bytesRead = fis.read(encryptedBlock);
                
                if (bytesRead != blockSize) {
                    throw new IOException("Unexpected end of file");
                }
                
                // Decrypt block
                byte[] decryptedBlock = cipher.doFinal(encryptedBlock);
                fos.write(decryptedBlock);
                
                blockCount++;
                if (blockCount % 100 == 0) {
                    System.out.println("Decrypted " + blockCount + " blocks...");
                }
            }
            
            long endTime = System.nanoTime();
            double elapsed = (endTime - startTime) / 1_000_000_000.0;
            
            // Print statistics
            File outFile = new File(outputFile);
            double outSizeMB = outFile.length() / (1024.0 * 1024.0);
            
            System.out.println("\nDecryption successful!");
            System.out.println("Blocks processed: " + blockCount);
            System.out.println(String.format("Decrypted file size: %.2f MB", outSizeMB));
            System.out.println(String.format("Decryption time: %.4f seconds", elapsed));
            if (elapsed > 0) {
                System.out.println(String.format("Speed: %.2f MB/s", outSizeMB / elapsed));
            }
            
            return elapsed;
        }
    }
    
    /**
     * Interactive main menu
     */
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        Lab05_2 rsa = new Lab05_2();
        
        System.out.println("============================================================");
        System.out.println("RSA FILE ENCRYPTION/DECRYPTION PROGRAM");
        System.out.println("============================================================");
        
        try {
            System.out.println("\nChoose function:");
            System.out.println("1. Generate new key pair");
            System.out.println("2. Encrypt file");
            System.out.println("3. Decrypt file");
            System.out.println("4. Performance test (compare RSA vs DES)");
            
            System.out.print("\nChoice (1-4): ");
            String choice = scanner.nextLine().trim();
            
            switch (choice) {
                case "1":
                    // Generate keys
                    System.out.print("Enter key size (default 2048): ");
                    String sizeStr = scanner.nextLine().trim();
                    int keySize = sizeStr.isEmpty() ? 2048 : Integer.parseInt(sizeStr);
                    
                    rsa.generateKeys(keySize);
                    
                    System.out.print("Enter base name for key files (e.g., mykey): ");
                    String baseName = scanner.nextLine().trim();
                    if (baseName.isEmpty()) {
                        baseName = "rsa_key";
                    }
                    
                    rsa.saveKeys(baseName);
                    break;
                    
                case "2":
                    // Encrypt
                    System.out.print("Enter public key file name: ");
                    String pubKeyFile = scanner.nextLine().trim();
                    
                    if (!new File(pubKeyFile).exists()) {
                        System.out.println("File " + pubKeyFile + " does not exist!");
                        return;
                    }
                    
                    rsa.loadPublicKey(pubKeyFile);
                    
                    System.out.print("Enter file to encrypt: ");
                    String inputFile = scanner.nextLine().trim();
                    
                    if (!new File(inputFile).exists()) {
                        System.out.println("File " + inputFile + " does not exist!");
                        return;
                    }
                    
                    System.out.print("Enter output file name (default: output.enc): ");
                    String outputFile = scanner.nextLine().trim();
                    if (outputFile.isEmpty()) {
                        outputFile = "output.enc";
                    }
                    
                    rsa.encryptFile(inputFile, outputFile);
                    System.out.println("\nFile saved to: " + outputFile);
                    break;
                    
                case "3":
                    // Decrypt
                    System.out.print("Enter private key file name: ");
                    String privKeyFile = scanner.nextLine().trim();
                    
                    if (!new File(privKeyFile).exists()) {
                        System.out.println("File " + privKeyFile + " does not exist!");
                        return;
                    }
                    
                    rsa.loadPrivateKey(privKeyFile);
                    
                    System.out.print("Enter file to decrypt: ");
                    String encFile = scanner.nextLine().trim();
                    
                    if (!new File(encFile).exists()) {
                        System.out.println("File " + encFile + " does not exist!");
                        return;
                    }
                    
                    System.out.print("Enter output file name (default: output.dec): ");
                    String decFile = scanner.nextLine().trim();
                    if (decFile.isEmpty()) {
                        decFile = "output.dec";
                    }
                    
                    rsa.decryptFile(encFile, decFile);
                    System.out.println("\nFile saved to: " + decFile);
                    break;
                    
                case "4":
                    // Performance test
                    performanceTest();
                    break;
                    
                default:
                    System.out.println("Invalid choice!");
            }
            
        } catch (Exception e) {
            System.out.println("\nError: " + e.getMessage());
            e.printStackTrace();
        } finally {
            scanner.close();
        }
    }
    
    /**
     * Performance comparison between RSA and DES
     */
    private static void performanceTest() throws Exception {
        System.out.println("\n============================================================");
        System.out.println("PERFORMANCE COMPARISON: RSA vs DES");
        System.out.println("============================================================");
        
        // Create test file if needed
        String testFile = "test_10mb.bin";
        if (!new File(testFile).exists()) {
            System.out.println("\nCreating 10MB test file...");
            try (FileOutputStream fos = new FileOutputStream(testFile)) {
                byte[] buffer = new byte[1024 * 1024];  // 1MB buffer
                SecureRandom random = new SecureRandom();
                for (int i = 0; i < 10; i++) {
                    random.nextBytes(buffer);
                    fos.write(buffer);
                }
            }
            System.out.println("Test file created: " + testFile);
        }
        
        // Test RSA
        System.out.println("\n--- Testing RSA ---");
        Lab05_2 rsa = new Lab05_2();
        rsa.generateKeys(2048);
        
        double rsaEncTime = rsa.encryptFile(testFile, "temp_rsa.enc");
        double rsaDecTime = rsa.decryptFile("temp_rsa.enc", "temp_rsa.dec");
        
        new File("temp_rsa.enc").delete();
        new File("temp_rsa.dec").delete();
        
        // Test DES
        System.out.println("\n--- Testing DES ---");
        byte[] desKey = "abcdEFGH".getBytes(StandardCharsets.UTF_8);
        
        double desEncTime = Lab05_1.encryptFile(testFile, "temp_des.enc", desKey, "CBC", "PKCS5Padding");
        double desDecTime = Lab05_1.decryptFile("temp_des.enc", "temp_des.dec", desKey, "CBC", "PKCS5Padding");
        
        new File("temp_des.enc").delete();
        new File("temp_des.dec").delete();
        
        // Print comparison
        System.out.println("\n============================================================");
        System.out.println("COMPARISON RESULTS");
        System.out.println("============================================================");
        System.out.println("\nTest file: 10MB");
        System.out.println("\nRSA (2048-bit):");
        System.out.println(String.format("  Encryption: %.4f seconds", rsaEncTime));
        System.out.println(String.format("  Decryption: %.4f seconds", rsaDecTime));
        System.out.println(String.format("  Total: %.4f seconds", rsaEncTime + rsaDecTime));
        
        System.out.println("\nDES (CBC/PKCS5Padding):");
        System.out.println(String.format("  Encryption: %.4f seconds", desEncTime));
        System.out.println(String.format("  Decryption: %.4f seconds", desDecTime));
        System.out.println(String.format("  Total: %.4f seconds", desEncTime + desDecTime));
        
        if (desEncTime > 0 && desDecTime > 0) {
            System.out.println("\nRSA is slower than DES:");
            System.out.println(String.format("  Encryption: %.1fx", rsaEncTime / desEncTime));
            System.out.println(String.format("  Decryption: %.1fx", rsaDecTime / desDecTime));
        }
    }
}
