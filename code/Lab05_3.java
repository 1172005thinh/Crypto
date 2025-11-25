import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Scanner;

/**
 * Lab05_3: Digital Signatures with SHA1withRSA
 * 
 * WARNING: SHA-1 is cryptographically broken (collision attacks demonstrated).
 * This implementation uses SHA1withRSA for EDUCATIONAL PURPOSES ONLY as required by assignment.
 * 
 * For production use:
 * - Use SHA256withRSA or SHA512withRSA instead
 * - Consider using EdDSA (Ed25519) for better performance and security
 * 
 * Implements:
 * 1. Basic sign/verify operations
 * 2. signAndEncrypt: Sign data, then encrypt (data + signature) with DES
 * 3. decryptAndVerify: Decrypt data, then verify signature
 */
public class Lab05_3 {
    
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private byte[] desKey;
    
    /**
     * Generates RSA key pair for signatures
     */
    public void generateRSAKeys(int keySize) throws NoSuchAlgorithmException {
        System.out.println("Generating " + keySize + "-bit RSA key pair...");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(keySize);
        KeyPair keyPair = keyGen.generateKeyPair();
        
        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();
        
        System.out.println("[SUCCESS] Key generation successful!");
    }
    
    /**
     * Saves RSA keys to files
     */
    public void saveRSAKeys(String baseFilename) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(baseFilename + ".key")) {
            fos.write(privateKey.getEncoded());
        }
        
        try (FileOutputStream fos = new FileOutputStream(baseFilename + ".pub")) {
            fos.write(publicKey.getEncoded());
        }
        
        System.out.println("[SUCCESS] RSA keys saved:");
        System.out.println("  Private: " + baseFilename + ".key");
        System.out.println("  Public: " + baseFilename + ".pub");
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
     * Sets DES key (8 bytes) for encryption
     * Assumes this key is shared between sender and receiver
     */
    public void setDESKey(String key) {
        if (key.length() != 8) {
            throw new IllegalArgumentException("[INFO] DES key must be 8 characters");
        }
        this.desKey = key.getBytes(StandardCharsets.UTF_8);
    }
    
    /**
     * Signs data using SHA1withRSA
     * 
     * @param data Data to sign
     * @return Digital signature
     */
    public byte[] sign(String data) throws Exception {
        if (privateKey == null) {
            throw new IllegalStateException("[ERR] No private key loaded!");
        }
        
        byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);
        
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(privateKey);
        signature.update(dataBytes);
        
        byte[] signatureBytes = signature.sign();
        
        System.out.println("Signed message (length: " + dataBytes.length + " bytes)");
        System.out.println("Signature (length: " + signatureBytes.length + " bytes)");
        
        return signatureBytes;
    }
    
    /**
     * Verifies signature using SHA1withRSA
     * 
     * @param data Original data
     * @param signatureBytes Digital signature
     * @return true if signature is valid
     */
    public boolean verifySignature(String data, byte[] signatureBytes) throws Exception {
        if (publicKey == null) {
            throw new IllegalStateException("[ERR] No public key loaded!");
        }
        
        byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);
        
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initVerify(publicKey);
        signature.update(dataBytes);
        
        boolean isValid = signature.verify(signatureBytes);
        
        if (isValid) {
            System.out.println("[PASS] Signature is valid!");
        } else {
            System.out.println("[FAIL] Signature is invalid!");
        }
        
        return isValid;
    }
    
    /**
     * Sign-and-Encrypt: Signs data, then encrypts (data + signature) with DES
     * 
     * Format: [4 bytes: data_length][4 bytes: sig_length][data][signature]
     * All encrypted with DES/CBC/PKCS5Padding
     * Output: [8 bytes: IV][encrypted_content]
     */
    public void signAndEncrypt(String data, String outputFile) throws Exception {
        if (privateKey == null) {
            throw new IllegalStateException("[ERR] No private key loaded!");
        }
        if (desKey == null) {
            throw new IllegalStateException("[ERR] DES key not set!");
        }
        
        System.out.println("\n=== SIGN AND ENCRYPT ===");
        
        byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);
        
        // Step 1: Sign data
        System.out.println("Step 1: Signing data...");
        byte[] signatureBytes = sign(data);
        
        // Step 2: Create package (data + signature)
        System.out.println("Step 2: Creating data package...");
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        
        dos.writeInt(dataBytes.length);
        dos.writeInt(signatureBytes.length);
        dos.write(dataBytes);
        dos.write(signatureBytes);
        dos.flush();
        
        byte[] packageBytes = baos.toByteArray();
        
        // Step 3: Encrypt with DES
        System.out.println("Step 3: Encrypting with DES...");
        SecretKeySpec secretKey = new SecretKeySpec(desKey, "DES");
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        
        byte[] iv = cipher.getIV();
        byte[] ciphertext = cipher.doFinal(packageBytes);
        
        // Save to file (IV + ciphertext)
        try (FileOutputStream fos = new FileOutputStream(outputFile)) {
            fos.write(iv);
            fos.write(ciphertext);
        }
        
        System.out.println("[SUCCESS] Sign and encrypt completed, saved to " + outputFile);
        System.out.println("  - Original data: " + dataBytes.length + " bytes");
        System.out.println("  - Signature: " + signatureBytes.length + " bytes");
        System.out.println("  - Encrypted file: " + (iv.length + ciphertext.length) + " bytes");
    }
    
    /**
     * Decrypt-and-Verify: Decrypts data, then verifies signature
     * 
     * @param inputFile Encrypted file
     * @return Decrypted data if signature is valid
     */
    public String decryptAndVerify(String inputFile) throws Exception {
        if (publicKey == null) {
            throw new IllegalStateException("[ERR] No public key loaded!");
        }
        if (desKey == null) {
            throw new IllegalStateException("[ERR] DES key not set!");
        }
        
        System.out.println("\n=== DECRYPT AND VERIFY ===");
        
        // Step 1: Decrypt with DES
        System.out.println("Step 1: Decrypting with DES...");
        byte[] fileBytes = Files.readAllBytes(Paths.get(inputFile));
        
        byte[] iv = new byte[8];
        System.arraycopy(fileBytes, 0, iv, 0, 8);
        
        byte[] ciphertext = new byte[fileBytes.length - 8];
        System.arraycopy(fileBytes, 8, ciphertext, 0, ciphertext.length);
        
        SecretKeySpec secretKey = new SecretKeySpec(desKey, "DES");
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        
        byte[] packageBytes = cipher.doFinal(ciphertext);
        
        // Step 2: Extract data and signature
        System.out.println("Step 2: Extracting data and signature...");
        ByteArrayInputStream bais = new ByteArrayInputStream(packageBytes);
        DataInputStream dis = new DataInputStream(bais);
        
        int dataLength = dis.readInt();
        int sigLength = dis.readInt();
        
        byte[] dataBytes = new byte[dataLength];
        byte[] signatureBytes = new byte[sigLength];
        
        dis.readFully(dataBytes);
        dis.readFully(signatureBytes);
        
        String data = new String(dataBytes, StandardCharsets.UTF_8);
        
        System.out.println("  - Data: " + dataLength + " bytes");
        System.out.println("  - Signature: " + sigLength + " bytes");
        
        // Step 3: Verify signature
        System.out.println("Step 3: Verifying signature...");
        boolean isValid = verifySignature(data, signatureBytes);
        
        if (!isValid) {
            throw new SecurityException("[FAIL] Signature verification failed!");
        }
        
        return data;
    }
    
    /**
     * Interactive main menu
     */
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        Lab05_3 ds = new Lab05_3();
        
        System.out.println("============================================================");
        System.out.println("DIGITAL SIGNATURE PROGRAM (SHA1withRSA)");
        System.out.println("============================================================");
        System.out.println("WARNING: SHA-1 is deprecated. For educational use only!");
        
        try {
            System.out.println("\nChoose function:");
            System.out.println("1. Generate RSA key pair");
            System.out.println("2. Sign message");
            System.out.println("3. Verify signature");
            System.out.println("4. Sign and encrypt (signAndEncrypt)");
            System.out.println("5. Decrypt and verify (decryptAndVerify)");
            System.out.println("6. Demo basic sign/verify");
            System.out.println("7. Demo sign-and-encrypt");
            
            System.out.print("\nChoice (1-7): ");
            String choice = scanner.nextLine().trim();
            
            switch (choice) {
                case "1":
                    // Generate keys
                    System.out.print("Enter key size (default 2048): ");
                    String sizeStr = scanner.nextLine().trim();
                    int keySize = sizeStr.isEmpty() ? 2048 : Integer.parseInt(sizeStr);
                    
                    ds.generateRSAKeys(keySize);
                    
                    System.out.print("Enter base name for key files: ");
                    String baseName = scanner.nextLine().trim();
                    if (baseName.isEmpty()) {
                        baseName = "signature_key";
                    }
                    
                    ds.saveRSAKeys(baseName);
                    break;
                    
                case "2":
                    // Sign
                    System.out.print("Enter private key file: ");
                    String privKey = scanner.nextLine().trim();
                    
                    if (!new File(privKey).exists()) {
                        System.out.println("File " + privKey + " does not exist!");
                        return;
                    }
                    
                    ds.loadPrivateKey(privKey);
                    
                    System.out.print("Enter message to sign: ");
                    String message = scanner.nextLine().trim();
                    
                    byte[] signature = ds.sign(message);
                    
                    System.out.print("Enter file to save signature (default: signature.bin): ");
                    String sigFile = scanner.nextLine().trim();
                    if (sigFile.isEmpty()) {
                        sigFile = "signature.bin";
                    }
                    
                    try (FileOutputStream fos = new FileOutputStream(sigFile)) {
                        fos.write(signature);
                    }
                    System.out.println("Signature saved to " + sigFile);
                    break;
                    
                case "3":
                    // Verify
                    System.out.print("Enter public key file: ");
                    String pubKey = scanner.nextLine().trim();
                    
                    if (!new File(pubKey).exists()) {
                        System.out.println("File " + pubKey + " does not exist!");
                        return;
                    }
                    
                    ds.loadPublicKey(pubKey);
                    
                    System.out.print("Enter original message: ");
                    String origMessage = scanner.nextLine().trim();
                    
                    System.out.print("Enter signature file: ");
                    String sigFileVerify = scanner.nextLine().trim();
                    
                    if (!new File(sigFileVerify).exists()) {
                        System.out.println("File " + sigFileVerify + " does not exist!");
                        return;
                    }
                    
                    byte[] signatureBytes = Files.readAllBytes(Paths.get(sigFileVerify));
                    ds.verifySignature(origMessage, signatureBytes);
                    break;
                    
                case "4":
                    // Sign and encrypt
                    System.out.print("Enter private key file: ");
                    String privKey2 = scanner.nextLine().trim();
                    
                    if (!new File(privKey2).exists()) {
                        System.out.println("File " + privKey2 + " does not exist!");
                        return;
                    }
                    
                    ds.loadPrivateKey(privKey2);
                    
                    System.out.print("Enter DES key (8 characters): ");
                    String desKey = scanner.nextLine().trim();
                    ds.setDESKey(desKey);
                    
                    System.out.print("Enter message: ");
                    String msg = scanner.nextLine().trim();
                    
                    System.out.print("Enter output file (default: encrypted.bin): ");
                    String outFile = scanner.nextLine().trim();
                    if (outFile.isEmpty()) {
                        outFile = "encrypted.bin";
                    }
                    
                    ds.signAndEncrypt(msg, outFile);
                    break;
                    
                case "5":
                    // Decrypt and verify
                    System.out.print("Enter public key file: ");
                    String pubKey2 = scanner.nextLine().trim();
                    
                    if (!new File(pubKey2).exists()) {
                        System.out.println("File " + pubKey2 + " does not exist!");
                        return;
                    }
                    
                    ds.loadPublicKey(pubKey2);
                    
                    System.out.print("Enter DES key (8 characters): ");
                    String desKey2 = scanner.nextLine().trim();
                    ds.setDESKey(desKey2);
                    
                    System.out.print("Enter encrypted file: ");
                    String inFile = scanner.nextLine().trim();
                    
                    if (!new File(inFile).exists()) {
                        System.out.println("File " + inFile + " does not exist!");
                        return;
                    }
                    
                    String decryptedData = ds.decryptAndVerify(inFile);
                    
                    System.out.println("\n--- RESULT ---");
                    System.out.println("Decrypted data: " + decryptedData);
                    break;
                    
                case "6":
                    demoBasicSignVerify();
                    break;
                    
                case "7":
                    demoSignAndEncrypt();
                    break;
                    
                default:
                    System.out.println("[ERR] Invalid choice!");
            }
            
        } catch (Exception e) {
            System.out.println("\nError: " + e.getMessage());
            e.printStackTrace();
        } finally {
            scanner.close();
        }
    }
    
    /**
     * Demo: Basic sign and verify
     */
    private static void demoBasicSignVerify() throws Exception {
        System.out.println("\n============================================================");
        System.out.println("DEMO: BASIC SIGN AND VERIFY");
        System.out.println("============================================================");
        
        Lab05_3 ds = new Lab05_3();
        ds.generateRSAKeys(2048);
        
        String message = "This is a test message for digital signature!";
        System.out.println("\nMessage: " + message);
        
        // Sign
        System.out.println("\n--- Signing message ---");
        byte[] signature = ds.sign(message);
        
        // Verify (correct)
        System.out.println("\n--- Verifying signature (original message) ---");
        ds.verifySignature(message, signature);
        
        // Verify (tampered)
        System.out.println("\n--- Verifying signature (tampered message) ---");
        String tamperedMessage = "This message has been TAMPERED!";
        ds.verifySignature(tamperedMessage, signature);
    }
    
    /**
     * Demo: Sign and encrypt complete workflow
     */
    private static void demoSignAndEncrypt() throws Exception {
        System.out.println("\n============================================================");
        System.out.println("DEMO: SIGN AND ENCRYPT WORKFLOW");
        System.out.println("============================================================");
        
        // Sender
        System.out.println("\n--- SENDER ---");
        Lab05_3 sender = new Lab05_3();
        sender.generateRSAKeys(2048);
        sender.setDESKey("sharedKY");  // Shared DES key
        
        String message = "Secret message that needs confidentiality and authenticity!";
        System.out.println("Message: " + message);
        
        sender.signAndEncrypt(message, "encrypted_message.bin");
        
        // Receiver
        System.out.println("\n--- RECEIVER ---");
        Lab05_3 receiver = new Lab05_3();
        receiver.publicKey = sender.publicKey;  // Received public key from sender
        receiver.setDESKey("sharedKY");  // Shared DES key
        
        String decryptedData = receiver.decryptAndVerify("encrypted_message.bin");
        
        System.out.println("\n--- RESULT ---");
        System.out.println("Received message: " + decryptedData);
        System.out.println("Message authenticity: VERIFIED");
        
        // Clean up
        new File("encrypted_message.bin").delete();
    }
}
