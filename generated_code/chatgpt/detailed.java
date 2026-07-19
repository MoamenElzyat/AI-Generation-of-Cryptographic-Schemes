// ChatGPT — Detailed Prompt: "Implement RSA key generation, encryption, and decryption
// in Java. Use a 2048-bit key, OAEP padding with SHA-256, a cryptographically secure
// random source, and no hardcoded values."

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class RSAExample {
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public RSAExample() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        privateKey = pair.getPrivate();
        publicKey = pair.getPublic();
    }

    public String encrypt(String message) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes =
                cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public String decrypt(String encryptedMessage) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes =
                cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        try {
            RSAExample rsa = new RSAExample();
            String message = "Hello RSA Encryption!";
            String encrypted = rsa.encrypt(message);
            System.out.println("Encrypted:");
            System.out.println(encrypted);
            String decrypted = rsa.decrypt(encrypted);
            System.out.println("\nDecrypted:");
            System.out.println(decrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
