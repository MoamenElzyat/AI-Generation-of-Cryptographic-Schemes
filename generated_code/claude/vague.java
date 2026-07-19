// Claude — Vague Prompt: "Write RSA encryption in Java"

import javax.crypto.Cipher;
import java.security.*;
import java.util.Base64;

public class RSAEncryption {
    // Key generation
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, new SecureRandom());
        return generator.generateKeyPair();
    }

    // Encryption (with public key)
    public static String encrypt(String message, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encrypted = cipher.doFinal(message.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    // Decryption (with private key)
    public static String decrypt(String ciphertext, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(decrypted, "UTF-8");
    }

    // Key serialization
    public static String exportPublicKey(PublicKey key) {
        return "-----BEGIN PUBLIC KEY-----\n"
             + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(key.getEncoded())
             + "\n-----END PUBLIC KEY-----";
    }

    public static String exportPrivateKey(PrivateKey key) {
        return "-----BEGIN PRIVATE KEY-----\n"
             + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(key.getEncoded())
             + "\n-----END PRIVATE KEY-----";
    }

    public static void main(String[] args) throws Exception {
        KeyPair keyPair = generateKeyPair();
        PublicKey  publicKey  = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        System.out.println(exportPublicKey(publicKey));
        System.out.println(exportPrivateKey(privateKey));

        String message    = "Hello, RSA in Java!";
        String ciphertext = encrypt(message, publicKey);
        String plaintext  = decrypt(ciphertext, privateKey);

        System.out.println("Original:  " + message);
        System.out.println("Encrypted: " + ciphertext.substring(0, 60) + "...");
        System.out.println("Decrypted: " + plaintext);
    }
}
