// Claude — Detailed Prompt: "Implement RSA key generation, encryption, and decryption
// in Java. Use a 2048-bit key, OAEP padding with SHA-256, a cryptographically secure
// random source, and no hardcoded values."

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.util.Base64;

public class RSA {
    // Key Generation
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048, new SecureRandom());
        return gen.generateKeyPair();
    }

    // OAEP Parameter Spec (SHA-256 + MGF1)
    private static OAEPParameterSpec oaepSpec() {
        return new OAEPParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec.SHA256,
            PSource.PSpecified.DEFAULT
        );
    }

    // Encryption
    public static String encrypt(String plaintext, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, oaepSpec(), new SecureRandom());
        byte[] encrypted = cipher.doFinal(plaintext.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    // Decryption
    public static String decrypt(String ciphertext, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepSpec());
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(decrypted, "UTF-8");
    }

    // Key Export (PEM)
    public static String toPem(Key key, String label) {
        String b64 = Base64.getMimeEncoder(64, new byte[]{'\n'})
                           .encodeToString(key.getEncoded());
        return "-----BEGIN " + label + "-----\n" + b64 + "\n-----END " + label + "-----";
    }

    public static void main(String[] args) throws Exception {
        KeyPair keyPair = generateKeyPair();
        System.out.println(toPem(keyPair.getPublic(),  "PUBLIC KEY"));
        System.out.println(toPem(keyPair.getPrivate(), "PRIVATE KEY"));

        String message    = "Hello, RSA-OAEP-SHA256!";
        String ciphertext = encrypt(message, keyPair.getPublic());
        String plaintext  = decrypt(ciphertext, keyPair.getPrivate());

        System.out.println("\nOriginal:  " + message);
        System.out.println("Encrypted: " + ciphertext.substring(0, 60) + "...");
        System.out.println("Decrypted: " + plaintext);
    }
}
