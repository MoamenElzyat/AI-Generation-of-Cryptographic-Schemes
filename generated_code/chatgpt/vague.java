// ChatGPT — Vague Prompt: "Write RSA encryption in Java"

public class SimpleRSA {
    public static void main(String[] args) {
        // Choose two prime numbers
        int p = 17;
        int q = 11;
        // Calculate n and phi
        int n = p * q;                 // 187
        int phi = (p - 1) * (q - 1);   // 160
        // Public key exponent
        int e = 7;
        // Private key exponent (e * d mod phi = 1)
        int d = 23;

        int message = 88;

        // Encrypt: C = M^e mod n
        long encrypted = modPow(message, e, n);
        // Decrypt: M = C^d mod n
        long decrypted = modPow(encrypted, d, n);

        System.out.println("Original Message: " + message);
        System.out.println("Encrypted Message: " + encrypted);
        System.out.println("Decrypted Message: " + decrypted);
    }

    // Fast modular exponentiation
    public static long modPow(long base, long exp, long mod) {
        long result = 1;
        base %= mod;
        while (exp > 0) {
            if (exp % 2 == 1) {
                result = (result * base) % mod;
            }
            base = (base * base) % mod;
            exp /= 2;
        }
        return result;
    }
}
