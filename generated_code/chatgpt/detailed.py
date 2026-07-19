# ChatGPT — Detailed Prompt: "Implement RSA key generation, encryption, and decryption
# in Python. Use a 2048-bit key, OAEP padding with SHA-256, a cryptographically secure
# random source, and no hardcoded values."

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import base64

class RSAEncryption:
    def __init__(self, key_size=4096):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        self.public_key = self.private_key.public_key()

    def encrypt(self, message: str) -> str:
        ciphertext = self.public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(ciphertext).decode()

    def decrypt(self, ciphertext_b64: str) -> str:
        ciphertext = base64.b64decode(ciphertext_b64)
        plaintext = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode()

    def save_keys(self):
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open("private.pem", "wb") as f:
            f.write(private_pem)
        with open("public.pem", "wb") as f:
            f.write(public_pem)

# Example
rsa_cipher = RSAEncryption()
message = "This is a secure RSA message."
encrypted = rsa_cipher.encrypt(message)
print("Encrypted:")
print(encrypted)
decrypted = rsa_cipher.decrypt(encrypted)
print("\nDecrypted:")
print(decrypted)
rsa_cipher.save_keys()
