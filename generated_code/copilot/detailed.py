# GitHub Copilot (chat interface) — Detailed Prompt
# "Implement RSA key generation, encryption, and decryption in Python.
#  Use a 2048-bit key, OAEP padding with SHA-256, a cryptographically
#  secure random source, and no hardcoded values."

"""
RSA Encryption Module

This module provides secure RSA key generation, encryption, and decryption
using industry-standard practices:
- 2048-bit RSA keys
- OAEP padding with SHA-256
- Cryptographically secure random source
- No hardcoded values
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import os


class RSAEncryption:
    """
    A secure RSA encryption handler supporting key generation,
    encryption, and decryption operations.
    """

    # RSA key size in bits
    KEY_SIZE = 2048
    # Public exponent (standard value)
    PUBLIC_EXPONENT = 65537

    def __init__(self):
        """Initialize the RSA encryption handler."""
        self.private_key = None
        self.public_key = None

    def generate_keys(self) -> tuple:
        """
        Generate a new RSA key pair using a cryptographically secure random source.

        Returns:
            tuple: A tuple of (private_key, public_key) objects from cryptography library.
        """
        # Generate private key with secure random source via default_backend
        self.private_key = rsa.generate_private_key(
            public_exponent=self.PUBLIC_EXPONENT,
            key_size=self.KEY_SIZE,
            backend=default_backend()
        )
        # Extract public key from private key
        self.public_key = self.private_key.public_key()

        return self.private_key, self.public_key

    def encrypt(self, plaintext: bytes, public_key=None) -> bytes:
        """
        Encrypt plaintext using RSA with OAEP padding and SHA-256.
        """
        key = public_key or self.public_key

        if key is None:
            raise ValueError(
                "No public key available. Generate keys first or provide a public_key parameter."
            )

        # Encrypt using OAEP padding with SHA-256
        ciphertext = key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return ciphertext

    def decrypt(self, ciphertext: bytes, private_key=None) -> bytes:
        """
        Decrypt ciphertext using RSA with OAEP padding and SHA-256.
        """
        key = private_key or self.private_key

        if key is None:
            raise ValueError(
                "No private key available. Generate keys first or provide a private_key parameter."
            )

        # Decrypt using OAEP padding with SHA-256
        plaintext = key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return plaintext

    def serialize_private_key(self, password: bytes = None) -> bytes:
        """
        Serialize the private key to PEM format.
        Encrypts with password if provided.
        """
        if self.private_key is None:
            raise ValueError("No private key available to serialize.")

        encryption_algorithm = (
            serialization.BestAvailableEncryption(password)
            if password
            else serialization.NoEncryption()
        )

        pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )

        return pem

    def serialize_public_key(self) -> bytes:
        """Serialize the public key to PEM format."""
        if self.public_key is None:
            raise ValueError("No public key available to serialize.")

        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return pem

    @staticmethod
    def load_private_key(pem_data: bytes, password: bytes = None):
        """Load a private key from PEM format."""
        return serialization.load_pem_private_key(
            pem_data,
            password=password,
            backend=default_backend()
        )

    @staticmethod
    def load_public_key(pem_data: bytes):
        """Load a public key from PEM format."""
        return serialization.load_pem_public_key(
            pem_data,
            backend=default_backend()
        )


def main():
    """Demonstration of RSA encryption/decryption functionality."""
    print("=" * 60)
    print("RSA Encryption Demo - 2048-bit Key, OAEP+SHA256")
    print("=" * 60)

    rsa_handler = RSAEncryption()

    print("\n[1] Generating 2048-bit RSA key pair...")
    private_key, public_key = rsa_handler.generate_keys()
    print("Key pair generated successfully")

    message = b"Hello, this is a secure message!"
    print(f"\n[2] Original Message: {message.decode()}")

    print("\n[3] Encrypting message...")
    ciphertext = rsa_handler.encrypt(message)
    print(f"Ciphertext (hex): {ciphertext.hex()[:64]}...")
    print(f"  Ciphertext length: {len(ciphertext)} bytes")

    print("\n[4] Decrypting message...")
    plaintext = rsa_handler.decrypt(ciphertext)
    print(f"Decrypted Message: {plaintext.decode()}")

    print("\n[5] Verification:")
    if plaintext == message:
        print("Encryption/Decryption successful - messages match!")
    else:
        print("Error - messages do not match!")

    print("\n[6] Serializing keys to PEM format...")
    private_pem = rsa_handler.serialize_private_key()
    public_pem = rsa_handler.serialize_public_key()
    print(f"Private key size: {len(private_pem)} bytes")
    print(f"Public key size: {len(public_pem)} bytes")

    print("\n[7] Loading keys from PEM format...")
    loaded_private_key = RSAEncryption.load_private_key(private_pem)
    loaded_public_key = RSAEncryption.load_public_key(public_pem)
    print("Keys loaded successfully")

    print("\n[8] Testing encryption with loaded public key...")
    ciphertext2 = rsa_handler.encrypt(message, loaded_public_key)
    plaintext2 = rsa_handler.decrypt(ciphertext2, loaded_private_key)
    print(f"Round-trip message: {plaintext2.decode()}")

    print("\n" + "=" * 60)
    print("All tests completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    main()
