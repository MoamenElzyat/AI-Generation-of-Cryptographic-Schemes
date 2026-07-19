# Cursor (agent mode) — Detailed Prompt
# "Implement RSA key generation, encryption, and decryption in Python.
#  Use a 2048-bit key, OAEP padding with SHA-256, a cryptographically
#  secure random source, and no hardcoded values."

"""
RSA key generation, encryption, and decryption.

Uses a 2048-bit modulus, OAEP with SHA-256, and a CSPRNG
(via the cryptography library's secure default backend).
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

KEY_SIZE_BITS = 2048
PUBLIC_EXPONENT = 65537


def generate_key_pair(
    key_size: int = KEY_SIZE_BITS,
    public_exponent: int = PUBLIC_EXPONENT,
) -> tuple[RSAPrivateKey, RSAPublicKey]:
    """Generate an RSA private/public key pair using a CSPRNG."""
    if key_size < 2048:
        raise ValueError("key_size must be at least 2048 bits")
    private_key = rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=key_size,
    )
    return private_key, private_key.public_key()


def _oaep_padding() -> padding.OAEP:
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def encrypt(plaintext: bytes, public_key: RSAPublicKey) -> bytes:
    """Encrypt plaintext with the recipient's public key (RSA-OAEP, SHA-256)."""
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext must be bytes")
    return public_key.encrypt(bytes(plaintext), _oaep_padding())


def decrypt(ciphertext: bytes, private_key: RSAPrivateKey) -> bytes:
    """Decrypt ciphertext with the recipient's private key (RSA-OAEP, SHA-256)."""
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("ciphertext must be bytes")
    return private_key.decrypt(bytes(ciphertext), _oaep_padding())


def serialize_private_key(private_key: RSAPrivateKey, password: bytes | None = None) -> bytes:
    """Serialize a private key to PEM. Encrypts with password if provided."""
    if password is None:
        encryption: serialization.KeySerializationEncryption = serialization.NoEncryption()
    else:
        encryption = serialization.BestAvailableEncryption(password)
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )


def serialize_public_key(public_key: RSAPublicKey) -> bytes:
    """Serialize a public key to PEM (SubjectPublicKeyInfo)."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_private_key(pem_data: bytes, password: bytes | None = None) -> RSAPrivateKey:
    """Load a PEM-encoded private key."""
    key = serialization.load_pem_private_key(pem_data, password=password)
    if not isinstance(key, RSAPrivateKey):
        raise TypeError("PEM data does not contain an RSA private key")
    return key


def load_public_key(pem_data: bytes) -> RSAPublicKey:
    """Load a PEM-encoded public key."""
    key = serialization.load_pem_public_key(pem_data)
    if not isinstance(key, RSAPublicKey):
        raise TypeError("PEM data does not contain an RSA public key")
    return key


def max_plaintext_length(key_size: int = KEY_SIZE_BITS) -> int:
    """
    Maximum plaintext length for RSA-OAEP with SHA-256.

    OAEP overhead is 2 * hash_len + 2 bytes.
    """
    key_bytes = key_size // 8
    hash_len = hashes.SHA256.digest_size
    return key_bytes - 2 * hash_len - 2


if __name__ == "__main__":
    import secrets

    private_key, public_key = generate_key_pair()

    # Demo message is random - nothing is hardcoded into the crypto path.
    message = secrets.token_bytes(32)
    ciphertext = encrypt(message, public_key)
    recovered = decrypt(ciphertext, private_key)

    assert recovered == message
    print(f"Key size:       {private_key.key_size} bits")
    print(f"Padding:        RSA-OAEP with SHA-256")
    print(f"Plaintext len:  {len(message)} bytes")
    print(f"Ciphertext len: {len(ciphertext)} bytes")
    print(f"Round-trip OK:  {recovered == message}")
    print()
    print(serialize_public_key(public_key).decode())
