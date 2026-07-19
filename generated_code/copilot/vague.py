# GitHub Copilot (chat interface) — Vague Prompt
# "Write RSA encryption in Python."

"""
RSA Encryption Implementation in Python

This module provides a complete RSA encryption/decryption implementation
including key generation, encryption, and decryption.
"""

import random
from math import gcd
from typing import Tuple


def is_prime(n: int, k: int = 5) -> bool:
    """
    Miller-Rabin primality test to check if a number is prime.

    Args:
        n: Number to test for primality
        k: Number of rounds (higher k = higher accuracy)

    Returns:
        True if n is likely prime, False if n is composite
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Witness loop
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True


def generate_prime(bits: int) -> int:
    """
    Generate a random prime number with specified bit length.

    Args:
        bits: Number of bits for the prime

    Returns:
        A random prime number
    """
    while True:
        num = random.getrandbits(bits)
        num |= (1 << bits - 1) | 1  # Set MSB and LSB to 1
        if is_prime(num):
            return num


def mod_inverse(a: int, m: int) -> int:
    """
    Calculate modular multiplicative inverse using Extended Euclidean Algorithm.

    Args:
        a: The number to find inverse for
        m: The modulus

    Returns:
        The modular inverse of a mod m

    Raises:
        ValueError: If modular inverse doesn't exist
    """
    if gcd(a, m) != 1:
        raise ValueError("Modular inverse does not exist")

    def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
        if a == 0:
            return b, 0, 1
        gcd_val, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd_val, x, y

    _, x, _ = extended_gcd(a % m, m)
    return (x % m + m) % m


def generate_keys(bits: int = 1024) -> Tuple[Tuple[int, int], Tuple[int, int]]:
    """
    Generate RSA public and private keys.

    Args:
        bits: Number of bits for each prime (default 1024)

    Returns:
        Tuple of ((e, n), (d, n)) where:
        - (e, n) is the public key
        - (d, n) is the private key
    """
    # Generate two distinct prime numbers
    p = generate_prime(bits)
    q = generate_prime(bits)

    while p == q:
        q = generate_prime(bits)

    # Calculate n and phi(n)
    n = p * q
    phi_n = (p - 1) * (q - 1)

    # Choose public exponent e
    e = 65537  # Common choice for public exponent
    while gcd(e, phi_n) != 1:
        e = random.randrange(2, phi_n)

    # Calculate private exponent d
    d = mod_inverse(e, phi_n)

    return (e, n), (d, n)


def encrypt(message: int, public_key: Tuple[int, int]) -> int:
    """
    Encrypt a message using RSA public key.

    Args:
        message: The message to encrypt (as integer)
        public_key: Tuple of (e, n)

    Returns:
        The encrypted message
    """
    e, n = public_key
    return pow(message, e, n)


def decrypt(ciphertext: int, private_key: Tuple[int, int]) -> int:
    """
    Decrypt a ciphertext using RSA private key.

    Args:
        ciphertext: The encrypted message
        private_key: Tuple of (d, n)

    Returns:
        The decrypted message
    """
    d, n = private_key
    return pow(ciphertext, d, n)


def text_to_int(text: str) -> int:
    """Convert text to integer for encryption."""
    return int(text.encode().hex(), 16)


def int_to_text(num: int) -> str:
    """Convert integer back to text after decryption."""
    hex_str = hex(num)[2:]
    # Add leading zero if necessary
    if len(hex_str) % 2:
        hex_str = '0' + hex_str
    return bytes.fromhex(hex_str).decode()


# Example usage
if __name__ == "__main__":
    print("RSA Encryption Example\n")
    print("=" * 50)

    # Generate keys (using smaller bits for faster demo)
    print("Generating RSA keys (512-bit)...")
    public_key, private_key = generate_keys(bits=512)

    e, n = public_key
    d, n_priv = private_key

    print(f"Public Key (e): {e}")
    print(f"Modulus (n): {n}")
    print(f"\nPrivate Key (d): {d}")
    print(f"Modulus (n): {n_priv}")

    print("\n" + "=" * 50)

    # Message to encrypt
    message = "Hello RSA!"
    print(f"\nOriginal message: {message}")

    # Convert message to integer
    message_int = text_to_int(message)
    print(f"Message as integer: {message_int}")

    # Check if message is smaller than n
    if message_int >= n:
        print("Error: Message is too large for this key size!")
    else:
        # Encrypt
        ciphertext = encrypt(message_int, public_key)
        print(f"Encrypted: {ciphertext}")

        # Decrypt
        decrypted_int = decrypt(ciphertext, private_key)
        decrypted_message = int_to_text(decrypted_int)
        print(f"Decrypted: {decrypted_message}")

        # Verify
        print(f"\nEncryption/Decryption successful!" if decrypted_message == message else "Failed!")
