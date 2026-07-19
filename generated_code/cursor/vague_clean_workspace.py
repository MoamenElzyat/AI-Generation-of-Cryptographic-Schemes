# Cursor (agent mode, CLEAN empty workspace) — Vague Prompt
# "Write RSA encryption in Python."

"""RSA encryption and decryption using only the Python standard library."""

from __future__ import annotations

import secrets
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Number theory helpers
# ---------------------------------------------------------------------------


def _extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Return (g, x, y) such that a*x + b*y = g = gcd(a, b)."""
    if b == 0:
        return a, 1, 0
    g, x1, y1 = _extended_gcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def modinv(a: int, m: int) -> int:
    """Modular multiplicative inverse of a modulo m."""
    g, x, _ = _extended_gcd(a % m, m)
    if g != 1:
        raise ValueError(f"No modular inverse for {a} modulo {m}")
    return x % m


def _is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Miller-Rabin primality test."""
    if n < 2:
        return False
    # Small primes fast-path
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31)
    for p in small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False

    # Write n - 1 = 2^s * d with d odd
    s, d = 0, n - 1
    while d % 2 == 0:
        s += 1
        d //= 2

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2  # in [2, n - 2]
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _generate_prime(bits: int) -> int:
    """Generate a probable prime of the given bit length."""
    if bits < 2:
        raise ValueError("Prime bit length must be at least 2")
    while True:
        # Ensure top bit set (exact bit length) and odd
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(candidate):
            return candidate


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PublicKey:
    n: int
    e: int

    def encrypt(self, plaintext: bytes) -> bytes:
        return encrypt(plaintext, self)

    def to_dict(self) -> dict[str, int]:
        return {"n": self.n, "e": self.e}


@dataclass(frozen=True)
class PrivateKey:
    n: int
    d: int
    e: int
    p: int
    q: int

    @property
    def public_key(self) -> PublicKey:
        return PublicKey(self.n, self.e)

    def decrypt(self, ciphertext: bytes) -> bytes:
        return decrypt(ciphertext, self)

    def to_dict(self) -> dict[str, int]:
        return {"n": self.n, "d": self.d, "e": self.e, "p": self.p, "q": self.q}


def generate_keypair(bits: int = 2048, e: int = 65537) -> tuple[PublicKey, PrivateKey]:
    """
    Generate an RSA key pair.

    ``bits`` is the modulus size (n = p * q). Each prime gets roughly bits/2 bits.
    """
    if bits < 512:
        raise ValueError("Use at least 512 bits for a usable key size")
    if e % 2 == 0 or e < 3:
        raise ValueError("Public exponent e must be an odd integer >= 3")

    half = bits // 2
    while True:
        p = _generate_prime(half)
        q = _generate_prime(bits - half)
        if p == q:
            continue
        if p < q:
            p, q = q, p
        n = p * q
        if n.bit_length() != bits:
            continue
        phi = (p - 1) * (q - 1)
        if _extended_gcd(e, phi)[0] != 1:
            continue
        d = modinv(e, phi)
        public = PublicKey(n=n, e=e)
        private = PrivateKey(n=n, d=d, e=e, p=p, q=q)
        return public, private


# ---------------------------------------------------------------------------
# PKCS#1 v1.5-style padding (simple, for teaching / small demos)
# ---------------------------------------------------------------------------


def _pkcs1_v15_pad(message: bytes, k: int) -> bytes:
    """
    Pad message to k bytes as: 0x00 || 0x02 || PS || 0x00 || M
    where PS is at least 8 non-zero random bytes.
    """
    if len(message) > k - 11:
        raise ValueError(
            f"Message too long for key size: need <= {k - 11} bytes, got {len(message)}"
        )
    ps_len = k - len(message) - 3
    ps = bytearray()
    while len(ps) < ps_len:
        b = secrets.token_bytes(ps_len - len(ps))
        ps.extend(x for x in b if x != 0)
    return b"\x00\x02" + bytes(ps) + b"\x00" + message


def _pkcs1_v15_unpad(padded: bytes) -> bytes:
    if len(padded) < 11 or padded[0] != 0x00 or padded[1] != 0x02:
        raise ValueError("Invalid PKCS#1 v1.5 padding")
    sep = padded.find(b"\x00", 2)
    if sep < 10:  # PS must be at least 8 bytes => separator index >= 10
        raise ValueError("Invalid PKCS#1 v1.5 padding")
    return padded[sep + 1 :]


def _int_to_bytes(value: int, length: int) -> bytes:
    return value.to_bytes(length, byteorder="big")


def _bytes_to_int(data: bytes) -> int:
    return int.from_bytes(data, byteorder="big")


# ---------------------------------------------------------------------------
# Encrypt / decrypt
# ---------------------------------------------------------------------------


def encrypt(plaintext: bytes, public_key: PublicKey) -> bytes:
    """Encrypt ``plaintext`` with the public key. Returns ciphertext bytes."""
    k = (public_key.n.bit_length() + 7) // 8
    em = _pkcs1_v15_pad(plaintext, k)
    m = _bytes_to_int(em)
    if m >= public_key.n:
        raise ValueError("Padded message representative out of range")
    c = pow(m, public_key.e, public_key.n)
    return _int_to_bytes(c, k)


def decrypt(ciphertext: bytes, private_key: PrivateKey) -> bytes:
    """Decrypt ``ciphertext`` with the private key. Returns plaintext bytes."""
    k = (private_key.n.bit_length() + 7) // 8
    if len(ciphertext) != k:
        raise ValueError(f"Ciphertext must be {k} bytes, got {len(ciphertext)}")
    c = _bytes_to_int(ciphertext)
    if c >= private_key.n:
        raise ValueError("Ciphertext representative out of range")

    # Chinese Remainder Theorem speedup when p, q are known
    if private_key.p and private_key.q:
        m1 = pow(c, private_key.d % (private_key.p - 1), private_key.p)
        m2 = pow(c, private_key.d % (private_key.q - 1), private_key.q)
        qinv = modinv(private_key.q, private_key.p)
        h = (qinv * (m1 - m2)) % private_key.p
        m = m2 + h * private_key.q
    else:
        m = pow(c, private_key.d, private_key.n)

    em = _int_to_bytes(m, k)
    return _pkcs1_v15_unpad(em)


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    print("Generating 1024-bit RSA key pair...")
    pub, priv = generate_keypair(bits=1024)

    message = b"Hello, RSA!"
    print(f"Plaintext : {message!r}")

    ciphertext = pub.encrypt(message)
    print(f"Ciphertext: {ciphertext.hex()[:64]}... ({len(ciphertext)} bytes)")

    recovered = priv.decrypt(ciphertext)
    print(f"Decrypted : {recovered!r}")
    assert recovered == message
    print("OK - round-trip succeeded.")
