# Cursor Self-Audit — Full Text (Phase 5, Turn 2)

Source: audit produced by Cursor (agent mode) reviewing its own vague-prompt
output (`rsa_crypto.py`, PKCS#1 v1.5 version). Reproduced verbatim.

---

**RSA security audit**
Review of rsa.py (stdlib RSA with PKCS#1 v1.5). Not safe for production
confidentiality without major changes.

- 1 P0 critical
- 2 P1 high
- 4 P2 medium
- 2 P3 low

**Verdict: do not use for real secrets**

The padding-oracle surface alone is enough to treat this as a teaching demo
only. Prefer cryptography (PyCA) RSA-OAEP or an authenticated hybrid
construction for anything that matters.

## Findings

| ID | Severity | Issue | Location |
|---|---|---|---|
| P0-1 | Critical | PKCS#1 v1.5 enables Bleichenbacher padding-oracle attacks | rsa.py:162–168, 195–215 |
| P1-1 | High | Allow 512-bit moduli that are trivially factorable | rsa.py:115–116 |
| P1-2 | High | Decrypt error paths form a practical oracle | rsa.py:198–215 |
| P2-1 | Medium | No \|p − q\| separation check | rsa.py:120–130 |
| P2-2 | Medium | Private exponent not checked against Wiener / Boneh–Durfee bounds | rsa.py:134 |
| P2-3 | Medium | CRT decrypt has no fault-attack countermeasure | rsa.py:205–210 |
| P2-4 | Medium | No modular-exponentiation blinding against timing leaks | rsa.py:191, 206–212 |
| P3-1 | Low | PrivateKey.to_dict() dumps raw secret material | rsa.py:105–106 |
| P3-2 | Low | Direct RSA encryption invites misuse for bulk data | rsa.py:145–152, 184 |

## Detail

**PKCS#1 v1.5 enables Bleichenbacher padding-oracle attacks** (rsa.py:162–168, 195–215)

Decrypt returns distinguishable errors for invalid ciphertext vs bad padding.
An attacker who can observe success/failure (or timing) can recover plaintext
without the private key. `_pkcs1_v15_unpad` fails fast on header bytes,
separator position, and message content. Combined with PKCS#1 v1.5 encryption
padding, this is the classic Bleichenbacher attack surface. Production RSA
encryption must use OAEP (or a hybrid scheme) and constant-time decrypt that
does not leak padding validity.

**Allow 512-bit moduli that are trivially factorable** (rsa.py:115–116)

`generate_keypair` accepts `bits >= 512`. 512-bit RSA has been publicly
factored; 1024-bit is deprecated. Callers using the documented minimum get
broken confidentiality. Reject keys below 2048 bits (3072+ preferred for
long-lived keys). The `__main__` demo also generates 1024-bit keys,
normalizing weak sizes.

**Decrypt error paths form a practical oracle** (rsa.py:198–215)

Different `ValueError` messages and early returns for length, range, and
padding failures let remote callers map ciphertext validity. Even with OAEP,
decrypt should use a single generic failure, constant-time padding checks,
and no attacker-visible distinction between error classes when serving
untrusted ciphertext.

**No \|p − q\| separation check** (rsa.py:120–130)

Equal-size primes can be close enough for Fermat factorization. There is no
bound ensuring \|p − q\| is sufficiently large. After choosing p and q,
reject pairs where `abs(p - q)` is below ~`2^(bits/2 − 100)`, or regenerate
until the gap is safe.

**Private exponent not checked against Wiener / Boneh–Durfee bounds** (rsa.py:134)

`d = e⁻¹ mod φ(n)` is used without verifying d is large. Unusual e values
could yield a small d vulnerable to continued-fraction attacks. Prefer
`d = e⁻¹ mod λ(n) = lcm(p−1, q−1)`, and reject keys where d is too small
(e.g. `d < n^(1/4)`).

**CRT decrypt has no fault-attack countermeasure** (rsa.py:205–210)

A single faulty CRT recombination (bit flip, glitch) can leak the private
key via the Boneh–DeMillo–Lipton attack. Verify `pow(m, e, n) == c` after
CRT decrypt (or recompute with the full exponent) before releasing
plaintext.

**No modular-exponentiation blinding against timing leaks** (rsa.py:191, 206–212)

`pow(m, e, n)` / CRT paths are not blinded. Local timing or cache side
channels can leak key bits over many operations. Use cryptographic libraries
with constant-time big-int ops, or blind: decrypt `c·r^e`, then multiply by
`r⁻¹`.

**PrivateKey.to_dict() dumps raw secret material** (rsa.py:105–106)

Serialization returns n, d, e, p, q with no encryption or redaction — easy
to log or persist accidentally. Omit from public API, or require an explicit
`export_unsafe()` and document that callers must protect the output.

**Direct RSA encryption invites misuse for bulk data** (rsa.py:145–152, 184)

Only k−11 bytes fit per ciphertext. No hybrid (RSA-KEM + AEAD) path, so
callers may chunk plaintext unsafely or assume stream encryption. Expose
`wrap_key()` / hybrid helpers, or document that RSA encrypts only short
secrets (e.g. AES keys).

## What looks fine

- **CSPRNG usage:** Prime candidates and PKCS padding bytes use `secrets`,
  not `random`.
- **Miller–Rabin rounds:** 40 random-base rounds are far above typical needs
  for ≥1024-bit candidates.
- **Default exponent:** e = 65537 is the standard Fermat prime; default
  modulus size is 2048.
- **Message bound check:** Rejects m ≥ n and enforces ciphertext length = k,
  avoiding trivial range mistakes.

## Remediation priority

**Must fix before any real use:** Replace PKCS#1 v1.5 with RSA-OAEP
(SHA-256), unify decrypt errors, raise minimum key size to 2048, add CRT
fault check.

**Better still:** Do not ship custom RSA. Use
`cryptography.hazmat.primitives.asymmetric.rsa` with OAEP, or a KEM +
AES-GCM hybrid. Custom number theory is for education only.

*Source: static review of rsa.py · no dynamic exploit PoC run*
