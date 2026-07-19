# ChatGPT — Vague Prompt: "Write RSA encryption in Python"

# Simple RSA Example (Educational)
# Public key (e, n)
e = 17
n = 3233
# Private key (d, n)
d = 2753

# Message to encrypt
message = 65

# Encrypt
ciphertext = pow(message, e, n)
print("Encrypted:", ciphertext)

# Decrypt
decrypted = pow(ciphertext, d, n)
print("Decrypted:", decrypted)

# Public key
e = 17
n = 3233
# Private key
d = 2753

text = "HELLO"
# Encrypt each character
encrypted = [pow(ord(ch), e, n) for ch in text]
print("Encrypted:", encrypted)

# Decrypt
decrypted = ''.join(chr(pow(c, d, n)) for c in encrypted)
print("Decrypted:", decrypted)
