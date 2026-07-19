# Claude — Vague Prompt: "Write RSA encryption in Python"

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

# Generate RSA key pair
key = RSA.generate(2048)
private_key = key
public_key = key.publickey()

# Encrypt
def encrypt(message: str, pub_key) -> str:
    cipher = PKCS1_OAEP.new(pub_key)
    encrypted = cipher.encrypt(message.encode())
    return base64.b64encode(encrypted).decode()

# Decrypt
def decrypt(ciphertext: str, priv_key) -> str:
    cipher = PKCS1_OAEP.new(priv_key)
    decrypted = cipher.decrypt(base64.b64decode(ciphertext))
    return decrypted.decode()

# Demo
message = "Hello, RSA!"
ciphertext = encrypt(message, public_key)
plaintext = decrypt(ciphertext, private_key)
print(f"Original:  {message}")
print(f"Encrypted: {ciphertext}")
print(f"Decrypted: {plaintext}")
