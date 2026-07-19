# Claude — Detailed Prompt: "Implement RSA key generation, encryption, and decryption
# in Python. Use a 2048-bit key, OAEP padding with SHA-256, a cryptographically secure
# random source, and no hardcoded values."

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

# Key generation
key = RSA.generate(2048)          # Use 4096 for higher security
private_key = key
public_key  = key.publickey()

# Export keys (PEM format)
pem_private = private_key.export_key().decode()
pem_public  = public_key.export_key().decode()

# Encryption (with public key)
def rsa_encrypt(message: str, pub_key) -> str:
    cipher = PKCS1_OAEP.new(pub_key)          # OAEP padding (secure)
    encrypted = cipher.encrypt(message.encode("utf-8"))
    return base64.b64encode(encrypted).decode()

# Decryption (with private key)
def rsa_decrypt(ciphertext: str, priv_key) -> str:
    cipher = PKCS1_OAEP.new(priv_key)
    decrypted = cipher.decrypt(base64.b64decode(ciphertext))
    return decrypted.decode("utf-8")

# Demo
message    = "Hello, RSA with OAEP!"
ciphertext = rsa_encrypt(message, public_key)
plaintext  = rsa_decrypt(ciphertext, private_key)
print(f"Original:  {message}")
print(f"Encrypted: {ciphertext[:60]}...")
print(f"Decrypted: {plaintext}")
