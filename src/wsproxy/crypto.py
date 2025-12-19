import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class Cipher:
    def __init__(self, password: str):
        if not password:
            self.aead = None
        else:
            # Derive a 32-byte key from the password
            # For simplicity, we use SHA256. 
            # In production, use PBKDF2 with a salt (but we need to sync salt).
            # Here we assume pre-shared fixed key for simplicity.
            key = hashlib.sha256(password.encode('utf-8')).digest()
            self.aead = AESGCM(key)

    def encrypt(self, data: bytes) -> bytes:
        if not self.aead:
            return data
        # Generate a random 12-byte nonce
        nonce = os.urandom(12)
        ciphertext = self.aead.encrypt(nonce, data, None)
        return nonce + ciphertext

    def decrypt(self, data: bytes) -> bytes:
        if not self.aead:
            return data
        if len(data) < 12:
            raise ValueError("Data too short for decryption")
        nonce = data[:12]
        ciphertext = data[12:]
        return self.aead.decrypt(nonce, ciphertext, None)
