import os
import hashlib
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class Cipher:
    def __init__(self, password: str):
        if not password:
            self.aead = None
        else:
            # Derive a 32-byte key from the password
            key = hashlib.sha256(password.encode('utf-8')).digest()
            self.aead = AESGCM(key)
            # Use a random 8-byte prefix and a 4-byte counter for the nonce
            self.nonce_prefix = os.urandom(8)
            self.nonce_counter = 0

    def encrypt(self, data: bytes) -> bytes:
        if not self.aead:
            return data
        
        # Construct a 12-byte nonce: prefix (8B) + counter (4B)
        nonce = self.nonce_prefix + struct.pack("!I", self.nonce_counter & 0xFFFFFFFF)
        self.nonce_counter += 1
        
        ciphertext = self.aead.encrypt(nonce, data, None)
        return nonce + ciphertext

    def decrypt(self, data: bytes) -> bytes:
        if not self.aead:
            return data
        if len(data) < 12:
            raise ValueError("Data too short for decryption")
        
        # Use memoryview to avoid copies during slicing
        mv = memoryview(data)
        nonce = mv[:12]
        ciphertext = mv[12:]
        return self.aead.decrypt(nonce, ciphertext, None)
