import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class SecureChannel:
    """Encrypt message on AES-GCM"""
    def __init__(self, key: bytes):
        if len(key) < 32:
            raise ValueError("Key must be 32 bytes for AES-256-GCM")
        self.key = key[:32]
        self.aesgcm = AESGCM(self.key)

    def encrypt(self, plaintext: bytes, aad: bytes | None = None) -> bytes:
        nonce = os.urandom(12)
        ciphertext = self.aesgcm.encrypt(nonce, plaintext, aad)
        return nonce + ciphertext

    def decrypt(self, data: bytes, aad: bytes | None = None) -> bytes:
        nonce, ciphertext = data[:12], data[12:]
        return self.aesgcm.decrypt(nonce, ciphertext, aad)
