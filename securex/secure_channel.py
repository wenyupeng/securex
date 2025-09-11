import os, hmac
from cryptography.hazmat.primitives import hashes, hmac as hmac_lib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class SecureChannel:
    def __init__(self, aes_key: bytes, hmac_key: bytes):
        self.aesgcm = AESGCM(aes_key)
        self.hmac_key = hmac_key

    def encrypt(self, plaintext: bytes, aad: bytes | None = None) -> bytes:
        nonce = os.urandom(12)
        ciphertext = self.aesgcm.encrypt(nonce, plaintext, aad)
        # HMAC Check = nonce + ciphertext
        h = hmac_lib.HMAC(self.hmac_key, hashes.SHA256())
        h.update(nonce + ciphertext)
        tag = h.finalize()
        return nonce + ciphertext + tag

    def decrypt(self, data: bytes, aad: bytes | None = None) -> bytes:
        nonce, ciphertext_tag = data[:12], data[12:]
        ciphertext, tag = ciphertext_tag[:-32], ciphertext_tag[-32:]
        # Check HMAC
        h = hmac_lib.HMAC(self.hmac_key, hashes.SHA256())
        h.update(nonce + ciphertext)
        h.verify(tag)
        return self.aesgcm.decrypt(nonce, ciphertext, aad)
