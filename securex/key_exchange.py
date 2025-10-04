from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Elliptic Curve Diffie-Hellman (ECDH) key exchange and HKDF key derivation
class KeyExchange:
    """ECDH for exchange Key + HKDF to derive shared key"""
    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()

    def get_public_bytes(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def derive_shared_keys(self, peer_public_bytes: bytes):
        peer_public_key = serialization.load_pem_public_key(peer_public_bytes)
        shared_secret = self.private_key.exchange(ec.ECDH(), peer_public_key)

        # One-time expansion of 64 bytes: the first 32 bytes are used for AES, the last 32 bytes are used for HMAC
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=b"SecureX-v1",
        )
        key_material = hkdf.derive(shared_secret)
        aes_key, hmac_key = key_material[:32], key_material[32:]
        return aes_key, hmac_key
