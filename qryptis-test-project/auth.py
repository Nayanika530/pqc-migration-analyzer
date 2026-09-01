# qryptis-test-project/auth.py
"""
Authentication and Session Token Management Module.
Contains RSA-2048 keypair generation for JWT signing and PKCS#1 v1.5 verification.
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import base64


class JWTAuthManager:
    """Manages JWT tokens and RSA keypair infrastructure for API authentication."""

    def __init__(self, key_size: int = 2048):
        # RSA-2048 asymmetric private key generation for JWT signing
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        self.public_key = self.private_key.public_key()

    def sign_jwt_payload(self, payload_bytes: bytes) -> bytes:
        """Signs a JWT token payload using RSA-PSS signature scheme."""
        signature = self.private_key.sign(
            payload_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.urlsafe_b64encode(signature)

    def verify_token(self, payload_bytes: bytes, signature_bytes: bytes) -> bool:
        """Verifies an incoming token signature using the RSA public key."""
        try:
            raw_sig = base64.urlsafe_b64decode(signature_bytes)
            self.public_key.verify(
                raw_sig,
                payload_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
