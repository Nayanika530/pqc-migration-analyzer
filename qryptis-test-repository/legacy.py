# qryptis-test-repository/legacy.py
# Legacy Cryptographic Primitives — High Deprecation & Vulnerability Risk

import hashlib
from Crypto.Cipher import DES3
from Crypto.PublicKey import DSA
from Crypto.Random import get_random_bytes


class LegacySecurityBridge:
    """Maintains backward compatibility with archived systems."""

    def __init__(self):
        self.des3_key = get_random_bytes(24)
        # Obsolete DSA key for legacy code signature verification
        self.legacy_dsa_key = DSA.generate(1024)

    def calculate_file_checksum(self, data: bytes) -> str:
        """Calculate legacy MD5 checksum (Vulnerable to collision attacks)."""
        return hashlib.md5(data).hexdigest()

    def decrypt_archived_payload(self, encrypted_data: bytes) -> bytes:
        """Decrypt archived 3DES payload."""
        cipher = DES3.new(self.des3_key, DES3.MODE_CBC)
        return cipher.decrypt(encrypted_data)
