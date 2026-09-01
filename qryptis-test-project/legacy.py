# qryptis-test-project/legacy.py
"""
Legacy Payment Gateway and Archive Storage Module.
Contains deprecated 3DES (Triple DES / Sweet32 vulnerable) and MD5 hash routines.
"""

from Crypto.Cipher import DES3
import hashlib


class LegacyPaymentProcessor:
    """Processes legacy banking batch transactions using obsolete 3DES."""

    def __init__(self, raw_key: bytes = b"012345678901234567890123"):
        # 3DES block cipher (deprecated by NIST SP 800-131A due to 64-bit Sweet32 collision attacks)
        self.key = raw_key

    def encrypt_transaction_record(self, record_data: bytes) -> bytes:
        """Encrypts financial record using 3DES CBC mode."""
        cipher = DES3.new(self.key, DES3.MODE_CBC)
        return cipher.encrypt(record_data)

    def calculate_file_checksum(self, file_bytes: bytes) -> str:
        """Computes MD5 hash digest (cryptographically broken by collision attacks)."""
        return hashlib.md5(file_bytes).hexdigest()
