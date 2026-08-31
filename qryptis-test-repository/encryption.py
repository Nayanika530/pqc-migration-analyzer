# qryptis-test-repository/encryption.py
# Data-at-Rest & Legacy Backup Encryption Service

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


class StorageEncryptionEngine:
    """Manages database column and file backup encryption."""

    def __init__(self):
        self.cbc_key = get_random_bytes(16)  # 128-bit key
        # Weak legacy RSA key for archived customer records
        self.legacy_backup_key = RSA.generate(1024)

    def encrypt_file_chunk(self, data: bytes) -> bytes:
        """Encrypt disk block using AES-128-CBC."""
        cipher = AES.new(self.cbc_key, AES.MODE_CBC)
        return cipher.encrypt(data)
