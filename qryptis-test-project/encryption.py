# qryptis-test-project/encryption.py
"""
Data Encryption Module.
Implements modern symmetric AES-256-GCM encryption for database field vaults.
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from typing import Tuple


class DatabaseFieldEncryptor:
    """Handles symmetric authenticated encryption for sensitive PII data."""

    def __init__(self):
        # 256-bit AES master key (quantum-resilient against Grover's algorithm)
        self.master_key = get_random_bytes(32)

    def encrypt_field(self, plaintext: bytes) -> Tuple[bytes, bytes, bytes]:
        """Encrypts sensitive customer field using AES-256 in GCM authenticated mode."""
        cipher = AES.new(self.master_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return cipher.nonce, ciphertext, tag

    def decrypt_field(self, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
        """Decrypts and verifies authentication tag."""
        cipher = AES.new(self.master_key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)
