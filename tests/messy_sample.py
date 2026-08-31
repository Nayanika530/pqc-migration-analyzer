"""
messy_sample.py
Real-world, messy legacy enterprise sample file containing mixed crypto implementations,
helper utilities, comments, and deprecated ciphers for scanner testing.
"""

import os
import sys
import base64
import hashlib
from Crypto.PublicKey import RSA, DSA
from Crypto.Cipher import DES3, AES
from Crypto.Random import get_random_bytes

class LegacyPaymentProcessor:
    """Enterprise payment processing utility with legacy crypto."""
    
    def __init__(self, key_size=1024):
        # Generate weak RSA key (1024-bit) - Critical risk
        self.signing_key = RSA.generate(1024)
        self.session_id = None

    def create_legacy_session(self, master_secret):
        # 3DES block cipher usage - Deprecated
        triple_des_key = master_secret[:24]
        cipher = DES3.new(triple_des_key, DES3.MODE_CBC)
        return cipher

    def hash_transaction_record(self, raw_payload: bytes) -> str:
        # Broken MD5 hash usage - Deprecated
        hasher = hashlib.md5(raw_payload)
        return hasher.hexdigest()

    def generate_dsa_token(self):
        # Legacy DSA signature key generation - Vulnerable
        dsa_key = DSA.generate(2048)
        return dsa_key

    def modern_data_vault(self, data: bytes):
        # Modern AES-256 usage - Safe
        aes_key = get_random_bytes(32)
        aes_cipher = AES.new(aes_key, AES.MODE_GCM)
        return aes_cipher


def helper_rsa_key_export():
    # Another RSA instance with standard 2048-bit key
    export_key = RSA.generate(2048)
    return export_key.publickey().export_key()


if __name__ == "__main__":
    processor = LegacyPaymentProcessor()
    print("Payment processor initialized.")
