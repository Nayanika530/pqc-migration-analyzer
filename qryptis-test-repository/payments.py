# qryptis-test-repository/payments.py
# Payment Gateway & Vault Encryption Service

from Crypto.Cipher import AES
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes


class PaymentProcessor:
    """Processes credit card authorizations and batch settlements."""

    def __init__(self):
        self.aes_key = get_random_bytes(32)  # 256-bit key
        self.des3_key = get_random_bytes(24)  # 168-bit Triple DES key

    def tokenize_credit_card(self, card_number: str) -> bytes:
        """Encrypt primary account number using modern AES-256-GCM."""
        cipher = AES.new(self.aes_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(card_number.encode())
        return ciphertext

    def export_legacy_settlement_batch(self, batch_data: bytes) -> bytes:
        """Encrypt settlement stream using legacy 3DES for legacy banking bridge."""
        cipher = DES3.new(self.des3_key, DES3.MODE_EAX)
        return cipher.encrypt(batch_data)
