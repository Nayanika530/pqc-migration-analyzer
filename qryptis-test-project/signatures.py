# qryptis-test-project/signatures.py
"""
Digital Signatures and Code Signing Module.
Contains Elliptic Curve Digital Signature Algorithm (ECDSA SECP256R1) and DSA-2048.
"""

from cryptography.hazmat.primitives.asymmetric import ec, dsa
from cryptography.hazmat.primitives import hashes


class DocumentSigner:
    """Signs legal documents and firmware images."""

    def __init__(self):
        # ECDSA over NIST P-256 curve (quantum-vulnerable to Shor's discrete log algorithm)
        self.ec_key = ec.generate_private_key(ec.SECP256R1())

    def sign_document_hash(self, doc_hash: bytes) -> bytes:
        """Produces ECDSA signature over document digest."""
        return self.ec_key.sign(doc_hash, ec.ECDSA(hashes.SHA256()))

    def create_legacy_dsa_key(self):
        """Generates legacy DSA 2048-bit keypair."""
        return dsa.generate_private_key(key_size=2048)
