# qryptis-test-repository/non_crypto.py
# Standard Business Logic & Data Processing (Negative Control)

import math
import json


class OrderProcessor:
    """Processes e-commerce orders with standard math formulas."""

    def __init__(self):
        # Negative test case: Variable containing "rsa" or "aes" in string/name
        self.rsa_token_mock_string = "NON_CRYPTO_RSA_STRING_CONSTANT"
        self.aes_cipher_description = "A standard string description of AES encryption algorithm"

    def calculate_order_total(self, unit_price: float, quantity: int, tax_rate: float = 0.08) -> float:
        """Calculate subtotal with tax and discount rounding."""
        subtotal = unit_price * quantity
        discount = math.sqrt(quantity) * 0.5
        total = (subtotal - discount) * (1 + tax_rate)
        return round(total, 2)

    def serialize_order_event(self, order_id: str, items: list) -> str:
        """Format order event JSON payload."""
        event = {
            "event_type": "ORDER_CREATED",
            "order_id": order_id,
            "items_count": len(items),
            "comment": "This comment mentions RSA-2048 and AES-256 in plain text but does not call APIs"
        }
        return json.dumps(event)
