# qryptis-test-project/normal_code.py
"""
Business Logic and Utility Functions Module.
Contains standard string processing, math, and data aggregation routines with zero cryptographic primitives.
"""

import math
import json
from typing import List, Dict, Any


class DataProcessor:
    """Standard business logic processing without any cryptographic operations."""

    def __init__(self, service_name: str = "BillingService"):
        self.service_name = service_name
        self.processed_records: List[Dict[str, Any]] = []

    def calculate_invoice_totals(self, items: List[Dict[str, float]], tax_rate: float = 0.08) -> float:
        """Calculates subtotal and taxes for customer line items."""
        subtotal = sum(item.get("price", 0.0) * item.get("quantity", 1) for item in items)
        tax = subtotal * tax_rate
        return round(subtotal + tax, 2)

    def compute_vector_similarity(self, vec_a: List[float], vec_b: List[float]) -> float:
        """Computes cosine similarity between two numeric vectors."""
        if len(vec_a) != len(vec_b) or not vec_a:
            return 0.0
        dot_product = sum(a * b for a, b in zip(vec_a, vec_b))
        norm_a = math.sqrt(sum(a * a for a in vec_a))
        norm_b = math.sqrt(sum(b * b for b in vec_b))
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return dot_product / (norm_a * norm_b)

    def format_status_json(self, status: str, count: int) -> str:
        """Serializes health check payload to JSON."""
        return json.dumps({
            "service": self.service_name,
            "status": status,
            "items_count": count
        })
