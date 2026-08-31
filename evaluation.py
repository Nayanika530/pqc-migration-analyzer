# evaluation.py
# Qryptis — Academic Static Analysis Evaluation & Ground-Truth Benchmark Suite
# Computes Precision, Recall, F1-Score, and Accuracy across labeled cryptographic test cases

from typing import List, Dict, Any
from scanner import scan_code


# 42 Ground Truth Labeled Test Samples (Positive & Negative Controls)
GROUND_TRUTH_DATASET = [
    # --- Positive Test Cases: Key Generation & Asymmetric ---
    {"id": "TC-01", "code": "from Crypto.PublicKey import RSA\nkey = RSA.generate(2048)", "expected_algo": "RSA", "expected_present": True, "category": "Asymmetric KEM"},
    {"id": "TC-02", "code": "from Crypto.PublicKey import RSA\nkey = RSA.generate(4096)", "expected_algo": "RSA", "expected_present": True, "category": "Asymmetric KEM"},
    {"id": "TC-03", "code": "from Crypto.PublicKey import RSA\nweak_key = RSA.generate(1024)", "expected_algo": "RSA", "expected_present": True, "category": "Asymmetric KEM (Weak)"},
    {"id": "TC-04", "code": "from Crypto.PublicKey import ECC\necc_key = ECC.generate(curve='P-256')", "expected_algo": "ECC", "expected_present": True, "category": "Elliptic Curve"},
    {"id": "TC-05", "code": "from Crypto.PublicKey import ECC\necc_key = ECC.generate(curve='P-384')", "expected_algo": "ECC", "expected_present": True, "category": "Elliptic Curve"},
    {"id": "TC-06", "code": "from Crypto.PublicKey import DSA\ndsa_key = DSA.generate(1024)", "expected_algo": "DSA", "expected_present": True, "category": "Digital Signature"},
    {"id": "TC-07", "code": "from Crypto.PublicKey import DSA\ndsa_key = DSA.generate(2048)", "expected_algo": "DSA", "expected_present": True, "category": "Digital Signature"},
    {"id": "TC-08", "code": "from cryptography.hazmat.primitives.asymmetric import rsa\npk = rsa.generate_private_key(public_exponent=65537, key_size=2048)", "expected_algo": "RSA", "expected_present": True, "category": "Hazmat Asymmetric"},
    {"id": "TC-09", "code": "from cryptography.hazmat.primitives.asymmetric import rsa\npk = rsa.generate_private_key(public_exponent=65537, key_size=4096)", "expected_algo": "RSA", "expected_present": True, "category": "Hazmat Asymmetric"},

    # --- Positive Test Cases: Symmetric Ciphers ---
    {"id": "TC-10", "code": "from Crypto.Cipher import AES\ncipher = AES.new(key, AES.MODE_GCM)", "expected_algo": "AES", "expected_present": True, "category": "Symmetric (Modern)"},
    {"id": "TC-11", "code": "from Crypto.Cipher import AES\ncipher = AES.new(key, AES.MODE_CBC)", "expected_algo": "AES", "expected_present": True, "category": "Symmetric (CBC)"},
    {"id": "TC-12", "code": "from Crypto.Cipher import AES\ncipher = AES.new(key, AES.MODE_CTR)", "expected_algo": "AES", "expected_present": True, "category": "Symmetric (CTR)"},
    {"id": "TC-13", "code": "from Crypto.Cipher import DES3\ncipher = DES3.new(key, DES3.MODE_EAX)", "expected_algo": "3DES", "expected_present": True, "category": "Symmetric (Deprecated)"},
    {"id": "TC-14", "code": "from Crypto.Cipher import DES3\ncipher = DES3.new(key, DES3.MODE_CBC)", "expected_algo": "3DES", "expected_present": True, "category": "Symmetric (Deprecated)"},
    {"id": "TC-15", "code": "from Crypto.Cipher import DES\ncipher = DES.new(key)", "expected_algo": "3DES", "expected_present": True, "category": "Symmetric (Legacy DES)"},

    # --- Positive Test Cases: Hashes & Post-Quantum ---
    {"id": "TC-16", "code": "import hashlib\ndigest = hashlib.md5(data).digest()", "expected_algo": "MD5", "expected_present": True, "category": "Hash (Broken)"},
    {"id": "TC-17", "code": "from Crypto.Hash import MD5\nh = MD5.new()", "expected_algo": "MD5", "expected_present": True, "category": "Hash (Broken)"},
    {"id": "TC-18", "code": "import oqs\nkem = oqs.KeyEncapsulation('ML-KEM-768')", "expected_algo": "ML-KEM", "expected_present": True, "category": "PQC Native KEM"},
    {"id": "TC-19", "code": "import oqs\nkem = oqs.KeyEncapsulation('ML-KEM-512')", "expected_algo": "ML-KEM", "expected_present": True, "category": "PQC Native KEM"},
    {"id": "TC-20", "code": "import oqs\nsig = oqs.Signature('ML-DSA-65')", "expected_algo": "ML-DSA", "expected_present": True, "category": "PQC Native Signature"},
    {"id": "TC-21", "code": "import oqs\nsig = oqs.Signature('SLH-DSA-128s')", "expected_algo": "SLH-DSA", "expected_present": True, "category": "PQC Native Signature"},

    # --- Negative Controls: Non-Cryptographic Code (Should NOT flag) ---
    {"id": "TC-22", "code": "def calculate_subtotal(items):\n    return sum(item['price'] for item in items)", "expected_algo": None, "expected_present": False, "category": "Negative Control"},
    {"id": "TC-23", "code": "rsa_variable_string = 'RSA_MOCK_TOKEN'\ncount = 10", "expected_algo": None, "expected_present": False, "category": "Negative (String contains 'RSA')"},
    {"id": "TC-24", "code": "aes_algorithm_name = 'AES-256-GCM is cool'\nprint(aes_algorithm_name)", "expected_algo": None, "expected_present": False, "category": "Negative (String contains 'AES')"},
    {"id": "TC-25", "code": "# TODO: migrate from RSA-2048 to ML-KEM-768 next quarter\nx = 42 * 2", "expected_algo": None, "expected_present": False, "category": "Negative (Comment with algo names)"},
    {"id": "TC-26", "code": "class PaymentOrder:\n    def __init__(self, amount):\n        self.amount = amount", "expected_algo": None, "expected_present": False, "category": "Negative Control"},
    {"id": "TC-27", "code": "import math\nval = math.sqrt(2048) * math.pi", "expected_algo": None, "expected_present": False, "category": "Negative (Math constants)"},
    {"id": "TC-28", "code": "def des3_helper():\n    return 'not_a_cipher_instance'", "expected_algo": None, "expected_present": False, "category": "Negative (Function name with 'des3')"},
    {"id": "TC-29", "code": "data = {'md5_checksum_header': 'abc123xyz'}\nstatus = 200", "expected_algo": None, "expected_present": False, "category": "Negative (Dict key string)"},
    {"id": "TC-30", "code": "import json\nresult = json.loads('{\"status\": \"ok\"}')", "expected_algo": None, "expected_present": False, "category": "Negative Control"},
    {"id": "TC-31", "code": "for i in range(1024):\n    pass", "expected_algo": None, "expected_present": False, "category": "Negative (Loop with key size constant)"},
    {"id": "TC-32", "code": "buffer_size = 4096\nmax_connections = 128", "expected_algo": None, "expected_present": False, "category": "Negative (Network buffer numbers)"},
    {"id": "TC-33", "code": "class UserProfile:\n    name: str = 'Alice'\n    role: str = 'Admin'", "expected_algo": None, "expected_present": False, "category": "Negative Control"},
    {"id": "TC-34", "code": "import os\ncurrent_dir = os.getcwd()", "expected_algo": None, "expected_present": False, "category": "Negative Control"},
    {"id": "TC-35", "code": "html_template = '<div>RSA and AES security analyzer</div>'", "expected_algo": None, "expected_present": False, "category": "Negative (HTML string)"},
    {"id": "TC-36", "code": "def generate_random_seed():\n    return 42", "expected_algo": None, "expected_present": False, "category": "Negative (Generic generate function)"},
    {"id": "TC-37", "code": "class RSA_Config_Object:\n    port = 8080", "expected_algo": None, "expected_present": False, "category": "Negative (Class name contains RSA)"},

    # --- Nested & Method Scoped Invocations ---
    {"id": "TC-38", "code": "class Vault:\n    def open(self):\n        from Crypto.PublicKey import RSA\n        return RSA.generate(2048)", "expected_algo": "RSA", "expected_present": True, "category": "Method Scoped Asymmetric"},
    {"id": "TC-39", "code": "class TokenManager:\n    def get_cipher(self):\n        from Crypto.Cipher import AES\n        return AES.new(self.k, AES.MODE_GCM)", "expected_algo": "AES", "expected_present": True, "category": "Method Scoped Symmetric"},
    {"id": "TC-40", "code": "def create_legacy_bridge():\n    from Crypto.Cipher import DES3\n    return DES3.new(b'123456781234567812345678', DES3.MODE_CBC)", "expected_algo": "3DES", "expected_present": True, "category": "Function Scoped Legacy"},
    {"id": "TC-41", "code": "def hash_password(pwd):\n    import hashlib\n    return hashlib.md5(pwd.encode()).hexdigest()", "expected_algo": "MD5", "expected_present": True, "category": "Function Scoped MD5"},
    {"id": "TC-42", "code": "def init_kyber():\n    import oqs\n    return oqs.KeyEncapsulation('ML-KEM-1024')", "expected_algo": "ML-KEM", "expected_present": True, "category": "PQC Native Max Security"}
]


class StaticAnalysisEvaluator:
    """Runs ground-truth static analysis evaluation and computes statistical performance metrics."""

    @staticmethod
    def evaluate(dataset: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        data = dataset or GROUND_TRUTH_DATASET
        tp = 0
        fp = 0
        fn = 0
        tn = 0
        detailed_results = []

        for sample in data:
            code = sample["code"]
            expected_algo = sample["expected_algo"]
            expected_present = sample["expected_present"]

            findings = scan_code(code, file_path="eval_test_snippet.py")
            detected_present = len(findings) > 0
            detected_algos = [f["algorithm"] for f in findings]

            # Classification Logic
            if expected_present and detected_present:
                # Check if detected algorithm matches expected
                matched = any(expected_algo in da or da in expected_algo for da in detected_algos)
                if matched:
                    classification = "TP"  # True Positive
                    tp += 1
                else:
                    classification = "FP"  # Flagged wrong algorithm
                    fp += 1
            elif expected_present and not detected_present:
                classification = "FN"  # False Negative (missed)
                fn += 1
            elif not expected_present and detected_present:
                classification = "FP"  # False Positive (false alarm)
                fp += 1
            else:
                classification = "TN"  # True Negative (correctly ignored)
                tn += 1

            detailed_results.append({
                "id": sample["id"],
                "category": sample["category"],
                "expected": expected_algo or "None (Clean)",
                "detected": ", ".join(detected_algos) if detected_algos else "None",
                "classification": classification,
                "status": "PASS" if classification in ("TP", "TN") else "FAIL",
                "code_snippet": code.splitlines()[0] if code else ""
            })

        total = len(data)
        precision = (tp / (tp + fp)) * 100 if (tp + fp) > 0 else 100.0
        recall = (tp / (tp + fn)) * 100 if (tp + fn) > 0 else 100.0
        f1_score = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 1.0
        accuracy = ((tp + tn) / total) * 100 if total > 0 else 100.0

        return {
            "total_samples": total,
            "true_positives": tp,
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "precision": round(precision, 2),
            "recall": round(recall, 2),
            "f1_score": round(f1_score / 100.0, 3) if f1_score > 1.0 else round(f1_score, 3),
            "accuracy": round(accuracy, 2),
            "results": detailed_results
        }

    @staticmethod
    def format_cli_report(metrics: Dict[str, Any], unicode_mode: bool = True) -> str:
        """Format an academic scientific benchmark evaluation report."""
        v_check = "✅" if unicode_mode else "[PASS]"
        v_cross = "❌" if unicode_mode else "[FAIL]"
        h_line = "─" * 78 if unicode_mode else "-" * 78

        lines = [
            "\n" + ("🔬 QRYPTIS STATIC ANALYSIS EVALUATION (GROUND TRUTH BENCHMARK)" if unicode_mode else "QRYPTIS STATIC ANALYSIS EVALUATION"),
            h_line,
            f"{'ID':<6} | {'Category':<22} | {'Expected':<14} | {'Detected':<16} | {'Result'}",
            h_line
        ]

        for r in metrics["results"]:
            mark = v_check if r["status"] == "PASS" else v_cross
            lines.append(
                f"{r['id']:<6} | {r['category'][:22]:<22} | {r['expected'][:14]:<14} | {r['detected'][:16]:<16} | {mark} {r['classification']}"
            )

        lines.extend([
            h_line,
            "\nEVALUATION METRICS",
            h_line,
            f"Total Test Samples:        {metrics['total_samples']}",
            f"True Positives (TP):       {metrics['true_positives']} (Cryptographic primitives detected)",
            f"True Negatives (TN):       {metrics['true_negatives']} (Non-cryptographic code ignored)",
            f"False Positives (FP):      {metrics['false_positives']} (False alarms on clean code)",
            f"False Negatives (FN):      {metrics['false_negatives']} (Missed cryptographic calls)",
            "",
            f"Precision:                 {metrics['precision']}%",
            f"Recall:                    {metrics['recall']}%",
            f"F1-Score:                  {metrics['f1_score']}",
            f"Overall Accuracy:          {metrics['accuracy']}%",
            h_line
        ])

        return "\n".join(lines)


def run_evaluation() -> Dict[str, Any]:
    return StaticAnalysisEvaluator.evaluate()
