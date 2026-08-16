# scanner.py
# Scans source code text to detect cryptographic algorithm usage
# and suggests secure replacement code

import re
from crypto_analyzer import generate_report

# Each pattern: (regex to search for, algorithm name, typical key size to assume if not specified)
DETECTION_PATTERNS = [
    (r"RSA\.generate\(\s*(\d+)", "RSA", None),
    (r"DES3\.new\(", "3DES", 168),
    (r"AES\.new\(", "AES", 256),
    (r"hashlib\.md5\(", "MD5", None),
    (r"DSA\.generate\(\s*(\d+)", "DSA", None),
]

# Suggested replacement code for each vulnerable/deprecated algorithm
FIX_SNIPPETS = {
    "RSA": (
        "# Replace RSA with ML-KEM-768 (NIST PQC standard) for key exchange:\n"
        "import oqs\n"
        "with oqs.KeyEncapsulation('ML-KEM-768') as kem:\n"
        "    public_key = kem.generate_keypair()\n"
        "    # Send public_key to the other party, they encapsulate a shared secret back"
    ),
    "3DES": (
        "# Replace 3DES with AES-256:\n"
        "from Crypto.Cipher import AES\n"
        "from Crypto.Random import get_random_bytes\n"
        "key = get_random_bytes(32)  # 256-bit key\n"
        "cipher = AES.new(key, AES.MODE_CBC)"
    ),
    "DSA": (
        "# Replace DSA with ML-DSA-65 (NIST PQC standard) for signatures:\n"
        "import oqs\n"
        "with oqs.Signature('ML-DSA-65') as sig:\n"
        "    public_key = sig.generate_keypair()\n"
        "    signature = sig.sign(message)"
    ),
    "MD5": (
        "# Replace MD5 with SHA-256 (MD5 is broken, not even a quantum issue):\n"
        "import hashlib\n"
        "hashlib.sha256(data).hexdigest()"
    ),
}


def scan_code(code_text: str) -> list:
    """Scan a block of code text for known crypto patterns and return findings."""
    findings = []

    for pattern, algo_name, default_key_size in DETECTION_PATTERNS:
        matches = re.finditer(pattern, code_text)
        for match in matches:
            if match.groups():
                key_size = int(match.group(1))
            else:
                key_size = default_key_size

            line_number = code_text[:match.start()].count("\n") + 1

            findings.append({
                "algorithm": algo_name,
                "key_size": key_size,
                "line_number": line_number,
                "matched_text": match.group(0)
            })

    return findings


def scan_and_report(code_text: str) -> list:
    """Scan code and attach a full vulnerability report + suggested fix to each finding."""
    findings = scan_code(code_text)
    results = []

    for finding in findings:
        algo = finding["algorithm"]

        if finding["key_size"] is not None and algo != "MD5":
            report = generate_report(algo, finding["key_size"])
        else:
            report = {"error": f"{algo} detected but not in our vulnerability database yet."}

        suggested_fix = FIX_SNIPPETS.get(algo)

        results.append({
            "line_number": finding["line_number"],
            "matched_text": finding["matched_text"],
            "report": report,
            "suggested_fix": suggested_fix
        })

    return results


if __name__ == "__main__":
    sample_code = """
import rsa
from Crypto.PublicKey import RSA
from Crypto.Cipher import DES3, AES
import hashlib

key = RSA.generate(1024)
cipher = DES3.new(key, DES3.MODE_CBC)
aes_cipher = AES.new(key, AES.MODE_CBC)
hashlib.md5(b"test")
"""
    results = scan_and_report(sample_code)
    for r in results:
        print(f"Line {r['line_number']}: {r['matched_text']}")
        print(r['report'])
        if r['suggested_fix']:
            print("Suggested fix:")
            print(r['suggested_fix'])
        print("-" * 40)