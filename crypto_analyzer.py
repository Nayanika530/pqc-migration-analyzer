# crypto_analyzer.py
# Core logic: maps classical algorithms to quantum vulnerability + PQC replacement

import json


def load_benchmarks() -> dict:
    """Load pre-computed benchmark results from disk."""
    try:
        with open("benchmark_results.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


BENCHMARK_DATA = load_benchmarks()

# Maps each algorithm to its corresponding benchmark key in benchmark_results.json
BENCHMARK_LOOKUP = {
    "RSA": "RSA-2048",
    "DIFFIE-HELLMAN": "RSA-2048",  # closest available comparison for now
    "AES": "AES-256",
    "3DES": "3DES",
}

# Minimum key size considered secure against classical (non-quantum) attacks today
MIN_SECURE_KEY_SIZE = {
    "RSA": 2048,
    "ECC": 256,
    "AES": 128,
    "DSA": 2048,
    "DIFFIE-HELLMAN": 2048,
    "3DES": 168
}


def check_key_size(name: str, key_size: int) -> dict:
    """Check if a given key size is classically secure today, on top of quantum vulnerability."""
    key = name.strip().upper()
    if key not in MIN_SECURE_KEY_SIZE:
        return {"error": f"'{name}' not found in database."}

    minimum = MIN_SECURE_KEY_SIZE[key]
    classically_secure = key_size >= minimum

    return {
        "algorithm": key,
        "provided_key_size": key_size,
        "minimum_recommended": minimum,
        "classically_secure_today": classically_secure,
        "note": (
            f"{key_size}-bit {key} meets today's classical security minimum."
            if classically_secure else
            f"{key_size}-bit {key} is BELOW the classical security minimum ({minimum}-bit) -- vulnerable even without a quantum computer."
        )
    }


ALGORITHM_DB = {
    "RSA": {
        "type": "asymmetric encryption / key exchange",
        "quantum_vulnerable": True,
        "reason": "RSA relies on factoring large numbers, which Shor's Algorithm solves efficiently on a quantum computer.",
        "pqc_replacement": "ML-KEM-768",
        "replacement_type": "Key Encapsulation Mechanism (KEM)",
        "deprecated": False
    },
    "ECC": {
        "type": "asymmetric encryption / key exchange",
        "quantum_vulnerable": True,
        "reason": "ECC relies on the elliptic curve discrete logarithm problem, also broken efficiently by Shor's Algorithm.",
        "pqc_replacement": "ML-KEM-768",
        "replacement_type": "Key Encapsulation Mechanism (KEM)",
        "deprecated": False
    },
    "AES": {
        "type": "symmetric encryption",
        "quantum_vulnerable": False,
        "reason": "AES isn't broken by quantum computers, but Grover's Algorithm halves its effective security, so key sizes should be doubled (e.g. AES-128 -> AES-256).",
        "pqc_replacement": "AES-256 (same algorithm, larger key)",
        "replacement_type": "Symmetric encryption (no PQC swap needed, just bigger key)",
        "deprecated": False
    },
    "DSA": {
        "type": "digital signature",
        "quantum_vulnerable": True,
        "reason": "DSA relies on the discrete logarithm problem, which Shor's Algorithm solves efficiently on a quantum computer.",
        "pqc_replacement": "ML-DSA-65",
        "replacement_type": "Digital Signature Algorithm",
        "deprecated": False
    },
    "DIFFIE-HELLMAN": {
        "type": "key exchange",
        "quantum_vulnerable": True,
        "reason": "Diffie-Hellman relies on the discrete logarithm problem, broken efficiently by Shor's Algorithm.",
        "pqc_replacement": "ML-KEM-768",
        "replacement_type": "Key Encapsulation Mechanism (KEM)",
        "deprecated": False
    },
    "3DES": {
        "type": "symmetric encryption",
        "quantum_vulnerable": False,
        "reason": "3DES isn't broken by quantum computers the way RSA is, but it's already considered weak by classical standards (small effective key strength) and Grover's Algorithm weakens it further -- it should be retired regardless of quantum risk.",
        "pqc_replacement": "AES-256",
        "replacement_type": "Symmetric encryption (full replacement recommended, not just PQC upgrade)",
        "deprecated": True
    }
}


def analyze_algorithm(name: str) -> dict:
    """Look up an algorithm and return its quantum vulnerability info."""
    key = name.strip().upper()
    if key not in ALGORITHM_DB:
        return {"error": f"'{name}' not found in database. Try RSA, ECC, AES, DSA, DIFFIE-HELLMAN, or 3DES."}
    return ALGORITHM_DB[key]


def generate_report(name: str, key_size: int) -> dict:
    """Combine algorithm lookup + key size check + benchmark data into one full report."""
    algo_info = analyze_algorithm(name)
    if "error" in algo_info:
        return algo_info

    size_info = check_key_size(name, key_size)
    if "error" in size_info:
        return size_info

    key = name.strip().upper()

    # Overall verdict combines classical weakness, deprecation status, AND quantum vulnerability
    if algo_info["deprecated"]:
        verdict = "DEPRECATED -- considered insecure by modern standards regardless of quantum risk. Retire immediately."
    elif not size_info["classically_secure_today"]:
        verdict = "CRITICAL -- broken today, no quantum computer needed."
    elif algo_info["quantum_vulnerable"]:
        verdict = "AT RISK -- safe today, but will be broken once quantum computers mature."
    else:
        verdict = "OK -- not significantly threatened by quantum computers."

    # Attach real benchmark data if available for this algorithm.
    # Only asymmetric algorithms (RSA, Diffie-Hellman) get compared against ML-KEM-768,
    # since that's their actual PQC replacement. AES and 3DES don't use ML-KEM at all.
    benchmark_key = BENCHMARK_LOOKUP.get(key)
    benchmark_info = None

    if benchmark_key and benchmark_key in BENCHMARK_DATA:
        current = BENCHMARK_DATA[benchmark_key]
        benchmark_info = {
            "current_algorithm_keygen_ms": current["keygen"].get("avg_keygen_time_ms"),
            "current_algorithm_operation_ms": current["operation"]["avg_time_ms"]
        }

        if key in ("RSA", "DIFFIE-HELLMAN") and "ML-KEM-768" in BENCHMARK_DATA:
            pqc = BENCHMARK_DATA["ML-KEM-768"]
            benchmark_info["pqc_replacement_keygen_ms"] = pqc["keygen"]["avg_keygen_time_ms"]
            benchmark_info["pqc_replacement_operation_ms"] = pqc["operation"]["avg_time_ms"]

    return {
        "algorithm": key,
        "key_size": key_size,
        "type": algo_info["type"],
        "quantum_vulnerable": algo_info["quantum_vulnerable"],
        "reason": algo_info["reason"],
        "classically_secure_today": size_info["classically_secure_today"],
        "key_size_note": size_info["note"],
        "recommended_replacement": algo_info["pqc_replacement"],
        "replacement_type": algo_info["replacement_type"],
        "verdict": verdict,
        "benchmark": benchmark_info
    }


if __name__ == "__main__":
    test_cases = [("RSA", 1024), ("RSA", 2048), ("AES", 256), ("3DES", 168)]
    for algo, size in test_cases:
        print(generate_report(algo, size))
        print("-" * 40)