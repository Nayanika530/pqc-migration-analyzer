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

def calculate_harvest_risk(algorithm: str, key_size: int, years_secret_needed: int) -> dict:
    """
    Calculate 'harvest now, decrypt later' risk: how urgent is migration
    based on how long this data needs to stay confidential.
    """
    report = generate_report(algorithm, key_size)
    if "error" in report:
        return report

    if not report["quantum_vulnerable"]:
        return {
            "algorithm": report["algorithm"],
            "years_secret_needed": years_secret_needed,
            "harvest_risk": "NOT APPLICABLE",
            "explanation": f"{report['algorithm']} is not quantum-vulnerable, so harvest-now-decrypt-later does not apply."
        }

    # Rough, clearly-labeled estimate window for when quantum computers might
    # realistically threaten current RSA/ECC-class encryption -- based on general
    # industry expectations (NOT a scientific prediction), roughly 10-20 years out.
    estimated_years_until_quantum_threat = 15

    years_of_exposure = years_secret_needed - estimated_years_until_quantum_threat

    if years_of_exposure <= 0:
        risk_level = "LOW"
        explanation = (
            f"Data protected by {report['algorithm']} needs to stay secret for {years_secret_needed} years. "
            f"That's within the window before quantum computers are expected to threaten this algorithm, "
            f"so exposure risk is currently low -- but migration should still happen eventually."
        )
    elif years_of_exposure <= 10:
        risk_level = "MEDIUM"
        explanation = (
            f"Data protected by {report['algorithm']} needs to stay secret for {years_secret_needed} years, "
            f"which extends {years_of_exposure} years past the estimated quantum threat window. "
            f"Migration should be planned soon."
        )
    else:
        risk_level = "HIGH"
        explanation = (
            f"Data protected by {report['algorithm']} needs to stay secret for {years_secret_needed} years, "
            f"which extends {years_of_exposure} years past the estimated quantum threat window. "
            f"This data is at serious risk of being harvested now and decrypted later. Migrate urgently."
        )

    return {
        "algorithm": report["algorithm"],
        "years_secret_needed": years_secret_needed,
        "estimated_years_until_quantum_threat": estimated_years_until_quantum_threat,
        "harvest_risk": risk_level,
        "explanation": explanation
    }

import ollama

def get_ai_explanation(report: dict) -> str:
    """
    Ask the local Ollama model to explain a vulnerability report
    in plain, beginner-friendly language.
    """
    if "error" in report:
        return "No explanation available -- this algorithm wasn't found in the database."

    prompt = f"""You are a friendly cybersecurity assistant. Explain this cryptography
vulnerability report in simple, plain English for someone with zero security background.
Keep it under 100 words. Do not use bullet points, just a short conversational paragraph.

Algorithm: {report['algorithm']} ({report['key_size']}-bit)
Verdict: {report['verdict']}
Reason: {report['reason']}
Recommended replacement: {report['recommended_replacement']}
"""

    try:
        response = ollama.chat(
            model="mistral",
            messages=[{"role": "user", "content": prompt}]
        )
        return response["message"]["content"]
    except Exception as e:
        return f"AI explanation unavailable right now ({str(e)}). Make sure Ollama is running."

def chat_with_assistant(user_message: str) -> str:
    """
    General-purpose chat assistant that knows about this tool
    and can guide users on how to use it or answer crypto questions.
    """
    system_context = """You are a helpful assistant embedded in the PQC Migration Analyzer website.
This tool helps users:
- Manually check if a cryptographic algorithm (RSA, ECC, AES, DSA, Diffie-Hellman, 3DES) and key size is vulnerable to quantum computers
- Scan real source code to automatically detect vulnerable cryptography
- Calculate harvest-now-decrypt-later risk based on how long data needs to stay secret
- Generate a cryptographic agility score and migration roadmap for scanned code
- Export findings as a CBOM (Cryptographic Bill of Materials) or Markdown report

Guide users to the right page: Manual Lookup is at /manual, Code Scanner is at /scan.
Keep answers short, friendly, and beginner-appropriate. Under 80 words unless asked for detail."""

    try:
        response = ollama.chat(
            model="mistral",
            messages=[
                {"role": "system", "content": system_context},
                {"role": "user", "content": user_message}
            ]
        )
        return response["message"]["content"]
    except Exception as e:
        return f"Sorry, the assistant is unavailable right now. Make sure Ollama is running. ({str(e)})"

if __name__ == "__main__":
    test_cases = [("RSA", 1024), ("RSA", 2048), ("AES", 256), ("3DES", 168)]
    for algo, size in test_cases:
        print(generate_report(algo, size))
        print("-" * 40)