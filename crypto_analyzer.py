# crypto_analyzer.py
# Core logic: maps classical algorithms to quantum vulnerability + PQC replacement

import json
import ssl
import socket


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
    "3DES": 168,
    "MD5": 256,  # MD5 is 128-bit digest; minimum secure hash digest today is 256-bit (e.g. SHA-256)
    "HQC": 128,
    "ML-KEM": 512,
    "ML-KEM-512": 512,
    "ML-KEM-768": 768,
    "ML-KEM-1024": 1024,
    "ML-DSA": 44,
    "ML-DSA-44": 44,
    "ML-DSA-65": 65,
    "ML-DSA-87": 87,
    "SLH-DSA": 128,
    "SLH-DSA-128S": 128,
    "SLH-DSA-128F": 128
}


def check_key_size(name: str, key_size: int) -> dict:
    """Check if a given key size is classically secure today, on top of quantum vulnerability."""
    if not isinstance(key_size, int) or key_size <= 0:
        return {"error": "Key size must be a positive integer greater than 0."}

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


# ============================================================
# OFFICIAL NIST POST-QUANTUM CRYPTOGRAPHY STANDARDS LAYER
# Live ecosystem tracking (FIPS 203, 204, 205 + Round 4 HQC Selection)
# ============================================================
NIST_STANDARDS_DB = [
    {
        "standard": "FIPS 203",
        "algorithm": "ML-KEM",
        "name": "Module-Lattice Key Encapsulation Mechanism",
        "type": "Key Encapsulation (KEM)",
        "status": "✓ Final",
        "status_badge": "final",
        "date": "August 2024",
        "hardness": "Module-LWE (Lattice)",
        "security_category": "General Purpose / Primary KEM",
        "nist_guidance": "NIST recommends immediate migration for general encryption and key establishment (TLS, VPNs, data-in-transit)."
    },
    {
        "standard": "FIPS 204",
        "algorithm": "ML-DSA",
        "name": "Module-Lattice Digital Signature Algorithm",
        "type": "Digital Signature",
        "status": "✓ Final",
        "status_badge": "final",
        "date": "August 2024",
        "hardness": "Module-SIS (Lattice)",
        "security_category": "General Purpose / Primary Signature",
        "nist_guidance": "NIST recommends ML-DSA as the primary digital signature standard for certificates, PKI, and code signing."
    },
    {
        "standard": "FIPS 205",
        "algorithm": "SLH-DSA",
        "name": "Stateless Hash-Based Digital Signature Algorithm",
        "type": "Digital Signature",
        "status": "✓ Final",
        "status_badge": "final",
        "date": "August 2024",
        "hardness": "Cryptographic Hash (SPHINCS+)",
        "security_category": "Stateless Hash / Zero Lattice Dependency",
        "nist_guidance": "Recommended as a conservative, non-lattice backup signature scheme with established hash-based security proofs."
    },
    {
        "standard": "NIST Round 4 Selection",
        "algorithm": "HQC",
        "name": "Hamming Quasi-Cyclic",
        "type": "Key Encapsulation (KEM)",
        "status": "◐ Selected for Standardization",
        "status_badge": "selected",
        "date": "March 2025",
        "hardness": "Quasi-Cyclic Syndrome Decoding (Code-Based)",
        "security_category": "Code-Based / Non-Lattice KEM Alternative",
        "nist_guidance": "Selected by NIST in Round 4 as the official non-lattice general KEM alternative to ML-KEM for cryptographic diversification."
    },
    {
        "standard": "FIPS 206 (Draft)",
        "algorithm": "FN-DSA (FALCON)",
        "name": "Fast-Fourier Lattice-based Digital Signature",
        "type": "Digital Signature",
        "status": "◐ In Progress",
        "status_badge": "draft",
        "date": "Draft 2025/2026",
        "hardness": "NTRU Lattice",
        "security_category": "Compact High-Performance Signature",
        "nist_guidance": "Selected for compact signature size requirements in bandwidth-constrained environments."
    },
    {
        "standard": "Round 4 Evaluation",
        "algorithm": "Classic McEliece",
        "name": "Classic McEliece",
        "type": "Key Encapsulation (KEM)",
        "status": "○ Under Evaluation",
        "status_badge": "evaluation",
        "date": "Active Round 4",
        "hardness": "Goppa Codes (Code-Based)",
        "security_category": "Conservative Code-Based KEM",
        "nist_guidance": "Evaluated for ultra-compact ciphertexts (large public key footprint suited for static hardware)."
    }
]


ALGORITHM_DB = {
    "RSA": {
        "type": "asymmetric encryption / key exchange",
        "quantum_vulnerable": True,
        "reason": "RSA relies on factoring large numbers, which Shor's Algorithm solves efficiently on a quantum computer.",
        "pqc_replacement": "ML-KEM-768",
        "replacement_type": "Key Encapsulation Mechanism (KEM)",
        "hybrid_recommendation": "X25519 + ML-KEM-768 hybrid KEM (IETF draft standard) for backward compatibility and defense-in-depth",
        "deprecated": False
    },
    "ECC": {
        "type": "asymmetric encryption / key exchange",
        "quantum_vulnerable": True,
        "reason": "ECC relies on the elliptic curve discrete logarithm problem, also broken efficiently by Shor's Algorithm.",
        "pqc_replacement": "ML-KEM-768",
        "replacement_type": "Key Encapsulation Mechanism (KEM)",
        "hybrid_recommendation": "X25519 + ML-KEM-768 for key exchange; ECDSA + ML-DSA-65 hybrid for digital signatures",
        "deprecated": False
    },
    "AES": {
        "type": "symmetric encryption",
        "quantum_vulnerable": False,
        "reason": "AES isn't broken by quantum computers, but Grover's Algorithm halves its effective security, so key sizes should be doubled (e.g. AES-128 -> AES-256).",
        "pqc_replacement": "AES-256 (same algorithm, larger key)",
        "replacement_type": "Symmetric encryption (no PQC swap needed, just bigger key)",
        "hybrid_recommendation": "Use AES-256-GCM for authenticated encryption (no hybrid wrapper needed)",
        "deprecated": False
    },
    "DSA": {
        "type": "digital signature",
        "quantum_vulnerable": True,
        "reason": "DSA relies on the discrete logarithm problem, which Shor's Algorithm solves efficiently on a quantum computer.",
        "pqc_replacement": "ML-DSA-65",
        "replacement_type": "Digital Signature Algorithm",
        "hybrid_recommendation": "ECDSA + ML-DSA-65 hybrid signature scheme to maintain classical verification while deploying PQC",
        "deprecated": False
    },
    "DIFFIE-HELLMAN": {
        "type": "key exchange",
        "quantum_vulnerable": True,
        "reason": "Diffie-Hellman relies on the discrete logarithm problem, broken efficiently by Shor's Algorithm.",
        "pqc_replacement": "ML-KEM-768",
        "replacement_type": "Key Encapsulation Mechanism (KEM)",
        "hybrid_recommendation": "X25519 + ML-KEM-768 hybrid key exchange (FIPS 203 compliant)",
        "deprecated": False
    },
    "3DES": {
        "type": "symmetric encryption",
        "quantum_vulnerable": False,
        "reason": "3DES isn't broken by quantum computers the way RSA is, but it's already considered weak by classical standards (small effective key strength) and Grover's Algorithm weakens it further -- it should be retired regardless of quantum risk.",
        "pqc_replacement": "AES-256",
        "replacement_type": "Symmetric encryption (full replacement recommended, not just PQC upgrade)",
        "hybrid_recommendation": "Direct migration to AES-256-GCM",
        "deprecated": True
    },
    "MD5": {
        "type": "cryptographic hash function",
        "quantum_vulnerable": False,
        "reason": "MD5 has catastrophic classical collision vulnerabilities and was cryptographically broken in 2004. It should be retired immediately for security and integrity verification regardless of quantum risk.",
        "pqc_replacement": "SHA-256 / SHA-3 for hashing; ML-DSA-65 for integrity signatures",
        "replacement_type": "Cryptographic hash / collision-resistant digest",
        "hybrid_recommendation": "SHA-256 or SHA-512 with HMAC, or combine with ML-DSA for quantum-secure signatures",
        "deprecated": True
    },
    "HQC": {
        "type": "asymmetric encryption / key encapsulation (code-based)",
        "quantum_vulnerable": False,
        "reason": "HQC is a quantum-secure Key Encapsulation Mechanism based on quasi-cyclic syndrome decoding. Selected by NIST in March 2025 as the official non-lattice KEM standard alternative to ML-KEM.",
        "pqc_replacement": "HQC-128 / HQC-192 / HQC-256 (Native PQC Standard)",
        "replacement_type": "Code-Based KEM (NIST Standardized Alternative)",
        "hybrid_recommendation": "X25519 + HQC-128 or hybrid with ML-KEM for multi-family algorithm diversification",
        "deprecated": False,
        "is_pqc_native": True
    },
    "ML-KEM": {
        "type": "asymmetric encryption / key encapsulation (module lattice)",
        "quantum_vulnerable": False,
        "reason": "ML-KEM (FIPS 203) is the primary finalized NIST standard for general key encapsulation and public-key encryption.",
        "pqc_replacement": "ML-KEM-768 (Native NIST FIPS 203 Standard)",
        "replacement_type": "Module-Lattice KEM (FIPS 203)",
        "hybrid_recommendation": "X25519 + ML-KEM-768 for defense-in-depth transition",
        "deprecated": False,
        "is_pqc_native": True
    },
    "ML-DSA": {
        "type": "digital signature (module lattice)",
        "quantum_vulnerable": False,
        "reason": "ML-DSA (FIPS 204) is the primary finalized NIST standard for general digital signatures and PKI authentication.",
        "pqc_replacement": "ML-DSA-65 (Native NIST FIPS 204 Standard)",
        "replacement_type": "Module-Lattice Digital Signature (FIPS 204)",
        "hybrid_recommendation": "ECDSA + ML-DSA-65 for backward-compatible verification",
        "deprecated": False,
        "is_pqc_native": True
    },
    "SLH-DSA": {
        "type": "digital signature (stateless hash-based)",
        "quantum_vulnerable": False,
        "reason": "SLH-DSA (FIPS 205) is standardized by NIST as a stateless hash-based signature scheme with zero lattice dependencies.",
        "pqc_replacement": "SLH-DSA-128 (Native NIST FIPS 205 Standard)",
        "replacement_type": "Stateless Hash-Based Digital Signature (FIPS 205)",
        "hybrid_recommendation": "ECDSA + SLH-DSA-128 for high-assurance long-term code signing",
        "deprecated": False,
        "is_pqc_native": True
    },
    "ML-KEM-768": {
        "type": "asymmetric encryption / key encapsulation (module lattice)",
        "quantum_vulnerable": False,
        "reason": "ML-KEM-768 (NIST FIPS 203) is the primary finalized NIST standard at Security Category 3 (AES-192 equivalent).",
        "pqc_replacement": "ML-KEM-768 (Native NIST FIPS 203 Standard)",
        "replacement_type": "Module-Lattice KEM (FIPS 203)",
        "hybrid_recommendation": "X25519 + ML-KEM-768 for defense-in-depth transition",
        "deprecated": False,
        "is_pqc_native": True
    },
    "ML-DSA-65": {
        "type": "digital signature (module lattice)",
        "quantum_vulnerable": False,
        "reason": "ML-DSA-65 (NIST FIPS 204) is the primary finalized NIST standard at Security Category 3 for general digital signatures.",
        "pqc_replacement": "ML-DSA-65 (Native NIST FIPS 204 Standard)",
        "replacement_type": "Module-Lattice Digital Signature (FIPS 204)",
        "hybrid_recommendation": "ECDSA + ML-DSA-65 for backward-compatible verification",
        "deprecated": False,
        "is_pqc_native": True
    }
}


def analyze_algorithm(name: str) -> dict:
    """Look up an algorithm and return its quantum vulnerability info."""
    key = name.strip().upper()
    if key in ALGORITHM_DB:
        return ALGORITHM_DB[key]
    
    # Prefix fallback (e.g. ML-KEM-512 -> ML-KEM, ECDSA P-256 -> ECC)
    for db_key in ALGORITHM_DB:
        if key.startswith(db_key) or db_key.startswith(key):
            return ALGORITHM_DB[db_key]
            
    return {"error": f"'{name}' not found in database. Supported algorithms: {', '.join(ALGORITHM_DB.keys())}."}



def generate_report(name: str, key_size: int, purpose: str = None) -> dict:
    """
    Combine algorithm lookup + key size check + purpose-aware reasoning + benchmark data into one full report.
    Purpose-aware reasoning distinguishes digital signatures (ML-DSA) from key establishment (ML-KEM).
    """
    algo_info = analyze_algorithm(name)
    if "error" in algo_info:
        return algo_info

    size_info = check_key_size(name, key_size)
    if "error" in size_info:
        return size_info

    key = name.strip().upper()
    norm_purpose = (purpose or "").lower().strip()

    recommended_replacement = algo_info["pqc_replacement"]
    replacement_type = algo_info["replacement_type"]
    hybrid_rec = algo_info.get("hybrid_recommendation", "")

    # Purpose-Aware Cryptographic Reasoning Rules Engine
    if key == "RSA":
        if any(sig_term in norm_purpose for sig_term in ("sig", "jwt", "token", "pki", "cert", "verify", "auth")):
            recommended_replacement = "ML-DSA-65"
            replacement_type = "Module-Lattice Digital Signature Algorithm (NIST FIPS 204)"
            hybrid_rec = "RSA + ML-DSA-65 or ECDSA + ML-DSA-65 dual-signing hybrid scheme"
        else:
            recommended_replacement = "ML-KEM-768"
            replacement_type = "Module-Lattice Key Encapsulation Mechanism (NIST FIPS 203)"
            hybrid_rec = "X25519 + ML-KEM-768 hybrid KEM (IETF draft standard) for backward compatibility and defense-in-depth"
    elif key in ("ECC", "ECDSA"):
        if any(kem_term in norm_purpose for kem_term in ("kem", "exchange", "ecdh", "establishment")):
            recommended_replacement = "ML-KEM-768"
            replacement_type = "Key Encapsulation Mechanism (NIST FIPS 203)"
            hybrid_rec = "X25519 + ML-KEM-768 hybrid KEM"
        else:
            recommended_replacement = "ML-DSA-65"
            replacement_type = "Digital Signature Algorithm (NIST FIPS 204)"
            hybrid_rec = "ECDSA + ML-DSA-65 hybrid signature scheme"
    elif key == "AES":
        if key_size >= 256:
            recommended_replacement = "AES-256-GCM (Retain / Quantum Resilient)"
            replacement_type = "Symmetric Encryption (No PQC swap needed; Grover's algorithm leaves 128 bits of quantum security)"
            hybrid_rec = "Use AES-256-GCM for authenticated encryption"
        else:
            recommended_replacement = "AES-256-GCM"
            replacement_type = "Symmetric Encryption (Upgrade key size from 128-bit to 256-bit for Grover resilience)"
            hybrid_rec = "Direct migration to AES-256-GCM"

    # Overall verdict combines classical weakness, deprecation status, AND quantum vulnerability
    if algo_info["deprecated"]:
        verdict = "DEPRECATED -- considered insecure by modern standards regardless of quantum risk. Retire immediately."
    elif not size_info["classically_secure_today"]:
        verdict = "CRITICAL -- broken today, no quantum computer needed."
    elif algo_info["quantum_vulnerable"]:
        verdict = "AT RISK -- safe today, but will be broken once quantum computers mature."
    elif key == "AES" and key_size >= 256:
        verdict = "QUANTUM RESILIENT -- Grover's algorithm halves 256-bit strength to 128-bit quantum security; safe to continue using."
    else:
        verdict = "OK -- not significantly threatened by quantum computers."

    # Attach benchmark data if available
    benchmark_key = BENCHMARK_LOOKUP.get(key)
    benchmark_info = None

    if benchmark_key and benchmark_key in BENCHMARK_DATA:
        current = BENCHMARK_DATA[benchmark_key]
        benchmark_info = {
            "current_algorithm_keygen_ms": current["keygen"].get("avg_keygen_time_ms"),
            "current_algorithm_operation_ms": current["operation"]["avg_time_ms"]
        }

        pqc_target = "ML-DSA-65" if "DSA" in recommended_replacement else "ML-KEM-768"
        if pqc_target in BENCHMARK_DATA:
            pqc = BENCHMARK_DATA[pqc_target]
            benchmark_info["pqc_replacement_keygen_ms"] = pqc["keygen"]["avg_keygen_time_ms"]
            benchmark_info["pqc_replacement_operation_ms"] = pqc["operation"]["avg_time_ms"]

    return {
        "algorithm": key,
        "key_size": key_size,
        "purpose": purpose,
        "type": algo_info["type"],
        "quantum_vulnerable": algo_info["quantum_vulnerable"],
        "deprecated": algo_info["deprecated"],
        "reason": algo_info["reason"],
        "classically_secure_today": size_info["classically_secure_today"],
        "key_size_note": size_info["note"],
        "recommended_replacement": recommended_replacement,
        "replacement_type": replacement_type,
        "hybrid_recommendation": hybrid_rec,
        "verdict": verdict,
        "benchmark": benchmark_info
    }

def calculate_harvest_risk(algorithm: str, key_size: int, years_secret_needed: int) -> dict:
    """
    Calculate 'harvest now, decrypt later' risk: how urgent is migration
    based on how long this data needs to stay confidential.
    """
    if not isinstance(years_secret_needed, int) or years_secret_needed < 0:
        return {"error": "Years secret needed must be a non-negative integer (0 or greater)."}

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
        import ollama
        client = ollama.Client(timeout=2.0)
        response = client.chat(
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
- Manually check if a cryptographic algorithm (RSA, ECC, AES, DSA, Diffie-Hellman, 3DES, MD5) and key size is vulnerable to quantum computers
- Scan real source code to automatically detect vulnerable cryptography
- Calculate harvest-now-decrypt-later risk based on how long data needs to stay secret
- Generate a cryptographic agility score and migration roadmap for scanned code
- Export findings as a CBOM (Cryptographic Bill of Materials) or Markdown report

Guide users to the right page: Manual Lookup is at /manual, Code Scanner is at /scan.
Keep answers short, friendly, and beginner-appropriate. Under 80 words unless asked for detail."""

    try:
        import ollama
        client = ollama.Client(timeout=2.0)
        response = client.chat(
            model="mistral",
            messages=[
                {"role": "system", "content": system_context},
                {"role": "user", "content": user_message}
            ]
        )
        return response["message"]["content"]
    except Exception as e:
        return f"Sorry, the assistant is unavailable right now. Make sure Ollama is running. ({str(e)})"

def scan_live_website(domain: str) -> dict:
    """
    Connect to a real website and inspect its actual TLS certificate
    and cipher suite in use, right now, over the live internet.
    """
    domain = domain.strip().replace("https://", "").replace("http://", "").split("/")[0]

    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher_name, tls_version, secret_bits = ssock.cipher()

                issuer = dict(x[0] for x in cert.get("issuer", []))
                subject = dict(x[0] for x in cert.get("subject", []))

                # Try to match the cipher suite name against algorithms we know about
                detected_algorithms = []
                cipher_upper = cipher_name.upper()
                if "RSA" in cipher_upper:
                    detected_algorithms.append("RSA")
                if "ECDSA" in cipher_upper or "ECDHE" in cipher_upper:
                    detected_algorithms.append("ECC")
                if "AES" in cipher_upper:
                    detected_algorithms.append("AES")

                reports = []
                for algo in detected_algorithms:
                    if algo == "AES":
                        report = generate_report("AES", secret_bits)
                    else:
                        report = generate_report(algo, secret_bits)
                    if "error" not in report:
                        reports.append(report)

                return {
                    "domain": domain,
                    "connection_successful": True,
                    "tls_version": tls_version,
                    "cipher_suite": cipher_name,
                    "key_bits": secret_bits,
                    "certificate_issuer": issuer.get("organizationName", "Unknown"),
                    "certificate_subject": subject.get("commonName", domain),
                    "cert_expires": cert.get("notAfter", "Unknown"),
                    "detected_algorithms": detected_algorithms,
                    "reports": reports
                }

    except socket.timeout:
        return {"connection_successful": False, "error": f"Connection to {domain} timed out."}
    except socket.gaierror:
        return {"connection_successful": False, "error": f"Could not resolve domain: {domain}. Check the spelling."}
    except Exception as e:
        return {"connection_successful": False, "error": f"Could not connect to {domain}: {str(e)}"}

if __name__ == "__main__":
    test_cases = [("RSA", 1024), ("RSA", 2048), ("AES", 256), ("3DES", 168)]
    for algo, size in test_cases:
        print(generate_report(algo, size))
        print("-" * 40)