# scanner.py
# Scans source code text to detect cryptographic algorithm usage
# and suggests secure replacement code

import re
from crypto_analyzer import generate_report

# Each pattern: (regex to search for, algorithm name, typical key size to assume if not specified)
DETECTION_PATTERNS = [
    (r"RSA\.generate\(\s*(\d+)", "RSA", 2048),
    (r"DES3\.new\(", "3DES", 168),
    (r"AES\.new\(", "AES", 256),
    (r"hashlib\.md5\(", "MD5", 128),
    (r"DSA\.generate\(\s*(\d+)", "DSA", 2048),
]

# Suggested replacement code for each vulnerable/deprecated algorithm
FIX_SNIPPETS = {
    "RSA": (
        "# Option A: Direct NIST PQC Replacement (ML-KEM-768 for key exchange):\n"
        "import oqs\n"
        "with oqs.KeyEncapsulation('ML-KEM-768') as kem:\n"
        "    public_key = kem.generate_keypair()\n"
        "    # Send public_key to recipient; recipient encapsulates shared secret\n\n"
        "# Option B: Hybrid Transition (X25519 + ML-KEM-768 for defense-in-depth):\n"
        "# Combine classical ECDH (X25519) with ML-KEM-768 and derive shared key via HKDF"
    ),
    "3DES": (
        "# Replace 3DES with AES-256-GCM:\n"
        "from Crypto.Cipher import AES\n"
        "from Crypto.Random import get_random_bytes\n"
        "key = get_random_bytes(32)  # 256-bit key\n"
        "cipher = AES.new(key, AES.MODE_GCM)"
    ),
    "DSA": (
        "# Option A: Direct NIST PQC Signature (ML-DSA-65):\n"
        "import oqs\n"
        "with oqs.Signature('ML-DSA-65') as sig:\n"
        "    public_key = sig.generate_keypair()\n"
        "    signature = sig.sign(message)\n\n"
        "# Option B: Hybrid Dual-Signature (ECDSA + ML-DSA-65) for backward compatibility"
    ),
    "MD5": (
        "# Replace MD5 with SHA-256 / SHA-3 (MD5 is broken by classical collision attacks):\n"
        "import hashlib\n"
        "digest = hashlib.sha256(data).hexdigest()"
    ),
}


# Affected architectural components mapped by cryptographic algorithm
AFFECTED_COMPONENTS = {
    "RSA": ["Authentication", "API Gateway", "JWT Verification", "Key Exchange (PKI)"],
    "ECC": ["TLS Handshake", "API Gateway", "Digital Signatures", "Mobile Client Auth"],
    "AES": ["Data-at-Rest Encryption", "Database Vault", "Session Management"],
    "3DES": ["Legacy Payment Gateway", "Archived Backup Storage", "Hardware Security Module (HSM)"],
    "MD5": ["File Integrity Verification", "Password Hashing (Insecure)", "ETag / Cache Validation"],
    "DSA": ["SSH Keypairs", "Code Signing", "PKI Infrastructure"],
    "DIFFIE-HELLMAN": ["TLS Key Exchange", "VPN Tunnel Negotiation", "Session Forward Secrecy"]
}

# Migration effort / complexity assessment
MIGRATION_DIFFICULTY = {
    "RSA": "MEDIUM",
    "ECC": "MEDIUM",
    "DSA": "MEDIUM",
    "DIFFIE-HELLMAN": "MEDIUM",
    "AES": "LOW",
    "3DES": "HIGH",
    "MD5": "HIGH"
}


def scan_code(code_text: str) -> list:
    """Scan a block of code text for known crypto patterns and return findings."""
    findings = []

    for pattern, algo_name, default_key_size in DETECTION_PATTERNS:
        matches = re.finditer(pattern, code_text)
        for match in matches:
            if match.groups() and match.group(1):
                try:
                    key_size = int(match.group(1))
                except ValueError:
                    key_size = default_key_size
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


def scan_and_report(code_text: str, file_path: str = "pasted_code.py") -> list:
    """Scan code and attach a full vulnerability report, metadata, and code snippet to each finding."""
    findings = scan_code(code_text)
    results = []
    lines = code_text.splitlines()

    for finding in findings:
        algo = finding["algorithm"]
        key_size = finding["key_size"]

        if key_size is not None:
            report = generate_report(algo, key_size)
        else:
            report = {"error": f"{algo} detected but key size could not be determined."}

        suggested_fix = FIX_SNIPPETS.get(algo)
        line_num = finding["line_number"]

        # Extract surrounding code snippet (2 lines before and after)
        target_idx = line_num - 1
        start_idx = max(0, target_idx - 2)
        end_idx = min(len(lines), target_idx + 3)
        code_snippet = []
        for idx in range(start_idx, end_idx):
            code_snippet.append({
                "line_num": idx + 1,
                "code": lines[idx] if idx < len(lines) else "",
                "is_target": (idx == target_idx)
            })

        # Calculate granular severity (CRITICAL, HIGH, MEDIUM, LOW)
        verdict = report.get("verdict", "")
        if report.get("deprecated") or "CRITICAL" in verdict or "DEPRECATED" in verdict:
            severity = "CRITICAL"
        elif report.get("quantum_vulnerable"):
            severity = "HIGH"
        elif algo == "AES" and key_size and key_size < 256:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        # Determine readable quantum & classical statuses
        if report.get("quantum_vulnerable"):
            quantum_status = "🔴 VULNERABLE"
        else:
            quantum_status = "🟢 QUANTUM SECURE"

        if report.get("deprecated"):
            classical_status = "🟡 DEPRECATED"
        elif not report.get("classically_secure_today", True):
            classical_status = "🔴 BROKEN TODAY"
        else:
            classical_status = f"🟢 Currently acceptable ({key_size}-bit)"

        # Determine usage description
        usage = report.get("type", "Cryptographic operation").capitalize()
        if "asymmetric" in usage.lower() or "kem" in usage.lower():
            if algo == "DSA":
                usage = "Digital signature"
            elif algo in ["RSA", "ECC"]:
                usage = "Digital signature / Key exchange"
            elif algo == "DIFFIE-HELLMAN":
                usage = "Key exchange"
        elif "symmetric" in usage.lower():
            usage = "Symmetric encryption"
        elif "hash" in usage.lower():
            usage = "Cryptographic hash / integrity digest"

        results.append({
            "file_path": file_path,
            "line_number": line_num,
            "location": f"{file_path}:{line_num}",
            "matched_text": finding["matched_text"],
            "report": report,
            "suggested_fix": suggested_fix,
            "code_snippet": code_snippet,
            "severity": severity,
            "quantum_status": quantum_status,
            "classical_status": classical_status,
            "usage": usage,
            "migration_target": report.get("recommended_replacement", "ML-KEM-768"),
            "migration_difficulty": MIGRATION_DIFFICULTY.get(algo, "MEDIUM"),
            "affected_components": AFFECTED_COMPONENTS.get(algo, ["Authentication", "API Gateway", "Data Security"]),
        })

    return results


import os

def scan_directory(target_path: str) -> dict:
    """
    Recursively scans a directory or single file for cryptographic usages.
    Ignores common non-code / dependency directories (.git, venv, node_modules).
    """
    supported_extensions = {
        ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go",
        ".c", ".cpp", ".cc", ".h", ".hpp", ".cs", ".rb", ".php",
        ".swift", ".kt", ".rs", ".txt"
    }
    ignored_dirs = {
        ".git", ".svn", ".hg", "venv", "env", "node_modules",
        "__pycache__", "build", "dist", "target", ".idea", ".vscode",
        ".pytest_cache", "liboqs"
    }

    all_findings = []
    files_scanned = 0
    files_with_findings = set()

    if os.path.isfile(target_path):
        try:
            with open(target_path, "r", encoding="utf-8", errors="ignore") as f:
                code_text = f.read()
            findings = scan_and_report(code_text, file_path=target_path)
            all_findings.extend(findings)
            files_scanned = 1
            if findings:
                files_with_findings.add(target_path)
        except Exception as e:
            pass
    elif os.path.isdir(target_path):
        for root, dirs, files in os.walk(target_path):
            # Modify dirs in-place to skip ignored directories
            dirs[:] = [d for d in dirs if d not in ignored_dirs and not d.startswith(".")]

            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in supported_extensions or file.endswith("rc"):
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, target_path)
                    try:
                        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                            code_text = f.read()
                        files_scanned += 1
                        findings = scan_and_report(code_text, file_path=rel_path)
                        if findings:
                            all_findings.extend(findings)
                            files_with_findings.add(rel_path)
                    except Exception:
                        continue

    agility = calculate_agility_score(all_findings)
    roadmap = generate_migration_roadmap(all_findings)
    forecast = generate_risk_forecast(all_findings)
    cbom = generate_cbom(all_findings, source_name=os.path.basename(target_path) or target_path)

    counts = {
        "critical": sum(1 for r in all_findings if r.get("severity") == "CRITICAL"),
        "high": sum(1 for r in all_findings if r.get("severity") == "HIGH"),
        "medium": sum(1 for r in all_findings if r.get("severity") == "MEDIUM"),
        "low": sum(1 for r in all_findings if r.get("severity") == "LOW"),
    }

    return {
        "target_path": target_path,
        "files_scanned": files_scanned,
        "files_with_findings_count": len(files_with_findings),
        "total_findings": len(all_findings),
        "results": all_findings,
        "summary": counts,
        "agility": agility,
        "roadmap": roadmap,
        "forecast": forecast,
        "cbom": cbom
    }


import datetime

def generate_cbom(scan_results: list, source_name: str = "pasted_code") -> dict:
    """Generate a Cryptographic Bill of Materials (CBOM) from scan results."""
    components = []

    for finding in scan_results:
        report = finding.get("report", {})
        if "error" in report:
            continue  # skip findings we couldn't fully analyze

        components.append({
            "type": "cryptographic-asset",
            "algorithm": report.get("algorithm"),
            "key-size-bits": report.get("key_size"),
            "location": {
                "source": finding.get("file_path", source_name),
                "line": finding.get("line_number")
            },
            "quantum-vulnerable": report.get("quantum_vulnerable"),
            "deprecated": "DEPRECATED" in report.get("verdict", ""),
            "risk-verdict": report.get("verdict"),
            "recommended-replacement": report.get("recommended_replacement"),
            "hybrid-recommendation": report.get("hybrid_recommendation", "")
        })

    return {
        "bomFormat": "CBOM",
        "specVersion": "custom-simplified-1.0",
        "serialNumber": f"urn:uuid:pqc-scan-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.datetime.now().isoformat(),
            "tool": "PQC Migration Analyzer",
            "source": source_name
        },
        "components": components,
        "summary": {
            "total_findings": len(components),
            "quantum_vulnerable_count": sum(1 for c in components if c["quantum-vulnerable"]),
            "deprecated_count": sum(1 for c in components if c["deprecated"]),
        }
    }
def calculate_agility_score(scan_results: list) -> dict:
    """
    Score how cryptographically 'agile' a codebase is -- i.e. how easy
    it would be to swap out its crypto without a painful rewrite.
    Based on how much of what was found is deprecated, quantum-vulnerable,
    or lacking diversity (everything hardcoded to one weak algorithm).
    """
    valid_findings = [f for f in scan_results if "error" not in f.get("report", {})]

    if not valid_findings:
        return {
            "score": None,
            "grade": "N/A",
            "explanation": "No analyzable cryptographic algorithms were found to score."
        }

    score = 100
    deprecated_count = 0
    vulnerable_count = 0
    algorithms_used = set()

    for finding in valid_findings:
        report = finding["report"]
        algorithms_used.add(report["algorithm"])

        if "DEPRECATED" in report["verdict"]:
            deprecated_count += 1
            score -= 15
        elif report["quantum_vulnerable"]:
            vulnerable_count += 1
            score -= 10

    # Penalize low diversity: if everything relies on just one algorithm,
    # swapping it out later means touching every single usage at once.
    if len(algorithms_used) == 1 and len(valid_findings) > 1:
        score -= 10

    score = max(score, 0)  # never go below 0

    if score >= 80:
        grade = "A -- Agile"
    elif score >= 60:
        grade = "B -- Reasonably Agile"
    elif score >= 40:
        grade = "C -- Needs Work"
    elif score >= 20:
        grade = "D -- Rigid"
    else:
        grade = "F -- Critical Rigidity"

    return {
        "score": score,
        "grade": grade,
        "total_findings": len(valid_findings),
        "deprecated_count": deprecated_count,
        "vulnerable_count": vulnerable_count,
        "unique_algorithms": len(algorithms_used),
        "explanation": (
            f"Found {len(valid_findings)} cryptographic usages across {len(algorithms_used)} "
            f"distinct algorithm(s), including {deprecated_count} deprecated and "
            f"{vulnerable_count} quantum-vulnerable instances."
        )
    }
def generate_migration_roadmap(scan_results: list) -> dict:
    """
    Group scan findings into a phased migration plan --
    what to fix first, second, third.
    """
    valid_findings = [f for f in scan_results if "error" not in f.get("report", {})]

    phase1_deprecated = []
    phase2_critical = []
    phase3_quantum_risk = []

    for finding in valid_findings:
        report = finding["report"]
        entry = {
            "line": finding["line_number"],
            "algorithm": report["algorithm"],
            "key_size": report["key_size"],
            "verdict": report["verdict"]
        }

        if "DEPRECATED" in report["verdict"]:
            phase1_deprecated.append(entry)
        elif "CRITICAL" in report["verdict"]:
            phase2_critical.append(entry)
        elif report["quantum_vulnerable"]:
            phase3_quantum_risk.append(entry)

    phases = []

    if phase1_deprecated:
        phases.append({
            "phase": 1,
            "title": "Remove deprecated algorithms",
            "urgency": "Immediate",
            "reason": "These are insecure by modern standards regardless of quantum risk.",
            "affected": phase1_deprecated
        })

    if phase2_critical:
        phases.append({
            "phase": len(phases) + 1,
            "title": "Fix critically weak key sizes",
            "urgency": "Immediate",
            "reason": "These are breakable by classical computers today, no quantum computer needed.",
            "affected": phase2_critical
        })

    if phase3_quantum_risk:
        phases.append({
            "phase": len(phases) + 1,
            "title": "Plan post-quantum migration",
            "urgency": "Near-term",
            "reason": "Currently safe classically, but will be broken once quantum computers mature.",
            "affected": phase3_quantum_risk
        })

    return {
        "total_phases": len(phases),
        "phases": phases
    }
def export_roadmap_as_markdown(roadmap: dict, agility: dict) -> str:
    """Convert the migration roadmap + agility score into a readable Markdown report."""
    lines = ["# Cryptographic Migration Report\n"]

    if agility and agility.get("score") is not None:
        lines.append(f"## Cryptographic Agility Score: {agility['score']}/100 — {agility['grade']}\n")
        lines.append(f"{agility['explanation']}\n")

    if roadmap["total_phases"] == 0:
        lines.append("No migration action needed — no vulnerable or deprecated cryptography found.\n")
    else:
        lines.append("## Migration Roadmap\n")
        for phase in roadmap["phases"]:
            lines.append(f"### Phase {phase['phase']}: {phase['title']} ({phase['urgency']})")
            lines.append(f"{phase['reason']}\n")
            for item in phase["affected"]:
                lines.append(f"- Line {item['line']}: **{item['algorithm']}** ({item['key_size']}-bit) — {item['verdict']}")
            lines.append("")  # blank line between phases

    return "\n".join(lines)


def generate_risk_forecast(scan_results: list) -> dict:
    """
    Simple visual-friendly risk forecast: estimates how migration urgency
    trends over the next 5 years based on what was found.
    NOT a scientific prediction of quantum computer timelines --
    just a rough visualization of accumulating risk if nothing is migrated.
    """
    valid_findings = [f for f in scan_results if "error" not in f.get("report", {})]

    deprecated = sum(1 for f in valid_findings if "DEPRECATED" in f["report"]["verdict"])
    critical = sum(1 for f in valid_findings if "CRITICAL" in f["report"]["verdict"])
    at_risk = sum(1 for f in valid_findings if "AT RISK" in f["report"]["verdict"])

    # Simple weighted "current risk" baseline out of 100
    base_risk = min((deprecated * 20) + (critical * 25) + (at_risk * 10), 100)

    # Rough curve: risk compounds over 5 years if nothing is migrated,
    # since exposure window shrinks and quantum computing progress continues
    forecast = []
    for year_offset in range(5):
        year = 2026 + year_offset
        projected_risk = min(base_risk + (year_offset * 8), 100)
        forecast.append({"year": year, "risk_score": projected_risk})

    return {
        "current_risk_score": base_risk,
        "forecast": forecast,
        "note": "This is a simplified illustrative trend based on unmigrated findings, not a scientific quantum-computing timeline prediction."
    }


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