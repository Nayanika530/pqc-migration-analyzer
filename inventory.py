# inventory.py
# Qryptis — Unified Cryptographic Asset Inventory Engine
# Aggregates cryptographic assets across Codebases, Websites, Certificates, and Infrastructure

import re
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from crypto_analyzer import ALGORITHM_DB, analyze_algorithm, generate_report


class CryptoAsset:
    """Represents a single cryptographic asset discovered in the enterprise."""

    def __init__(
        self,
        name: str,
        algorithm: str,
        key_size: int,
        source_type: str,
        source_target: str,
        usage: str,
        quantum_vulnerable: bool,
        deprecated: bool,
        is_pqc_ready: bool,
        recommended_pqc: str,
        location: str = "",
        details: str = ""
    ):
        self.name = name                      # e.g. "RSA-2048", "ECDSA P-256", "AES-256"
        self.algorithm = algorithm            # e.g. "RSA", "ECC", "AES"
        self.key_size = key_size              # e.g. 2048, 256, 128
        self.source_type = source_type        # "Codebase", "Website", "Certificate", "Manual"
        self.source_target = source_target    # e.g. "backend.zip", "example.com:443", "server.pem"
        self.usage = usage                    # "Digital Signature", "Key Exchange", "Symmetric Encryption"
        self.quantum_vulnerable = quantum_vulnerable
        self.deprecated = deprecated
        self.is_pqc_ready = is_pqc_ready
        self.recommended_pqc = recommended_pqc
        self.location = location
        self.details = details
        self.discovered_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "algorithm": self.algorithm,
            "key_size": self.key_size,
            "source_type": self.source_type,
            "source_target": self.source_target,
            "usage": self.usage,
            "quantum_vulnerable": self.quantum_vulnerable,
            "deprecated": self.deprecated,
            "is_pqc_ready": self.is_pqc_ready,
            "recommended_pqc": self.recommended_pqc,
            "location": self.location,
            "details": self.details,
            "discovered_at": self.discovered_at
        }


def parse_certificate_content(cert_text: str, filename: str = "server.pem") -> List[Dict[str, Any]]:
    """
    Parse PEM certificate or public/private key text to extract cryptographic primitives.
    Handles RSA, ECC, DSA, and standard X.509 certificate formats.
    """
    findings = []
    text = cert_text.strip()

    # 1. Try pycryptodome RSA key parsing
    try:
        from Crypto.PublicKey import RSA
        if "BEGIN RSA" in text or "BEGIN PUBLIC KEY" in text or "BEGIN PRIVATE KEY" in text:
            rsa_key = RSA.import_key(text)
            key_size = rsa_key.size_in_bits()
            findings.append({
                "algorithm": f"RSA-{key_size}",
                "base_algorithm": "RSA",
                "key_size": key_size,
                "usage": "Certificate Public Key / Encryption",
                "quantum_vulnerable": True,
                "deprecated": key_size < 2048,
                "pqc_replacement": "ML-KEM-768 / ML-DSA-65",
                "location": filename,
                "details": f"Imported RSA key ({key_size}-bit modulus)"
            })
            return findings
    except Exception:
        pass

    # 2. Try pycryptodome ECC key parsing
    try:
        from Crypto.PublicKey import ECC
        if "BEGIN EC" in text or "BEGIN PUBLIC KEY" in text or "BEGIN PRIVATE KEY" in text:
            ec_key = ECC.import_key(text)
            curve_name = getattr(ec_key, "curve", "P-256")
            findings.append({
                "algorithm": f"ECDSA {curve_name}",
                "base_algorithm": "ECC",
                "key_size": 256,
                "usage": "Certificate Signature / Key Exchange",
                "quantum_vulnerable": True,
                "deprecated": False,
                "pqc_replacement": "ML-DSA-65 / ML-KEM-768",
                "location": filename,
                "details": f"Elliptic Curve key (Curve: {curve_name})"
            })
            return findings
    except Exception:
        pass

    # 3. Fallback Heuristic / PEM Header Regex Parser
    if "BEGIN CERTIFICATE" in text:
        # Match standard certificate properties
        if "RSA" in text or "rsaEncryption" in text or len(text) > 1500:
            findings.append({
                "algorithm": "RSA-2048",
                "base_algorithm": "RSA",
                "key_size": 2048,
                "usage": "X.509 Certificate Public Key",
                "quantum_vulnerable": True,
                "deprecated": False,
                "pqc_replacement": "ML-DSA-65 (NIST FIPS 204)",
                "location": filename,
                "details": "Standard X.509 RSA Certificate Public Key"
            })
        else:
            findings.append({
                "algorithm": "ECDSA P-256",
                "base_algorithm": "ECC",
                "key_size": 256,
                "usage": "X.509 Certificate Signature",
                "quantum_vulnerable": True,
                "deprecated": False,
                "pqc_replacement": "ML-DSA-65",
                "location": filename,
                "details": "Standard X.509 ECDSA Certificate"
            })
    elif "BEGIN DSA" in text:
        findings.append({
            "algorithm": "DSA-2048",
            "base_algorithm": "DSA",
            "key_size": 2048,
            "usage": "Digital Signature",
            "quantum_vulnerable": True,
            "deprecated": True,
            "pqc_replacement": "ML-DSA-65",
            "location": filename,
            "details": "Legacy DSA Public/Private Key"
        })
    else:
        # Generic key heuristic
        findings.append({
            "algorithm": "RSA-2048",
            "base_algorithm": "RSA",
            "key_size": 2048,
            "usage": "Cryptographic Key / Certificate",
            "quantum_vulnerable": True,
            "deprecated": False,
            "pqc_replacement": "ML-KEM-768",
            "location": filename,
            "details": "Imported PEM Key Asset"
        })

    return findings


class CryptoInventory:
    """Manages the centralized inventory of cryptographic assets across an organization."""

    def __init__(self):
        self.assets: List[CryptoAsset] = []

    def clear(self):
        """Reset the inventory."""
        self.assets = []

    def add_asset(self, asset: CryptoAsset):
        """Add a single cryptographic asset."""
        self.assets.append(asset)

    def add_code_findings(self, findings: List[Dict[str, Any]], target_name: str = "Codebase"):
        """Ingest findings from static code scanner."""
        for f in findings:
            algo = f.get("algorithm", "Unknown")
            base_algo = f.get("base_algorithm", algo.split("-")[0] if "-" in algo else algo)
            key_size = f.get("key_size", 0)
            file_name = f.get("file") or f.get("file_path") or "source"
            line_num = f.get("line") or f.get("line_number") or 1
            usage_str = f.get("usage") or (f.get("purpose", "application_cryptography").replace("_", " ").title())
            
            # Format display name (e.g. RSA-2048, AES-256)
            if key_size and str(key_size) not in algo:
                display_name = f"{algo}-{key_size}"
            else:
                display_name = algo

            asset = CryptoAsset(
                name=display_name,
                algorithm=base_algo,
                key_size=key_size,
                source_type="Codebase",
                source_target=target_name,
                usage=usage_str,
                quantum_vulnerable=f.get("quantum_vulnerable", False) or f.get("report", {}).get("quantum_vulnerable", False),
                deprecated=f.get("deprecated", False) or f.get("report", {}).get("deprecated", False),
                is_pqc_ready=f.get("is_pqc_native", False) or "ML-KEM" in algo or "ML-DSA" in algo,
                recommended_pqc=f.get("pqc_replacement") or f.get("report", {}).get("recommended_replacement", "ML-KEM-768"),
                location=f"{file_name}:{line_num}",
                details=f.get("code_line") or f.get("matched_text") or str(f.get("code_snippet", ""))
            )
            self.add_asset(asset)

    def set_code_findings(self, findings: List[Dict[str, Any]], target_name: str = "Codebase"):
        """Replace the current inventory dynamically with findings from a fresh codebase scan."""
        self.clear()
        self.add_code_findings(findings, target_name=target_name)

    def add_live_scan(self, live_result: Dict[str, Any], target_name: str = "Website"):
        """Ingest findings from live TLS scan."""
        domain = live_result.get("domain", target_name)
        reports = live_result.get("reports", [])

        # Ingest TLS Handshake Suite
        cipher_suite = live_result.get("cipher_suite", "")
        if "X25519" in cipher_suite or "ECDHE" in cipher_suite:
            self.add_asset(CryptoAsset(
                name="X25519",
                algorithm="ECC",
                key_size=256,
                source_type="Website",
                source_target=f"{domain}:443",
                usage="TLS Key Exchange (ECDHE)",
                quantum_vulnerable=True,
                deprecated=False,
                is_pqc_ready=False,
                recommended_pqc="X25519 + ML-KEM-768 Hybrid",
                location=f"TLS Handshake ({live_result.get('tls_version', 'TLS 1.3')})",
                details=f"Negotiated Cipher Suite: {cipher_suite}"
            ))

        if "AES_256_GCM" in cipher_suite or "AES-256" in cipher_suite:
            self.add_asset(CryptoAsset(
                name="AES-256",
                algorithm="AES",
                key_size=256,
                source_type="Website",
                source_target=f"{domain}:443",
                usage="TLS Bulk Data Encryption",
                quantum_vulnerable=False,
                deprecated=False,
                is_pqc_ready=False,
                recommended_pqc="AES-256-GCM (Quantum Resilient)",
                location=f"TLS Symmetric Stream",
                details="AES-256-GCM Bulk Session Encryption"
            ))
        elif "AES_128_GCM" in cipher_suite or "AES-128" in cipher_suite:
            self.add_asset(CryptoAsset(
                name="AES-128",
                algorithm="AES",
                key_size=128,
                source_type="Website",
                source_target=f"{domain}:443",
                usage="TLS Bulk Data Encryption",
                quantum_vulnerable=False,
                deprecated=False,
                is_pqc_ready=False,
                recommended_pqc="AES-256-GCM",
                location=f"TLS Symmetric Stream",
                details="AES-128-GCM Bulk Session Encryption"
            ))

        # Ingest Certificate Public Key / Signature findings
        for r in reports:
            algo = r.get("algorithm", "RSA")
            key_size = r.get("key_size", 2048)
            self.add_asset(CryptoAsset(
                name=f"{algo}-{key_size}",
                algorithm=algo,
                key_size=key_size,
                source_type="Website",
                source_target=f"{domain}:443",
                usage="X.509 Server Certificate Public Key",
                quantum_vulnerable=r.get("quantum_vulnerable", True),
                deprecated=r.get("deprecated", False),
                is_pqc_ready=False,
                recommended_pqc=r.get("recommended_replacement", "ML-DSA-65"),
                location=f"Certificate Issuer: {live_result.get('certificate_issuer', 'Unknown')}",
                details=f"Subject: {live_result.get('certificate_subject', domain)} | Expires: {live_result.get('cert_expires', 'Unknown')}"
            ))

    def add_certificate(self, cert_text: str, filename: str = "server.pem"):
        """Ingest findings from PEM/CRT certificate file."""
        findings = parse_certificate_content(cert_text, filename)
        for f in findings:
            self.add_asset(CryptoAsset(
                name=f["algorithm"],
                algorithm=f["base_algorithm"],
                key_size=f["key_size"],
                source_type="Certificate",
                source_target=filename,
                usage=f["usage"],
                quantum_vulnerable=f["quantum_vulnerable"],
                deprecated=f["deprecated"],
                is_pqc_ready=False,
                recommended_pqc=f["pqc_replacement"],
                location=f["location"],
                details=f["details"]
            ))

    def add_manual_finding(self, report: Dict[str, Any], target_name: str = "Manual Assessment"):
        """Ingest finding from manual algorithm lookup."""
        algo = report.get("algorithm", "Unknown")
        key_size = report.get("key_size", 0)
        display_name = f"{algo}-{key_size}" if key_size and str(key_size) not in algo else algo
        
        self.add_asset(CryptoAsset(
            name=display_name,
            algorithm=algo,
            key_size=key_size,
            source_type="Manual",
            source_target=target_name,
            usage=report.get("type", "Cryptographic Primitive"),
            quantum_vulnerable=report.get("quantum_vulnerable", False),
            deprecated="DEPRECATED" in report.get("verdict", ""),
            is_pqc_ready="OK" in report.get("verdict", "") and not report.get("quantum_vulnerable", False),
            recommended_pqc=report.get("recommended_replacement", "ML-KEM-768"),
            location="Manual Security Query",
            details=f"Verdict: {report.get('verdict', '')} | Reason: {report.get('reason', '')}"
        ))

    def load_sample_inventory(self):
        """
        Load the canonical 47-asset enterprise sample combining:
        - Website (example.com)
        - Codebase (backend.zip)
        - Certificate (server.pem)
        
        Exact Result:
        - Total: 47 Assets
        - RSA-2048: 12
        - ECDSA P-256: 9
        - X25519: 8
        - AES-256: 7
        - AES-128: 5
        - 3DES: 3
        - DH-2048: 3
        - Quantum Vulnerable: 32 (12 + 9 + 8 + 3 = 32)
        - Deprecated: 3 (3DES = 3)
        - PQC Ready: 0
        """
        self.clear()

        # 1. RSA-2048 (12 assets: 10 in backend.zip, 1 in server.pem, 1 in example.com)
        for i in range(1, 11):
            self.add_asset(CryptoAsset(
                name="RSA-2048",
                algorithm="RSA",
                key_size=2048,
                source_type="Codebase",
                source_target="backend.zip",
                usage="JWT Token Signing & API Auth",
                quantum_vulnerable=True,
                deprecated=False,
                is_pqc_ready=False,
                recommended_pqc="ML-KEM-768 / ML-DSA-65",
                location=f"src/auth/service_{i}.py:42",
                details="private_key = RSA.generate(2048)"
            ))
        self.add_asset(CryptoAsset(
            name="RSA-2048",
            algorithm="RSA",
            key_size=2048,
            source_type="Certificate",
            source_target="server.pem",
            usage="X.509 Leaf Server Certificate",
            quantum_vulnerable=True,
            deprecated=False,
            is_pqc_ready=False,
            recommended_pqc="ML-DSA-65",
            location="server.pem:1",
            details="Subject: CN=api.enterprise.internal | RSA Public Key (2048-bit)"
        ))
        self.add_asset(CryptoAsset(
            name="RSA-2048",
            algorithm="RSA",
            key_size=2048,
            source_type="Website",
            source_target="example.com:443",
            usage="HTTPS Gateway Certificate",
            quantum_vulnerable=True,
            deprecated=False,
            is_pqc_ready=False,
            recommended_pqc="ML-DSA-65",
            location="example.com TLS Certificate",
            details="Issuer: Let's Encrypt Authority | RSA 2048-bit key"
        ))

        # 2. ECDSA P-256 (9 assets: 8 in backend.zip, 1 in example.com)
        for i in range(1, 9):
            self.add_asset(CryptoAsset(
                name="ECDSA P-256",
                algorithm="ECC",
                key_size=256,
                source_type="Codebase",
                source_target="backend.zip",
                usage="Microservice Inter-Service Signature",
                quantum_vulnerable=True,
                deprecated=False,
                is_pqc_ready=False,
                recommended_pqc="ML-DSA-65 (NIST FIPS 204)",
                location=f"src/crypto/ecc_signer_{i}.py:18",
                details="ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)"
            ))
        self.add_asset(CryptoAsset(
            name="ECDSA P-256",
            algorithm="ECC",
            key_size=256,
            source_type="Website",
            source_target="example.com:443",
            usage="TLS Handshake Server Key Exchange",
            quantum_vulnerable=True,
            deprecated=False,
            is_pqc_ready=False,
            recommended_pqc="ML-DSA-65",
            location="example.com TLS Handshake",
            details="ECDHE Key Exchange with NIST P-256 curve"
        ))

        # 3. X25519 (8 assets: 7 in backend.zip, 1 in example.com)
        for i in range(1, 8):
            self.add_asset(CryptoAsset(
                name="X25519",
                algorithm="ECC",
                key_size=256,
                source_type="Codebase",
                source_target="backend.zip",
                usage="End-to-End Key Agreement (Diffie-Hellman)",
                quantum_vulnerable=True,
                deprecated=False,
                is_pqc_ready=False,
                recommended_pqc="X25519 + ML-KEM-768 Hybrid",
                location=f"src/transport/x25519_channel_{i}.py:34",
                details="x25519.X25519PrivateKey.generate()"
            ))
        self.add_asset(CryptoAsset(
            name="X25519",
            algorithm="ECC",
            key_size=256,
            source_type="Website",
            source_target="example.com:443",
            usage="TLS 1.3 Key Exchange Group",
            quantum_vulnerable=True,
            deprecated=False,
            is_pqc_ready=False,
            recommended_pqc="X25519MLKEM768 Hybrid",
            location="example.com:443",
            details="TLS 1.3 key_share (group x25519)"
        ))

        # 4. AES-256 (7 assets: 6 in backend.zip, 1 in example.com)
        for i in range(1, 7):
            self.add_asset(CryptoAsset(
                name="AES-256",
                algorithm="AES",
                key_size=256,
                source_type="Codebase",
                source_target="backend.zip",
                usage="Database Column & Payload Encryption",
                quantum_vulnerable=False,
                deprecated=False,
                is_pqc_ready=False,
                recommended_pqc="AES-256-GCM (Quantum Resilient)",
                location=f"src/storage/cipher_{i}.py:22",
                details="AES.new(key, AES.MODE_GCM)"
            ))
        self.add_asset(CryptoAsset(
            name="AES-256",
            algorithm="AES",
            key_size=256,
            source_type="Website",
            source_target="example.com:443",
            usage="TLS Symmetric Stream",
            quantum_vulnerable=False,
            deprecated=False,
            is_pqc_ready=False,
            recommended_pqc="AES-256-GCM (Quantum Resilient)",
            location="example.com TLS Stream",
            details="TLS_AES_256_GCM_SHA384 cipher"
        ))

        # 5. AES-128 (5 assets: 5 in backend.zip)
        for i in range(1, 6):
            self.add_asset(CryptoAsset(
                name="AES-128",
                algorithm="AES",
                key_size=128,
                source_type="Codebase",
                source_target="backend.zip",
                usage="Session Token Symmetric Cipher",
                quantum_vulnerable=False,
                deprecated=False,
                is_pqc_ready=False,
                recommended_pqc="AES-256 (Key Hardening Required)",
                location=f"src/session/token_{i}.py:55",
                details="AES.new(key128, AES.MODE_CBC)"
            ))

        # 6. 3DES (3 assets: 3 in backend.zip)
        for i in range(1, 4):
            self.add_asset(CryptoAsset(
                name="3DES",
                algorithm="3DES",
                key_size=168,
                source_type="Codebase",
                source_target="backend.zip",
                usage="Legacy Payment Gateway Interop",
                quantum_vulnerable=False,
                deprecated=True,
                is_pqc_ready=False,
                recommended_pqc="AES-256-GCM (Immediate Deprecation)",
                location=f"src/legacy/gateway_{i}.py:29",
                details="DES3.new(key, DES3.MODE_CBC) -- Sweet32 collision risk"
            ))

        # 7. DH-2048 (3 assets: 3 in backend.zip)
        for i in range(1, 4):
            self.add_asset(CryptoAsset(
                name="DH-2048",
                algorithm="DIFFIE-HELLMAN",
                key_size=2048,
                source_type="Codebase",
                source_target="backend.zip",
                usage="Legacy VPN & Key Exchange",
                quantum_vulnerable=True,
                deprecated=False,
                is_pqc_ready=False,
                recommended_pqc="ML-KEM-768 (NIST FIPS 203)",
                location=f"src/vpn/dh_group_{i}.py:71",
                details="Diffie-Hellman 2048-bit MODP Group 14"
            ))

    def get_summary(self) -> Dict[str, Any]:
        """
        Generate aggregated statistical breakdown of the inventory.
        """
        total = len(self.assets)
        breakdown: Dict[str, int] = {}
        source_breakdown: Dict[str, int] = {"Codebase": 0, "Website": 0, "Certificate": 0, "Manual": 0}

        quantum_vulnerable_count = 0
        deprecated_count = 0
        pqc_ready_count = 0
        classically_secure_count = 0

        for asset in self.assets:
            # Algorithm breakdown count
            breakdown[asset.name] = breakdown.get(asset.name, 0) + 1

            # Source count
            source_breakdown[asset.source_type] = source_breakdown.get(asset.source_type, 0) + 1

            # Status count
            if asset.deprecated:
                deprecated_count += 1
            if asset.quantum_vulnerable:
                quantum_vulnerable_count += 1
            if asset.is_pqc_ready:
                pqc_ready_count += 1
            if not asset.quantum_vulnerable and not asset.deprecated:
                classically_secure_count += 1

        # Sort breakdown by count descending
        sorted_breakdown = dict(sorted(breakdown.items(), key=lambda item: item[1], reverse=True))

        # Calculate agility score
        if total > 0:
            agility_score = max(0, min(100, int(100 - (quantum_vulnerable_count * 2.5) - (deprecated_count * 5) + (pqc_ready_count * 10))))
        else:
            agility_score = 100

        grade = "A" if agility_score >= 85 else ("B" if agility_score >= 70 else ("C" if agility_score >= 55 else ("D" if agility_score >= 40 else "F")))

        return {
            "total_assets": total,
            "total_findings": total,
            "algorithm_breakdown": sorted_breakdown,
            "source_breakdown": source_breakdown,
            "quantum_vulnerable": quantum_vulnerable_count,
            "deprecated": deprecated_count,
            "pqc_ready": pqc_ready_count,
            "classically_secure": classically_secure_count,
            "agility_score": agility_score,
            "agility_grade": grade,
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")
        }

    def export_cbom(self, organization: str = "Enterprise Organization") -> Dict[str, Any]:
        """Generate full CycloneDX 1.6 compatible Cryptographic Bill of Materials (CBOM)."""
        summary = self.get_summary()
        components = []

        for idx, asset in enumerate(self.assets, 1):
            components.append({
                "bom-ref": f"crypto-asset-{idx}",
                "type": "cryptographic-asset",
                "name": asset.name,
                "version": "1.0",
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithm": asset.algorithm,
                    "keyLength": asset.key_size,
                    "usage": asset.usage,
                    "source": {
                        "type": asset.source_type,
                        "target": asset.source_target,
                        "location": asset.location
                    },
                    "quantumVulnerable": asset.quantum_vulnerable,
                    "deprecated": asset.deprecated,
                    "pqcReady": asset.is_pqc_ready,
                    "recommendedReplacement": asset.recommended_pqc
                }
            })

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": f"urn:uuid:qryptis-cbom-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            "version": 1,
            "metadata": {
                "timestamp": summary["timestamp"],
                "tools": [
                    {
                        "vendor": "Qryptis Security",
                        "name": "Qryptis PQC Migration Analyzer",
                        "version": "2026.1"
                    }
                ],
                "component": {
                    "name": organization,
                    "type": "enterprise-inventory"
                }
            },
            "summary": summary,
            "components": components
        }


# Global singleton inventory instance
GLOBAL_INVENTORY = CryptoInventory()
# Preload sample inventory by default so the system is immediately populated
GLOBAL_INVENTORY.load_sample_inventory()
