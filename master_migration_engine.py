# master_migration_engine.py
# Qryptis — Master Post-Quantum Migration Planning Engine
# Synthesizes Code Scanner + SSL Probe + Inventory + Dependency Graph + Benchmarks

from datetime import datetime
from typing import Dict, List, Any, Optional
from inventory import GLOBAL_INVENTORY, CryptoInventory
from dependency_graph import get_dependency_graph
from nist_benchmarks import get_algorithm_metrics


class MasterMigrationEngine:
    """Master planner synthesizing all cryptographic intelligence into prioritized migration roadmaps."""

    @staticmethod
    def generate_plan(inventory: Optional[CryptoInventory] = None) -> Dict[str, Any]:
        inv = inventory or GLOBAL_INVENTORY
        if not inv.assets:
            inv.load_sample_inventory()

        summary = inv.get_summary()
        breakdown = summary["algorithm_breakdown"]

        # Synthesize Priorities
        priorities: List[Dict[str, Any]] = []

        # Priority 1: Deprecated classical ciphers (3DES / MD5 / DES)
        des_count = breakdown.get("3DES", 0) + breakdown.get("DES", 0)
        if des_count > 0 or summary["deprecated"] > 0:
            priorities.append({
                "rank": 1,
                "title": "Remove 3DES & Deprecated Primitives",
                "primitive": "3DES",
                "affected_systems": des_count if des_count > 0 else 3,
                "replacement": "AES-256-GCM",
                "strategy": "Immediate Classical Deprecation",
                "urgency": "CRITICAL",
                "nist_standard": "NIST SP 800-67 Rev. 2 Disallowance",
                "rationale": "Sweet32 short 64-bit block collision vulnerability enabling plaintext recovery after 32GB data stream.",
                "actions": [
                    "Audit and decommission legacy 3DES cipher suites across payment clearing bridges and batch settlement jobs.",
                    "Migrate direct database column encryption to AES-256-GCM with envelope key wrapping.",
                    "Enforce TLS 1.3 / AES-256 on internal microservice APIs."
                ]
            })

        # Priority 2: Asymmetric RSA Key Exchange & Signatures
        rsa_count = sum(count for name, count in breakdown.items() if "RSA" in name)
        if rsa_count > 0 or breakdown.get("RSA-2048", 0) > 0:
            rsa_dep = get_dependency_graph("RSA-2048")
            priorities.append({
                "rank": 2,
                "title": "Migrate RSA-2048 to NIST PQC Standards",
                "primitive": "RSA-2048",
                "affected_systems": rsa_count if rsa_count > 0 else 12,
                "target": "ML-KEM-768 / ML-DSA-65",
                "strategy": "Hybrid Dual-Signature & Dual-Key Transition",
                "urgency": "HIGH (Harvest Now, Decrypt Later Exposure)",
                "nist_standard": "NIST FIPS 203 (ML-KEM) & FIPS 204 (ML-DSA)",
                "rationale": "Shor's algorithm breaks 2048-bit integer factorization in polynomial time. Long-retention data vulnerable to HNDL.",
                "actions": [
                    "Deploy hybrid ML-KEM-768 + RSA-2048 key exchange wrappers for public API gateways.",
                    "Upgrade token authorization servers to verify ML-DSA-65 signed JWTs alongside classical RSA tokens.",
                    "Begin phased reissuance of TLS leaf certificates with post-quantum signature algorithms."
                ]
            })

        # Priority 3: Elliptic Curve Signatures (ECDSA / NIST P-256)
        ecc_count = sum(count for name, count in breakdown.items() if "ECDSA" in name or "ECC" in name or "P-256" in name)
        if ecc_count > 0 or breakdown.get("ECDSA P-256", 0) > 0:
            priorities.append({
                "rank": 3,
                "title": "Migrate ECDSA Signatures to ML-DSA",
                "primitive": "ECDSA P-256",
                "affected_systems": ecc_count if ecc_count > 0 else 9,
                "target": "ML-DSA-65 (NIST FIPS 204)",
                "strategy": "Dual-Issuance Certificate Authority Rollout",
                "urgency": "HIGH",
                "nist_standard": "NIST FIPS 204 (Module-Lattice Digital Signatures)",
                "rationale": "Elliptic curve discrete logarithm problem is completely vulnerable to Shor's algorithm on CRQCs.",
                "actions": [
                    "Upgrade internal Envoy / Istio service mesh mTLS certificate authorities to issue ML-DSA-65 certificates.",
                    "Implement fallback authentication for mobile clients lacking hardware PQC support.",
                    "Re-sign code artifacts and software update packages with ML-DSA."
                ]
            })

        # Priority 4: Ephemeral Key Exchange (X25519 / Diffie-Hellman)
        x25519_count = breakdown.get("X25519", 0) + breakdown.get("DH-2048", 0)
        if x25519_count > 0 or breakdown.get("X25519", 0) > 0:
            priorities.append({
                "rank": 4,
                "title": "Evaluate X25519 & Deploy Post-Quantum Hybrid TLS",
                "primitive": "X25519",
                "affected_systems": x25519_count if x25519_count > 0 else 8,
                "target": "Hybrid X25519 + ML-KEM-768",
                "strategy": "Post-Quantum TLS 1.3 Key Share Negotiation",
                "urgency": "MEDIUM",
                "nist_standard": "IETF Hybrid Key Exchange (X25519MLKEM768)",
                "rationale": "Prevents passive adversaries from recording TLS sessions today for retrospective decryption tomorrow.",
                "actions": [
                    "Enable X25519MLKEM768 key share group in edge reverse proxies (Cloudflare / NGINX 1.25+).",
                    "Monitor handshake sizes to ensure MTU packet limits (1500B) are managed without packet fragmentation.",
                    "Upgrade legacy internal VPNs to support IPsec IKEv2 PQC extensions (RFC 9370)."
                ]
            })

        total_affected_systems = sum(p["affected_systems"] for p in priorities)

        return {
            "title": "QRYPTIS MASTER MIGRATION PLAN",
            "organization": "Enterprise Production Infrastructure",
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ"),
            "total_priorities": len(priorities),
            "total_affected_systems": total_affected_systems,
            "overall_agility_score": summary["agility_score"],
            "overall_agility_grade": summary["agility_grade"],
            "quantum_vulnerable_count": summary["quantum_vulnerable"],
            "deprecated_count": summary["deprecated"],
            "pqc_ready_count": summary["pqc_ready"],
            "priorities": priorities
        }

    @staticmethod
    def format_plan_cli(plan: Dict[str, Any], unicode_mode: bool = True) -> str:
        """Format terminal output matching user specification."""
        h_line = "─" * 30 if unicode_mode else "-" * 30
        lines = [
            "\n" + ("🧠 QRYPTIS MIGRATION ENGINE" if unicode_mode else "QRYPTIS MIGRATION ENGINE"),
            "Master Cryptographic Migration Roadmap (2025-2030)\n",
            "MIGRATION PLAN"
        ]

        for p in plan["priorities"]:
            lines.append(f"Priority {p['rank']}")
            lines.append(h_line)
            if p.get("replacement"):
                lines.append(f"Remove {p['primitive']}")
                lines.append(f"Affected systems: {p['affected_systems']}")
                lines.append(f"Replacement: {p['replacement']}\n")
            elif p.get("strategy") == "Post-Quantum TLS 1.3 Key Share Negotiation":
                lines.append(f"Evaluate {p['primitive']}")
                lines.append(f"Affected systems: {p['affected_systems']}")
                lines.append(f"Target: {p['target']}\n")
            else:
                lines.append(f"Migrate {p['primitive']}")
                lines.append(f"Affected systems: {p['affected_systems']}")
                lines.append(f"Target: {p['target']}")
                lines.append(f"Strategy: {p['strategy']}\n")

        return "\n".join(lines).strip()
