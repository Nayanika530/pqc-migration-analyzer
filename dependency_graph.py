# dependency_graph.py
# Qryptis — Cryptographic Dependency Graph & Blast Radius Analysis Engine
# Computes downstream microservice dependencies and migration blast radius

from typing import Dict, List, Any, Optional


# Canonical enterprise dependency map modeling real-world infrastructure dependencies
ENTERPRISE_DEPENDENCY_MAP = {
    "RSA-2048": {
        "algorithm": "RSA-2048",
        "base_algorithm": "RSA",
        "quantum_vulnerable": True,
        "migration_target": "ML-KEM-768 / ML-DSA-65",
        "domains": [
            {
                "name": "Auth API",
                "role": "Identity & Access Gateway",
                "usage": "JWT Token Minting & JWKS Public Key Distribution",
                "protocol": "OAuth 2.0 / OpenID Connect",
                "services_count": 4,
                "services": [
                    {"name": "user-session-service", "impact": "Token verification failure if signature algorithm changes"},
                    {"name": "api-gateway", "impact": "Central request authentication filter"},
                    {"name": "mobile-client-gateway", "impact": "OAuth2 client token exchange & refresh"},
                    {"name": "billing-service", "impact": "Admin authorization claims validation"}
                ]
            },
            {
                "name": "Payment",
                "role": "Payment Processing Engine",
                "usage": "Payload Signature & Webhook Verification",
                "protocol": "Signed Webhooks / mTLS",
                "services_count": 2,
                "services": [
                    {"name": "checkout-service", "impact": "Cardholder data tokenization & encryption"},
                    {"name": "fraud-detection-service", "impact": "Signed asynchronous webhook ingestion"}
                ]
            },
            {
                "name": "VPN",
                "role": "Remote Ingress Gateway",
                "usage": "TLS Server Certificate & Corporate Tunneling",
                "protocol": "TLS 1.3 / IPsec",
                "services_count": 1,
                "services": [
                    {"name": "bastion-ingress-proxy", "impact": "Corporate ingress tunnel handshake"}
                ]
            }
        ],
        "complexity": "HIGH",
        "breaking_changes": [
            "Client SDKs must be upgraded to verify ML-DSA-65 signatures or hybrid tokens",
            "JWKS endpoint (/auth/jwks.json) public key format transition",
            "TLS leaf certificate reissuance on ingress proxies"
        ],
        "mitigation_strategy": "Deploy Dual-Signature & Hybrid ML-KEM-768 / ML-DSA transition wrappers before hard deprecating RSA."
    },
    "ECDSA P-256": {
        "algorithm": "ECDSA P-256",
        "base_algorithm": "ECC",
        "quantum_vulnerable": True,
        "migration_target": "ML-DSA-65 (NIST FIPS 204)",
        "domains": [
            {
                "name": "Service Mesh",
                "role": "Inter-Service mTLS Auth",
                "usage": "Internal gRPC & microservice mutual authentication",
                "protocol": "gRPC / mTLS SPIFFE",
                "services_count": 5,
                "services": [
                    {"name": "order-service", "impact": "Service-to-service gRPC identity validation"},
                    {"name": "inventory-service", "impact": "Synchronous stock reservation calls"},
                    {"name": "shipping-service", "impact": "Carrier dispatch coordination API"},
                    {"name": "notification-service", "impact": "Push notification event worker"},
                    {"name": "analytics-worker", "impact": "Telemetry and metrics collection"}
                ]
            },
            {
                "name": "Mobile Attestation",
                "role": "App Integrity Verification",
                "usage": "Hardware key-backed client app attestation",
                "protocol": "App Attest / Play Integrity",
                "services_count": 2,
                "services": [
                    {"name": "ios-auth-relay", "impact": "Apple DeviceCheck / App Attest validation"},
                    {"name": "android-safetynet-proxy", "impact": "Play Integrity token verification"}
                ]
            }
        ],
        "complexity": "HIGH",
        "breaking_changes": [
            "Internal Envoy / Istio service mesh mTLS certificate authorities require PQC support",
            "Hardware Secure Enclaves on older devices do not natively support ML-DSA without software emulation"
        ],
        "mitigation_strategy": "Upgrade service mesh CA to dual-issuance ECDSA + ML-DSA certificates."
    },
    "X25519": {
        "algorithm": "X25519",
        "base_algorithm": "ECC",
        "quantum_vulnerable": True,
        "migration_target": "X25519 + ML-KEM-768 Hybrid (FIPS 203)",
        "domains": [
            {
                "name": "Edge CDN Gateway",
                "role": "Public Ingress Termination",
                "usage": "TLS 1.3 Key Encapsulation (ECDHE)",
                "protocol": "TLS 1.3",
                "services_count": 4,
                "services": [
                    {"name": "edge-router-us", "impact": "Public HTTPS handshake key negotiation"},
                    {"name": "edge-router-eu", "impact": "Public HTTPS handshake key negotiation"},
                    {"name": "edge-router-apac", "impact": "Public HTTPS handshake key negotiation"},
                    {"name": "api-proxy-main", "impact": "Reverse proxy backend TLS connection"}
                ]
            }
        ],
        "complexity": "MEDIUM",
        "breaking_changes": [
            "Client browsers/clients must support X25519Kyber768 or X25519MLKEM768 hybrid key exchange"
        ],
        "mitigation_strategy": "Enable X25519 + ML-KEM-768 hybrid key exchange group in NGINX / Cloudflare."
    },
    "3DES": {
        "algorithm": "3DES",
        "base_algorithm": "3DES",
        "quantum_vulnerable": False,
        "migration_target": "AES-256-GCM",
        "domains": [
            {
                "name": "Legacy Clearing",
                "role": "Mainframe POS Clearing",
                "usage": "Legacy magnetic-stripe card data encryption",
                "protocol": "ISO 8583 Banking Protocol",
                "services_count": 2,
                "services": [
                    {"name": "legacy-pos-ingest", "impact": "Point-of-sale terminal data decryption"},
                    {"name": "mainframe-clearing-bridge", "impact": "Batch settlement transaction encryption"}
                ]
            }
        ],
        "complexity": "MEDIUM",
        "breaking_changes": [
            "External banking partner integration requires cipher suite renegotiation"
        ],
        "mitigation_strategy": "Migrate direct database columns to AES-256-GCM with envelope encryption."
    },
    "DH-2048": {
        "algorithm": "DH-2048",
        "base_algorithm": "DIFFIE-HELLMAN",
        "quantum_vulnerable": True,
        "migration_target": "ML-KEM-768",
        "domains": [
            {
                "name": "Site-to-Site VPN",
                "role": "Datacenter Interconnect",
                "usage": "IPsec IKEv2 Phase 1 Key Exchange",
                "protocol": "IPsec IKEv2",
                "services_count": 3,
                "services": [
                    {"name": "datacenter-tunnel-east", "impact": "Cross-datacenter encrypted tunnel"},
                    {"name": "datacenter-tunnel-west", "impact": "Secondary datacenter encrypted tunnel"},
                    {"name": "backup-tunnel-dr", "impact": "Disaster recovery replication tunnel"}
                ]
            }
        ],
        "complexity": "HIGH",
        "breaking_changes": [
            "Hardware VPN firewalls must support Post-Quantum IKEv2 extensions (RFC 9370)"
        ],
        "mitigation_strategy": "Upgrade VPN appliances to support hybrid IKEv2 with ML-KEM key exchange."
    },
    "AES-256": {
        "algorithm": "AES-256",
        "base_algorithm": "AES",
        "quantum_vulnerable": False,
        "migration_target": "AES-256-GCM (Quantum Resilient)",
        "domains": [
            {
                "name": "Data Storage",
                "role": "Database Column & S3 Vault",
                "usage": "At-rest database encryption & object storage",
                "protocol": "Envelope Encryption / AES-GCM",
                "services_count": 6,
                "services": [
                    {"name": "user-vault-db", "impact": "PII data decryption"},
                    {"name": "transaction-ledger-db", "impact": "Financial record verification"},
                    {"name": "kms-key-manager", "impact": "Customer master key derivation"},
                    {"name": "audit-logger", "impact": "Tamper-evident log sealing"},
                    {"name": "backup-vault", "impact": "Daily snapshot archival encryption"},
                    {"name": "analytics-warehouse", "impact": "Data lake columnar decryption"}
                ]
            }
        ],
        "complexity": "LOW",
        "breaking_changes": [
            "Zero breaking changes required — AES-256 is quantum-safe under Grover's algorithm"
        ],
        "mitigation_strategy": "Maintain 256-bit key lengths and rotate KMS master keys annually."
    }
}


def get_dependency_graph(algorithm_name: str) -> Dict[str, Any]:
    """
    Compute the cryptographic dependency graph and blast radius impact for a given algorithm.
    """
    key = algorithm_name.strip().upper()
    
    # Direct match or alias resolution
    target_data = None
    for k, v in ENTERPRISE_DEPENDENCY_MAP.items():
        if k.upper() == key or v["base_algorithm"].upper() == key or k.upper().replace("-", "") == key.replace("-", ""):
            target_data = v
            break

    if not target_data:
        # Generate default dynamic dependency graph
        target_data = {
            "algorithm": algorithm_name,
            "base_algorithm": algorithm_name.split("-")[0],
            "quantum_vulnerable": True,
            "migration_target": "ML-KEM-768 / ML-DSA-65",
            "domains": [
                {
                    "name": "Core Application API",
                    "role": "Primary Cryptographic Consumer",
                    "usage": f"Cryptographic primitive ({algorithm_name}) operations",
                    "protocol": "Internal Application Stack",
                    "services_count": 2,
                    "services": [
                        {"name": "backend-core-service", "impact": "Direct cryptographic call invocations"},
                        {"name": "worker-queue-service", "impact": "Asynchronous job payload validation"}
                    ]
                }
            ],
            "complexity": "MEDIUM",
            "breaking_changes": ["Service interfaces must adopt PQC parameter structures"],
            "mitigation_strategy": "Introduce abstraction layer for cryptographic agility."
        }

    # Calculate total affected downstream services
    total_services = sum(d["services_count"] for d in target_data["domains"])
    domains_count = len(target_data["domains"])

    return {
        "algorithm": target_data["algorithm"],
        "base_algorithm": target_data["base_algorithm"],
        "quantum_vulnerable": target_data["quantum_vulnerable"],
        "migration_target": target_data["migration_target"],
        "domains_count": domains_count,
        "total_services_affected": total_services,
        "impact_statement": f"Replacing {target_data['algorithm']} affects {total_services} service{'s' if total_services != 1 else ''}.",
        "complexity": target_data["complexity"],
        "domains": target_data["domains"],
        "breaking_changes": target_data.get("breaking_changes", []),
        "mitigation_strategy": target_data.get("mitigation_strategy", "")
    }


def get_all_dependency_graphs() -> List[Dict[str, Any]]:
    """Return all modeled dependency graphs across the enterprise."""
    return [get_dependency_graph(name) for name in ENTERPRISE_DEPENDENCY_MAP.keys()]


def format_ascii_graph(algorithm_name: str, unicode_mode: bool = True) -> str:
    """
    Format a terminal-friendly ASCII/Unicode dependency graph matching the exact visual spec:
    
                      RSA-2048
                         │
              ┌──────────┼──────────┐
              ↓          ↓          ↓
          Auth API    Payment      VPN
              │          │          │
              ↓          ↓          ↓
          4 services   2 services   1 service
    
    Replacing RSA-2048 affects 7 services.
    """
    graph = get_dependency_graph(algorithm_name)
    algo = graph["algorithm"]
    domains = graph["domains"]
    total = graph["total_services_affected"]

    v_bar = "│" if unicode_mode else "|"
    d_arrow = "↓" if unicode_mode else "v"
    t_left = "┌" if unicode_mode else "+"
    t_cross = "┼" if unicode_mode else "+"
    t_right = "┐" if unicode_mode else "+"
    h_bar = "─" if unicode_mode else "-"

    if len(domains) == 3:
        d1, d2, d3 = domains[0], domains[1], domains[2]
        ascii_tree = f"""
                  {algo}
                     {v_bar}
          {t_left}{h_bar * 10}{t_cross}{h_bar * 10}{t_right}
          {d_arrow}          {d_arrow}          {d_arrow}
      {d1['name']:<10} {d2['name']:<10} {d3['name']:<10}
          {v_bar}          {v_bar}          {v_bar}
          {d_arrow}          {d_arrow}          {d_arrow}
      {d1['services_count']} services   {d2['services_count']} services   {d3['services_count']} service{'s' if d3['services_count'] != 1 else ''}

Replacing {algo} affects {total} services.
"""
    elif len(domains) == 2:
        d1, d2 = domains[0], domains[1]
        t_split = "┴" if unicode_mode else "+"
        ascii_tree = f"""
                  {algo}
                     {v_bar}
              {t_left}{h_bar * 6}{t_split}{h_bar * 6}{t_right}
              {d_arrow}             {d_arrow}
       {d1['name']:<14} {d2['name']:<14}
              {v_bar}             {v_bar}
              {d_arrow}             {d_arrow}
          {d1['services_count']} services      {d2['services_count']} services

Replacing {algo} affects {total} services.
"""
    else:
        d1 = domains[0]
        ascii_tree = f"""
                  {algo}
                     {v_bar}
                     {d_arrow}
              {d1['name']}
                     {v_bar}
                     {d_arrow}
                 {d1['services_count']} services

Replacing {algo} affects {total} services.
"""

    return ascii_tree.strip()
