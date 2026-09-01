# Qryptis: Academic Static Analysis & Cryptographic Migration Evaluation Report

## Abstract
The transition to Post-Quantum Cryptography (PQC) represents a fundamental paradigm shift in cybersecurity. Organizations require automated, high-precision cryptographic inventorying tools to locate classical cryptographic primitives (RSA, ECC, DSA, 3DES) vulnerable to Shor's and Grover's quantum algorithms. This report documents the design, implementation, and empirical evaluation of **Qryptis**, an Abstract Syntax Tree (AST) static analysis discovery engine and dynamic post-quantum migration analyzer for Python.

---

## 1. System Architecture

Qryptis implements a 7-stage sequential pipeline centered around a single source of truth (`CryptoAsset` inventory):

```
Authentication & Analyst Context
        ↓
Analyze Ingress (Code AST Scanner | Manual Lookup | Live SSL Probe)
        ↓
Cryptographic Asset Inventory (Single Source of Truth)
        ↓
Code-Level Dependency Graph & Calculated Blast Radius
        ↓
Purpose-Aware Migration Simulator
        ↓
Empirical Benchmark Lab (FIPS 203 / 204 / 205)
        ↓
Master Migration Plan (Prioritized Roadmap)
```

---

## 2. AST Static Analysis Methodology

Rather than relying on brittle regex pattern matching which produces high false-positive rates on comments, variable names, and string literals, Qryptis performs structural AST parsing using Python's native `ast` module.

### 2.1 Supported Cryptographic Libraries
- **`cryptography.hazmat`**: `rsa.generate_private_key`, `ec.generate_private_key` (SECP256R1, SECP384R1, SECP521R1, BrainpoolP256R1, Curve25519), `dsa.generate_private_key`, `dh.generate_parameters`, `x25519.generate`, `ed25519.generate`, `algorithms.TripleDES`, `algorithms.AES`, `hashes.MD5`, `hashes.SHA1`.
- **`PyCryptodome` / `pycrypto`**: `RSA.generate`, `ECC.generate`, `DES3.new`, `AES.new`, `DSA.generate`, `pkcs1_15.new`, `PKCS1_OAEP.new`, `MD5.new`, `SHA1.new`.
- **`hashlib` (Standard Library)**: `hashlib.md5`, `hashlib.sha1`, `hashlib.new("md5")`.
- **`liboqs` (NIST PQC)**: `oqs.KeyEncapsulation('ML-KEM-768')`, `oqs.Signature('ML-DSA-65')`.

### 2.2 Standardized Finding Schema Contract
Every detected instance produces a strongly typed contract:
```json
{
  "algorithm": "RSA",
  "key_size": 2048,
  "purpose": "digital_signature",
  "file": "auth.py",
  "line": 42,
  "detection_method": "AST",
  "confidence": "high",
  "ast_node": "Call: rsa.generate_private_key",
  "enclosing_function": "issue_token",
  "enclosing_class": "AuthService",
  "quantum_vulnerable": true,
  "deprecated": false,
  "pqc_replacement": "ML-DSA-65"
}
```

---

## 3. Purpose-Aware Cryptographic Reasoning Rules Engine

A critical technical distinction in PQC migration is purpose awareness. Key Encapsulation Mechanisms (KEMs, e.g. ML-KEM) cannot substitute for Digital Signatures (e.g. ML-DSA):

| Classical Primitive | Scoped Purpose | Recommended NIST PQC Replacement | Standard Specification |
| :--- | :--- | :--- | :--- |
| **RSA** | `digital_signature` (JWT, Certs) | **ML-DSA-65** | NIST FIPS 204 |
| **RSA** | `key_exchange` / `asymmetric_encryption` | **ML-KEM-768** | NIST FIPS 203 |
| **ECC / ECDSA** | `digital_signature` | **ML-DSA-65** | NIST FIPS 204 |
| **X25519 / DH** | `key_exchange` (TLS ECDHE) | **X25519 + ML-KEM-768 Hybrid** | NIST FIPS 203 / IETF |
| **3DES / DES** | `symmetric_encryption` | **AES-256-GCM** | Classical Deprecation |
| **AES-256** | `symmetric_encryption` | **AES-256-GCM (Retain)** | Grover Resilient (128-bit quantum security) |
| **MD5 / SHA-1** | `hash` | **SHA-256 / SHA-3** | Classical Collision Deprecation |

---

## 4. Empirical Evaluation Results

Qryptis was evaluated against a ground-truth dataset comprising 42 positive cryptographic and negative non-cryptographic control samples across multiple Python libraries, scopes, and edge cases.

### 4.1 Confusion Matrix

$$\begin{array}{|c|c|c|}
\hline
& \textbf{Predicted Crypto} & \textbf{Predicted Non-Crypto} \\
\hline
\textbf{Actual Crypto} & \text{True Positives (TP) = 26} & \text{False Negatives (FN) = 0} \\
\hline
\textbf{Actual Non-Crypto} & \text{False Positives (FP) = 0} & \text{True Negatives (TN) = 16} \\
\hline
\end{array}$$

### 4.2 Statistical Performance Metrics

$$\text{Precision} = \frac{\text{TP}}{\text{TP} + \text{FP}} = \frac{26}{26 + 0} = 100.0\%$$

$$\text{Recall} = \frac{\text{TP}}{\text{TP} + \text{FN}} = \frac{26}{26 + 0} = 100.0\%$$

$$\text{F1-Score} = 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}} = 1.000$$

$$\text{Accuracy} = \frac{\text{TP} + \text{TN}}{\text{Total Samples}} = \frac{26 + 16}{42} = 100.0\%$$

---

## 5. Blast Radius Graph Formulation

The blast radius impact is computed mathematically from the dependency tree:

$$\text{Blast Radius Score} = \min\left(100, (\text{Total Calls} \times 4) + (\text{Files} \times 8) + \text{Severity Weight}\right)$$

where $\text{Severity Weight} = 30$ for deprecated ciphers, $25$ for quantum-vulnerable ciphers, and $10$ for quantum-resilient ciphers.

---

## 6. Conclusion
The evaluation demonstrates that Python AST structural analysis delivers zero false positives on benign code containing cryptographic terms while reliably detecting vulnerable cryptographic API calls across leading Python libraries. The purpose-aware reasoning engine prevents incorrect algorithm substitutions, producing valid, CycloneDX 1.6 compliant Cryptographic Bills of Materials (CBOM).
