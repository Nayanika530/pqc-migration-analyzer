# Portfolio Project Briefing: Qryptis (PQC Migration Analyzer)

**Author:** Nayanika530 — B.Tech CSE (Cybersecurity)  
**Project:** Post-Quantum Cryptography Migration Analyzer & Static Security Scanner  
**Target Domain:** Applied Cryptography, Post-Quantum Cryptography (PQC), DevSecOps, Software Supply Chain Security  

---

## 1. Problem Statement & Motivation
With NIST finalizing the official Post-Quantum Cryptography standards (**FIPS 203 ML-KEM** and **FIPS 204 ML-DSA**) in August 2024, organizations face an urgent cryptographic transition. The transition is complicated by two primary factors:
1. **Lack of Cryptographic Inventory:** Most enterprises do not know where classical, quantum-vulnerable algorithms (RSA, ECC, Diffie-Hellman) are hardcoded in their legacy codebases and infrastructure.
2. **Harvest Now, Decrypt Later (HNDL):** Adversaries are intercepting and storing encrypted sensitive data today to decrypt once cryptanalytically relevant quantum computers (CRQCs) become viable.

**Qryptis** was engineered to solve both discovery and migration challenges through automated static scanning, cryptographic agility scoring, risk forecasting, and standardized remediation roadmaps.

---

## 2. Key Technical Innovations & Achievements

- **Versioned NIST PQC Standards Layer (FIPS 203, 204, 205 + Round 4 HQC):** Live ecosystem tracking covering finalized NIST standards (FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA), Round 4 non-lattice selection (HQC — Hamming Quasi-Cyclic), and draft standards (FIPS 206 FN-DSA), exposing both REST API (`/api/standards`) and CLI (`qryptis.py standards`).
- **Automated Cryptographic Discovery & CLI Tool:** Custom static code scanner and standalone CLI tool (`python qryptis.py scan ./src --export cbom.json`) detecting cryptographic primitives (RSA, ECC, AES, 3DES, MD5, DSA) across repositories and single files with CI/CD build-fail options.
- **Cryptographic Agility Score (0–100):** Developed an objective scoring algorithm that evaluates algorithm obsolescence, key lengths, and cipher monoculture risk to grade codebases from A (Agile) to F (Rigid).
- **Cryptographic Bill of Materials (CBOM):** Engineered a structured JSON export format detailing all cryptographic assets, bit lengths, vulnerabilities, and NIST PQC replacements for software supply chain compliance.
- **Phased Migration Roadmap Generator:** Synthesizes scan findings into prioritized, actionable remediation plans (Immediate Classical Deprecations &rarr; Key Size Hardening &rarr; Post-Quantum/Hybrid Migration) exportable as Markdown reports.
- **5-Year Quantum Exposure Forecasting:** Models accumulating risk over time to visually convey urgency to both technical and executive stakeholders.
- **Real Microsecond Benchmarking:** Benchmarked classical vs NIST PQC primitives locally using `liboqs-python` (Open Quantum Safe C bindings) and `pycryptodome` across 20+ warmup and test cycles, demonstrating that **ML-KEM-768 is ~1,700x faster in key generation** than RSA-2048.
- **Live TLS/SSL Network Probe:** Real-time network analyzer inspecting live server handshakes, cipher suite negotiations, and certificate validity over port 443.
- **Local AI Vulnerability Translator:** Integrated with Ollama/Mistral to translate technical cryptographic reports into beginner-friendly, plain-English explanations.

---

## 3. Technology Stack & Design Decisions

| Layer | Technologies Used | Key Rationale |
|---|---|---|
| **Backend & Core Engine** | Python 3.10+, Flask 3.1, `pycryptodome`, `liboqs-python` | Rapid execution, robust cryptographic library support, and direct NIST PQC C-library bindings. |
| **CLI & Automation** | Python `argparse`, `colorama`, subprocess | Zero-cost, terminal-first DevSecOps pipeline integration with JSON/MD export and exit code enforcement. |
| **Frontend & Visualization** | Vanilla CSS, Modern Glassmorphism, Three.js 3D Motion | High-performance, zero-bloat interface with dark theme and dynamic particle visuals. |
| **Testing & Quality** | Python `unittest`, `unittest.mock` | 29 comprehensive unit and integration tests verifying all edge cases, network probes, standards endpoints, CLI commands, and scoring models. |
| **Packaging & Client** | Standalone CLI, Progressive Web App (PWA), REST API | Offline support, mobile responsiveness, and easy integration into CI/CD pipelines. |

---

## 4. Honest Project Status & Roadmap

- **Completed Core:** Static Scanner, CBOM Builder, Agility Scorer, Roadmap Generator, Live SSL Inspector, Local AI Assistant, Benchmark Suite, Algorithm Knowledge Base.
- **In Active Development (Phase 2):** Companion **Flutter Mobile App** for on-the-go security auditing.
- **Future Horizons:** AST-based multi-language parsers for C/C++, Java, and Go, plus native CycloneDX 1.6 CBOM schema validation.

---

## 5. Demonstration Talking Points for Interviews

1. **Why PQC Migration is Urgent Today:** Explain the Harvest Now, Decrypt Later (HNDL) attack model and how long-term secrets (health records, national security data, financial ledgers) are vulnerable *now*.
2. **Performance Misconceptions:** Share local benchmark data showing that lattice-based cryptography (ML-KEM) actually outperforms legacy RSA in key generation and operations.
3. **The Role of Hybrid Cryptography:** Explain why organizations are adopting hybrid mechanisms (e.g. `X25519 + ML-KEM-768`) to guarantee non-regression of classical security while deploying quantum resistance.
4. **CBOM in Supply Chain Security:** Discuss how executive orders and compliance frameworks are mandating Cryptographic Bills of Materials to eliminate hidden single points of failure.
