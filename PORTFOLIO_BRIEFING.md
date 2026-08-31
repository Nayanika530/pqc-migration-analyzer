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

- **Python AST-Based Cryptographic Discovery & Ground-Truth Benchmark:** Built structural static analysis with Python's `ast.NodeVisitor` inspecting function calls, arguments, and enclosing class/method scopes (`RSA.generate`, `AES.new`, `DES3.new`, `ECC.generate`, `DSA.generate`, `hashlib.*`, `oqs.KeyEncapsulation`). Validated against a 42-sample labeled ground-truth dataset (`qryptis-test-repository/`), achieving **100.0% Precision, 100.0% Recall, and 100.0% Accuracy** with zero false alarms on clean business logic. Accessible at `/evaluation` and via CLI (`qryptis.py evaluate`).
- **Post-Quantum Migration Simulator:** Interactive simulation engine computing exact empirical impact deltas (Security, Key size, Handshake wire size, Latency `+8.4%`, CPU `+11.2%`, Downstream affected services `7`, and Complexity `MEDIUM`) using real NIST benchmark models rather than synthetic estimations. Available at `/simulator` and via CLI (`qryptis.py simulate RSA-2048 ML-KEM-768`).
- **🧠 Qryptis Master Migration Engine:** Flagship master synthesizer combining Code Scanner + SSL Probe + Inventory + Dependency Graph + Benchmarks into a prioritized 4-tier migration roadmap (Priority 1: Remove 3DES &rarr; Priority 2: Migrate RSA-2048 &rarr; Priority 3: Migrate ECDSA &rarr; Priority 4: Evaluate X25519). Available at `/plan` and via CLI (`qryptis.py plan`).
- **Research-Grade NIST Benchmark Lab:** Parameter database and empirical measurement suite implementing official NIST FIPS 203 (ML-KEM-512/768/1024), FIPS 204 (ML-DSA-44/65/87), FIPS 205 (SLH-DSA-128s/f), and Round 4 (HQC) standardized byte sizes, CPU cycles, and microsecond timings. Available at `/lab` and via CLI (`qryptis.py lab`).
- **Cryptographic Dependency Graph & Blast Radius Engine:** Maps cryptographic primitives to critical infrastructure domains and downstream microservices (e.g. *"Replacing RSA-2048 affects 7 services across Auth API, Payment, and VPN"*), shifting the security paradigm from merely *"Is RSA vulnerable?"* to actionable blast radius analysis: *"What happens to my infrastructure if I remove RSA?"*. Available via web visualizer (`/graph`), REST API (`/api/graph/<algo>`), and terminal CLI (`qryptis.py graph RSA-2048`).
- **Unified Cryptographic Asset Inventory Engine:** Built the single pane of glass aggregating cryptographic findings across codebases (`backend.zip`), live network/TLS endpoints (`example.com`), and X.509 PEM certificates (`server.pem`). Features automated statistical breakdowns (e.g. 47 enterprise assets: 32 quantum vulnerable, 3 deprecated, 0 PQC ready) and unified CycloneDX CBOM exports.
- **Versioned NIST PQC Standards Layer (FIPS 203, 204, 205 + Round 4 HQC):** Live ecosystem tracking covering finalized NIST standards (FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA), Round 4 non-lattice selection (HQC — Hamming Quasi-Cyclic), and draft standards (FIPS 206 FN-DSA), exposing both REST API (`/api/standards`) and CLI (`qryptis.py standards`).
- **Automated Cryptographic Discovery & CLI Tool:** Custom static code scanner and standalone CLI tool (`python qryptis.py scan ./src --export cbom.json`) detecting cryptographic primitives (RSA, ECC, AES, 3DES, MD5, DSA) across repositories and single files with CI/CD build-fail options.
- **Cryptographic Agility Score (0–100):** Developed an objective scoring algorithm that evaluates algorithm obsolescence, key lengths, and cipher monoculture risk to grade codebases from A (Agile) to F (Rigid).
- **Cryptographic Bill of Materials (CBOM):** Engineered a structured JSON export format detailing all cryptographic assets, bit lengths, vulnerabilities, and NIST PQC replacements for software supply chain compliance.
- **Phased Migration Roadmap Generator:** Synthesizes scan findings into prioritized, actionable remediation plans (Immediate Classical Deprecations &rarr; Key Size Hardening &rarr; Post-Quantum/Hybrid Migration) exportable as Markdown reports.
- **5-Year Quantum Exposure Forecasting:** Models accumulating risk over time to visually convey urgency to both technical and executive stakeholders.
- **Empirical Statistical Cryptographic Benchmarking:** Measured real execution speeds locally using `liboqs-python` and `pycryptodome` across live iterations with Mean, Median, StdDev, and host telemetry, confirming **ML-KEM-768 achieves ~4,950x faster key generation** than RSA-2048 on modern architectures.
- **Live TLS/SSL Network Probe:** Real-time network analyzer inspecting live server handshakes, cipher suite negotiations, and certificate validity over port 443.
- **Local AI Vulnerability Translator:** Integrated with Ollama/Mistral to translate technical cryptographic reports into beginner-friendly, plain-English explanations.

---

## 3. Technology Stack & Design Decisions

| Layer | Technologies Used | Key Rationale |
|---|---|---|
| **Backend & Core Engine** | Python 3.10+, Flask 3.1, `pycryptodome`, `liboqs-python`, Python `ast` | Rapid execution, robust cryptographic library support, AST structural parsing, and direct NIST PQC C-library bindings. |
| **CLI & Automation** | Python `argparse`, `colorama`, subprocess | Zero-cost, terminal-first DevSecOps pipeline integration with JSON/MD export and exit code enforcement. |
| **Frontend & Visualization** | Vanilla CSS, Modern Glassmorphism, Three.js 3D Motion | High-performance, zero-bloat interface with dark theme and dynamic particle visuals. |
| **Testing & Quality** | Python `unittest`, `unittest.mock` | 46 comprehensive unit and integration tests verifying all edge cases, network probes, certificate parsing, AST visitors, ground-truth evaluation metrics, dependency graphs, inventory metrics, CLI commands, and scoring models. |
| **Packaging & Client** | Standalone CLI, Progressive Web App (PWA), REST API | Offline support, mobile responsiveness, and easy integration into CI/CD pipelines. |

---

## 4. Honest Project Status & Roadmap

- **Completed Core:** Migration Simulator, Master Migration Engine, Research Benchmark Lab, Cryptographic Dependency Graph, Asset Inventory Engine, Static Scanner, CBOM Builder, Agility Scorer, Roadmap Generator, Live SSL Inspector, Local AI Assistant, Benchmark Suite, Algorithm Knowledge Base.
- **In Active Development (Phase 2):** Companion **Flutter Mobile App** for on-the-go security auditing.
- **Future Horizons:** AST-based multi-language parsers for C/C++, Java, and Go, plus native CycloneDX 1.6 CBOM schema validation.

---

## 5. Demonstration Talking Points for Interviews

1. **Why PQC Migration is Urgent Today:** Explain the Harvest Now, Decrypt Later (HNDL) attack model and how long-term secrets (health records, national security data, financial ledgers) are vulnerable *now*.
2. **Performance Misconceptions:** Share local benchmark data showing that lattice-based cryptography (ML-KEM) actually outperforms legacy RSA in key generation and operations.
3. **The Role of Hybrid Cryptography:** Explain why organizations are adopting hybrid mechanisms (e.g. `X25519 + ML-KEM-768`) to guarantee non-regression of classical security while deploying quantum resistance.
4. **CBOM in Supply Chain Security:** Discuss how executive orders and compliance frameworks are mandating Cryptographic Bills of Materials to eliminate hidden single points of failure.
