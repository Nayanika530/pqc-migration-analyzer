# PQC Migration Analyzer

A tool that analyzes cryptographic algorithms for quantum vulnerability and automatically scans source code to detect and help fix outdated crypto — built as part of a cybersecurity portfolio focused on post-quantum cryptography (PQC).

## What it does

- **Vulnerability Analysis** — Input any algorithm (RSA, ECC, AES, DSA, Diffie-Hellman, 3DES) and key size, get a full report: is it quantum-vulnerable, is it already broken by classical computers today, is it deprecated for other reasons, and what NIST-approved PQC algorithm should replace it.
- **Code Scanner** — Paste in real source code and the tool automatically detects cryptographic algorithm usage (no manual input needed), flags each finding with a full vulnerability report, and shows a suggested code fix using the correct PQC replacement.
- **Real Benchmark Data** — Speed comparisons aren't guessed — they're measured. RSA, AES, 3DES (via `pycryptodome`) and ML-KEM-768 (via `liboqs`, the official Open Quantum Safe library implementing NIST's finalized PQC standard) were benchmarked locally, averaged over 20+ rounds with proper warm-up runs to eliminate cold-start noise.

## Why this matters

NIST finalized official post-quantum cryptography standards (FIPS 203, 204, 205) in August 2024. Most organizations haven't migrated yet, and many don't even have a clear inventory of where classical, quantum-vulnerable cryptography exists in their own systems. This tool addresses both problems: automatic discovery (via the scanner) and clear migration guidance (via the analysis engine).

It also accounts for the **"harvest now, decrypt later"** threat — data encrypted today with RSA/ECC can be intercepted and stored now, then decrypted once quantum computers mature, making migration urgent even before quantum computers are fully practical.

## Tech Stack

- **Backend:** Python, Flask
- **Classical Cryptography:** [pycryptodome](https://pycryptodome.readthedocs.io/)
- **Post-Quantum Cryptography:** [liboqs-python](https://github.com/open-quantum-safe/liboqs-python) (Open Quantum Safe project)
- **Frontend:** HTML/CSS (dark theme, in progress)

## Sample Findings

| Algorithm | Verdict | Recommended Replacement |
|---|---|---|
| RSA-1024 | CRITICAL — broken today, no quantum computer needed | ML-KEM-768 |
| RSA-2048 | AT RISK — safe today, broken once quantum computers mature | ML-KEM-768 |
| 3DES | DEPRECATED — insecure by modern standards regardless of quantum risk | AES-256 |
| AES-256 | OK — not significantly threatened by quantum computers | — |

## Measured Performance (local benchmarks)

| Algorithm | Keygen | Operation |
|---|---|---|
| RSA-2048 | ~646ms | ~3.0ms (encrypt+decrypt) |
| ML-KEM-768 | ~0.36ms | ~0.58ms (full key exchange) |
| AES-256 | instant | ~0.02ms (encrypt+decrypt) |
| 3DES | instant | ~0.05ms (encrypt+decrypt) |

## Running Locally

```bash
git clone https://github.com/Nayanika530/pqc-migration-analyzer.git
cd pqc-migration-analyzer
python -m venv venv
venv\Scripts\Activate.ps1   # Windows PowerShell
pip install -r requirements.txt
python app.py
```

Then open `http://127.0.0.1:5000` in your browser.

**Note:** `liboqs-python` compiles the liboqs C library from source on first run and requires CMake + a C++ compiler (e.g. Visual Studio Build Tools on Windows) to be installed.

## Roadmap

- [ ] Styled, animated frontend
- [ ] File upload support for the code scanner (currently paste-only)
- [ ] Expanded detection patterns across more languages/libraries
- [ ] Downloadable PDF reports
- [ ] Deployment to Render

## Author

Nayanika530 — B.Tech CSE (Cybersecurity), building toward a specialization in post-quantum cryptography.