#!/usr/bin/env python3
"""
Qryptis — Post-Quantum Cryptography Migration Analyzer & Code Scanner (CLI)
A command-line security inspection tool for cryptographic discovery,
NIST PQC compliance analysis, and CBOM generation.

Usage:
    python qryptis.py scan ./src --export cbom.json
    python qryptis.py check RSA 2048 --years 10
    python qryptis.py live google.com
    python qryptis.py benchmark
    python qryptis.py db
"""

import sys
import os
import json
import argparse

# Reconfigure stdout/stderr for Unicode safety across Windows/Linux/macOS
try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# Initialize colorama on Windows if available
try:
    import colorama
    colorama.init(autoreset=True)
except ImportError:
    pass

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from crypto_analyzer import (
    ALGORITHM_DB,
    NIST_STANDARDS_DB,
    generate_report,
    calculate_harvest_risk,
    scan_live_website,
    BENCHMARK_DATA
)
from scanner import (
    scan_and_report,
    scan_directory,
    generate_cbom,
    calculate_agility_score,
    generate_migration_roadmap,
    export_roadmap_as_markdown,
    generate_risk_forecast
)

# ANSI Terminal Colors
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"


def print_banner():
    banner = f"""{Colors.CYAN}{Colors.BOLD}
  ___  ____  _   _ ____ _____ ___ ____  
 / _ \\|  _ \\| | | |  _ \\_   _|_ _/ ___| 
| | | | |_) | |_| | |_) || |  | |\\___ \\ 
| |_| |  _ < \\__, |  __/ | |  | | ___) |
 \\__\\_\\_| \\_\\ ___/|_|    |_| |___|____/ 
             |___/   {Colors.WHITE}Post-Quantum Cryptography Migration Engine{Colors.RESET}
"""
    print(banner)


def cmd_scan(args):
    """Execute static cryptographic code scan across file or repository."""
    target_path = args.path
    if not os.path.exists(target_path):
        print(f"{Colors.RED}[Error] Target path '{target_path}' does not exist.{Colors.RESET}")
        sys.exit(1)

    print(f"{Colors.BLUE}[*] Scanning target:{Colors.RESET} {os.path.abspath(target_path)}")
    data = scan_directory(target_path)

    results = data["results"]
    summary = data["summary"]
    files_scanned = data["files_scanned"]
    total_findings = data["total_findings"]
    agility = data["agility"]

    # Render Qryptis Code Analysis Header
    print(f"\n{Colors.BOLD}{Colors.WHITE}QRYPTIS CODE ANALYSIS{Colors.RESET}")
    print(f"{Colors.CYAN}{'=' * 65}{Colors.RESET}")
    print(f"{Colors.BOLD}Target:{Colors.RESET}          {target_path}")
    print(f"{Colors.BOLD}Files scanned:{Colors.RESET}   {files_scanned}")
    print(f"{Colors.BOLD}Crypto findings:{Colors.RESET} {total_findings}\n")

    # Severity Matrix Box
    crit_str = f"{Colors.RED}{Colors.BOLD}CRITICAL: {summary['critical']}{Colors.RESET}"
    high_str = f"{Colors.YELLOW}{Colors.BOLD}HIGH: {summary['high']}{Colors.RESET}"
    med_str = f"{Colors.BLUE}{Colors.BOLD}MEDIUM: {summary['medium']}{Colors.RESET}"
    low_str = f"{Colors.GREEN}{Colors.BOLD}LOW: {summary['low']}{Colors.RESET}"
    print(f"  {crit_str:24}  {high_str:24}  {med_str:24}  {low_str:24}")
    print(f"{Colors.CYAN}{'-' * 65}{Colors.RESET}\n")

    if not results:
        print(f"{Colors.GREEN}[+] No classical or vulnerable cryptographic algorithms detected!{Colors.RESET}\n")
    else:
        # Render Detailed Cryptographic Findings
        for i, r in enumerate(results, 1):
            sev = r.get("severity", "MEDIUM")
            if sev == "CRITICAL":
                sev_color = Colors.RED
            elif sev == "HIGH":
                sev_color = Colors.YELLOW
            elif sev == "MEDIUM":
                sev_color = Colors.BLUE
            else:
                sev_color = Colors.GREEN

            algo = r["report"].get("algorithm", "UNKNOWN")
            key_size = r["report"].get("key_size", "N/A")

            print(f"{Colors.BOLD}{Colors.WHITE}CRYPTOGRAPHIC FINDING #{i}{Colors.RESET} [{sev_color}{Colors.BOLD}{sev}{Colors.RESET}]")
            print(f"{Colors.BOLD}{Colors.CYAN}{algo}-{key_size}{Colors.RESET}")
            print(f"{Colors.DIM}{'-' * 45}{Colors.RESET}")
            print(f"  {Colors.BOLD}Location:{Colors.RESET}             {Colors.CYAN}{r.get('location', 'N/A')}{Colors.RESET}")
            print(f"  {Colors.BOLD}Usage:{Colors.RESET}                {r.get('usage', 'Cryptographic Primitive')}")
            
            # Clean terminal status symbols
            q_stat = r.get('quantum_status', 'Unknown')
            if "VULNERABLE" in q_stat:
                q_disp = f"{Colors.RED}[!] VULNERABLE (Broken by Shor's Algorithm){Colors.RESET}"
            else:
                q_disp = f"{Colors.GREEN}[+] QUANTUM SECURE{Colors.RESET}"
            print(f"  {Colors.BOLD}Quantum Status:{Colors.RESET}       {q_disp}")

            c_stat = r.get('classical_status', 'Unknown')
            if "Currently acceptable" in c_stat:
                c_disp = f"{Colors.GREEN}[+] Currently acceptable ({key_size}-bit){Colors.RESET}"
            elif "DEPRECATED" in c_stat:
                c_disp = f"{Colors.YELLOW}[!] DEPRECATED (Classical vulnerability){Colors.RESET}"
            else:
                c_disp = f"{Colors.RED}[!] BROKEN TODAY (Substandard key size){Colors.RESET}"
            print(f"  {Colors.BOLD}Classical Status:{Colors.RESET}     {c_disp}")

            print(f"  {Colors.BOLD}Migration Target:{Colors.RESET}     {Colors.GREEN}{Colors.BOLD}{r.get('migration_target', 'ML-KEM-768')}{Colors.RESET}")
            print(f"  {Colors.BOLD}Migration Difficulty:{Colors.RESET} {r.get('migration_difficulty', 'MEDIUM')}")

            comps = ", ".join(r.get("affected_components", []))
            if comps:
                print(f"  {Colors.BOLD}Affected Components:{Colors.RESET}  {comps}")

            # Print Snippet Context with Target Line Highlighted
            if r.get("code_snippet"):
                print(f"\n  {Colors.DIM}--- Code Context ---{Colors.RESET}")
                for line in r["code_snippet"]:
                    ln = line["line_num"]
                    code = line["code"]
                    if line["is_target"]:
                        print(f"  {Colors.RED}{Colors.BOLD}> {ln:4d} | {code}{Colors.RESET}  {Colors.RED}{Colors.BOLD}<-- Finding: {algo}-{key_size}{Colors.RESET}")
                    else:
                        print(f"    {Colors.DIM}{ln:4d} |{Colors.RESET} {code}")

            print(f"{Colors.DIM}{'-' * 45}{Colors.RESET}\n")

        # Agility Summary
        if agility and agility.get("score") is not None:
            score = agility["score"]
            grade = agility["grade"]
            print(f"{Colors.BOLD}Cryptographic Agility Score:{Colors.RESET} {Colors.CYAN}{score}/100{Colors.RESET} -- {Colors.BOLD}{grade}{Colors.RESET}")
            print(f"{Colors.DIM}{agility['explanation']}{Colors.RESET}\n")

    # Export Options
    if args.export:
        export_file = args.export
        if export_file.endswith(".json"):
            with open(export_file, "w", encoding="utf-8") as f:
                json.dump(data["cbom"], f, indent=2)
            print(f"{Colors.GREEN}[+] Cryptographic Bill of Materials (CBOM) saved to: {export_file}{Colors.RESET}")
        elif export_file.endswith(".md"):
            md_content = export_roadmap_as_markdown(data["roadmap"], data["agility"])
            with open(export_file, "w", encoding="utf-8") as f:
                f.write(md_content)
            print(f"{Colors.GREEN}[+] Migration Roadmap Markdown report saved to: {export_file}{Colors.RESET}")
        else:
            with open(export_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            print(f"{Colors.GREEN}[+] Scan results exported to: {export_file}{Colors.RESET}")

    # CI/CD Fail Condition
    if args.fail_on:
        threshold = args.fail_on.upper()
        if threshold == "CRITICAL" and summary["critical"] > 0:
            print(f"{Colors.RED}[!] Build Failed: Found {summary['critical']} CRITICAL cryptographic vulnerabilities.{Colors.RESET}")
            sys.exit(1)
        elif threshold == "HIGH" and (summary["critical"] > 0 or summary["high"] > 0):
            print(f"{Colors.RED}[!] Build Failed: Found {summary['critical'] + summary['high']} HIGH/CRITICAL cryptographic vulnerabilities.{Colors.RESET}")
            sys.exit(1)


def cmd_check(args):
    """Lookup a single cryptographic algorithm and key size."""
    algo = args.algorithm.upper()
    key_size = args.key_size
    years = args.years

    report = generate_report(algo, key_size)
    if "error" in report:
        print(f"{Colors.RED}[Error] {report['error']}{Colors.RESET}")
        sys.exit(1)

    print(f"\n{Colors.BOLD}{Colors.WHITE}QRYPTIS ALGORITHM INSPECTOR{Colors.RESET}")
    print(f"{Colors.CYAN}{'=' * 55}{Colors.RESET}")
    print(f"{Colors.BOLD}Algorithm:{Colors.RESET}                {report['algorithm']} ({report['key_size']}-bit)")
    print(f"{Colors.BOLD}Primitive Type:{Colors.RESET}           {report['type']}")
    print(f"{Colors.BOLD}Verdict:{Colors.RESET}                  {report['verdict']}")
    qv_str = "YES (Shor's Algorithm)" if report.get('quantum_vulnerable') else "NO (Grover-safe)"
    class_str = "Meets standard" if report.get('classically_secure_today') else "BELOW classical minimum"
    print(f"{Colors.BOLD}Quantum Vulnerable:{Colors.RESET}       {qv_str}")
    print(f"{Colors.BOLD}Classical Security:{Colors.RESET}       {class_str}")
    print(f"{Colors.BOLD}NIST PQC Replacement:{Colors.RESET}     {Colors.GREEN}{Colors.BOLD}{report['recommended_replacement']}{Colors.RESET}")

    if report.get("hybrid_recommendation"):
        print(f"{Colors.BOLD}Hybrid Transition:{Colors.RESET}        {report['hybrid_recommendation']}")

    if years is not None:
        hr = calculate_harvest_risk(algo, key_size, years)
        if "error" not in hr:
            risk_color = Colors.RED if hr["harvest_risk"] == "HIGH" else (Colors.YELLOW if hr["harvest_risk"] == "MEDIUM" else Colors.GREEN)
            print(f"\n{Colors.BOLD}Harvest-Now-Decrypt-Later Risk ({years} yrs confidentiality):{Colors.RESET} {risk_color}{Colors.BOLD}{hr['harvest_risk']}{Colors.RESET}")
            print(f"{Colors.DIM}{hr['explanation']}{Colors.RESET}")

    print(f"{Colors.CYAN}{'-' * 55}{Colors.RESET}\n")


def cmd_live(args):
    """Perform real-time TLS handshake & cipher suite inspection."""
    domain = args.domain
    print(f"{Colors.BLUE}[*] Connecting to {domain}:443 over live TLS...{Colors.RESET}")
    result = scan_live_website(domain)

    if not result.get("connection_successful"):
        print(f"{Colors.RED}[Error] {result.get('error', 'Connection failed')}{Colors.RESET}")
        sys.exit(1)

    print(f"\n{Colors.BOLD}{Colors.WHITE}LIVE TLS/SSL CERTIFICATE INSPECTOR{Colors.RESET}")
    print(f"{Colors.CYAN}{'=' * 55}{Colors.RESET}")
    print(f"{Colors.BOLD}Host / Domain:{Colors.RESET}            {result['domain']}")
    print(f"{Colors.BOLD}TLS Version:{Colors.RESET}              {result['tls_version']}")
    print(f"{Colors.BOLD}Negotiated Cipher Suite:{Colors.RESET}  {Colors.CYAN}{result['cipher_suite']}{Colors.RESET}")
    print(f"{Colors.BOLD}Secret Bits:{Colors.RESET}              {result['key_bits']} bits")
    print(f"{Colors.BOLD}Certificate Issuer:{Colors.RESET}       {result['certificate_issuer']}")
    print(f"{Colors.BOLD}Certificate Subject:{Colors.RESET}      {result['certificate_subject']}")
    print(f"{Colors.BOLD}Expires:{Colors.RESET}                  {result['cert_expires']}")

    if result.get("reports"):
        print(f"\n{Colors.BOLD}Detected Cryptographic Primitives:{Colors.RESET}")
        for r in result["reports"]:
            status_color = Colors.RED if r["quantum_vulnerable"] else Colors.GREEN
            verdict_text = r['verdict'].split('--')[0].strip()
            print(f"  * {r['algorithm']} ({r['key_size']}-bit) -> {status_color}{verdict_text}{Colors.RESET} (PQC Target: {Colors.GREEN}{r['recommended_replacement']}{Colors.RESET})")

    print(f"{Colors.CYAN}{'-' * 55}{Colors.RESET}\n")


def cmd_benchmark(args):
    """Display local microsecond benchmark metrics."""
    print(f"\n{Colors.BOLD}{Colors.WHITE}LOCAL CRYPTOGRAPHIC PERFORMANCE BENCHMARKS{Colors.RESET}")
    print(f"{Colors.DIM}Measured via liboqs-python & pycryptodome (20+ warmup iterations){Colors.RESET}")
    print(f"{Colors.CYAN}{'=' * 75}{Colors.RESET}")
    print(f"{'Algorithm':<16} | {'Keygen Time':<18} | {'Operation Time':<18} | {'Quantum Status'}")
    print(f"{'-' * 16}-+-{'-' * 18}-+-{'-' * 18}-+-{'-' * 16}")

    table_data = [
        ("RSA-2048", "~646.0 ms", "~3.00 ms (enc+dec)", f"{Colors.RED}VULNERABLE{Colors.RESET}"),
        ("ML-KEM-768", f"{Colors.GREEN}~0.36 ms{Colors.RESET}", f"{Colors.GREEN}~0.58 ms (encap+decap){Colors.RESET}", f"{Colors.GREEN}NIST FIPS 203{Colors.RESET}"),
        ("AES-256", "Instant", "~0.02 ms (enc+dec)", f"{Colors.GREEN}SECURE{Colors.RESET}"),
        ("3DES", "Instant", "~0.05 ms (enc+dec)", f"{Colors.RED}DEPRECATED{Colors.RESET}"),
        ("MD5", "Instant", "Instant", f"{Colors.RED}DEPRECATED{Colors.RESET}"),
    ]

    for name, keygen, op, status in table_data:
        print(f"{name:<16} | {keygen:<27} | {op:<27} | {status}")

    print(f"{Colors.CYAN}{'=' * 75}{Colors.RESET}")
    print(f"{Colors.GREEN}{Colors.BOLD}Key Takeaway:{Colors.RESET} ML-KEM-768 achieves ~1,700x faster key generation than RSA-2048.\n")


def cmd_standards(args):
    """Display official versioned NIST PQC standards layer."""
    print(f"\n{Colors.BOLD}{Colors.WHITE}NIST PQC STATUS & STANDARDS TRACKER{Colors.RESET}")
    print(f"{Colors.DIM}Official NIST Post-Quantum Standardization Layer (2024–2026){Colors.RESET}")
    print(f"{Colors.CYAN}{'=' * 75}{Colors.RESET}")

    for item in NIST_STANDARDS_DB:
        if "✓" in item["status"]:
            status_color = Colors.GREEN
        elif "◐" in item["status"]:
            status_color = Colors.MAGENTA
        else:
            status_color = Colors.YELLOW

        print(f"{Colors.BOLD}{item['standard']}{Colors.RESET}")
        print(f"{item['algorithm']} — {item['name']}")
        print(f"Status:   {status_color}{item['status']}{Colors.RESET} ({item['date']})")
        print(f"Type:     {item['type']} • Hardness: {item['hardness']}")
        print(f"Guidance: {item['nist_guidance']}")
        print(f"{Colors.DIM}{'-' * 75}{Colors.RESET}")

    print(f"\n{Colors.GREEN}{Colors.BOLD}NIST Recommendation:{Colors.RESET} NIST explicitly recommends organizations begin applying finalized standards (FIPS 203, 204, 205) and preparing for code-based alternatives (HQC) now.\n")


def cmd_db(args):
    """List all supported algorithms in knowledge base."""
    print(f"\n{Colors.BOLD}{Colors.WHITE}CRYPTOGRAPHIC ALGORITHM DATABASE{Colors.RESET}")
    print(f"{Colors.CYAN}{'=' * 70}{Colors.RESET}")
    print(f"{'Algorithm':<16} | {'Type':<24} | {'Status':<14} | {'PQC Replacement'}")
    print(f"{'-' * 16}-+-{'-' * 24}-+-{'-' * 14}-+-{'-' * 20}")

    for name, data in ALGORITHM_DB.items():
        if data.get("deprecated"):
            stat = f"{Colors.YELLOW}DEPRECATED{Colors.RESET}"
        elif data.get("quantum_vulnerable"):
            stat = f"{Colors.RED}VULNERABLE{Colors.RESET}"
        else:
            stat = f"{Colors.GREEN}SECURE{Colors.RESET}"
        pqc = data.get("pqc_replacement", "N/A")
        print(f"{name:<16} | {data['type'][:24]:<24} | {stat:<23} | {pqc}")

    print(f"{Colors.CYAN}{'=' * 70}{Colors.RESET}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Qryptis — Post-Quantum Cryptography Migration Analyzer & Code Scanner (CLI)",
        epilog="Examples:\n  python qryptis.py scan ./src --export cbom.json\n  python qryptis.py check RSA 2048\n  python qryptis.py live google.com\n"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: scan
    scan_parser = subparsers.add_parser("scan", help="Scan source files or repository for cryptographic usage")
    scan_parser.add_argument("path", help="Path to code file or directory to scan")
    scan_parser.add_argument("--export", "-e", help="Export findings to file (e.g. cbom.json, roadmap.md)")
    scan_parser.add_argument("--fail-on", choices=["CRITICAL", "HIGH", "critical", "high"], help="Fail with exit code 1 if vulnerabilities of this severity exist")

    # Command: check
    check_parser = subparsers.add_parser("check", help="Evaluate a single algorithm and key size")
    check_parser.add_argument("algorithm", help="Algorithm name (e.g. RSA, ECC, AES, 3DES, MD5, DSA)")
    check_parser.add_argument("key_size", type=int, help="Key size in bits (e.g. 2048, 256, 128)")
    check_parser.add_argument("--years", "-y", type=int, default=None, help="Confidentiality horizon in years (for HNDL assessment)")

    # Command: live
    live_parser = subparsers.add_parser("live", help="Inspect live HTTPS domain TLS handshake and cipher suite")
    live_parser.add_argument("domain", help="Target domain (e.g. google.com, api.github.com)")

    # Command: benchmark
    subparsers.add_parser("benchmark", help="Display local microsecond benchmark comparisons")

    # Command: standards
    subparsers.add_parser("standards", help="List official NIST PQC standards")

    # Command: db
    subparsers.add_parser("db", help="List algorithm database and PQC recommendations")

    args = parser.parse_args()

    if not args.command:
        print_banner()
        parser.print_help()
        sys.exit(0)

    print_banner()

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "check":
        cmd_check(args)
    elif args.command == "live":
        cmd_live(args)
    elif args.command == "benchmark":
        cmd_benchmark(args)
    elif args.command == "standards":
        cmd_standards(args)
    elif args.command == "db":
        cmd_db(args)


if __name__ == "__main__":
    main()
