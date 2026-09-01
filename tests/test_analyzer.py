"""
Unit and Integration Tests for PQC Migration Analyzer.
Covers core analysis engine, scanner, CBOM generator, agility scoring,
edge cases, and Flask routes.
"""

import unittest
from unittest import mock
import json
import os
import sys

# Add parent directory to path so modules can be imported
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from crypto_analyzer import (
    ALGORITHM_DB,
    MIN_SECURE_KEY_SIZE,
    analyze_algorithm,
    check_key_size,
    generate_report,
    calculate_harvest_risk,
    scan_live_website
)
from scanner import (
    scan_code,
    scan_and_report,
    generate_cbom,
    calculate_agility_score,
    generate_migration_roadmap,
    export_roadmap_as_markdown,
    generate_risk_forecast
)
from app import app


class TestCryptoAnalyzerEngine(unittest.TestCase):
    """Test suite for the core crypto analysis engine."""

    def test_algorithm_db_completeness(self):
        """Verify all essential algorithms exist with required schema keys."""
        required_algos = ["RSA", "ECC", "AES", "DSA", "DIFFIE-HELLMAN", "3DES", "MD5", "HQC", "ML-KEM", "ML-DSA", "SLH-DSA"]
        for algo in required_algos:
            self.assertIn(algo, ALGORITHM_DB)
            entry = ALGORITHM_DB[algo]
            self.assertIn("type", entry)
            self.assertIn("quantum_vulnerable", entry)
            self.assertIn("reason", entry)
            self.assertIn("pqc_replacement", entry)
            self.assertIn("replacement_type", entry)
            self.assertIn("hybrid_recommendation", entry)
            self.assertIn("deprecated", entry)

    def test_hqc_and_nist_standards(self):
        """Verify HQC and versioned NIST PQC standards layer."""
        from crypto_analyzer import NIST_STANDARDS_DB
        self.assertGreaterEqual(len(NIST_STANDARDS_DB), 4)
        
        # Verify FIPS 203, 204, 205 and HQC exist
        standards_names = [s["standard"] for s in NIST_STANDARDS_DB]
        algos = [s["algorithm"] for s in NIST_STANDARDS_DB]
        self.assertIn("FIPS 203", standards_names)
        self.assertIn("FIPS 204", standards_names)
        self.assertIn("FIPS 205", standards_names)
        self.assertIn("HQC", algos)

        # Test HQC lookup
        rep_hqc = generate_report("HQC", 128)
        self.assertFalse(rep_hqc["quantum_vulnerable"])
        self.assertIn("OK", rep_hqc["verdict"])

    def test_md5_deprecation(self):
        """Verify MD5 is marked deprecated due to classical collision flaws."""
        report = generate_report("MD5", 128)
        self.assertNotIn("error", report)
        self.assertIn("DEPRECATED", report["verdict"])
        self.assertFalse(report["quantum_vulnerable"])
        self.assertIn("SHA-256", report["recommended_replacement"])

    def test_rsa_verdicts(self):
        """Test RSA with weak key vs secure classical key."""
        # 1024-bit RSA -> CRITICAL (broken classically)
        rep_1024 = generate_report("RSA", 1024)
        self.assertIn("CRITICAL", rep_1024["verdict"])
        self.assertTrue(rep_1024["quantum_vulnerable"])

        # 2048-bit RSA -> AT RISK (safe today, broken by quantum)
        rep_2048 = generate_report("RSA", 2048)
        self.assertIn("AT RISK", rep_2048["verdict"])
        self.assertTrue(rep_2048["quantum_vulnerable"])
        self.assertEqual(rep_2048["recommended_replacement"], "ML-KEM-768")

    def test_aes_verdict(self):
        """Test AES-256 (not quantum vulnerable)."""
        rep_aes = generate_report("AES", 256)
        self.assertTrue("OK" in rep_aes["verdict"] or "QUANTUM RESILIENT" in rep_aes["verdict"])
        self.assertFalse(rep_aes["quantum_vulnerable"])

    def test_3des_deprecation(self):
        """Test 3DES is flagged as DEPRECATED."""
        rep_3des = generate_report("3DES", 168)
        self.assertIn("DEPRECATED", rep_3des["verdict"])

    def test_key_size_edge_cases(self):
        """Test negative, zero, and invalid key sizes."""
        self.assertIn("error", check_key_size("RSA", 0))
        self.assertIn("error", check_key_size("RSA", -2048))
        self.assertIn("error", generate_report("RSA", -1024))
        self.assertIn("error", generate_report("UNKNOWN_ALGO", 2048))

    def test_harvest_risk_calculation(self):
        """Test harvest now decrypt later risk logic and edge cases."""
        # Low risk: secret needed for 5 years (< 15 yr estimate)
        hr_low = calculate_harvest_risk("RSA", 2048, 5)
        self.assertEqual(hr_low["harvest_risk"], "LOW")

        # Medium risk: secret needed for 20 years
        hr_med = calculate_harvest_risk("RSA", 2048, 20)
        self.assertEqual(hr_med["harvest_risk"], "MEDIUM")

        # High risk: secret needed for 30 years
        hr_high = calculate_harvest_risk("RSA", 2048, 30)
        self.assertEqual(hr_high["harvest_risk"], "HIGH")

        # Non-quantum algorithm
        hr_aes = calculate_harvest_risk("AES", 256, 30)
        self.assertEqual(hr_aes["harvest_risk"], "NOT APPLICABLE")

        # Edge case: negative years
        hr_neg = calculate_harvest_risk("RSA", 2048, -5)
        self.assertIn("error", hr_neg)


class TestScannerAndCBOM(unittest.TestCase):
    """Test suite for static code scanner, CBOM, Agility score, and Roadmap."""

    def setUp(self):
        with open(os.path.join(os.path.dirname(__file__), "messy_sample.py"), "r") as f:
            self.messy_code = f.read()

    def test_messy_code_scan(self):
        """Verify the scanner detects all expected patterns in messy real-world code."""
        findings = scan_and_report(self.messy_code)
        self.assertGreaterEqual(len(findings), 5)

        detected_algos = [f["report"].get("algorithm") for f in findings if "report" in f and "algorithm" in f["report"]]
        self.assertIn("RSA", detected_algos)
        self.assertIn("3DES", detected_algos)
        self.assertIn("MD5", detected_algos)
        self.assertIn("DSA", detected_algos)
        self.assertIn("AES", detected_algos)

    def test_cbom_generation(self):
        """Verify CBOM JSON structure and valid summary counts."""
        findings = scan_and_report(self.messy_code)
        cbom = generate_cbom(findings, source_name="messy_sample.py")

        self.assertEqual(cbom["bomFormat"], "CBOM")
        self.assertIn("components", cbom)
        self.assertIn("summary", cbom)
        self.assertGreater(cbom["summary"]["total_findings"], 0)
        self.assertGreater(cbom["summary"]["quantum_vulnerable_count"], 0)
        self.assertGreater(cbom["summary"]["deprecated_count"], 0)

    def test_agility_score_calculation(self):
        """Verify agility score properly penalizes deprecated and quantum-vulnerable crypto."""
        findings = scan_and_report(self.messy_code)
        agility = calculate_agility_score(findings)

        self.assertIsNotNone(agility["score"])
        self.assertIsInstance(agility["score"], int)
        self.assertGreaterEqual(agility["score"], 0)
        self.assertLessEqual(agility["score"], 100)
        self.assertIn("grade", agility)

    def test_roadmap_generation(self):
        """Verify roadmap creates multi-phase migration priorities."""
        findings = scan_and_report(self.messy_code)
        roadmap = generate_migration_roadmap(findings)

        self.assertGreater(roadmap["total_phases"], 0)
        markdown_text = export_roadmap_as_markdown(roadmap, calculate_agility_score(findings))
        self.assertIn("# Cryptographic Migration Report", markdown_text)
        self.assertIn("Migration Roadmap", markdown_text)

    def test_risk_forecast(self):
        """Verify 5-year forecast generation."""
        findings = scan_and_report(self.messy_code)
        forecast = generate_risk_forecast(findings)

        self.assertIn("current_risk_score", forecast)
        self.assertEqual(len(forecast["forecast"]), 5)

    def test_empty_scan_input(self):
        """Verify scanner handles empty code gracefully."""
        findings = scan_and_report("")
        self.assertEqual(len(findings), 0)
        agility = calculate_agility_score(findings)
        self.assertIsNone(agility["score"])


class TestLiveScannerNetwork(unittest.TestCase):
    """Test suite for live TLS scanner and network edge cases."""

    def test_invalid_domain_handling(self):
        """Verify scanner handles unresolvable domains without throwing exceptions."""
        result = scan_live_website("this-domain-does-not-exist-xyz-987654.invalid")
        self.assertFalse(result["connection_successful"])
        self.assertIn("error", result)

    def test_malformed_domain_handling(self):
        """Verify scanner cleans URLs and protocols."""
        result = scan_live_website("https://invalid-nonexistent-subdomain.com/path/test")
        self.assertFalse(result["connection_successful"])
        self.assertIn("error", result)


class TestFlaskWebRoutes(unittest.TestCase):
    """Integration test suite for Flask endpoints."""

    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_routes_status_codes(self):
        """Verify all major HTML pages return 200 OK."""
        routes = ["/login", "/analyze", "/manual", "/scan", "/live-scan", "/database", "/qryptis", "/health"]
        for route in routes:
            response = self.client.get(route)
            self.assertEqual(response.status_code, 200, f"Route {route} failed with status {response.status_code}")

    def test_health_check(self):
        """Verify /health endpoint returns JSON status ok."""
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "ok")

    @unittest.mock.patch("app.get_ai_explanation", return_value="AI Explanation: RSA is vulnerable to Shor's algorithm.")
    def test_manual_post_valid(self, mock_ai):
        """Verify manual form submission returns valid report."""
        response = self.client.post("/manual", data={"algorithm": "RSA", "key_size": "2048", "years_secret": "10"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Analysis Results", response.data)
        self.assertIn(b"ML-KEM-768", response.data)

    def test_manual_post_edge_cases(self):
        """Verify manual form returns friendly errors on invalid numbers."""
        response = self.client.post("/manual", data={"algorithm": "RSA", "key_size": "-2048", "years_secret": "10"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Key size must be a positive integer greater than 0", response.data)

    def test_scan_api_json(self):
        """Verify /api/scan JSON endpoint."""
        payload = {"code": "from Crypto.PublicKey import RSA\nkey = RSA.generate(1024)", "filename": "test.py"}
        response = self.client.post("/api/scan", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(len(data["results"]), 1)
        self.assertIn("agility", data)
        self.assertIn("roadmap", data)

    def test_scan_api_empty(self):
        """Verify /api/scan returns 400 on empty code."""
        response = self.client.post("/api/scan", json={"code": ""})
        self.assertEqual(response.status_code, 400)

    def test_api_chat_empty(self):
        """Verify /api/chat handles empty input."""
        response = self.client.post("/api/chat", json={"message": ""})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["reply"], "Please type a question.")

    def test_api_standards(self):
        """Verify /api/standards returns NIST PQC standards layer."""
        response = self.client.get("/api/standards")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("nist_pqc_standards", data)
        self.assertIn("recommendation", data)
        standards = [s["standard"] for s in data["nist_pqc_standards"]]
        self.assertIn("FIPS 203", standards)
        self.assertIn("FIPS 204", standards)
        self.assertIn("FIPS 205", standards)

    def test_inventory_routes_and_api(self):
        """Verify /inventory HTML and REST API endpoints."""
        # 1. HTML View
        res_html = self.client.get("/inventory")
        self.assertEqual(res_html.status_code, 200)
        self.assertIn(b"Cryptographic Asset Inventory", res_html.data)

        # 2. JSON API
        res_api = self.client.get("/api/inventory")
        self.assertEqual(res_api.status_code, 200)
        data = res_api.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("inventory", data)
        self.assertEqual(data["inventory"]["total_assets"], 47)
        self.assertEqual(data["inventory"]["quantum_vulnerable"], 32)
        self.assertEqual(data["inventory"]["deprecated"], 3)
        self.assertEqual(data["inventory"]["pqc_ready"], 0)

        # 3. Load sample
        res_sample = self.client.post("/api/inventory/load-sample")
        self.assertEqual(res_sample.status_code, 200)
        self.assertEqual(res_sample.get_json()["summary"]["total_assets"], 47)


from inventory import CryptoInventory, parse_certificate_content
from dependency_graph import get_dependency_graph, get_all_dependency_graphs, format_ascii_graph

class TestCryptoAssetInventory(unittest.TestCase):
    """Test suite for Unified Crypto Asset Inventory."""

    def test_canonical_47_asset_sample(self):
        """Verify the canonical enterprise inventory produces exact target metrics."""
        inv = CryptoInventory()
        inv.load_sample_inventory()
        summary = inv.get_summary()

        # 47 Cryptographic Assets
        self.assertEqual(summary["total_assets"], 47)

        # Algorithm Breakdown
        bd = summary["algorithm_breakdown"]
        self.assertEqual(bd["RSA-2048"], 12)
        self.assertEqual(bd["ECDSA P-256"], 9)
        self.assertEqual(bd["X25519"], 8)
        self.assertEqual(bd["AES-256"], 7)
        self.assertEqual(bd["AES-128"], 5)
        self.assertEqual(bd["3DES"], 3)
        self.assertEqual(bd["DH-2048"], 3)

        # Posture Status
        self.assertEqual(summary["quantum_vulnerable"], 32)
        self.assertEqual(summary["deprecated"], 3)
        self.assertEqual(summary["pqc_ready"], 0)
        self.assertEqual(summary["classically_secure"], 12)

    def test_certificate_parser(self):
        """Verify PEM certificate parser extracts RSA / ECC public keys."""
        from Crypto.PublicKey import RSA
        sample_pem = RSA.generate(2048).export_key("PEM").decode("utf-8")
        findings = parse_certificate_content(sample_pem, "server.pem")
        self.assertGreaterEqual(len(findings), 1)
        self.assertIn("RSA-2048", findings[0]["algorithm"])
        self.assertTrue(findings[0]["quantum_vulnerable"])

    def test_dependency_graph_rsa2048(self):
        """Verify RSA-2048 dependency graph and blast radius metrics."""
        graph = get_dependency_graph("RSA-2048")
        self.assertEqual(graph["algorithm"], "RSA-2048")
        self.assertEqual(graph["domains_count"], 3)
        self.assertEqual(graph["total_services_affected"], 7)
        self.assertIn("Replacing RSA-2048 affects 7 services.", graph["impact_statement"])
        self.assertEqual(graph["complexity"], "HIGH")

        ascii_tree = format_ascii_graph("RSA-2048", unicode_mode=False)
        self.assertIn("Auth API", ascii_tree)
        self.assertIn("Payment", ascii_tree)
        self.assertIn("VPN", ascii_tree)
        self.assertIn("Replacing RSA-2048 affects 7 services.", ascii_tree)


import subprocess

class TestQryptisCLI(unittest.TestCase):
    """Test suite for Qryptis CLI tool."""

    def test_cli_scan_directory(self):
        """Verify directory scan logic in scanner.py."""
        from scanner import scan_directory
        res = scan_directory("./tests")
        self.assertGreater(res["files_scanned"], 0)
        self.assertGreater(res["total_findings"], 0)
        self.assertIn("summary", res)
        self.assertIn("cbom", res)

    def test_cli_subprocess_check(self):
        """Verify CLI check command via subprocess."""
        result = subprocess.run(
            [sys.executable, "qryptis.py", "check", "RSA", "2048", "--years", "10"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace"
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("ML-KEM-768", result.stdout)
        self.assertIn("Harvest-Now-Decrypt-Later", result.stdout)

    def test_cli_subprocess_scan(self):
        """Verify CLI scan command via subprocess."""
        result = subprocess.run(
            [sys.executable, "qryptis.py", "scan", "./tests/messy_sample.py"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace"
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("QRYPTIS CODE ANALYSIS", result.stdout)
        self.assertIn("RSA-1024", result.stdout)
        self.assertTrue("ML-DSA-65" in result.stdout or "ML-KEM-768" in result.stdout)

    def test_cli_subprocess_benchmark(self):
        """Verify CLI benchmark command."""
        result = subprocess.run(
            [sys.executable, "qryptis.py", "benchmark"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace"
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("ML-KEM-768", result.stdout)

    def test_cli_subprocess_standards(self):
        """Verify CLI standards command."""
        result = subprocess.run(
            [sys.executable, "qryptis.py", "standards"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace"
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("FIPS 203", result.stdout)
        self.assertIn("FIPS 204", result.stdout)
        self.assertIn("FIPS 205", result.stdout)
        self.assertIn("HQC", result.stdout)

    def test_cli_subprocess_inventory(self):
        """Verify CLI inventory command."""
        result = subprocess.run(
            [sys.executable, "qryptis.py", "inventory", "--sample"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace"
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("CRYPTO INVENTORY", result.stdout)
        self.assertIn("Cryptographic Assets", result.stdout)
        self.assertIn("RSA", result.stdout)

    def test_cli_subprocess_graph(self):
        """Verify CLI graph / impact command."""
        result = subprocess.run(
            [sys.executable, "qryptis.py", "graph", "RSA-2048"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace"
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("DEPENDENCY GRAPH", result.stdout)
        self.assertTrue("Auth API" in result.stdout or "Module" in result.stdout or "services" in result.stdout)

    def test_cli_subprocess_simulate(self):
        """Verify CLI simulate command."""
        result = subprocess.run(
            [sys.executable, "qryptis.py", "simulate", "RSA-2048", "ML-KEM-768"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace"
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("MIGRATION SIMULATOR", result.stdout)
        self.assertIn("RSA-2048", result.stdout)
        self.assertIn("ML-KEM-768", result.stdout)

    def test_cli_subprocess_plan(self):
        """Verify CLI plan command."""
        result = subprocess.run(
            [sys.executable, "qryptis.py", "plan"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace"
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("MIGRATION", result.stdout)
        self.assertIn("Priority 1", result.stdout)
        self.assertIn("3DES", result.stdout)

    def test_cli_subprocess_lab(self):
        """Verify CLI lab command."""
        result = subprocess.run(
            [sys.executable, "qryptis.py", "lab"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace"
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("NIST PQC BENCHMARK LAB", result.stdout)
        self.assertIn("ML-KEM-768", result.stdout)
        self.assertIn("1184 B", result.stdout)


from migration_simulator import MigrationSimulator
from nist_benchmarks import get_algorithm_metrics, get_all_benchmark_metrics
from master_migration_engine import MasterMigrationEngine

class TestMigrationSimulatorAndPlan(unittest.TestCase):
    """Test suite for Migration Simulator, Benchmark Lab, and Master Migration Engine."""

    def test_simulation_rsa2048_to_mlkem768(self):
        """Verify exact simulation deltas for RSA-2048 to ML-KEM-768."""
        sim = MigrationSimulator.simulate("RSA-2048", "ML-KEM-768")
        self.assertEqual(sim["source_algorithm"], "RSA-2048")
        self.assertEqual(sim["target_algorithm"], "ML-KEM-768")
        self.assertEqual(sim["affected_services"], 7)
        self.assertEqual(sim["complexity"], "MEDIUM")
        self.assertEqual(sim["latency"]["delta_percent"], 8.4)
        self.assertEqual(sim["cpu"]["delta_percent"], 11.2)
        self.assertEqual(sim["key_size"]["target_bytes"], 1184)
        self.assertEqual(sim["handshake_size"]["target_bytes"], 1088)

    def test_nist_benchmark_metrics_accuracy(self):
        """Verify official NIST parameter sizes."""
        mlkem768 = get_algorithm_metrics("ML-KEM-768")
        self.assertEqual(mlkem768["public_key_bytes"], 1184)
        self.assertEqual(mlkem768["ciphertext_bytes"], 1088)
        self.assertEqual(mlkem768["security_category"], 3)

        mldsa65 = get_algorithm_metrics("ML-DSA-65")
        self.assertEqual(mldsa65["public_key_bytes"], 1952)
        self.assertEqual(mldsa65["signature_bytes"], 3309)

    def test_master_migration_plan_priorities(self):
        """Verify master migration plan generates the 4 prioritized tiers."""
        plan = MasterMigrationEngine.generate_plan()
        self.assertEqual(plan["total_priorities"], 4)
        ranks = [p["rank"] for p in plan["priorities"]]
        self.assertEqual(ranks, [1, 2, 3, 4])
        self.assertIn("3DES", plan["priorities"][0]["primitive"])
        self.assertIn("RSA", plan["priorities"][1]["primitive"])
        self.assertIn("ECDSA", plan["priorities"][2]["primitive"])
from ast_scanner import scan_python_code_ast
from evaluation import run_evaluation
from benchmark import get_system_telemetry, compute_statistics
from dependency_graph import build_codebase_dependency_graph


class TestASTScannerAndEvaluation(unittest.TestCase):
    """Test suite for AST Parser, Ground Truth Evaluation, and Statistical Telemetry."""

    def test_ast_scanner_structural_discovery(self):
        """Verify AST correctly inspects Python code scopes, calls, and key sizes."""
        code = """
class AuthService:
    def __init__(self):
        from Crypto.PublicKey import RSA
        self.key = RSA.generate(2048)

    def verify(self):
        from Crypto.Cipher import AES
        c = AES.new(b"1234567812345678", AES.MODE_CBC)
"""
        findings = scan_python_code_ast(code, file_path="auth.py")
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]["algorithm"], "RSA")
        self.assertEqual(findings[0]["key_size"], 2048)
        self.assertEqual(findings[0]["enclosing_class"], "AuthService")
        self.assertEqual(findings[0]["enclosing_function"], "__init__")
        self.assertEqual(findings[0]["detection_method"], "AST")
        self.assertEqual(findings[0]["confidence"], "high")
        self.assertEqual(findings[0]["purpose"], "digital_signature")
        self.assertEqual(findings[0]["file"], "auth.py")
        self.assertEqual(findings[0]["line"], 5)

        self.assertEqual(findings[1]["algorithm"], "AES")
        self.assertEqual(findings[1]["enclosing_function"], "verify")
        self.assertEqual(findings[1]["purpose"], "symmetric_encryption")

    def test_ast_cryptography_hazmat_detection(self):
        """Verify AST detects cryptography.hazmat RSA, ECC, DSA, DH, 3DES, AES, and Hashes."""
        code = """
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, dh, x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes

class GatewayCrypto:
    def setup_keys(self):
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        ec_key = ec.generate_private_key(ec.SECP384R1())
        dsa_key = dsa.generate_private_key(key_size=2048)
        dh_params = dh.generate_parameters(generator=2, key_size=2048)
        x_key = x25519.X25519PrivateKey.generate()
        
    def setup_ciphers(self, key):
        des_cipher = algorithms.TripleDES(key)
        aes_cipher = algorithms.AES(key)
        md5_hash = hashes.MD5()
        sha1_hash = hashes.SHA1()
"""
        findings = scan_python_code_ast(code, file_path="gateway.py")
        algo_names = [f["algorithm"] for f in findings]
        self.assertIn("RSA", algo_names)
        self.assertIn("ECC", algo_names)
        self.assertIn("DSA", algo_names)
        self.assertIn("Diffie-Hellman", algo_names)
        self.assertIn("X25519", algo_names)
        self.assertIn("3DES", algo_names)
        self.assertIn("AES", algo_names)
        self.assertIn("MD5", algo_names)
        self.assertIn("SHA1", algo_names)

        # Check RSA-4096
        rsa_finding = next(f for f in findings if f["algorithm"] == "RSA")
        self.assertEqual(rsa_finding["key_size"], 4096)
        self.assertEqual(rsa_finding["confidence"], "high")
        self.assertEqual(rsa_finding["enclosing_class"], "GatewayCrypto")
        self.assertEqual(rsa_finding["enclosing_function"], "setup_keys")

        # Check ECC-384
        ec_finding = next(f for f in findings if f["algorithm"] == "ECC")
        self.assertEqual(ec_finding["key_size"], 384)

    def test_ast_pycryptodome_and_signatures(self):
        """Verify AST detects PyCryptodome and signature algorithms."""
        code = """
from Crypto.PublicKey import RSA, ECC, DSA
from Crypto.Cipher import DES3, AES
from Crypto.Signature import pkcs1_15, PKCS1_OAEP

def create_signatures(key):
    sig_scheme = pkcs1_15.new(key)
    enc_scheme = PKCS1_OAEP.new(key)
    legacy_3des = DES3.new(b"012345678901234567890123", DES3.MODE_CBC)
"""
        findings = scan_python_code_ast(code, file_path="signatures.py")
        self.assertGreaterEqual(len(findings), 3)
        self.assertTrue(any(f["algorithm"] == "RSA" and f["purpose"] == "digital_signature" for f in findings))
        self.assertTrue(any(f["algorithm"] == "RSA" and f["purpose"] == "asymmetric_encryption" for f in findings))
        self.assertTrue(any(f["algorithm"] == "3DES" and f["purpose"] == "symmetric_encryption" for f in findings))

    def test_ast_hashlib_and_oqs(self):
        """Verify AST detects stdlib hashlib and liboqs PQC algorithms."""
        code = """
import hashlib
import oqs

def run_protocols():
    h1 = hashlib.md5(b"user_data")
    h2 = hashlib.new("sha1")
    with oqs.KeyEncapsulation('ML-KEM-768') as kem:
        kp = kem.generate_keypair()
    with oqs.Signature('ML-DSA-65') as sig:
        sp = sig.generate_keypair()
"""
        findings = scan_python_code_ast(code, file_path="protocols.py")
        self.assertGreaterEqual(len(findings), 4)
        self.assertTrue(any(f["algorithm"] == "MD5" and f["purpose"] == "hash" for f in findings))
        self.assertTrue(any(f["algorithm"] == "SHA1" and f["purpose"] == "hash" for f in findings))
        self.assertTrue(any(f["algorithm"] == "ML-KEM-768" and f["purpose"] == "key_exchange" for f in findings))
        self.assertTrue(any(f["algorithm"] == "ML-DSA-65" and f["purpose"] == "digital_signature" for f in findings))

    def test_standardized_finding_schema_contract(self):
        """Verify every finding produced by scanner adheres strictly to the required schema contract."""
        code = """
from Crypto.PublicKey import RSA
key = RSA.generate(2048)
"""
        results = scan_and_report(code, file_path="auth.py")
        self.assertEqual(len(results), 1)
        finding = results[0]

        # Exact schema requirements:
        self.assertEqual(finding["algorithm"], "RSA")
        self.assertEqual(finding["key_size"], 2048)
        self.assertEqual(finding["purpose"], "digital_signature")
        self.assertEqual(finding["file"], "auth.py")
        self.assertEqual(finding["line"], 3)
        self.assertEqual(finding["detection_method"], "AST")
        self.assertEqual(finding["confidence"], "high")

    def test_ast_negative_controls_no_false_positives(self):
        """Verify variables or comments with crypto names are ignored by AST parser."""
        code = """
# RSA-2048 and AES-256 in comments
rsa_string_var = "RSA_MOCK_VALUE"
aes_dict = {"AES_CIPHER": 123}
def normal_calc(x, y):
    return x * y + 2048
"""
        findings = scan_python_code_ast(code, file_path="non_crypto.py")
        self.assertEqual(len(findings), 0)

    def test_ground_truth_evaluation_metrics(self):
        """Verify ground-truth benchmark achieves high precision and recall."""
        eval_metrics = run_evaluation()
        self.assertGreaterEqual(eval_metrics["total_samples"], 40)
        self.assertGreaterEqual(eval_metrics["precision"], 95.0)
        self.assertGreaterEqual(eval_metrics["recall"], 95.0)
        self.assertGreaterEqual(eval_metrics["accuracy"], 95.0)
        self.assertEqual(eval_metrics["false_positives"], 0)

    def test_statistical_telemetry(self):
        """Verify system telemetry capture and statistics calculations."""
        telemetry = get_system_telemetry()
        self.assertIn("os_platform", telemetry)
        self.assertIn("cpu_architecture", telemetry)
        self.assertIn("python_version", telemetry)

        stats = compute_statistics([10.0, 20.0, 30.0, 40.0, 50.0])
        self.assertEqual(stats["mean_ms"], 30.0)
        self.assertEqual(stats["median_ms"], 30.0)
        self.assertEqual(stats["min_ms"], 10.0)
        self.assertEqual(stats["max_ms"], 50.0)

    def test_codebase_dependency_graph_mapping(self):
        """Verify dynamic dependency graph constructed from scanned findings."""
        sample_findings = [
            {
                "algorithm": "RSA-2048",
                "file_path": "authentication.py",
                "enclosing_class": "AuthService",
                "enclosing_function": "issue_jwt",
                "line_number": 42,
                "usage": "JWT Token Signing",
                "quantum_status": "VULNERABLE",
                "migration_target": "ML-KEM-768"
            }
        ]
        graph = build_codebase_dependency_graph(sample_findings)
        self.assertIn("RSA-2048", graph)
        self.assertEqual(graph["RSA-2048"]["total_services_affected"], 1)
        self.assertEqual(graph["RSA-2048"]["domains"][0]["name"], "Authentication Module")

    def test_complete_seven_stage_pipeline_lifecycle(self):
        """
        Verify the complete frozen 7-stage PQC Migration Pipeline:
        1. Authentication / Analyst Session Context
        2. Analyze Ingress (Code Scanner, Manual Lookup, Live SSL Probe)
        3. Crypto Inventory Aggregation & CycloneDX CBOM Export
        4. Dependency Graph & Infrastructure Blast Radius
        5. Post-Quantum Migration Simulator
        6. NIST Benchmark Lab Parameter Matrix & Host Telemetry
        7. Master Migration Engine Prioritized Roadmap
        """
        from inventory import CryptoInventory
        from dependency_graph import get_dependency_graph
        from migration_simulator import MigrationSimulator
        from nist_benchmarks import get_all_benchmark_metrics
        from master_migration_engine import MasterMigrationEngine

        # Stage 1 & 2: Analyze Ingress
        # 2.1 Code Scan
        code_snippet = """
from Crypto.PublicKey import RSA
key = RSA.generate(2048)
"""
        scan_res = scan_and_report(code_snippet)
        self.assertGreaterEqual(len(scan_res), 1)
        self.assertEqual(scan_res[0]["report"]["algorithm"], "RSA")

        # 2.2 Manual Lookup
        manual_report = generate_report("RSA", 2048)
        self.assertEqual(manual_report["algorithm"], "RSA")
        self.assertTrue(manual_report["quantum_vulnerable"])
        self.assertEqual(manual_report["recommended_replacement"], "ML-KEM-768")

        # Stage 3: Unified Crypto Inventory
        inv = CryptoInventory()
        inv.add_code_findings(scan_res, target_name="auth_service.py")
        inv.add_manual_finding(manual_report, target_name="Manual Query")
        inv.load_sample_inventory()
        
        summary = inv.get_summary()
        self.assertGreaterEqual(summary["total_assets"], 47)
        self.assertGreaterEqual(summary["quantum_vulnerable"], 30)

        # Ingest CBOM
        cbom = inv.export_cbom()
        self.assertEqual(cbom["bomFormat"], "CycloneDX")
        self.assertEqual(cbom["specVersion"], "1.6")
        self.assertIn("cryptoProperties", cbom["components"][0])

        # Stage 4: Dependency Graph & Blast Radius
        dep_graph = get_dependency_graph("RSA-2048")
        self.assertEqual(dep_graph["algorithm"], "RSA-2048")
        self.assertEqual(dep_graph["total_services_affected"], 7)
        self.assertGreaterEqual(len(dep_graph["domains"]), 3)
        self.assertIn("ML-KEM-768", dep_graph["migration_target"])

        # Stage 5: Migration Simulator
        sim = MigrationSimulator.simulate("RSA-2048", "ML-KEM-768")
        self.assertEqual(sim["source_algorithm"], "RSA-2048")
        self.assertEqual(sim["target_algorithm"], "ML-KEM-768")
        self.assertEqual(sim["security"]["target_score"], 100)
        self.assertEqual(sim["affected_services"], 7)
        self.assertGreater(len(sim["remediation_steps"]), 0)

        # Stage 6: Benchmark Lab
        metrics = get_all_benchmark_metrics()
        self.assertGreaterEqual(len(metrics["pqc_kems"]), 3)
        self.assertGreaterEqual(len(metrics["pqc_signatures"]), 4)
        self.assertGreaterEqual(len(metrics["classical_baselines"]), 4)
        # Verify ML-KEM-768 primary standard in metrics
        kem_names = [k["name"] for k in metrics["pqc_kems"]]
        self.assertIn("ML-KEM-768", kem_names)

        # Stage 7: Master Migration Plan
        plan = MasterMigrationEngine.generate_plan()
        self.assertEqual(plan["total_priorities"], 4)
        self.assertEqual(plan["priorities"][0]["target"], "AES-256-GCM")
        self.assertIn("ML-KEM-768", plan["priorities"][1]["target"])
        self.assertIn("ML-DSA-65", plan["priorities"][2]["target"])
        self.assertIn("Hybrid X25519", plan["priorities"][3]["target"])
    def test_qryptis_test_project_directory_scan(self):
        """Verify scanning the official qryptis-test-project directory discovers all ground-truth primitives."""
        import os
        from scanner import scan_directory
        test_dir = os.path.abspath("qryptis-test-project")
        if os.path.exists(test_dir):
            scan_out = scan_directory(test_dir)
            self.assertGreaterEqual(scan_out["total_findings"], 6)
            algos_found = [r["algorithm"] for r in scan_out["results"]]
            self.assertIn("RSA", algos_found)
            self.assertIn("ECC", algos_found)
            self.assertIn("3DES", algos_found)
            self.assertIn("AES", algos_found)
            self.assertIn("MD5", algos_found)

    def test_purpose_aware_reasoning(self):
        """Verify purpose-aware reasoning recommends ML-DSA for signatures and ML-KEM for key establishment."""
        # RSA for Digital Signature (e.g. JWT) -> ML-DSA-65
        rep_sig = generate_report("RSA", 2048, purpose="digital_signature")
        self.assertEqual(rep_sig["recommended_replacement"], "ML-DSA-65")
        self.assertIn("Digital Signature", rep_sig["replacement_type"])

        # RSA for Key Encapsulation / PKI -> ML-KEM-768
        rep_kem = generate_report("RSA", 2048, purpose="key_exchange")
        self.assertEqual(rep_kem["recommended_replacement"], "ML-KEM-768")
        self.assertIn("Key Encapsulation", rep_kem["replacement_type"])

        # AES-256 -> Grover Resilient (Continue using it, no PQC swap required)
        rep_aes = generate_report("AES", 256)
        self.assertFalse(rep_aes["quantum_vulnerable"])
        self.assertIn("QUANTUM RESILIENT", rep_aes["verdict"])
        self.assertIn("Retain", rep_aes["recommended_replacement"])

        # 3DES -> Deprecated -> AES-256-GCM
        rep_3des = generate_report("3DES", 168)
        self.assertTrue(rep_3des["deprecated"])
        self.assertEqual(rep_3des["recommended_replacement"], "AES-256")

    def test_dynamic_inventory_and_cbom_synchronization(self):
        """Verify dynamic inventory sets exact asset count and CBOM matches 1:1."""
        from inventory import CryptoInventory
        test_inv = CryptoInventory()
        sample_findings = [
            {"algorithm": "RSA", "key_size": 2048, "purpose": "digital_signature", "file": "auth.py", "line": 10},
            {"algorithm": "AES", "key_size": 256, "purpose": "symmetric_encryption", "file": "db.py", "line": 20},
            {"algorithm": "3DES", "key_size": 168, "purpose": "symmetric_encryption", "file": "legacy.py", "line": 30},
            {"algorithm": "ECC", "key_size": 256, "purpose": "digital_signature", "file": "sig.py", "line": 40},
        ]
        test_inv.set_code_findings(sample_findings, target_name="microservice_bundle")
        
        # Exact 4 assets
        self.assertEqual(len(test_inv.assets), 4)
        summary = test_inv.get_summary()
        self.assertEqual(summary["total_assets"], 4)

        # Exact 4 CBOM components
        cbom = test_inv.export_cbom()
        self.assertEqual(len(cbom["components"]), 4)
        self.assertEqual(cbom["components"][0]["cryptoProperties"]["algorithm"], "RSA")

    def test_calculated_blast_radius_scores(self):
        """Verify mathematical calculation of blast radius score."""
        from dependency_graph import calculate_blast_radius_score
        res = calculate_blast_radius_score(total_calls=5, file_count=3, is_quantum_vulnerable=True, is_deprecated=False)
        # (5 * 4) + (3 * 8) + 25 = 20 + 24 + 25 = 69
        self.assertEqual(res["score"], 69)
        self.assertIn("calls", res["formula"])


if __name__ == "__main__":
    unittest.main()


