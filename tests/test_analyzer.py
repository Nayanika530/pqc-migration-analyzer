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
        required_algos = ["RSA", "ECC", "AES", "DSA", "DIFFIE-HELLMAN", "3DES", "MD5"]
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
        self.assertIn("OK", rep_aes["verdict"])
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

    @unittest.mock.patch("app.chat_with_assistant", return_value="Here is advice on post-quantum migration.")
    def test_api_chat_with_message(self, mock_chat):
        """Verify /api/chat handles real questions."""
        response = self.client.post("/api/chat", json={"message": "What replaces RSA?"})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("post-quantum", data["reply"])


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
            text=True
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("ML-KEM-768", result.stdout)
        self.assertIn("Harvest-Now-Decrypt-Later", result.stdout)

    def test_cli_subprocess_scan(self):
        """Verify CLI scan command via subprocess."""
        result = subprocess.run(
            [sys.executable, "qryptis.py", "scan", "./tests/messy_sample.py"],
            capture_output=True,
            text=True
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("QRYPTIS CODE ANALYSIS", result.stdout)
        self.assertIn("RSA-1024", result.stdout)
        self.assertIn("ML-KEM-768", result.stdout)

    def test_cli_subprocess_benchmark(self):
        """Verify CLI benchmark command."""
        result = subprocess.run(
            [sys.executable, "qryptis.py", "benchmark"],
            capture_output=True,
            text=True
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("ML-KEM-768", result.stdout)


if __name__ == "__main__":
    unittest.main()
