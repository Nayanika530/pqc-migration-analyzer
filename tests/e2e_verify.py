"""
e2e_verify.py
Runs an end-to-end verification of all routes, algorithms, scanner, exports, and edge cases.
"""

import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import app

def run_all():
    client = app.test_client()

    print("=== 1. Testing GET Routes ===")
    routes = ['/', '/analyze', '/database', '/manual', '/scan', '/live-scan', '/login', '/qryptis']
    for r in routes:
        res = client.get(r)
        print(f"  GET {r:14} -> HTTP {res.status_code}")
        assert res.status_code == 200, f"Failed on {r}"

    print("\n=== 2. Testing Manual Lookup ===")
    res_rsa = client.post('/manual', data={'algorithm': 'RSA', 'key_size': '2048', 'years_secret': '10'})
    assert res_rsa.status_code == 200 and b"ML-KEM-768" in res_rsa.data
    print("  RSA-2048: OK (Recommended ML-KEM-768)")

    res_md5 = client.post('/manual', data={'algorithm': 'MD5', 'key_size': '128', 'years_secret': '0'})
    assert res_md5.status_code == 200 and b"DEPRECATED" in res_md5.data
    print("  MD5: OK (Deprecated verdict returned)")

    print("\n=== 3. Testing Scanner, CBOM & Roadmap Downloads ===")
    with open('tests/messy_sample.py') as f:
        code = f.read()

    res_scan = client.post('/scan', data={'code_text': code})
    assert res_scan.status_code == 200 and b"CBOM Summary" in res_scan.data
    print("  Code Scanner on messy_sample.py: OK")

    res_cbom = client.get('/download-cbom')
    assert res_cbom.status_code == 200
    cbom_data = json.loads(res_cbom.data)
    total_findings = cbom_data['summary']['total_findings']
    print(f"  CBOM Export: OK ({total_findings} findings exported)")

    res_rm = client.get('/download-roadmap')
    assert res_rm.status_code == 200 and b"Migration Roadmap" in res_rm.data
    print("  Roadmap Export: OK (Markdown report ready)")

    print("\n=== 4. Testing Edge Cases ===")
    res_neg = client.post('/manual', data={'algorithm': 'RSA', 'key_size': '-512'})
    assert b"positive integer" in res_neg.data
    print("  Negative key size rejected: OK")

    res_zero = client.post('/manual', data={'algorithm': 'RSA', 'key_size': '0'})
    assert b"positive integer" in res_zero.data
    print("  Zero key size rejected: OK")

    res_empty = client.post('/api/scan', json={'code': ''})
    assert res_empty.status_code == 400
    print("  Empty scan input returns 400: OK")

    print("\n>>> ALL CHECKS PASSED PERFECTLY! <<<")

if __name__ == "__main__":
    run_all()
