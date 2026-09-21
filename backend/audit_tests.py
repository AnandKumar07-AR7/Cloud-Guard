import requests
import time
import subprocess
import os
import json

BASE_URL = "http://localhost:8000"

def print_header(title):
    print(f"\n{'='*60}")
    print(f" {title}")
    print(f"{'='*60}")

def test_health():
    print_header("16. DATABASE HEALTH (AVAILABLE)")
    resp = requests.get(f"{BASE_URL}/health")
    print(f"Status: {resp.status_code}")
    data = resp.json()
    print(json.dumps(data, indent=2))
    assert data["status"] == "healthy"
    assert data["database_status"] == "available"
    print("Health check PASSED")

def run_scan():
    print_header("7. SCAN PERSISTENCE")
    resp = requests.post(f"{BASE_URL}/scans", json={"provider": "demo", "scenario": "default"})
    print(f"POST /scans Status: {resp.status_code}")
    data = resp.json()
    scan_id = data["scan_id"]
    print(f"Scan ID: {scan_id}")
    
    # Verify scan can be retrieved
    resp = requests.get(f"{BASE_URL}/scans/{scan_id}")
    scan_data = resp.json()
    print(f"GET /scans/{scan_id} Status: {resp.status_code}")
    assert scan_data["scan_id"] == scan_id
    assert scan_data["status"] == "COMPLETED"
    print("Scan retrieval PASSED")
    
    # Verify findings are persisted
    resp = requests.get(f"{BASE_URL}/findings?scan_id={scan_id}")
    findings = resp.json()["items"]
    print(f"Retrieved {len(findings)} findings for scan")
    assert len(findings) > 0
    return scan_id, findings

def test_outage():
    print_header("12. DATABASE OUTAGE")
    print("Stopping PostgreSQL...")
    subprocess.run(["docker", "stop", "cloudguard-postgres"], check=True)
    time.sleep(2)
    
    try:
        print("Testing /health during outage:")
        resp = requests.get(f"{BASE_URL}/health")
        print(f"Status: {resp.status_code}")
        data = resp.json()
        print(json.dumps(data, indent=2))
        
        print("Testing POST /scans during outage (Persistence Operation):")
        resp = requests.post(f"{BASE_URL}/scans", json={"provider": "demo"})
        print(f"Status: {resp.status_code}")
        # Should fail with 500 or appropriate error, not 201 (no sqlite fallback)
        assert resp.status_code != 201
    finally:
        print("Starting PostgreSQL...")
        subprocess.run(["docker", "start", "cloudguard-postgres"], check=True)
        time.sleep(5)
        
    print("Testing /health after recovery:")
    resp = requests.get(f"{BASE_URL}/health")
    print(f"Status: {resp.status_code}")
    assert resp.json()["database_status"] == "available"
    print("Outage recovery PASSED")

if __name__ == "__main__":
    try:
        test_health()
        scan_id, findings = run_scan()
        test_outage()
    except Exception as e:
        print(f"TEST FAILED: {e}")
    except Exception as e:
        print(f"TEST FAILED: {e}")
