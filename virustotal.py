"""
VirusTotal URL Scanner (User Input)
Now accepts domain input (e.g., example.com) and auto-adds https://
Loads VirusTotal API key from token.txt using absolute path
"""

import requests
import time
import os
import sys

# --------------------------------------------------
# CONFIG
# --------------------------------------------------
TOKEN_FILE = r"E:\RECON ROJECT\Duplicate Version\token.txt"
VT_API_BASE = "https://www.virustotal.com/api/v3"

# --------------------------------------------------
# LOAD API KEY
# --------------------------------------------------
def load_virustotal_key():
    if not os.path.exists(TOKEN_FILE):
        print(f"❌ token.txt not found at:\n{TOKEN_FILE}")
        sys.exit(1)

    with open(TOKEN_FILE, "r", encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            if key.strip().lower() == "virustotal":
                return value.strip()

    print("❌ VirusTotal API key not found in token.txt")
    sys.exit(1)

API_KEY = load_virustotal_key()
HEADERS = {"x-apikey": API_KEY}

# --------------------------------------------------
# URL SCAN
# --------------------------------------------------
def scan_url(target_url, api_key=None):
    # Auto-add https:// if not present
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
    
    print(f"\n🦠 Scanning URL: {target_url}")
    print("=" * 60)

    # Allow caller to override API key
    headers = HEADERS if api_key is None else {"x-apikey": api_key}

    try:
        submit = requests.post(
            f"{VT_API_BASE}/urls",
            headers=headers,
            data={"url": target_url},
            timeout=30
        )

        if submit.status_code != 200:
            return fail(f"HTTP {submit.status_code}: {submit.text}")

        analysis_id = submit.json()["data"]["id"]
        return wait_for_results(analysis_id, headers)

    except requests.RequestException as e:
        return fail(str(e))

# --------------------------------------------------
# ANALYSIS POLLING
# --------------------------------------------------
def wait_for_results(analysis_id, headers):
    print(f"[*] Analysis ID: {analysis_id}")
    print("[*] Waiting for results...")

    for _ in range(10):
        time.sleep(5)
        r = requests.get(
            f"{VT_API_BASE}/analyses/{analysis_id}",
            headers=headers
        )

        if r.status_code == 200:
            status = r.json()["data"]["attributes"]["status"]
            if status == "completed":
                return display_results(r.json())

    return fail("Analysis still queued")

# --------------------------------------------------
# OUTPUT
# --------------------------------------------------
def display_results(data):
    stats = data["data"]["attributes"]["stats"]

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values())

    print("\n📊 RESULTS")
    print("-" * 60)
    print(f"Malicious : {malicious}")
    print(f"Suspicious: {suspicious}")
    print(f"Total     : {total}")

    if malicious or suspicious:
        print("\n⚠️ THREATS DETECTED")
    else:
        print("\n✅ CLEAN")

    print("=" * 60)
    return stats

def fail(msg):
    print(f"❌ {msg}")
    return {"error": msg}

# --------------------------------------------------
# MAIN
# --------------------------------------------------
def main():
    # Updated prompt to accept domain input
    target_url = input("Enter target domain (e.g., example.com): ").strip()
    
    if not target_url:
        print("❌ No domain provided. Exiting.")
        return

    scan_url(target_url)

if __name__ == "__main__":
    main()