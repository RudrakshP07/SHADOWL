"""
Shodan Scanner - Renamed to avoid conflict with shodan library
"""

import shodan
import json
import socket
from datetime import datetime

# ==============================
# HARD-CODED SHODAN API KEY
# ==============================
SHODAN_API_KEY = ""
api = shodan.Shodan(SHODAN_API_KEY)


def is_ip(target):
    try:
        socket.inet_aton(target)
        return True
    except socket.error:
        return False


def resolve_domain(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def gather_host_info(ip):
    return api.host(ip)


def save_json(data, target):
    filename = f"shodan_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
    print(f"\n[+] Results saved to: {filename}")


def display_summary(data):
    print("\n====== SHODAN SUMMARY ======\n")
    print(f"IP Address   : {data.get('ip_str')}")
    print(f"Organization : {data.get('org')}")
    print(f"ISP          : {data.get('isp')}")
    print(f"ASN          : {data.get('asn')}")
    print(f"Country      : {data.get('country_name')}")
    print(f"City         : {data.get('city')}")
    print(f"OS           : {data.get('os')}")
    print(f"Open Ports   : {data.get('ports')}")
    print(f"Hostnames    : {data.get('hostnames')}")
    print(f"Domains      : {data.get('domains')}")

    if "vulns" in data:
        print("\nVulnerabilities:")
        for vuln in data["vulns"]:
            print(f" - {vuln}")

    print("\nServices:")
    for service in data.get("data", []):
        print(f" - Port {service.get('port')} | {service.get('product')} {service.get('version')}")


def main():
    print("\n=== Shodan Recon CLI ===\n")
    target = input("Enter target domain or IP address: ").strip()

    if is_ip(target):
        ip = target
    else:
        ip = resolve_domain(target)
        if not ip:
            print("[-] Could not resolve domain.")
            return

    print(f"\n[+] Processing IP: {ip}")

    try:
        result = gather_host_info(ip)
    except shodan.APIError as e:
        print(f"[-] Shodan API error: {e}")
        return

    display_summary(result)
    save_json(result, target)


if __name__ == "__main__":
    main()