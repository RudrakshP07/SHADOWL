"""
VAPT-Grade SSL Certificate & Subdomain Finder using crt.sh
Enhanced version - Prints ALL certificates and saves to single JSON file
"""

import requests
import time
import re
import sys
import os
import json
from datetime import datetime, timezone
from typing import List, Dict, Set, Optional, Any

def fetch_with_retry(url: str, max_retries: int = 3) -> Optional[requests.Response]:
    """
    Fetch URL with retry logic for handling 502 errors
    """
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'application/json',
    }
    
    for attempt in range(max_retries):
        try:
            print(f"  Attempt {attempt + 1}/{max_retries}...")
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                return response
            elif response.status_code == 502:
                wait_time = 2 ** attempt  # Exponential backoff: 1, 2, 4 seconds
                print(f"  ⚠️ crt.sh returned 502 Bad Gateway. Retrying in {wait_time} seconds...")
                time.sleep(wait_time)
            else:
                print(f"  ⚠️ HTTP {response.status_code}. Retrying...")
                time.sleep(2)
                
        except requests.exceptions.Timeout:
            print(f"  ⚠️ Timeout on attempt {attempt + 1}")
            time.sleep(2 ** attempt)
        except Exception as e:
            print(f"  ⚠️ Error: {e}")
            time.sleep(2 ** attempt)
    
    return None

def try_html_parsing(domain: str) -> Set[str]:
    """
    Parse HTML table from crt.sh as fallback when JSON fails
    """
    print("\n🔄 Falling back to HTML parsing...")
    
    url = f"https://crt.sh/?q=%25.{domain}"
    response = fetch_with_retry(url, max_retries=2)
    
    if not response or response.status_code != 200:
        print("❌ HTML parsing also failed")
        return set()
    
    html = response.text
    subdomains = set()
    
    # Pattern to find subdomains in the HTML table
    patterns = [
        r'<TD>([a-zA-Z0-9*.-]+\.' + re.escape(domain) + ')</TD>',
        r'>([a-zA-Z0-9*.-]+\.' + re.escape(domain) + ')<',
        r'([a-zA-Z0-9*.-]+\.' + re.escape(domain) + ')',
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, html, re.IGNORECASE)
        for match in matches:
            sub = match.strip().lower()
            # Remove wildcards
            if sub.startswith('*.'):
                sub = sub[2:]
            # Remove any trailing special characters
            sub = sub.rstrip('.').strip()
            # Validate it's actually a subdomain
            if sub.endswith(domain) and sub != domain:
                subdomains.add(sub)
    
    # Also look for common_name field in hidden data
    common_name_pattern = r'common_name.*?([a-zA-Z0-9*.-]+\.' + re.escape(domain) + ')'
    cn_matches = re.findall(common_name_pattern, html, re.IGNORECASE)
    for match in cn_matches:
        sub = match.strip().lower()
        if sub.startswith('*.'):
            sub = sub[2:]
        if sub.endswith(domain) and sub != domain:
            subdomains.add(sub)
    
    return subdomains

def try_alternative_queries(domain: str) -> Optional[List[Dict]]:
    """
    Try different query formats to crt.sh
    """
    print("\n🔄 Trying alternative query methods...")
    
    query_variations = [
        f"https://crt.sh/?q={domain}&output=json",
        f"https://crt.sh/?q=*.{domain}&output=json",
        f"https://crt.sh/?q=%25{domain}&output=json",
        f"https://crt.sh/?q={domain}",
    ]
    
    for url in query_variations:
        print(f"  Trying: {url}")
        response = fetch_with_retry(url, max_retries=2)
        
        if response and response.status_code == 200:
            # Check if it's JSON or HTML
            content_type = response.headers.get('content-type', '')
            if 'json' in content_type or url.endswith('json'):
                try:
                    certs = response.json()
                    if certs:
                        print(f"  ✅ Found {len(certs)} certificates via alternative query")
                        return certs
                except ValueError:
                    continue
            else:
                # It's HTML, try to parse it
                html = response.text
                # Check if there's JSON data in the HTML
                json_match = re.search(r'\[\s*\{.*\}\s*\]', html, re.DOTALL)
                if json_match:
                    try:
                        import json
                        certs = json.loads(json_match.group())
                        if certs:
                            print(f"  ✅ Found {len(certs)} certificates in HTML JSON")
                            return certs
                    except:
                        pass
    
    return None

def save_results_to_json(domain: str, subdomains: Set[str], filtered_certs: List[Dict], raw_certs: List[Dict] = None):
    """
    Save ALL results to a single JSON file in {domain} folder
    """
    # Create folder name
    folder_name = f"{domain}"
    
    # Create directory if it doesn't exist
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)
        print(f"\n📁 Created folder: {folder_name}/")
    
    # Prepare the complete JSON data
    json_data = {
        "metadata": {
            "target_domain": domain,
            "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "scan_timestamp": datetime.now().isoformat(),
            "tool": "SSL Certificate & Subdomain Finder",
            "version": "3.0"
        },
        "statistics": {
            "total_subdomains": len(subdomains),
            "total_certificates": len(filtered_certs),
            "raw_certificates_count": len(raw_certs) if raw_certs else 0
        },
        "subdomains": {
            "all": sorted(list(subdomains)),
            "by_level": {
                "first_level": [],
                "deeper_level": []
            }
        },
        "certificates": filtered_certs,
        "raw_data": raw_certs if raw_certs else []
    }
    
    # Group subdomains by level
    for sub in subdomains:
        if sub == domain:
            continue
        parts = sub.split('.')
        if len(parts) == len(domain.split('.')) + 1:
            json_data["subdomains"]["by_level"]["first_level"].append(sub)
        else:
            json_data["subdomains"]["by_level"]["deeper_level"].append(sub)
    
    # Sort the subdomain lists
    json_data["subdomains"]["by_level"]["first_level"] = sorted(json_data["subdomains"]["by_level"]["first_level"])
    json_data["subdomains"]["by_level"]["deeper_level"] = sorted(json_data["subdomains"]["by_level"]["deeper_level"])
    
    # Save to JSON file
    json_file = os.path.join(folder_name, f"{domain}_certsh.json")
    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump(json_data, f, indent=2, default=str)
    
    print(f"✅ ALL results saved to: {json_file}")
    print(f"   • File size: {os.path.getsize(json_file) / 1024:.2f} KB")
    print(f"   • Subdomains: {len(subdomains)}")
    print(f"   • Certificates: {len(filtered_certs)}")
    
    return json_file

def find_certificates(domain: str):
    """
    Main function to find certificates and subdomains
    """
    print(f"\n{'='*70}")
    print(f"🔍 SSL Certificate & Subdomain Finder for: {domain}")
    print(f"{'='*70}\n")
    
    # Clean domain input
    domain = domain.lower().strip()
    if domain.startswith('http://'):
        domain = domain[7:]
    if domain.startswith('https://'):
        domain = domain[8:]
    if domain.startswith('www.'):
        domain = domain[4:]
    
    print(f"📡 Connecting to crt.sh...")
    
    # Primary query
    primary_url = f"https://crt.sh/?q=%25.{domain}&output=json"
    print(f"  Primary URL: {primary_url}")
    
    response = fetch_with_retry(primary_url)
    certs = None
    
    if response and response.status_code == 200:
        try:
            certs = response.json()
            print(f"✅ Successfully retrieved {len(certs) if certs else 0} raw certificates")
        except ValueError as e:
            print(f"⚠️ JSON parsing error: {e}")
            certs = None
    
    # If primary method failed, try alternatives
    if not certs:
        certs = try_alternative_queries(domain)
    
    if certs:
        process_certificates(domain, certs)
    else:
        print("\n❌ Could not retrieve certificate data via JSON API")
        print("🔄 Attempting HTML parsing as last resort...")
        subdomains = try_html_parsing(domain)
        
        if subdomains:
            display_results(domain, subdomains, [], certs)
            save_results_to_json(domain, subdomains, [], certs)
        else:
            print("\n❌ All methods failed!")

def process_certificates(domain: str, raw_certs: List[Dict]):
    """
    Process certificate data and extract subdomains
    """
    subdomains: Set[str] = set()
    filtered_certs = []
    seen_names = set()
    
    print(f"\n📊 Processing {len(raw_certs)} raw certificates...")
    
    for cert in raw_certs:
        # Get names from multiple possible fields
        name_sources = []
        
        # Try common_name field
        if 'common_name' in cert and cert['common_name']:
            name_sources.append(cert['common_name'])
        
        # Try name_value field (primary)
        if 'name_value' in cert and cert['name_value']:
            name_sources.append(cert['name_value'])
        
        # Try dNSName field (Subject Alternative Names)
        if 'dNSName' in cert and cert['dNSName']:
            name_sources.append(cert['dNSName'])
        
        # Combine all names
        all_names = []
        for source in name_sources:
            if isinstance(source, str):
                names = source.split('\n')
                all_names.extend([n.strip() for n in names])
        
        matched_names = []
        
        for name in all_names:
            name = name.strip().lower()
            if not name:
                continue
                
            # Handle wildcards
            if name.startswith('*.'):
                name = name[2:]
            
            # Check if it's a subdomain of our target
            if name == domain or name.endswith('.' + domain):
                subdomains.add(name)
                matched_names.append(name)
        
        if matched_names:
            # Create unique key for deduplication
            names_key = tuple(sorted(set(matched_names)))
            
            if names_key not in seen_names:
                seen_names.add(names_key)
                
                # Calculate expiry status
                not_after = cert.get("not_after", "N/A")
                status = "UNKNOWN"
                days_remaining = None
                
                if not_after and not_after != "N/A":
                    try:
                        now = datetime.now(timezone.utc)
                        if not_after.endswith('Z'):
                            expiry_date = datetime.strptime(not_after, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
                        else:
                            expiry_date = datetime.strptime(not_after, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
                        
                        if expiry_date < now:
                            status = "EXPIRED"
                            days_remaining = -((now - expiry_date).days)
                        else:
                            status = "ACTIVE"
                            days_remaining = (expiry_date - now).days
                    except Exception:
                        status = "DATE_ERROR"
                
                filtered_certs.append({
                    "certificate_id": cert.get("id", "N/A"),
                    "issuer": cert.get("issuer_name", cert.get("issuer_ca_id", "N/A")),
                    "not_before": cert.get("not_before", "N/A"),
                    "not_after": not_after,
                    "status": status,
                    "days_remaining": days_remaining,
                    "names_count": len(matched_names),
                    "names": matched_names,
                    "entry_timestamp": cert.get("entry_timestamp", "N/A")
                })
    
    display_results(domain, subdomains, filtered_certs, raw_certs)

def display_results(domain: str, subdomains: Set[str], filtered_certs: List[Dict], raw_certs: List[Dict] = None):
    """
    Display ALL results without any limits
    """
    print(f"\n{'='*70}")
    print(f"📊 RESULTS FOR: {domain}")
    print(f"{'='*70}")
    
    if filtered_certs:
        print(f"✅ Unique certificates found: {len(filtered_certs)}")
    print(f"✅ Unique subdomains found: {len(subdomains)}")
    
    if subdomains:
        print(f"\n📋 SUBDOMAINS ({len(subdomains)} total):")
        print("-" * 70)
        
        # Group subdomains by level
        first_level = set()
        deeper_level = set()
        
        for sub in subdomains:
            if sub == domain:
                continue
            parts = sub.split('.')
            if len(parts) == len(domain.split('.')) + 1:
                first_level.add(sub)
            else:
                deeper_level.add(sub)
        
        if first_level:
            print("\n🌐 First-level subdomains:")
            for sub in sorted(first_level):
                print(f"  • {sub}")
        
        if deeper_level:
            print("\n🔍 Deeper subdomains:")
            for sub in sorted(deeper_level):
                print(f"  • {sub}")
    
    if filtered_certs:
        print(f"\n{'='*70}")
        print(f"📜 CERTIFICATE DETAILS (ALL {len(filtered_certs)} certificates):")
        print(f"{'='*70}")
        
        now = datetime.now(timezone.utc)
        
        for i, cert in enumerate(filtered_certs, 1):
            print(f"\n{'='*50}")
            print(f"[{i}/{len(filtered_certs)}] CERTIFICATE ID: {cert['certificate_id']}")
            print(f"{'='*50}")
            
            # Format issuer name
            issuer = cert['issuer']
            if isinstance(issuer, str) and len(issuer) > 100:
                print(f"🏢 Issuer: {issuer[:97]}...")
            else:
                print(f"🏢 Issuer: {issuer}")
            
            # Display expiry info
            status_icon = "✅" if cert['status'] == "ACTIVE" else "❌" if cert['status'] == "EXPIRED" else "⚠️"
            print(f"📆 Valid From: {cert.get('not_before', 'N/A')}")
            print(f"📅 Valid Until: {cert['not_after']}")
            print(f"📊 Status: {status_icon} {cert['status']}", end="")
            if cert['days_remaining'] is not None:
                if cert['status'] == "ACTIVE":
                    print(f" ({cert['days_remaining']} days remaining)")
                elif cert['status'] == "EXPIRED":
                    print(f" ({abs(cert['days_remaining'])} days ago)")
                else:
                    print()
            else:
                print()
            
            print(f"📝 Entry Timestamp: {cert.get('entry_timestamp', 'N/A')}")
            print(f"🌐 Names in certificate: {cert['names_count']}")
            
            if cert['names']:
                print(f"\n🔖 Domain Names:")
                for j, name in enumerate(cert['names'], 1):
                    print(f"   {j:2}. {name}")
            
            print(f"{'='*50}")
    
    print(f"\n{'='*70}")
    print(f"📈 FINAL STATISTICS:")
    print(f"{'='*70}")
    print(f"   • Target domain: {domain}")
    print(f"   • Scan time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"   • Raw certificates from crt.sh: {len(raw_certs) if raw_certs else 0}")
    if filtered_certs:
        print(f"   • Unique certificates processed: {len(filtered_certs)}")
    print(f"   • Unique subdomains discovered: {len(subdomains)}")
    
    print(f"\n💡 VAPT RECOMMENDATIONS:")
    print(f"   1. Validate which subdomains are still live")
    print(f"   2. Check for development/staging environments")
    print(f"   3. Look for exposed admin panels or APIs")
    print(f"   4. Test SSL/TLS configuration on live hosts")
    print(f"   5. Investigate any unexpected subdomains")
    
    print(f"\n{'='*70}")
    
    # Automatically save ALL results to single JSON file
    print(f"\n💾 Saving ALL results to single JSON file...")
    json_file = save_results_to_json(domain, subdomains, filtered_certs, raw_certs)
    
    print(f"\n📁 Folder structure:")
    print(f"   {domain}_certsh/")
    print(f"   └── {domain}_certsh.json (all results)")
    print(f"\n📦 JSON file contains:")
    print(f"   • Metadata (scan info)")
    print(f"   • Statistics")
    print(f"   • All subdomains (sorted)")
    print(f"   • All certificates (detailed)")
    print(f"   • Raw certificate data from crt.sh")

def print_banner():
    """
    Print a nice banner
    """
    banner = r"""
    ╔══════════════════════════════════════════════════════════╗
    ║         SSL Certificate & Subdomain Finder v3.0          ║
    ║                  Powered by crt.sh                       ║
    ║        Shows ALL certificates • Single JSON output       ║
    ╚══════════════════════════════════════════════════════════╝
    """
    print(banner)

def main():
    """
    Main entry point
    """
    print_banner()
    
    if len(sys.argv) > 1:
        domain = sys.argv[1].strip()
    else:
        domain = input("\n🎯 Enter target domain (e.g. example.com): ").strip()
    
    if not domain:
        print("❌ No domain provided. Exiting.")
        return
    
    print(f"\n🚀 Starting reconnaissance on: {domain}")
    print(f"⏰ Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*70}\n")
    
    try:
        find_certificates(domain)
    except KeyboardInterrupt:
        print("\n\n⚠️ Operation cancelled by user.")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        print("Please report this issue if it persists.")
    
    print(f"\n{'='*70}")
    print(f"⏰ End time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*70}")

if __name__ == "__main__":
    main()