"""
Enhanced WHOIS Lookup Tool - Windows PowerShell Compatible
Automatically saves output in a folder named after the target domain
"""

import socket
import json
import os
import re
from datetime import datetime
from tabulate import tabulate

# Optional HTTP RDAP fallback
try:
    import requests
except Exception:
    requests = None

# ==========================================================
# WHOIS SOCKET QUERY
# ==========================================================

def whois_query(domain, server='whois.iana.org', port=43, timeout=10):
    """Perform a WHOIS query via TCP socket to a WHOIS server.
    Returns decoded text or string starting with 'Error:' on failure.
    """
    try:
        # resolve server first (will raise socket.gaierror if DNS fails)
        addr = socket.gethostbyname(server)
    except Exception as e:
        return f"Error: unable to resolve whois server {server} ({e})"

    try:
        with socket.create_connection((server, port), timeout=timeout) as s:
            s.sendall((domain + '\r\n').encode())
            chunks = []
            while True:
                data = s.recv(4096)
                if not data:
                    break
                chunks.append(data)
            return b''.join(chunks).decode('utf-8', errors='ignore')
    except Exception as e:
        return f"Error: {str(e)}"

# ==========================================================
# WHOIS SERVER SELECTION
# ==========================================================

def find_whois_server(domain):
    tld = domain.split('.')[-1].lower()
    mapping = {
        'com': 'whois.verisign-grs.com',
        'net': 'whois.verisign-grs.com',
        'org': 'whois.pir.org',
        'info': 'whois.afilias.net',
        'biz': 'whois.biz',
        'us': 'whois.nic.us',
        'uk': 'whois.nic.uk',
        'ca': 'whois.cira.ca',
        'au': 'whois.auda.org.au',
        'de': 'whois.denic.de',
        'fr': 'whois.afnic.fr',
        'io': 'whois.nic.io',
        'ai': 'whois.nic.ai',
        'co': 'whois.nic.co',
        'in': 'whois.registry.in',
    }

    if tld in mapping:
        return mapping[tld]

    # Fallback: try to ask whois.iana.org for referral
    try:
        resp = whois_query(tld, server='whois.iana.org')
        for line in resp.splitlines():
            if line.lower().startswith('whois:'):
                return line.split(':',1)[1].strip()
    except Exception:
        pass

    return 'whois.iana.org'

# ==========================================================
# WHOIS PARSER
# ==========================================================

def parse_whois_data(text):
    """Parse WHOIS free-text with both key:value parsing and regex fallbacks."""
    data = {
        'domain': '',
        'registrar': '',
        'creation_date': '',
        'expiration_date': '',
        'updated_date': '',
        'name_servers': [],
        'status': [],
        'registrant_org': '',
        'registrant_state': '',
        'registrant_country': '',
        'dnssec': '',
        'emails': [],
        'abuse_email': '',
        'abuse_phone': '',
        'iana_id': '',
        'registrar_url': '',
        'raw_whois': text
    }

    # Key: value parsing (robust to variant keys)
    for line in text.splitlines():
        if ':' not in line:
            continue
        key, value = line.split(':', 1)
        key = key.lower().strip()
        value = value.strip()

        if 'domain name' in key and not data['domain']:
            data['domain'] = value
        elif 'registrar' in key and not data['registrar']:
            data['registrar'] = value
        elif 'creation date' in key or 'created on' in key:
            data['creation_date'] = value
        elif 'expiry' in key or 'expiration date' in key or 'registry expiry' in key:
            data['expiration_date'] = value
        elif 'updated date' in key or 'last updated' in key:
            data['updated_date'] = value
        elif 'name server' in key:
            data['name_servers'].append(value.lower())
        elif key.startswith('status'):
            data['status'].append(value)
        elif 'registrant organization' in key or 'registrant org' in key or 'person' in key and not data['registrant_org']:
            data['registrant_org'] = value
        elif 'registrant state/province' in key or 'state' in key and not data['registrant_state']:
            data['registrant_state'] = value
        elif 'registrant country' in key or 'country' in key and not data['registrant_country']:
            data['registrant_country'] = value
        elif 'dnssec' in key:
            data['dnssec'] = value

        # Emails
        if '@' in value:
            # collect all emails in the value
            for email in re.findall(r"[\w\.-]+@[\w\.-]+", value):
                if email not in data['emails']:
                    data['emails'].append(email)

        # IANA ID
        if 'iana id' in key:
            data['iana_id'] = value

        # Registrar URL
        if 'registrar url' in key or 'referral url' in key or 'url' in key and 'registrar' in key:
            data['registrar_url'] = value

    # If some key fields are empty, attempt regex extraction on raw text
    # Domain
    if not data['domain']:
        m = re.search(r"Domain Name:\s*(\S+)", text, re.I)
        if m:
            data['domain'] = m.group(1)

    # Dates
    if not data['creation_date']:
        m = re.search(r"(\d{4}-\d{2}-\d{2})", text)
        if m:
            data['creation_date'] = m.group(1)
        else:
            m = re.search(r"(\d{1,2}-[A-Za-z]{3}-\d{4})", text)
            if m:
                data['creation_date'] = m.group(1)

    if not data['expiration_date']:
        m = re.search(r"(\d{4}-\d{2}-\d{2})", text)
        if m:
            data['expiration_date'] = m.group(1)

    # IANA ID
    if not data['iana_id']:
        m = re.search(r"IANA ID:\s*(\d+)", text, re.I)
        if m:
            data['iana_id'] = m.group(1)

    # Abuse email / phone heuristics
    if not data['abuse_email']:
        # look for 'abuse' context
        m = re.search(r"abuse[\w\s:\-]*([\w\.-]+@[\w\.-]+)", text, re.I)
        if m:
            data['abuse_email'] = m.group(1)
        elif data['emails']:
            data['abuse_email'] = data['emails'][0]

    if not data['abuse_phone']:
        m = re.search(r"(\+?\d[\d\-\s]{6,}\d)", text)
        if m:
            data['abuse_phone'] = m.group(1).strip()

    # Clean duplicates in name servers / emails
    data['name_servers'] = list(dict.fromkeys([ns.lower() for ns in data['name_servers']]))
    data['emails'] = list(dict.fromkeys(data['emails']))

    return data

# ==========================================================
# DATE ANALYSIS
# ==========================================================

def parse_date(date_str):
    if not date_str:
        return None
    date_str = date_str.strip()
    # Try common formats
    patterns = ["%Y-%m-%d", "%d-%b-%Y", "%Y/%m/%d", "%d-%m-%Y", "%d %b %Y"]
    # Extract simple yyyy-mm-dd style first
    m = re.search(r"(\d{4}-\d{2}-\d{2})", date_str)
    if m:
        date_str = m.group(1)
    for fmt in patterns:
        try:
            return datetime.strptime(date_str.split('T')[0], fmt)
        except Exception:
            continue
    return None

# ==========================================================
# SAVE RESULTS (DOMAIN-NAMED FOLDER)
# ==========================================================

def save_results(domain, parsed, raw_data):
    folder = domain
    os.makedirs(folder, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    json_file = os.path.join(folder, f"whois_{timestamp}.json")
    txt_file = os.path.join(folder, f"whois_summary_{timestamp}.txt")

    json_data = {
        "domain": domain,
        "scan_time": datetime.now().isoformat(),
        "whois_data": parsed,
        "raw_data": raw_data
    }

    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(json_data, f, indent=2)

    # Human-friendly summary
    with open(txt_file, "w", encoding="utf-8") as f:
        f.write(f"{parsed.get('domain', domain)}\n")
        f.write(f"Updated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("Domain Information\n")
        f.write("Domain:\t" + (parsed.get('domain') or domain) + "\n")
        f.write("Registered On:\t" + (parsed.get('creation_date') or 'N/A') + "\n")
        f.write("Expires On:\t" + (parsed.get('expiration_date') or 'N/A') + "\n")
        f.write("Updated On:\t" + (parsed.get('updated_date') or 'N/A') + "\n")
        f.write("Status:\t" + (', '.join(parsed.get('status') or []) or 'N/A') + "\n")
        f.write("Name Servers:\t" + (', '.join(parsed.get('name_servers') or []) or 'N/A') + "\n\n")

        f.write("Registrar Information\n")
        f.write("Registrar:\t" + (parsed.get('registrar') or 'N/A') + "\n")
        if parsed.get('iana_id'):
            f.write("IANA ID:\t" + parsed.get('iana_id') + "\n")
        if parsed.get('registrar_url'):
            f.write("URL:\t" + parsed.get('registrar_url') + "\n")
        if parsed.get('abuse_email'):
            f.write("Abuse Email:\t" + parsed.get('abuse_email') + "\n")
        if parsed.get('abuse_phone'):
            f.write("Abuse Phone:\t" + parsed.get('abuse_phone') + "\n")

        f.write("\nRegistrant Contact\n")
        f.write("Organization:\t" + (parsed.get('registrant_org') or 'N/A') + "\n")
        if parsed.get('registrant_state'):
            f.write("State:\t" + parsed.get('registrant_state') + "\n")
        if parsed.get('registrant_country'):
            f.write("Country:\t" + parsed.get('registrant_country') + "\n")

    print(f"\n💾 Saved JSON  : {json_file}")
    print(f"📝 Saved TXT   : {txt_file}")

# ==========================================================
# MAIN LOOKUP
# ==========================================================

def whois_lookup(domain):
    domain = domain.lower().replace("http://", "").replace("https://", "").split("/")[0]

    print(f"\n🔍 WHOIS Lookup: {domain}")
    print("=" * 60)

    server = find_whois_server(domain)
    print(f"[*] Using WHOIS server: {server}")

    raw = whois_query(domain, server)

    # If we failed to reach server, try IANA referral for TLD
    if raw.startswith('Error:') or len(raw.strip()) < 20:
        print("⚠️  Primary WHOIS server failed or returned no data, trying IANA referral...")
        tld = domain.split('.')[-1]
        try:
            iana_resp = whois_query(tld, server='whois.iana.org')
            for line in iana_resp.splitlines():
                if line.lower().startswith('whois:'):
                    ref = line.split(':',1)[1].strip()
                    print(f"[*] IANA suggests: {ref}, trying it...")
                    raw = whois_query(domain, ref)
                    break
        except Exception as e:
            print(f"⚠️  IANA referral failed: {e}")

    # If still not good, try RDAP HTTP fallback
    if (not raw) or raw.startswith('Error:') or len(raw.strip()) < 20:
        print("⚠️  Falling back to RDAP HTTP lookup (if available)...")
        if requests is not None:
            try:
                r = requests.get(f"https://rdap.org/domain/{domain}", timeout=10)
                if r.status_code == 200:
                    rd = r.json()
                    # Build a readable raw representation and parse important fields
                    raw = json.dumps(rd, indent=2)
                    parsed = {
                        'domain': rd.get('ldhName') or rd.get('objectClassName') or domain,
                        'registrar': rd.get('entities', [{}])[0].get('vcardArray', [[]]) if isinstance(rd.get('entities', [{}])[0].get('vcardArray', None), list) else '',
                        'creation_date': rd.get('events', [{}])[0].get('eventDate') if rd.get('events') else '',
                        'expiration_date': next((e.get('eventDate') for e in rd.get('events', []) if e.get('eventAction') == 'expiration'), ''),
                        'updated_date': next((e.get('eventDate') for e in rd.get('events', []) if e.get('eventAction') == 'last changed'), ''),
                        'name_servers': [ns.get('ldhName') for ns in rd.get('nameservers', [])] if rd.get('nameservers') else [],
                        'status': rd.get('status', []),
                        'emails': [],
                        'raw_whois': raw
                    }
                    # Extract contact emails if present
                    if rd.get('entities'):
                        for ent in rd.get('entities'):
                            for v in ent.get('vcardArray', [[],[]])[1]:
                                if v and v[0] == 'email':
                                    parsed['emails'].append(v[3])
                    # Print and save
                    table = [
                        ["Domain", parsed['domain'] or domain],
                        ["Registrar", parsed.get('registrar')],
                        ["Created", parsed.get('creation_date')],
                        ["Expires", parsed.get('expiration_date')],
                        ["Updated", parsed.get('updated_date')],
                        ["Name Servers", "\n".join(parsed.get('name_servers') or [])],
                        ["Status", "\n".join(parsed.get('status') or [])],
                        ["Emails", "\n".join(parsed.get('emails') or []) or "None"]
                    ]
                    print(tabulate(table, tablefmt="fancy_grid"))
                    save_results(domain, parsed, raw)
                    return
            except Exception as e:
                print(f"⚠️  RDAP lookup failed: {e}")
        else:
            print("⚠️  requests library not available for RDAP fallback")

    # If the raw answer says 'no match' we still save it
    if isinstance(raw, str) and "no match" in raw.lower():
        print("❌ Domain not registered")
        parsed = {
            'domain': domain,
            'status': ['not registered'],
            'raw_whois': raw
        }
        save_results(domain, parsed, raw)
        return

    parsed = parse_whois_data(raw)

    table = [
        ["Domain", parsed['domain'] or domain],
        ["Registrar", parsed['registrar']],
        ["Created", parsed['creation_date']],
        ["Expires", parsed['expiration_date']],
        ["Updated", parsed['updated_date']],
        ["DNSSEC", parsed.get('dnssec')],
        ["Name Servers", "\n".join(parsed['name_servers'])],
        ["Status", "\n".join(parsed['status'])],
        ["Emails", "\n".join(parsed['emails']) or "None"]
    ]

    print(tabulate(table, tablefmt="fancy_grid"))

    save_results(domain, parsed, raw)

# ==========================================================
# ENTRY POINT
# ==========================================================

if __name__ == "__main__":
    print("=" * 60)
    print(" 🔍 WHOIS Lookup Tool (Auto Domain Folder)")
    print("=" * 60)

    import sys
    if len(sys.argv) > 1:
        whois_lookup(sys.argv[1])
    else:
        target = input("\nEnter domain (example.com): ").strip()
        if target:
            whois_lookup(target)
