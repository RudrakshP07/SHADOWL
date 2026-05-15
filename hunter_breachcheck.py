import requests
import json
import os
import time
from pathlib import Path
from tabulate import tabulate

# ==============================
# CONFIG
# ==============================
HUNTER_BASE_URL = "https://api.hunter.io/v2"
HUNTER_API_KEY = ""
LEAKLOOKUP_API_KEY = ""
LEAKLOOKUP_API_URL = "https://api.leak-lookup.com/api/search"

LEAKLOOKUP_HEADERS = {
    "Content-Type": "application/json",
    "X-API-Key": LEAKLOOKUP_API_KEY,
    "User-Agent": "LeakLookup-Checker/1.0"
}

# ==============================
# UTILS
# ==============================

def make_safe_domain(domain):
    return domain.replace("/", "_").replace("\\", "_").replace(":", "_")

def save_json(data, filename):
    script_dir = Path(__file__).resolve().parent
    file_path = script_dir / filename
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
    return file_path

def extract_emails(hunter_data):
    emails = []
    for entry in hunter_data.get("data", {}).get("emails", []):
        value = entry.get("value")
        if value:
            emails.append(value)
    return emails

def load_emails_from_hunter(file_path):
    if not os.path.exists(file_path):
        print(f"[-] File not found: {file_path}")
        return []
    
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    emails = []
    for item in data.get("data", {}).get("emails", []):
        email_value = item.get("value")
        if email_value:
            emails.append(email_value)
    return emails

def check_email_leak_lookup(email):
    """
    Query Leak-Lookup API for a single email.
    Based on the example response format provided.
    """
    payload = {
        "type": "email_address",
        "query": email
    }

    try:
        response = requests.post(
            LEAKLOOKUP_API_URL, 
            headers=LEAKLOOKUP_HEADERS, 
            json=payload, 
            timeout=30
        )
        
        # Debug: Print raw response for first email
        # if email == emails[0]:  # Uncomment to debug
        #     print(f"[DEBUG] Status: {response.status_code}")
        #     print(f"[DEBUG] Response: {response.text[:500]}")
        
        if response.status_code == 200:
            data = response.json()
            
            # Handle different response formats
            if isinstance(data, dict):
                if "success" in data and not data["success"]:
                    if data.get("error") == "No results found":
                        return []
                    else:
                        print(f"[-] API error for {email}: {data.get('error')}")
                        return []
                
                # Check for results in various possible structures
                if "results" in data:
                    return data["results"]
                elif "data" in data:
                    return data["data"]
                else:
                    # Return the entire response if it contains breach data
                    return [data] if data else []
            
            elif isinstance(data, list):
                return data
            
            return []
        
        elif response.status_code == 404:
            return []  # No breaches found
        
        else:
            print(f"[-] HTTP {response.status_code} for {email}: {response.text[:200]}")
            return None
            
    except requests.exceptions.Timeout:
        print(f"[-] Timeout checking {email}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"[-] Request error checking {email}: {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"[-] JSON decode error for {email}: {e}")
        print(f"[-] Response text: {response.text[:200]}")
        return None

def format_leaks_for_table(leaks):
    """
    Convert Leak-Lookup results into readable string for CLI table.
    Based on the example format provided.
    """
    if not leaks:
        return "No breaches found"

    # Handle different possible structures
    if isinstance(leaks, dict):
        leaks = [leaks]
    
    lines = []
    
    for idx, leak in enumerate(leaks, start=1):
        # Extract information based on the example structure
        db_name = "Unknown Database"
        date_indexed = "Unknown"
        total_records = "Unknown"
        records_found = "0"
        
        # Try to extract from various possible field names
        if isinstance(leak, dict):
            # Extract database/source name
            db_name = leak.get("Database Name") or leak.get("database_name") or \
                     leak.get("source") or leak.get("Database") or \
                     "Unknown Database"
            
            # Extract date
            date_indexed = leak.get("Date Indexed") or leak.get("date_indexed") or \
                          leak.get("Date") or leak.get("date") or "Unknown"
            
            # Extract record counts
            if "Total Records" in leak:
                total_records = str(leak["Total Records"])
            elif "total_records" in leak:
                total_records = str(leak["total_records"])
            elif "count" in leak:
                total_records = str(leak["count"])
            
            # Extract records found for this email
            if "Records found" in leak:
                records_found = str(leak["Records found"])
            elif "records_found" in leak:
                records_found = str(leak["records_found"])
            elif "found" in leak:
                records_found = str(leak["found"])
            
            # Check for specific data fields
            data_fields = []
            for field in ["email_address", "username", "password", "ipaddress", "phone", "userid"]:
                if field in leak and leak[field]:
                    data_fields.append(field)
            
            # Format the output
            line = f"{idx}. {db_name}"
            if records_found != "0" and records_found != "Unknown":
                line += f" ({records_found} record(s) found)"
            
            lines.append(line)
            
            # Add details
            if date_indexed != "Unknown":
                lines.append(f"   Date: {date_indexed}")
            
            if total_records != "Unknown":
                lines.append(f"   Total in DB: {total_records}")
            
            if data_fields:
                lines.append(f"   Data exposed: {', '.join(data_fields)}")
            
            # Add separator between entries
            if idx < len(leaks):
                lines.append("")
    
    return "\n".join(lines)

def parse_leak_lookup_response(leaks):
    """
    Parse the Leak-Lookup API response to extract structured information.
    """
    if not leaks:
        return []
    
    processed_leaks = []
    
    if isinstance(leaks, dict):
        leaks = [leaks]
    
    for leak in leaks:
        if not isinstance(leak, dict):
            continue
            
        processed = {
            "database_name": leak.get("Database Name") or leak.get("database_name") or 
                            leak.get("source") or leak.get("Database") or "Unknown",
            "date_indexed": leak.get("Date Indexed") or leak.get("date_indexed") or 
                           leak.get("Date") or leak.get("date") or "Unknown",
            "total_records": leak.get("Total Records") or leak.get("total_records") or 
                            leak.get("count") or "Unknown",
            "records_found": leak.get("Records found") or leak.get("records_found") or 
                            leak.get("found") or "0",
            "exposed_data": {}
        }
        
        # Extract any exposed data fields
        for field in ["email_address", "username", "password", "ipaddress", 
                     "phone", "userid", "salt"]:
            if field in leak:
                processed["exposed_data"][field] = leak[field]
        
        processed["raw_data"] = leak
        processed_leaks.append(processed)
    
    return processed_leaks

def display_summary_statistics(results, emails):
    """
    Display summary statistics of breach checks.
    """
    print("\n" + "="*50)
    print("SUMMARY STATISTICS")
    print("="*50)
    
    total_emails = len(emails)
    emails_with_breaches = 0
    total_breaches = 0
    unique_databases = set()
    
    for email, leaks in results.items():
        if leaks and len(leaks) > 0:
            emails_with_breaches += 1
            total_breaches += len(leaks)
            for leak in leaks:
                if isinstance(leak, dict):
                    db_name = leak.get("database_name", "Unknown")
                    unique_databases.add(db_name)
    
    print(f"Total emails checked: {total_emails}")
    print(f"Emails with breaches: {emails_with_breaches} ({emails_with_breaches/total_emails*100:.1f}%)")
    print(f"Emails safe (no breaches): {total_emails - emails_with_breaches}")
    print(f"Total breach instances found: {total_breaches}")
    print(f"Unique databases/breaches identified: {len(unique_databases)}")
    
    if unique_databases:
        print("\nDatabases found:")
        for db in sorted(unique_databases):
            print(f"  • {db}")

# ==============================
# HUNTER API
# ==============================

class HunterAPI:
    def __init__(self, api_key):
        if not api_key:
            raise ValueError("Hunter API key missing")
        self.api_key = api_key

    def domain_search(self, domain):
        url = f"{HUNTER_BASE_URL}/domain-search"
        params = {
            "domain": domain,
            "api_key": self.api_key
        }
        try:
            r = requests.get(url, params=params, timeout=15)
            r.raise_for_status()
            return r.json()
        except requests.exceptions.RequestException as e:
            print(f"[-] Hunter.io API error: {e}")
            return {"data": {"emails": []}}

# ==============================
# MAIN PIPELINE
# ==============================

def main():
    print("\n" + "="*60)
    print("HUNTER.IO → LEAK-LOOKUP BREACH CHECKER")
    print("="*60)
    
    domain = input("\nEnter target domain: ").strip()
    if not domain:
        print("[-] No domain provided. Exiting.")
        return
    
    safe_domain = make_safe_domain(domain)
    
    # Initialize Hunter API
    hunter = HunterAPI(HUNTER_API_KEY)
    
    # Step 1: Get emails from Hunter.io
    print(f"\n[1] Searching for emails on domain: {domain}")
    try:
        hunter_result = hunter.domain_search(domain)
    except Exception as e:
        print(f"[-] Failed to query Hunter.io: {e}")
        print("[*] Trying to load from existing file...")
        hunter_file = f"hunter_output_{safe_domain}.json"
        if os.path.exists(hunter_file):
            with open(hunter_file, "r", encoding="utf-8") as f:
                hunter_result = json.load(f)
        else:
            print("[-] No existing data found. Exiting.")
            return
    
    # Save Hunter.io results
    hunter_file = f"hunter_output_{safe_domain}.json"
    save_json(hunter_result, hunter_file)
    print(f"[+] Hunter.io results saved to: {hunter_file}")
    
    # Extract emails
    emails = extract_emails(hunter_result)
    print(f"[+] Extracted {len(emails)} email(s)")
    
    if not emails:
        print("[-] No emails found. Exiting.")
        return
    
    # Save email list
    email_file = f"email_list_{safe_domain}.json"
    save_json(emails, email_file)
    print(f"[+] Email list saved to: {email_file}")
    
    # Step 2: Check each email against Leak-Lookup
    print(f"\n[2] Checking {len(emails)} email(s) against Leak-Lookup...")
    print("-" * 60)
    
    breach_results = {
        "domain": domain,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "hunter_source": hunter_file,
        "checked_emails": len(emails),
        "results": {}
    }
    
    table_data = []
    checked_count = 0
    
    for idx, email in enumerate(emails, 1):
        checked_count += 1
        print(f"[{idx}/{len(emails)}] Checking: {email}")
        
        leaks = check_email_leak_lookup(email)
        
        if leaks is None:
            status = "Error - API request failed"
            breach_results["results"][email] = []
        else:
            # Parse the leaks
            parsed_leaks = parse_leak_lookup_response(leaks)
            breach_results["results"][email] = parsed_leaks
            
            # Format for table display
            status = format_leaks_for_table(parsed_leaks)
            
            # Print summary
            if parsed_leaks:
                print(f"   Found in {len(parsed_leaks)} breach(es)")
            else:
                print(f"   No breaches found")
        
        table_data.append([email, status])
        
        # Rate limiting to avoid API throttling
        if idx < len(emails):
            time.sleep(1)  # Adjust as needed
    
    # Step 3: Save all results
    print(f"\n[3] Saving results...")
    breach_file = f"leaklookup_results_{safe_domain}.json"
    save_json(breach_results, breach_file)
    print(f"[+] All results saved to: {breach_file}")
    
    # Step 4: Display results
    print("\n" + "="*60)
    print("BREACH CHECK RESULTS")
    print("="*60)
    
    # Display table
    print(tabulate(table_data, headers=["Email", "Breach Details"], tablefmt="grid"))
    
    # Display summary
    display_summary_statistics(breach_results["results"], emails)
    
    # Step 5: Export options
    print("\n" + "="*60)
    print("EXPORT OPTIONS")
    print("="*60)
    print(f"1. Hunter.io results: {hunter_file}")
    print(f"2. Email list: {email_file}")
    print(f"3. Complete breach results: {breach_file}")
    
    # Create a simple CSV summary
    csv_file = f"breach_summary_{safe_domain}.csv"
    with open(csv_file, "w", encoding="utf-8") as f:
        f.write("Email,Breaches Found,Database Count\n")
        for email, leaks in breach_results["results"].items():
            breach_count = len(leaks) if leaks else 0
            databases = set()
            if leaks:
                for leak in leaks:
                    if isinstance(leak, dict) and "database_name" in leak:
                        databases.add(leak["database_name"])
            f.write(f"{email},{breach_count},{len(databases)}\n")
    print(f"4. CSV summary: {csv_file}")
    
    print("\n[✓] Scan completed successfully!")

if __name__ == "__main__":
    main()