"""
Simple Security Headers Checker
Now accepts domain input (e.g., example.com) and auto-adds https://
"""

import requests

# Important security headers to check
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]

def check_headers(url):
    """Check security headers for a given URL and return structured results"""
    
    # Auto-add https:// if not present
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        headers = response.headers

        print(f"\n🔒 Security Headers Check for: {url}")
        print("=" * 60)

        found = 0
        missing = 0
        headers_list = []

        for header in SECURITY_HEADERS:
            if header in headers:
                value = headers[header]
                print(f"✅ {header}: {value[:150]}{'...' if len(value)>150 else ''}")
                headers_list.append({"header": header, "present": True, "value": value})
                found += 1
            else:
                print(f"❌ {header}: Missing")
                headers_list.append({"header": header, "present": False, "value": None})
                missing += 1

        print("=" * 60)
        score = round((found/len(SECURITY_HEADERS))*100)
        print(f"Found: {found}/{len(SECURITY_HEADERS)} headers")
        print(f"Score: {score}%")

        return {
            "status": "completed",
            "url": url,
            "found": found,
            "missing": missing,
            "headers": headers_list,
            "score": score,
            "output": ''
        }

    except requests.exceptions.RequestException as e:
        msg = str(e)
        print(f"❌ Error: Could not connect to {url}")
        print(f"   Reason: {msg}")
        return {"status": "error", "url": url, "error": msg, "headers": [], "output": f"Error: {msg}"}

# Example usage
if __name__ == "__main__":
    # Now accepts domain input without https://
    target = input("Enter target domain (e.g., example.com): ").strip()
    
    if target:
        check_headers(target)
    else:
        print("❌ Please enter a valid domain")