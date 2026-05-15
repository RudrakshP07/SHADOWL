"""
Enhanced Google Dorking Tool - Windows PowerShell Compatible
Advanced dork collection for comprehensive reconnaissance
"""

import requests
import time

# Hardcoded Google Custom Search credentials (provided by user)
GOOGLE_API_KEY = ""  # Google API Key
SEARCH_ENGINE_ID = ""  # Search Engine ID (CSE ID)

# Comprehensive Google dork templates
DORK_CATEGORIES = {
    'Publicly Exposed Documents': [
        'site:{domain} ext:doc OR ext:docx OR ext:odt',
        'site:{domain} ext:rtf OR ext:pdf',
        'site:{domain} ext:ppt OR ext:pptx OR ext:pps',
        'site:{domain} ext:csv OR ext:xlsx',
    ],
    'Directory Listing Vulnerability': [
        'site:{domain} intitle:"index of"',
        'site:{domain} intitle:"index of /" "parent directory"',
        'site:{domain} inurl:upload intitle:"index of"',
    ],
    'Configuration Files': [
        'site:{domain} ext:xml OR ext:conf OR ext:cnf',
        'site:{domain} ext:reg OR ext:inf OR ext:rdp',
        'site:{domain} ext:cfg OR ext:txt OR ext:ini',
        'site:{domain} ext:env OR ext:ora',
    ],
    'Database Files': [
        'site:{domain} ext:sql',
        'site:{domain} ext:dbf OR ext:mdb',
        'site:{domain} ext:sqlite OR ext:db',
    ],
    'Log Files': [
        'site:{domain} ext:log',
        'site:{domain} inurl:log OR inurl:logs',
        'site:{domain} "access log" OR "error log"',
    ],
    'Backup and Old Files': [
        'site:{domain} ext:bkf OR ext:bkp OR ext:bak',
        'site:{domain} ext:old OR ext:backup',
        'site:{domain} inurl:backup OR inurl:old',
    ],
    'Login Pages': [
        'site:{domain} inurl:login',
        'site:{domain} inurl:signin OR inurl:auth',
        'site:{domain} intitle:"login" OR intitle:"sign in"',
        'site:{domain} inurl:admin/login',
    ],
    'SQL Errors': [
        'site:{domain} "SQL syntax error"',
        'site:{domain} "MySQL error" OR "PostgreSQL error"',
        'site:{domain} "PHP Parse error" OR "PHP Warning"',
        'site:{domain} "Microsoft OLE DB Provider"',
    ],
    'PHP Info': [
        'site:{domain} ext:php intitle:phpinfo',
        'site:{domain} "phpinfo()" OR "PHP Version"',
    ],
    'Sensitive Keywords': [
        'site:{domain} intext:"password"',
        'site:{domain} intext:"api_key" OR intext:"apikey"',
        'site:{domain} intext:"secret" OR intext:"token"',
        'site:{domain} "confidential" OR "internal use only"',
        'site:{domain} "DB_PASSWORD" OR "DATABASE_PASSWORD"',
    ],
    'Admin Panels': [
        'site:{domain} inurl:admin',
        'site:{domain} inurl:administrator',
        'site:{domain} inurl:dashboard',
        'site:{domain} intitle:"admin panel"',
        'site:{domain} inurl:wp-admin',
    ],
    'Signup Pages': [
        'site:{domain} inurl:signup',
        'site:{domain} inurl:register',
        'site:{domain} intitle:"signup" OR intitle:"register"',
    ],
    'API Endpoints': [
        'site:{domain} inurl:api',
        'site:{domain} inurl:swagger',
        'site:{domain} inurl:graphql OR inurl:graphiql',
        'site:{domain} inurl:/api/v1 OR inurl:/api/v2',
    ],
    'Development/Testing': [
        'site:{domain} inurl:test',
        'site:{domain} inurl:dev OR inurl:development',
        'site:{domain} inurl:staging',
        'site:{domain} inurl:debug',
    ],
    'File Upload Forms': [
        'site:{domain} inurl:upload',
        'site:{domain} intitle:"upload" OR "file upload"',
    ],
    'Git Exposed': [
        'site:{domain} inurl:.git',
        'site:{domain} intitle:"index of" .git',
    ],
    'Server Info': [
        'site:{domain} inurl:server-status',
        'site:{domain} inurl:server-info',
        'site:{domain} intitle:"Apache Status"',
    ],
    'Robots & Sitemaps': [
        'site:{domain} inurl:robots.txt',
        'site:{domain} inurl:sitemap.xml',
    ],
}

# External site dorks (search for domain mentions on other platforms)
EXTERNAL_DORKS = {
    'Pastebin & Paste Sites': [
        'site:pastebin.com "{domain}"',
        'site:paste2.org "{domain}"',
        'site:pastehtml.com "{domain}"',
        'site:hastebin.com "{domain}"',
        'site:dpaste.org "{domain}"',
        'site:codepad.org "{domain}"',
        'site:justpaste.it "{domain}"',
    ],
    'Code Repositories': [
        'site:github.com "{domain}"',
        'site:gitlab.com "{domain}"',
        'site:bitbucket.org "{domain}"',
    ],
    'Code Sharing': [
        'site:codepen.io "{domain}"',
        'site:jsfiddle.net "{domain}"',
        'site:repl.it "{domain}"',
        'site:ideone.com "{domain}"',
        'site:jsitor.com "{domain}"',
    ],
    'Q&A Sites': [
        'site:stackoverflow.com "{domain}"',
        'site:serverfault.com "{domain}"',
        'site:stackexchange.com "{domain}"',
    ],
    'Documentation Sites': [
        'site:trello.com "{domain}"',
        'site:atlassian.net "{domain}"',
    ],
}

# Subdomain discovery dorks
SUBDOMAIN_DORKS = [
    'site:*.{domain}',
    'site:*.*.{domain}',
]

def google_search(query, api_key, search_engine_id):
    """Perform Google Custom Search"""
    
    url = "https://www.googleapis.com/customsearch/v1"
    params = {
        'key': api_key,
        'cx': search_engine_id,
        'q': query,
        'num': 10
    }
    
    try:
        response = requests.get(url, params=params, timeout=15)
        
        if response.status_code == 429:
            print("⚠️  Rate limited - waiting 60 seconds...")
            time.sleep(60)
            return []
        
        if response.status_code == 400:
            print(f"❌ Bad Request - Invalid API key or Search Engine ID")
            return []
        
        if response.status_code == 403:
            print(f"❌ Access Denied - Check your API key and billing")
            return []
        
        if response.status_code != 200:
            print(f"❌ HTTP {response.status_code} error")
            return []
        
        data = response.json()
        items = data.get('items', [])
        
        return [item['link'] for item in items]
    
    except requests.exceptions.Timeout:
        print("❌ Request timeout")
        return []
    except requests.exceptions.RequestException as e:
        print(f"❌ Request error: {str(e)}")
        return []
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return []

def run_dorks(domain, api_key, search_engine_id, include_external=False):
    """Run all dorks for a domain"""
    
    print(f"\n🔎 Google Dorking: {domain}")
    print("=" * 70)
    
    # Check if API credentials are provided
    if not api_key or not search_engine_id:
        print("\n❌ Error: Google API key or Search Engine ID not provided")
        print("\n💡 Setup instructions:")
        print("1. Get API key: https://console.developers.google.com/")
        print("2. Create Custom Search Engine: https://cse.google.com/")
        print("3. Enable 'Search the entire web' in CSE settings")
        print("4. Add credentials to token.txt file")
        print("\n⚠️  Skipping Google Dorking scan...\n")
        return {
            'status': 'skipped',
            'message': 'Google API credentials not configured',
            'total_links': 0
        }
    
    all_results = {}
    total_links = 0
    
    # Run main domain dorks
    print("\n🎯 SCANNING TARGET DOMAIN")
    print("=" * 70)
    
    for category, dorks in DORK_CATEGORIES.items():
        print(f"\n📂 {category}")
        print("-" * 70)
        
        category_results = []
        
        for dork in dorks:
            query = dork.format(domain=domain)
            print(f"  Searching: {query[:60]}...")
            
            links = google_search(query, api_key, search_engine_id)
            
            if links:
                category_results.extend(links)
                print(f"  ✅ Found {len(links)} results")
            else:
                print(f"  ❌ No results")
            
            time.sleep(1)  # Rate limit protection
        
        category_results = list(set(category_results))
        all_results[category] = category_results
        total_links += len(category_results)
        
        if category_results:
            print(f"  📊 Total: {len(category_results)} unique results")
    
    # Run external site dorks
    if include_external:
        print("\n🌍 SCANNING EXTERNAL SITES")
        print("=" * 70)
        
        for category, dorks in EXTERNAL_DORKS.items():
            print(f"\n📂 {category}")
            print("-" * 70)
            
            category_results = []
            
            for dork in dorks:
                query = dork.format(domain=domain)
                print(f"  Searching: {query[:60]}...")
                
                links = google_search(query, api_key, search_engine_id)
                
                if links:
                    category_results.extend(links)
                    print(f"  ✅ Found {len(links)} results")
                else:
                    print(f"  ❌ No results")
                
                time.sleep(1)
            
            category_results = list(set(category_results))
            all_results[category] = category_results
            total_links += len(category_results)
            
            if category_results:
                print(f"  📊 Total: {len(category_results)} unique results")
    
    # Subdomain discovery
    print("\n🔎 SUBDOMAIN DISCOVERY")
    print("=" * 70)
    subdomain_results = []
    
    for dork in SUBDOMAIN_DORKS:
        query = dork.format(domain=domain)
        print(f"  Searching: {query}")
        
        links = google_search(query, api_key, search_engine_id)
        
        if links:
            subdomain_results.extend(links)
            print(f"  ✅ Found {len(links)} results")
        else:
            print(f"  ❌ No results")
        
        time.sleep(1)
    
    subdomain_results = list(set(subdomain_results))
    all_results['Subdomains'] = subdomain_results
    total_links += len(subdomain_results)
    
    # Display summary
    print("\n" + "=" * 70)
    print("📊 SUMMARY")
    print("=" * 70)
    print(f"Total unique links found: {total_links}")
    
    # Show high-risk categories first
    high_risk = ['SQL Errors', 'Database Files', 'Configuration Files', 
                 'Backup and Old Files', 'Login Pages', 'PHP Info']
    
    print("\n🚨 HIGH RISK FINDINGS:")
    print("-" * 70)
    found_high_risk = False
    for category in high_risk:
        if category in all_results and all_results[category]:
            found_high_risk = True
            print(f"\n{category}: {len(all_results[category])} results")
            for link in all_results[category][:3]:
                print(f"  • {link}")
            if len(all_results[category]) > 3:
                print(f"  ... and {len(all_results[category]) - 3} more")
    
    if not found_high_risk:
        print("  ✅ No high-risk exposures found")
    
    print("\n\n📋 ALL CATEGORIES:")
    print("-" * 70)
    for category, results in all_results.items():
        if results:
            print(f"{category}: {len(results)} results")
    
    print("\n" + "=" * 70)
    
    return {
        'status': 'completed',
        'results': all_results,
        'total_links': total_links
    }

def manual_search(domain=None):
    """Generate manual Google dork URLs"""
    
    print("\n🔎 Manual Google Dork Generator")
    print("=" * 70)
    
    if not domain:
        domain = input("\nEnter target domain (e.g., example.com): ").strip()
    
    if not domain:
        print("❌ Domain required!")
        return
    
    print(f"\n🎯 Top 20 Dorks for: {domain}")
    print("=" * 70)
    
    manual_dorks = [
        f'site:{domain} ext:sql OR ext:db',
        f'site:{domain} ext:env OR ext:ini',
        f'site:{domain} intext:"password"',
        f'site:{domain} intitle:"index of"',
        f'site:{domain} ext:log',
        f'site:{domain} ext:bak OR ext:backup',
        f'site:{domain} inurl:admin',
        f'site:{domain} "SQL syntax"',
        f'site:{domain} ext:php intitle:phpinfo',
        f'site:{domain} inurl:.git',
        f'site:{domain} inurl:login',
        f'site:{domain} ext:xml OR ext:conf',
        f'site:{domain} "confidential"',
        f'site:{domain} inurl:api',
        f'site:{domain} inurl:upload',
        f'site:github.com "{domain}"',
        f'site:pastebin.com "{domain}"',
        f'site:*.{domain}',
        f'site:{domain} inurl:robots.txt',
        f'site:{domain} inurl:swagger',
    ]
    
    for i, dork in enumerate(manual_dorks, 1):
        google_url = f"https://www.google.com/search?q={dork.replace(' ', '+')}"
        print(f"\n{i}. {dork}")
        print(f"   🔗 {google_url}")
    
    print("\n💡 Tip: Use these URLs in an incognito browser window")
    print("💡 You can also use DuckDuckGo by replacing google.com with duckduckgo.com")

def show_dork_library():
    """Display all available dorks"""
    
    print("\n📚 COMPLETE DORK LIBRARY")
    print("=" * 70)
    
    print("\n🎯 TARGET DOMAIN DORKS:")
    for category, dorks in DORK_CATEGORIES.items():
        print(f"\n{category}:")
        for dork in dorks:
            print(f"  • {dork}")
    
    print("\n\n🌍 EXTERNAL SITE DORKS:")
    for category, dorks in EXTERNAL_DORKS.items():
        print(f"\n{category}:")
        for dork in dorks:
            print(f"  • {dork}")
    
    print("\n\n🔎 SUBDOMAIN DISCOVERY:")
    for dork in SUBDOMAIN_DORKS:
        print(f"  • {dork}")

def main():
    """Main function"""
    
    print("=" * 70)
    print("  🔎 Enhanced Google Dorking Tool")
    print("  📊 70+ Advanced Dorks for Comprehensive Recon")
    print("=" * 70)
    
    print("\n[1] Automated Full Scan (requires Google API)")
    print("[2] Automated Domain Only (no external sites)")
    print("[3] Manual Dork URLs (no API needed)")
    print("[4] Show Complete Dork Library")
    print("[5] Exit")
    
    choice = input("\nSelect option (1-5): ").strip()
    
    if choice in ['1', '2']:
        domain = input("\nEnter target domain (e.g., example.com): ").strip()
        if not domain:
            print("❌ Domain required!")
            return
        
        print("\n💡 Using hardcoded Google Custom Search credentials.")
        print(f"   API key: {GOOGLE_API_KEY[:8]}... (hidden)")
        print(f"   Search Engine ID: {SEARCH_ENGINE_ID}")
        api_key = GOOGLE_API_KEY
        search_engine_id = SEARCH_ENGINE_ID
        include_external = (choice == '1')
        run_dorks(domain, api_key, search_engine_id, include_external)
    
    elif choice == '3':
        manual_search()
    
    elif choice == '4':
        show_dork_library()
    
    elif choice == '5':
        print("\n👋 Goodbye!")
    
    else:
        print("\n❌ Invalid choice!")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Interrupted by user. Goodbye!")
    except Exception as e:
        print(f"\n❌ Unexpected error: {str(e)}")