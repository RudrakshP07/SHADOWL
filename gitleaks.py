"""
Enhanced GitHub Secrets Leak Hunter - Windows PowerShell Compatible
Searches for exposed credentials, API keys, and sensitive data
"""

import requests
import re
import json
from datetime import datetime
import time


# Secret patterns to detect
SECRET_PATTERNS = {
    'AWS Access Key': r'AKIA[0-9A-Z]{16}',
    'AWS Secret Key': r'aws_secret_access_key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9/+=]{40})',
    'GitHub Token': r'(ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,}',
    'API Key': r'[aA][pP][iI][_-]?[kK][eE][yY]["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{32,})["\']',
    'Private Key': r'-----BEGIN [A-Z ]+ PRIVATE KEY-----',
    'Password': r'[pP][aA][sS][sS][wW][oO][rR][dD]["\']?\s*[:=]\s*["\']([^"\']{8,})["\']',
    'Secret Key': r'[sS][eE][cC][rR][eE][tT][_-]?[kK][eE][yY]["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{20,})',
    'Database URL': r'(mongodb|mysql|postgres)://[^"\s]+',
    'JWT Token': r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
    'Slack Token': r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}',
}


def search_repositories(domain, github_token=None):
    """Search GitHub repositories mentioning the domain"""
    
    headers = {
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'GitHub-Recon-Tool/1.0'
    }
    
    if github_token:
        headers['Authorization'] = f'token {github_token}'
    
    queries = [
        f'{domain}',
        f'{domain} password',
        f'{domain} api',
        f'{domain} credentials',
    ]
    
    all_repos = []
    
    for query in queries:
        try:
            url = 'https://api.github.com/search/repositories'
            params = {
                'q': query,
                'per_page': 10,
                'sort': 'stars'
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=15)
            
            if response.status_code == 403:
                print("⚠️  Rate limited by GitHub API")
                time.sleep(2)
                break
            
            if response.status_code == 401:
                print("❌ Invalid GitHub token")
                break
            
            if response.status_code != 200:
                continue
            
            data = response.json()
            
            for repo in data.get('items', [])[:5]:
                repo_info = {
                    'name': repo['full_name'],
                    'url': repo['html_url'],
                    'description': repo.get('description', 'No description'),
                    'stars': repo['stargazers_count'],
                    'language': repo.get('language', 'Unknown'),
                    'updated': repo['updated_at']
                }
                
                if repo_info not in all_repos:
                    all_repos.append(repo_info)
            
            time.sleep(1)  # Rate limiting
        
        except requests.exceptions.Timeout:
            print(f"⚠️  Timeout for query: {query}")
            continue
        except Exception as e:
            print(f"⚠️  Error searching repositories: {str(e)}")
            continue
    
    return all_repos


def search_code_secrets(domain, github_token=None):
    """Search for potential secrets in code"""
    
    headers = {
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'GitHub-Recon-Tool/1.0'
    }
    
    if github_token:
        headers['Authorization'] = f'token {github_token}'
    
    search_terms = [
        f'{domain} password',
        f'{domain} api_key',
        f'{domain} secret',
        f'{domain} token',
        f'{domain} credentials',
        f'{domain} DB_PASSWORD',
    ]
    
    findings = []
    
    for term in search_terms:
        try:
            url = 'https://api.github.com/search/code'
            params = {
                'q': term,
                'per_page': 10
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=15)
            
            if response.status_code == 403:
                print("⚠️  Rate limited on code search")
                time.sleep(2)
                break
            
            if response.status_code == 401:
                print("❌ Invalid GitHub token")
                break
            
            if response.status_code != 200:
                continue
            
            data = response.json()
            
            for item in data.get('items', [])[:5]:
                finding = {
                    'repo': item['repository']['full_name'],
                    'file': item['name'],
                    'path': item['path'],
                    'url': item['html_url'],
                    'search_term': term
                }
                
                findings.append(finding)
            
            time.sleep(1)  # Rate limiting
        
        except requests.exceptions.Timeout:
            print(f"⚠️  Timeout for search term: {term}")
            continue
        except Exception as e:
            print(f"⚠️  Error searching code: {str(e)}")
            continue
    
    return findings


def analyze_secrets(findings):
    """Analyze findings for known secret patterns"""
    
    high_risk = []
    medium_risk = []
    low_risk = []
    
    for finding in findings:
        risk_level = 'low'
        matched_patterns = []
        
        # Check file extension
        file_lower = finding['file'].lower()
        path_lower = finding['path'].lower()
        
        # High risk files
        if any(ext in file_lower for ext in ['.env', '.config', '.yml', '.yaml', '.json', '.ini']):
            risk_level = 'high'
        
        # Keywords indicating secrets
        if any(word in path_lower for word in ['secret', 'password', 'credential', 'api_key', 'token', 'config']):
            if risk_level == 'low':
                risk_level = 'medium'
        
        # Check against secret patterns
        search_term = finding.get('search_term', '').lower()
        for pattern_name, pattern in SECRET_PATTERNS.items():
            if any(word in search_term for word in pattern_name.lower().split()):
                matched_patterns.append(pattern_name)
                if risk_level == 'low':
                    risk_level = 'medium'
        
        finding['risk_level'] = risk_level
        finding['matched_patterns'] = matched_patterns
        
        if risk_level == 'high':
            high_risk.append(finding)
        elif risk_level == 'medium':
            medium_risk.append(finding)
        else:
            low_risk.append(finding)
    
    return {
        'high_risk': high_risk,
        'medium_risk': medium_risk,
        'low_risk': low_risk
    }


def github_recon(domain, github_token=None):
    """Main GitHub reconnaissance function - compatible with orchestrator"""
    
    print(f"\n📦 GitHub Secrets Hunter: {domain}")
    print("=" * 70)
    
    if not github_token:
        print("⚠️  Running without GitHub token (limited to 60 requests/hour)")
        print("💡 Add github_Token to token.txt for better results")
    else:
        print("✅ Using authenticated API (higher rate limits)")
    
    try:
        print("\n[*] Searching repositories...")
        
        # Search repositories
        repos = search_repositories(domain, github_token)
        
        if repos:
            print(f"[+] Found {len(repos)} repositories\n")
            
            print("📦 REPOSITORIES")
            print("-" * 70)
            for repo in repos[:10]:
                print(f"\n  • {repo['name']}")
                print(f"    ⭐ {repo['stars']} stars | Language: {repo['language']}")
                print(f"    🔗 {repo['url']}")
                if repo['description'] != 'No description':
                    desc = repo['description'][:60]
                    print(f"    📝 {desc}...")
        else:
            print("❌ No repositories found")
        
        # Search for secrets in code
        print("\n[*] Hunting for exposed secrets...")
        
        findings = search_code_secrets(domain, github_token)
        
        analyzed = None
        
        if findings:
            print(f"[+] Found {len(findings)} potential exposures\n")
            
            # Analyze risk levels
            analyzed = analyze_secrets(findings)
            
            # Display high risk findings
            if analyzed['high_risk']:
                print("🚨 HIGH RISK FINDINGS")
                print("-" * 70)
                for finding in analyzed['high_risk'][:10]:
                    print(f"\n  ⚠️  {finding['repo']}")
                    print(f"     File: {finding['path']}")
                    patterns = ', '.join(finding['matched_patterns']) if finding['matched_patterns'] else 'credential exposure'
                    print(f"     Risk: Potential {patterns}")
                    print(f"     URL: {finding['url']}")
            
            # Display medium risk
            if analyzed['medium_risk']:
                print("\n⚠️  MEDIUM RISK FINDINGS")
                print("-" * 70)
                for finding in analyzed['medium_risk'][:5]:
                    print(f"  • {finding['repo']} - {finding['file']}")
            
            # Summary
            print("\n📊 SUMMARY")
            print("-" * 70)
            print(f"🚨 High Risk:   {len(analyzed['high_risk'])}")
            print(f"⚠️  Medium Risk: {len(analyzed['medium_risk'])}")
            print(f"ℹ️  Low Risk:    {len(analyzed['low_risk'])}")
            
        else:
            print("✅ No obvious secrets found in public code")
        
        # Security recommendations
        print("\n🔐 SECURITY RECOMMENDATIONS")
        print("-" * 70)
        print("✅ Review all findings manually - automated scans can have false positives")
        print("✅ Use .gitignore to exclude sensitive files (.env, config files)")
        print("✅ Rotate any exposed credentials immediately")
        print("✅ Enable GitHub secret scanning alerts")
        print("✅ Use environment variables instead of hardcoded secrets")
        
        print("\n" + "=" * 70)
        
        return {
            'status': 'completed',
            'repositories': repos,
            'findings': findings,
            'analysis': analyzed,
            'total_repos': len(repos),
            'total_findings': len(findings),
            'high_risk_count': len(analyzed['high_risk']) if analyzed else 0
        }
    
    except requests.exceptions.RequestException as e:
        print(f"\n❌ Network error: {str(e)}")
        return {
            'status': 'error',
            'message': f'Network error: {str(e)}'
        }
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        return {
            'status': 'error',
            'message': str(e)
        }


# Example usage for standalone execution
if __name__ == "__main__":
    print("=" * 70)
    print("  🔍 GitHub Secrets Leak Hunter")
    print("=" * 70)
    
    domain = input("\nEnter domain/organization name (e.g., example.com): ").strip()
    
    if not domain:
        print("❌ Please enter a valid domain")
        exit()
    
    # Optional: GitHub token for higher rate limits
    print("\nOptional: Enter GitHub Personal Access Token (or press Enter to skip)")
    print("Get token from: https://github.com/settings/tokens")
    github_token = input("Token: ").strip() or None
    
    # Run reconnaissance
    result = github_recon(domain, github_token)
    
    print(f"\n✅ Scan completed with status: {result['status']}")