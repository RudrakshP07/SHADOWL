"""
Simple Technology Fingerprinting Tool
Detects web technologies passively (like Wappalyzer)
"""

import requests
import re

# Technology signatures
TECH_SIGNATURES = {
    'CMS': {
        'WordPress': [r'/wp-content/', r'/wp-includes/', r'wp-json'],
        'Joomla': [r'/components/com_', r'Joomla!'],
        'Drupal': [r'Drupal\.settings', r'/sites/default/'],
        'Magento': [r'/skin/frontend/', r'Mage\.Cookies'],
        'Shopify': [r'cdn\.shopify\.com'],
    },
    'Frameworks': {
        'React': [r'react', r'data-reactroot', r'__react'],
        'Vue.js': [r'vue\.js', r'v-if', r'v-for'],
        'Angular': [r'ng-app', r'ng-controller', r'angular\.js'],
        'Next.js': [r'__NEXT_DATA__', r'_next/static'],
        'Django': [r'csrfmiddlewaretoken'],
        'Laravel': [r'laravel_session'],
    },
    'Analytics': {
        'Google Analytics': [r'google-analytics\.com', r'gtag\.js'],
        'Google Tag Manager': [r'googletagmanager\.com/gtm'],
        'Hotjar': [r'hotjar\.com'],
    },
    'CDN': {
        'Cloudflare': [r'cloudflare'],
        'Amazon CloudFront': [r'cloudfront\.net'],
        'Akamai': [r'akamai'],
    }
}

def detect_from_headers(headers):
    """Detect technologies from HTTP headers"""
    found = []
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
    
    # Web Server
    if 'server' in headers_lower:
        server = headers_lower['server']
        found.append(('Server', server.split('/')[0].title()))
    
    # Programming Language
    if 'x-powered-by' in headers_lower:
        found.append(('Language', headers_lower['x-powered-by']))
    
    # CDN Detection
    if 'cf-ray' in headers_lower:
        found.append(('CDN', 'Cloudflare'))
    if 'x-amz-cf-id' in headers_lower:
        found.append(('CDN', 'Amazon CloudFront'))
    
    return found

def detect_from_content(html):
    """Detect technologies from HTML content"""
    found = []
    html_lower = html.lower()
    
    for category, techs in TECH_SIGNATURES.items():
        for tech_name, patterns in techs.items():
            for pattern in patterns:
                if re.search(pattern, html_lower):
                    found.append((category, tech_name))
                    break  # Found this tech, move to next
    
    return found

def fingerprint_site(url):
    """Main fingerprinting function

    Returns a structured dict with detected technologies and HTTP status code.
    """
    original = url
    try:
        # Add https:// if not present
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        # Make request
        response = requests.get(url, timeout=15, allow_redirects=True)

        status_code = response.status_code

        # Detect from headers and content
        header_techs = detect_from_headers(response.headers)
        content_techs = detect_from_content(response.text)

        # Combine and organize by category
        categories = {}
        for category, tech in list(set(header_techs + content_techs)):
            categories.setdefault(category, set()).add(tech)

        # Convert sets to sorted lists
        tech_map = {cat: sorted(list(v)) for cat, v in categories.items()}

        # Build a short summary string
        total = sum(len(v) for v in tech_map.values())
        summary = f"Detected {total} technology item(s) (HTTP {status_code})"

        # Return structured data
        return {
            'status_code': status_code,
            'technologies': tech_map,
            'summary': summary,
            'target': original
        }

    except requests.exceptions.RequestException as e:
        return {'error': f'Could not connect: {str(e)}', 'target': original}
    except Exception as e:
        return {'error': str(e), 'target': original}

# Example usage
if __name__ == "__main__":
    # Change this to any website you want to fingerprint
    target = input("Enter target URL (e.g., example.com): ").strip()
    
    if target:
        fingerprint_site(target)
    else:
        print("❌ Please enter a valid URL")