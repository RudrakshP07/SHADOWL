"""
Cloud Bucket Scanner - Data Wrapper
Returns structured data for main orchestrator
"""

import requests
import re

def find_buckets(text):
    """Extract bucket names from text"""
    
    patterns = [
        r'([a-z0-9\.-]+)\.s3\.amazonaws\.com',
        r'([a-z0-9\.-]+)\.storage\.googleapis\.com',
        r'([a-z0-9\.-]+)\.blob\.core\.windows\.net'
    ]
    
    buckets = set()
    for pattern in patterns:
        matches = re.findall(pattern, text.lower())
        buckets.update(matches)
    
    return list(buckets)

def check_bucket(bucket_name):
    """Check if bucket is accessible"""
    
    test_urls = [
        (f"https://{bucket_name}.s3.amazonaws.com", 'AWS S3'),
        (f"https://{bucket_name}.storage.googleapis.com", 'Google Cloud'),
        (f"https://{bucket_name}.blob.core.windows.net", 'Azure Blob')
    ]
    
    for url, provider in test_urls:
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                return {
                    'status': 'public',
                    'accessible': True,
                    'provider': provider,
                    'url': url,
                    'risk': 'high'
                }
            elif r.status_code == 403:
                return {
                    'status': 'private',
                    'accessible': False,
                    'provider': provider,
                    'url': url,
                    'risk': 'low'
                }
        except:
            continue
    
    return {
        'status': 'not_found',
        'accessible': False,
        'provider': 'unknown',
        'url': None,
        'risk': 'none'
    }

def scan_for_buckets_data(domain):
    """
    Scan domain for cloud storage buckets and return structured data
    
    Args:
        domain (str): Target domain
    
    Returns:
        dict: Found cloud buckets with accessibility status
    """
    result = {
        'domain': domain,
        'buckets_found': [],
        'public_buckets': [],
        'private_buckets': [],
        'statistics': {
            'total_buckets': 0,
            'public_count': 0,
            'private_count': 0,
            'not_found_count': 0
        },
        'high_risk_buckets': [],
        'success': False
    }
    
    try:
        # Clean domain
        domain = domain.strip().lower()
        domain = domain.replace('http://', '').replace('https://', '')
        domain = domain.split('/')[0]
        
        result['domain'] = domain
        
        # Get webpage content
        print(f"  → Scanning for cloud storage buckets...")
        try:
            response = requests.get(f"https://{domain}", timeout=10)
            content = response.text
        except:
            # Try HTTP if HTTPS fails
            try:
                response = requests.get(f"http://{domain}", timeout=10)
                content = response.text
            except:
                result['error'] = 'Could not fetch domain content'
                print(f"  ✗ Could not access domain")
                return result
        
        # Find potential buckets
        potential_buckets = find_buckets(content)
        
        if not potential_buckets:
            result['warning'] = 'No cloud buckets found in page content'
            result['success'] = True
            print(f"  ✓ No cloud buckets detected")
            return result
        
        print(f"  ✓ Found {len(potential_buckets)} potential bucket(s)")
        
        # Check each bucket
        for bucket in potential_buckets:
            bucket_info = check_bucket(bucket)
            bucket_data = {
                'name': bucket,
                **bucket_info
            }
            
            result['buckets_found'].append(bucket_data)
            
            if bucket_info['status'] == 'public':
                result['public_buckets'].append(bucket_data)
                result['high_risk_buckets'].append({
                    'name': bucket,
                    'url': bucket_info['url'],
                    'provider': bucket_info['provider'],
                    'message': 'Publicly accessible bucket detected!'
                })
            elif bucket_info['status'] == 'private':
                result['private_buckets'].append(bucket_data)
        
        # Calculate statistics
        result['statistics']['total_buckets'] = len(potential_buckets)
        result['statistics']['public_count'] = len(result['public_buckets'])
        result['statistics']['private_count'] = len(result['private_buckets'])
        result['statistics']['not_found_count'] = (
            result['statistics']['total_buckets'] - 
            result['statistics']['public_count'] - 
            result['statistics']['private_count']
        )
        
        result['success'] = True
        
        print(f"  ✓ Public buckets: {result['statistics']['public_count']}")
        print(f"  ✓ Private buckets: {result['statistics']['private_count']}")
        
        if result['statistics']['public_count'] > 0:
            print(f"  ⚠ WARNING: {result['statistics']['public_count']} public bucket(s) found!")
        
    except Exception as e:
        result['error'] = str(e)
        result['success'] = False
        print(f"  ✗ Error: {e}")
    
    return result