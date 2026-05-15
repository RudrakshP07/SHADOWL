"""
Optimized Wayback Machine URL Hunter - Ultra-Fast Version
Generates iframe URLs instead of processing during scan
Zero API calls during CLI execution = Instant results
"""


def wayback_recon(domain):
    """
    Ultra-fast Wayback Machine reconnaissance
    No API calls - just generates URLs for iframe embedding
    
    Args:
        domain: Target domain (will be cleaned automatically)
    
    Returns:
        dict: Contains status and CDX URLs for iframe embedding
    """
    
    print(f"\n🔍 Wayback Machine Recon for: {domain}")
    print("=" * 70)
    
    # Clean domain
    domain = domain.strip().lower()
    domain = domain.replace('http://', '').replace('https://', '')
    domain = domain.replace('www.', '')
    domain = domain.split('/')[0]
    
    # Generate CDX API URLs - these will be embedded in iframe
    cdx_text_url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey"
    cdx_json_url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original,timestamp&collapse=urlkey&limit=10000"
    calendar_url = f"https://web.archive.org/web/*/{domain}"
    
    print("\n✅ Wayback Machine URLs Generated (Instant!)")
    print("-" * 70)
    print(f"📊 Text Format URL:  {cdx_text_url[:80]}...")
    print(f"📊 JSON Format URL:  {cdx_json_url[:80]}...")
    print(f"📅 Calendar View:    {calendar_url}")
    print("\n💡 TIP: All archived URLs will be viewable in the HTML report")
    print("💡 The report embeds these URLs in an interactive iframe")
    print("=" * 70)
    
    # Return data structure for the report
    return {
        'status': 'completed',
        'mode': 'fast_iframe',
        'domain': domain,
        'cdx_text_url': cdx_text_url,
        'cdx_json_url': cdx_json_url,
        'calendar_url': calendar_url,
        'output': f"""
🕰️ WAYBACK MACHINE RECONNAISSANCE
{'=' * 70}

Target Domain: {domain}
Mode: Fast (iframe-based)

📊 Generated URLs:
   • Text Format: {cdx_text_url}
   • JSON Format: {cdx_json_url}
   • Calendar View: {calendar_url}

✅ Status: URLs generated successfully
💡 View archived URLs in the HTML report's interactive iframe

{'=' * 70}
""",
        'message': f'Wayback Machine URLs generated for {domain}. View in HTML report.'
    }


# Example standalone usage
if __name__ == "__main__":
    print("=" * 70)
    print("  🕐 Wayback Machine URL Hunter (Ultra-Fast)")
    print("  No API calls during scan = Instant results!")
    print("=" * 70)
    
    domain = input("\nEnter domain (e.g., tesla.com): ").strip()
    
    if not domain:
        print("❌ Please enter a valid domain")
    else:
        result = wayback_recon(domain)
        
        print("\n" + "=" * 70)
        print("✅ Wayback scan completed instantly!")
        print(f"📊 View full results in HTML report")
        print("=" * 70)
        
        # Display the CDX URL for manual testing
        print(f"\n🔗 Test URL (opens in browser):")
        print(f"   {result['cdx_text_url']}")