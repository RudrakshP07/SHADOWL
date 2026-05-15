"""
Enhanced DNS Reconnaissance Tool
Creates beautiful standalone HTML reports like dnsdumpster
"""

import dns.resolver
import socket
import json
import math
import os
import html
from datetime import datetime


# DNS record types to query
DNS_TYPES = ["A", "AAAA", "MX", "NS", "CNAME", "TXT", "SOA"]


def dns_lookup(domain, create_report=True, verbose=True):
    """
    Main DNS lookup function
    
    Args:
        domain: Target domain to query
        create_report: If True, creates standalone report.html
        verbose: If True, print detailed progress to stdout
    
    Returns:
        dict: DNS data structure
    """
    
    if verbose:
        print(f"\n🌐 DNS RECONNAISSANCE")
        print("=" * 70)
        print(f"Target: {domain}\n")
    
    # Initialize resolver with public DNS servers
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["8.8.8.8", "1.1.1.1", "8.8.4.4"]
    resolver.timeout = 8
    resolver.lifetime = 8
    
    dns_data = {}
    
    # Query each DNS record type
    for rtype in DNS_TYPES:
        if verbose:
            print(f"[*] Querying {rtype} records...", end=" ")
        try:
            answers = resolver.resolve(domain, rtype)
            
            if rtype == "MX":
                dns_data[rtype] = [
                    {"preference": r.preference, "exchange": str(r.exchange).rstrip(".")}
                    for r in answers
                ]
                if verbose:
                    print(f"✅ Found {len(dns_data[rtype])} records")
                
            elif rtype == "SOA":
                for r in answers:
                    dns_data[rtype] = {
                        "mname": str(r.mname).rstrip("."),
                        "rname": str(r.rname).rstrip("."),
                        "serial": r.serial,
                        "refresh": r.refresh,
                        "retry": r.retry,
                        "expire": r.expire,
                        "minimum": r.minimum
                    }
                if verbose:
                    print("✅ Found SOA record")
                
            elif rtype == "TXT":
                dns_data[rtype] = [str(r).strip('"') for r in answers]
                if verbose:
                    print(f"✅ Found {len(dns_data[rtype])} records")
                
            else:
                dns_data[rtype] = [str(r).rstrip(".") for r in answers]
                if verbose:
                    print(f"✅ Found {len(dns_data[rtype])} records")
                
        except dns.resolver.NoAnswer:
            dns_data[rtype] = []
            if verbose:
                print("⚠️  No records found")
        except dns.resolver.NXDOMAIN:
            dns_data[rtype] = []
            if verbose:
                print("❌ Domain does not exist")
        except dns.resolver.Timeout:
            dns_data[rtype] = []
            if verbose:
                print("⏱️  Query timeout")
        except Exception as e:
            dns_data[rtype] = []
            if verbose:
                print(f"❌ Error: {str(e)[:30]}")
    
    # Display results (only if verbose)
    if verbose:
        display_dns_results(domain, dns_data)
    
    # Create target-domain folder and save reports (HTML + JSON)
    report_filename = None
    json_file = None
    if create_report:
        folder_name = f"{domain}"
        if not os.path.exists(folder_name):
            os.makedirs(folder_name)
            print(f"\n📁 Created folder: {folder_name}/")

        # HTML report inside domain folder
        report_filename = os.path.join(folder_name, f"{domain}_dns_report.html")
        generate_html_report(domain, dns_data, report_filename)
        print(f"\n✅ HTML report created: {report_filename}")
        print(f"💡 Open {report_filename} in your browser to view the visual map")

        # Email auth checks (SPF / DMARC / DKIM)
        dns_data['spf'] = parse_spf(dns_data.get('TXT'))
        dns_data['dmarc'] = check_dmarc(domain)
        dns_data['dkim'] = check_dkim(domain)

        # Also save structured JSON results (similar to certsh.py logic)
        json_data = {
            "metadata": {
                "target_domain": domain,
                "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "tool": "DNS Reconnaissance",
                "version": "2.0"
            },
            "statistics": {
                "total_records": sum([len(v) if isinstance(v, list) else (0 if v==[] else 1) for v in dns_data.values()])
            },
            "dns_data": dns_data,
            "text_output": format_dns_output(domain, dns_data)
        }

        json_file = os.path.join(folder_name, f"{domain}_dns.json")
        with open(json_file, 'w', encoding='utf-8') as jf:
            json.dump(json_data, jf, indent=2, default=str)

        print(f"✅ JSON results saved to: {json_file}")
        try:
            print(f"   • File size: {os.path.getsize(json_file) / 1024:.2f} KB")
        except Exception:
            pass
    
    # Return structured data for main.py integration
    result = {
        "status": "completed",
        "domain": domain,
        "dns_data": dns_data,
        "output": format_dns_output(domain, dns_data),
        "has_visualization": True
    }

    if create_report:
        result.update({
            "report_file": report_filename,
            "json_file": json_file
        })

    return result


def display_dns_results(domain, dns_data):
    """Display DNS results in CLI"""
    
    print(f"\n📊 DNS RECORDS FOR {domain.upper()}")
    print("=" * 70)
    
    # A Records
    if dns_data.get("A"):
        print(f"\n🔸 A RECORDS (IPv4)")
        print("-" * 70)
        for ip in dns_data["A"]:
            print(f"  • {ip}")
    
    # AAAA Records
    if dns_data.get("AAAA"):
        print(f"\n🔸 AAAA RECORDS (IPv6)")
        print("-" * 70)
        for ip in dns_data["AAAA"]:
            print(f"  • {ip}")
    
    # MX Records
    if dns_data.get("MX"):
        print(f"\n📧 MX RECORDS (Mail Servers)")
        print("-" * 70)
        for mx in sorted(dns_data["MX"], key=lambda x: x["preference"]):
            print(f"  • Priority {mx['preference']:2d}: {mx['exchange']}")
    
    # NS Records
    if dns_data.get("NS"):
        print(f"\n🌐 NS RECORDS (Name Servers)")
        print("-" * 70)
        for ns in dns_data["NS"]:
            print(f"  • {ns}")
    
    # CNAME Records
    if dns_data.get("CNAME"):
        print(f"\n🔗 CNAME RECORDS (Aliases)")
        print("-" * 70)
        for cname in dns_data["CNAME"]:
            print(f"  • {cname}")
    
    # TXT Records
    if dns_data.get("TXT"):
        print(f"\n📝 TXT RECORDS")
        print("-" * 70)
        for txt in dns_data["TXT"][:5]:
            display_txt = txt[:80] + "..." if len(txt) > 80 else txt
            print(f"  • {display_txt}")
    
    print("\n" + "=" * 70)


def format_dns_output(domain, dns_data):
    """Format DNS data as text output for reports"""
    
    output = f"""
🌐 DNS RECONNAISSANCE RESULTS
{'=' * 70}

Target Domain: {domain}
Query Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

"""
    
    if dns_data.get("A"):
        output += f"\n🔸 A RECORDS (IPv4): {len(dns_data['A'])} found\n"
        output += "-" * 70 + "\n"
        for ip in dns_data["A"]:
            output += f"  • {ip}\n"
    
    if dns_data.get("MX"):
        output += f"\n📧 MX RECORDS: {len(dns_data['MX'])} found\n"
        output += "-" * 70 + "\n"
        for mx in sorted(dns_data["MX"], key=lambda x: x["preference"]):
            output += f"  • Priority {mx['preference']:2d}: {mx['exchange']}\n"
    
    if dns_data.get("NS"):
        output += f"\n🌐 NS RECORDS: {len(dns_data['NS'])} found\n"
        output += "-" * 70 + "\n"
        for ns in dns_data["NS"]:
            output += f"  • {ns}\n"
    
    # Email authentication summaries
    spf = dns_data.get('spf')
    if spf:
        output += f"\n✉️  SPF: {spf}\n"

    dmarc = dns_data.get('dmarc')
    if dmarc:
        output += f"\n✉️  DMARC: {dmarc.get('record','') or dmarc.get('policy','')}\n"

    dkim = dns_data.get('dkim') or []
    if dkim:
        selectors = ', '.join([s.get('selector') for s in dkim])
        output += f"\n✉️  DKIM selectors found: {selectors}\n"

    output += "\n" + "=" * 70 + "\n"
    return output


# ==========================================================
# Email authentication helpers: SPF / DMARC / DKIM
# ==========================================================

def parse_spf(txt_records):
    """Return first SPF string found in TXT records or None"""
    for txt in txt_records or []:
        if isinstance(txt, str) and txt.strip().lower().startswith('v=spf1'):
            return txt.strip()
    return None


def check_dmarc(domain):
    """Query _dmarc.domain TXT record and return parsed policy or None"""
    try:
        txts = [r.to_text().strip('"') for r in dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')]
        for t in txts:
            if t.lower().startswith('v=dmarc1'):
                # quick parse for policy
                parts = [p.strip() for p in t.split(';')]
                policy = None
                rua = None
                for part in parts:
                    if part.startswith('p='):
                        policy = part.split('=',1)[1]
                    if part.startswith('rua='):
                        rua = part.split('=',1)[1]
                return {'record': t, 'policy': policy, 'rua': rua}
    except Exception:
        return None


def check_dkim(domain, selectors=None):
    """Attempt to resolve common DKIM selectors for domain. Returns list of dicts found."""
    found = []
    if selectors is None:
        selectors = ['default','selector1','google','mail','smtp']

    for sel in selectors:
        name = f"{sel}._domainkey.{domain}"
        try:
            txts = [r.to_text().strip('"') for r in dns.resolver.resolve(name, 'TXT')]
            for t in txts:
                if t.lower().startswith('v=dkim1'):
                    found.append({'selector': sel, 'record': t, 'name': name})
        except Exception:
            continue
    return found


def generate_svg_diagram(domain, dns_data):
    """Generate SVG diagram like dnsdumpster"""
    
    # Collect all records
    all_records = []
    
    if dns_data.get("A"):
        for ip in dns_data["A"][:8]:
            all_records.append({'type': 'A', 'label': ip, 'color': '#4CAF50', 'icon': '🌐'})
    
    if dns_data.get("AAAA"):
        for ip in dns_data["AAAA"][:4]:
            display_ip = ip[:25] + "..." if len(ip) > 25 else ip
            all_records.append({'type': 'AAAA', 'label': display_ip, 'color': '#2196F3', 'icon': '🌍'})
    
    if dns_data.get("MX"):
        for mx in sorted(dns_data["MX"], key=lambda x: x["preference"])[:6]:
            mx_label = f"[{mx['preference']}] {mx['exchange']}"
            if len(mx_label) > 30:
                mx_label = mx_label[:27] + "..."
            all_records.append({'type': 'MX', 'label': mx_label, 'color': '#FF9800', 'icon': '📧'})
    
    if dns_data.get("NS"):
        for ns in dns_data["NS"][:8]:
            ns_label = ns[:30] + "..." if len(ns) > 30 else ns
            all_records.append({'type': 'NS', 'label': ns_label, 'color': '#9C27B0', 'icon': '🔧'})
    
    if dns_data.get("CNAME"):
        for cname in dns_data["CNAME"][:4]:
            cname_label = cname[:30] + "..." if len(cname) > 30 else cname
            all_records.append({'type': 'CNAME', 'label': cname_label, 'color': '#00BCD4', 'icon': '🔗'})
    
    num_records = len(all_records)
    if num_records == 0:
        return '<div style="padding:40px; text-align:center; color:#999;">No DNS records to visualize</div>'
    
    # Dynamic sizing
    svg_height = max(600, min(1200, 400 + (num_records * 60)))
    center_x = 500
    center_y = svg_height // 2
    radius = min(350, center_y - 100)
    
    svg = f'''<svg width="100%" height="{svg_height}" viewBox="0 0 1000 {svg_height}">
        <!-- Background grid -->
        <defs>
            <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
                <path d="M 40 0 L 0 0 0 40" fill="none" stroke="#f0f0f0" stroke-width="0.5"/>
            </pattern>
        </defs>
        <rect width="100%" height="100%" fill="url(#grid)"/>
        
        <!-- Radial guides -->
        <circle cx="{center_x}" cy="{center_y}" r="{radius}" 
                fill="none" stroke="#e0e0e0" stroke-width="1" stroke-dasharray="10,5"/>
        <circle cx="{center_x}" cy="{center_y}" r="{radius * 0.5}" 
                fill="none" stroke="#f0f0f0" stroke-width="1" stroke-dasharray="5,5"/>
        
        <!-- Central domain node -->
        <defs>
            <filter id="shadow">
                <feDropShadow dx="2" dy="2" stdDeviation="3" flood-opacity="0.3"/>
            </filter>
        </defs>
        
        <ellipse cx="{center_x}" cy="{center_y}" rx="150" ry="75" 
                 fill="#667eea" stroke="#5568d3" stroke-width="4" filter="url(#shadow)"/>
        <text x="{center_x}" y="{center_y - 10}" text-anchor="middle" 
              fill="white" font-size="22" font-weight="bold">{domain}</text>
        <text x="{center_x}" y="{center_y + 15}" text-anchor="middle" 
              fill="white" font-size="14" opacity="0.9">{num_records} DNS Records</text>
'''
    
    # Calculate positions in circular layout
    angle_step = 360 / num_records if num_records > 0 else 0
    
    for i, record in enumerate(all_records):
        angle_rad = math.radians(i * angle_step - 90)
        x = center_x + radius * math.cos(angle_rad)
        y = center_y + radius * math.sin(angle_rad)
        
        # Connection line with gradient
        svg += f'''
        <line x1="{center_x}" y1="{center_y}" x2="{x}" y2="{y}" 
              stroke="{record["color"]}" stroke-width="2.5" opacity="0.5" stroke-linecap="round"/>
'''
        
        node_width = min(240, max(180, len(record['label']) * 7 + 60))
        node_height = 50
        
        svg += f'''
        <!-- Node {i+1}: {record['type']} -->
        <rect x="{x - node_width//2}" y="{y - node_height//2}" 
              width="{node_width}" height="{node_height}" rx="10" 
              fill="{record["color"]}" stroke="#333" stroke-width="2.5" filter="url(#shadow)"/>
        
        <text x="{x - node_width//2 + 20}" y="{y + 7}" 
              font-size="22">{record["icon"]}</text>
        
        <text x="{x}" y="{y + 6}" text-anchor="middle" 
              fill="white" font-size="13" font-weight="600">{record["label"]}</text>
'''
    
    # Legend with better styling
    legend_items = []
    seen_types = set()
    type_info = {
        'A': ('🌐', 'A Record (IPv4)', '#4CAF50'),
        'AAAA': ('🌍', 'AAAA (IPv6)', '#2196F3'),
        'MX': ('📧', 'MX (Mail)', '#FF9800'),
        'NS': ('🔧', 'NS (Nameserver)', '#9C27B0'),
        'CNAME': ('🔗', 'CNAME (Alias)', '#00BCD4')
    }
    
    for record in all_records:
        if record['type'] not in seen_types:
            seen_types.add(record['type'])
            legend_items.append(type_info[record['type']])
    
    legend_height = 50 + len(legend_items) * 35
    
    svg += f'''
    <!-- Legend -->
    <g transform="translate(30, 30)">
        <rect x="0" y="0" width="220" height="{legend_height}" 
              fill="white" stroke="#333" stroke-width="2.5" rx="12" filter="url(#shadow)" opacity="0.95"/>
        <text x="110" y="28" text-anchor="middle" 
              font-size="18" font-weight="bold" fill="#333">Record Types</text>
        <line x1="20" y1="35" x2="200" y2="35" stroke="#ddd" stroke-width="1"/>
'''
    
    legend_y = 55
    for icon, label, color in legend_items:
        svg += f'''
        <rect x="15" y="{legend_y - 14}" width="40" height="26" rx="6" fill="{color}"/>
        <text x="25" y="{legend_y + 5}" font-size="18">{icon}</text>
        <text x="65" y="{legend_y + 5}" font-size="14" fill="#333" font-weight="500">{label}</text>
'''
        legend_y += 35
    
    svg += '''
    </g>
    
    <!-- Branding -->
    <text x="970" y="{}" text-anchor="end" fill="#999" font-size="12" font-family="monospace">
        DNS Recon Framework v2.0
    </text>
</svg>'''.format(svg_height - 20)
    
    return svg


def generate_html_report(domain, dns_data, filename):
    """Generate standalone HTML report like dnsdumpster"""
    
    svg_diagram = generate_svg_diagram(domain, dns_data)
    
    # Count records
    total_records = sum([
        len(dns_data.get('A', [])),
        len(dns_data.get('AAAA', [])),
        len(dns_data.get('MX', [])),
        len(dns_data.get('NS', [])),
        len(dns_data.get('CNAME', [])),
    ])
    
    html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DNS Report - {domain}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #FFFFFF;
            padding: 20px;
            min-height: 100vh;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        
        .header {{
            background: #1D1A1B;
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.8em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }}
        
        .header .domain {{
            font-size: 1.8em;
            opacity: 0.95;
            font-weight: 300;
            margin: 10px 0;
        }}
        
        .header .timestamp {{
            opacity: 0.85;
            font-size: 0.95em;
            margin-top: 15px;
        }}
        
        .stats-bar {{
            display: flex;
            justify-content: space-around;
            padding: 30px 20px;
            background: #f8f9fa;
            border-bottom: 3px solid #e0e0e0;
            flex-wrap: wrap;
            gap: 15px;
        }}
        
        .stat-box {{
            background: white;
            padding: 20px 30px;
            border-radius: 12px;
            text-align: center;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            min-width: 140px;
            transition: transform 0.2s;
        }}
        
        .stat-box:hover {{
            transform: translateY(-5px);
            box-shadow: 0 8px 20px rgba(0,0,0,0.15);
        }}
        
        .stat-box .number {{
            font-size: 2.5em;
            font-weight: bold;
            color: #F21F42;
            display: block;
        }}
        
        .stat-box .label {{
            color: #666;
            font-size: 0.95em;
            margin-top: 8px;
            display: block;
        }}
        
        .diagram-section {{
            padding: 40px;
            background: white;
        }}
        
        .diagram-section h2 {{
            color: #333;
            font-size: 2em;
            margin-bottom: 25px;
            text-align: center;
        }}
        
        .diagram-container {{
            background: #fafafa;
            padding: 30px;
            border-radius: 12px;
            border: 2px solid #e0e0e0;
            margin-bottom: 40px;
        }}
        
        .records-section {{
            padding: 40px;
            background: #f8f9fa;
        }}
        
        .record-table {{
            background: white;
            border-radius: 12px;
            overflow: hidden;
            margin-bottom: 30px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }}
        
        .record-table h3 {{
            background: #1D1A1B;
            color: white;
            padding: 20px;
            font-size: 1.4em;
        }}
        
        .record-table table {{
            width: 100%;
            border-collapse: collapse;
        }}
        
        .record-table th {{
            background: #f0f0f0;
            padding: 15px;
            text-align: left;
            font-weight: 600;
            color: #333;
            border-bottom: 2px solid #ddd;
        }}
        
        .record-table td {{
            padding: 15px;
            border-bottom: 1px solid #eee;
            color: #555;
        }}
        
        .record-table tr:hover {{
            background: #f8f9fa;
        }}
        
        .footer {{
            background: #1D1A1B;
            color: white;
            padding: 25px;
            text-align: center;
        }}
        
        .footer a {{
            color: #F21F42;
            text-decoration: none;
        }}
        
        @media print {{
            body {{
                background: white;
                padding: 0;
            }}
            
            .container {{
                box-shadow: none;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🌐 DNS Infrastructure Report</h1>
            <div class="domain">{domain}</div>
            <div class="timestamp">Generated: {datetime.now().strftime('%B %d, %Y at %H:%M:%S')}</div>
        </div>
        
        <div class="stats-bar">
            <div class="stat-box">
                <span class="number">{total_records}</span>
                <span class="label">Total Records</span>
            </div>
            <div class="stat-box">
                <span class="number">{len(dns_data.get('A', []))}</span>
                <span class="label">🌐 A Records</span>
            </div>
            <div class="stat-box">
                <span class="number">{len(dns_data.get('AAAA', []))}</span>
                <span class="label">🌍 AAAA Records</span>
            </div>
            <div class="stat-box">
                <span class="number">{len(dns_data.get('MX', []))}</span>
                <span class="label">📧 MX Records</span>
            </div>
            <div class="stat-box">
                <span class="number">{len(dns_data.get('NS', []))}</span>
                <span class="label">🔧 NS Records</span>
            </div>
            <div class="stat-box">
                <span class="number">{len(dns_data.get('CNAME', []))}</span>
                <span class="label">🔗 CNAME Records</span>
            </div>
        </div>
        
        <div class="diagram-section">
            <h2>📊 DNS Infrastructure Map</h2>
            <div class="diagram-container">
                {svg_diagram}
            </div>
        </div>
        
        <div class="records-section">
            <h2 style="text-align:center; margin-bottom:30px; color:#333;">📋 Detailed Records</h2>
'''
    
    # A Records Table
    if dns_data.get('A'):
        html_content += '''
            <div class="record-table">
                <h3>🌐 A Records (IPv4 Addresses)</h3>
                <table>
                    <tr>
                        <th>IP Address</th>
                        <th>Type</th>
                    </tr>
'''
        for ip in dns_data['A']:
            html_content += f'''
                    <tr>
                        <td><code>{ip}</code></td>
                        <td>IPv4</td>
                    </tr>
'''
        html_content += '''
                </table>
            </div>
'''
    
    # MX Records Table
    if dns_data.get('MX'):
        html_content += '''
            <div class="record-table">
                <h3>📧 MX Records (Mail Servers)</h3>
                <table>
                    <tr>
                        <th>Priority</th>
                        <th>Mail Server</th>
                    </tr>
'''
        for mx in sorted(dns_data['MX'], key=lambda x: x['preference']):
            html_content += f'''
                    <tr>
                        <td><strong>{mx['preference']}</strong></td>
                        <td><code>{mx['exchange']}</code></td>
                    </tr>
'''
        html_content += '''
                </table>
            </div>
'''
    
    # NS Records Table
    if dns_data.get('NS'):
        html_content += '''
            <div class="record-table">
                <h3>🔧 NS Records (Name Servers)</h3>
                <table>
                    <tr>
                        <th>Name Server</th>
                    </tr>
'''
        for ns in dns_data['NS']:
            html_content += f'''
                    <tr>
                        <td><code>{ns}</code></td>
                    </tr>
'''
        html_content += '''
                </table>
            </div>
'''
    
    # CNAME Records Table
    if dns_data.get('CNAME'):
        html_content += '''
            <div class="record-table">
                <h3>🔗 CNAME Records (Aliases)</h3>
                <table>
                    <tr>
                        <th>Canonical Name</th>
                    </tr>
'''
        for cname in dns_data['CNAME']:
            html_content += f'''
                    <tr>
                        <td><code>{cname}</code></td>
                    </tr>
'''
        html_content += '''
                </table>
            </div>
'''
    
    # TXT Records Table
    if dns_data.get('TXT'):
        html_content += '''
            <div class="record-table">
                <h3>📝 TXT Records</h3>
                <table>
                    <tr>
                        <th>Text Record</th>
                    </tr>
'''
        for txt in dns_data['TXT']:
            html_content += f'''
                    <tr>
                        <td><code style="word-break:break-all;">{txt[:200]}</code></td>
                    </tr>
'''
        html_content += '''
                </table>
            </div>
'''

    # Email authentication: SPF / DMARC / DKIM
    spf = dns_data.get('spf')
    dmarc = dns_data.get('dmarc')
    dkim = dns_data.get('dkim') or []

    if spf or dmarc or dkim:
        html_content += '''
            <div class="record-table">
                <h3>✉️ Email Authentication</h3>
                <table>
                    <tr>
                        <th>Mechanism</th>
                        <th>Value</th>
                    </tr>
'''
        # SPF
        if spf:
            display_spf = spf if len(spf) < 220 else spf[:217] + "..."
            html_content += f"\n                    <tr>\n                        <td><strong>SPF</strong></td>\n                        <td><code style=\"word-break:break-all;\">{display_spf}</code></td>\n                    </tr>\n"
        else:
            html_content += "\n                    <tr><td><strong>SPF</strong></td><td><em>Not found</em></td></tr>\n"

        # DMARC
        if dmarc:
            policy = dmarc.get('policy') or 'n/a'
            record = dmarc.get('record') or ''
            display_dmarc = record if len(record) < 220 else record[:217] + '...'
            html_content += f"\n                    <tr>\n                        <td><strong>DMARC</strong></td>\n                        <td><code style=\"word-break:break-all;\">Policy: {policy} | {display_dmarc}</code></td>\n                    </tr>\n"
        else:
            html_content += "\n                    <tr><td><strong>DMARC</strong></td><td><em>Not found</em></td></tr>\n"

        # DKIM
        if dkim:
            names = ', '.join([html.escape(d.get('selector') or d.get('name','')) for d in dkim])
            html_content += f"\n                    <tr>\n                        <td><strong>DKIM</strong></td>\n                        <td><code style=\"word-break:break-all;\">Selectors: {names}</code></td>\n                    </tr>\n"
        else:
            html_content += "\n                    <tr><td><strong>DKIM</strong></td><td><em>Not found</em></td></tr>\n"

        html_content += '''
                </table>
            </div>
'''
    
    html_content += f'''
        </div>
        
        <div class="footer">
            <p>DNS Reconnaissance Framework v2.0</p>
            <p style="margin-top:10px; font-size:0.9em; opacity:0.8;">
                Report for: {domain}
            </p>
        </div>
    </div>
</body>
</html>'''
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html_content)


def generate_dns_visualization_html(domain, dns_data):
    """
    For main.py integration - returns just the diagram HTML
    """
    return generate_svg_diagram(domain, dns_data)


# Standalone execution
if __name__ == "__main__":
    print("=" * 70)
    print("  🌐 DNS RECONNAISSANCE TOOL")
    print("=" * 70)
    
    domain = input("\nEnter domain (e.g., example.com): ").strip().lower()
    
    if not domain:
        print("❌ No domain entered")
        exit(1)
    
    result = dns_lookup(domain, create_report=True)
    
    print("\n" + "=" * 70)
    print("✅ DNS reconnaissance completed!")
    print("=" * 70)