"""
Passive Reconnaissance Framework – Main Orchestrator (v4)
Author: Rudra Potghan
Enhanced: Claude (Anthropic)

Changes in v4:
  * Full CLI with argparse (run / configure / status sub-commands)
  * API-key wizard runs automatically on first launch (platform-independent)
  * HTML report: dark-navy + electric-blue palette, much more readable
  * All original scan logic preserved exactly
"""

import sys
import json
import html
import io
import os
import argparse
import platform
from datetime import datetime
from contextlib import redirect_stdout
from pathlib import Path

# ── Config manager ─────────────────────────────────────────────────────────────
from config_manager import configure_keys, show_key_status, get_key

# ── Tool imports ───────────────────────────────────────────────────────────────
from dns_tool           import dns_lookup
from whois              import whois_lookup
from certsh             import find_certificates
from wayback            import wayback_recon
from dork               import run_dorks
from gitleaks           import github_recon
from cloud_buckets      import scan_for_buckets_data
from tech_fingerprinter import fingerprint_site
from security_headers   import check_headers
from virustotal         import scan_url

from hunter_breachcheck import (
    HunterAPI, extract_emails, make_safe_domain,
    check_email_leak_lookup,
    save_json as hunter_save_json,
    parse_leak_lookup_response,
)
from shodan_scanner import (
    is_ip          as sh_is_ip,
    resolve_domain as sh_resolve_domain,
    save_json      as sh_save_json,
    display_summary as sh_display_summary,
)

# ─────────────────────────────────────────────
#  Cross-platform colour helpers
# ─────────────────────────────────────────────
def _supports_color():
    if platform.system() == "Windows":
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleMode(       # type: ignore
                ctypes.windll.kernel32.GetStdHandle(-11), 7)   # type: ignore
            return True
        except Exception:
            return False
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

USE_COLOR = _supports_color()

def _c(t, code): return f"\033[{code}m{t}\033[0m" if USE_COLOR else t
def red(t):    return _c(t, "91")
def green(t):  return _c(t, "92")
def yellow(t): return _c(t, "93")
def cyan(t):   return _c(t, "96")
def bold(t):   return _c(t, "1")
def dim(t):    return _c(t, "2")

# ─────────────────────────────────────────────
#  Utilities
# ─────────────────────────────────────────────
def normalize_domain(domain: str) -> str:
    return domain.replace("http://","").replace("https://","").split("/")[0].lower()

def base_result(tool, domain):
    return {"tool": tool, "domain": domain, "status": "completed",
            "data": {}, "output": "", "meta": {}}

def read_json_file(filepath):
    try:
        if os.path.exists(filepath):
            with open(filepath, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception as e:
        print(f"  {yellow('⚠')} Error reading {filepath}: {e}")
    return None

# ─────────────────────────────────────────────
#  Scan functions  (logic unchanged from v3)
# ─────────────────────────────────────────────
def scan_dns(domain):
    r = base_result("dns", domain)
    try:
        data = dns_lookup(domain, create_report=True, verbose=False)
        r["data"] = data.get("dns_data", {})
        r["meta"]["report_file"] = data.get("report_file", "")
        r["meta"]["json_file"]   = data.get("json_file", "")
        r["output"] = data.get("output", "")
    except Exception as e:
        r["status"] = "error"; r["output"] = str(e)
    return r

def scan_whois(domain):
    r = base_result("whois", domain)
    try:
        whois_lookup(domain)
        folder = Path(domain)
        if folder.exists():
            jfiles = list(folder.glob("whois_*.json"))
            if jfiles:
                latest = max(jfiles, key=lambda p: p.stat().st_mtime)
                wj = read_json_file(latest)
                if wj:
                    import re
                    parsed = wj.get("whois_data", {}) or {}
                    raw    = wj.get("raw_data") or parsed.get("raw_whois","") or ""
                    def _ex(txt, pats):
                        for p in pats:
                            m = re.search(p, txt, re.I)
                            if m: return m.group(1).strip()
                        return None
                    r["data"] = {
                        "domain":          parsed.get("domain") or _ex(raw,[r"Domain Name\s*:\s*(\S+)"]) or domain,
                        "registrar":       parsed.get("registrar") or _ex(raw,[r"Registrar\s*:\s*(.+)"]) or "",
                        "creation_date":   parsed.get("creation_date") or _ex(raw,[r"Creation Date\s*:\s*(.+)"]) or "",
                        "expiration_date": parsed.get("expiration_date") or _ex(raw,[r"Expiry Date\s*:\s*(.+)",r"Expiration Date\s*:\s*(.+)"]) or "",
                        "updated_date":    parsed.get("updated_date") or _ex(raw,[r"Updated Date\s*:\s*(.+)"]) or "",
                        "dnssec":          parsed.get("dnssec") or _ex(raw,[r"DNSSEC\s*:\s*(.+)"]) or "",
                        "name_servers":    parsed.get("name_servers") or re.findall(r"Name Server\s*:\s*(\S+)", raw, re.I) or [],
                        "status":          parsed.get("status",[]),
                        "emails":          parsed.get("emails",[]),
                        "raw_whois":       raw,
                    }
                    r["meta"]["json_file"] = str(latest)
                    r["output"] = "WHOIS data retrieved from JSON file"
    except Exception as e:
        r["status"] = "error"; r["output"] = str(e)
    return r

def scan_certificates(domain):
    r = base_result("certificates", domain)
    try:
        find_certificates(domain)
        jf = Path(domain) / f"{domain}_certsh.json"
        if jf.exists():
            cd = read_json_file(jf)
            if cd:
                r["data"] = cd
                r["meta"]["json_file"] = str(jf)
                r["output"] = f"Found {cd.get('statistics',{}).get('total_subdomains',0)} subdomains"
    except Exception as e:
        r["status"] = "error"; r["output"] = str(e)
    return r

def scan_wayback(domain):
    r = base_result("wayback", domain)
    try:
        data = wayback_recon(domain)
        if isinstance(data, dict):
            r["data"] = data; r["output"] = data.get("output","")
    except Exception as e:
        r["status"] = "error"; r["output"] = str(e)
    return r

def scan_google_dorks(domain):
    r = base_result("google_dorks", domain)
    try:
        data = run_dorks(domain, get_key("google_api_key"), get_key("google_cse_id"), include_external=False)
        r["data"] = data
    except Exception as e:
        r["status"] = "error"; r["output"] = str(e)
    return r

def scan_github(domain):
    r = base_result("github", domain)
    try:
        r["data"] = github_recon(domain, get_key("github_token"))
    except Exception as e:
        r["status"] = "error"; r["output"] = str(e)
    return r

def scan_hunter(domain):
    r = base_result("hunter_breach", domain)
    try:
        hunter = HunterAPI(get_key("hunter_api_key"))
        hdata  = hunter.domain_search(domain)
        emails = extract_emails(hdata)
        print(f"  → Found {len(emails)} email(s)")
        breaches = {}
        for em in emails:
            print(f"  → Checking {em} for breaches…")
            leaks = check_email_leak_lookup(em)
            breaches[em] = parse_leak_lookup_response(leaks) if leaks else []
        r["data"] = {"emails": emails, "breach_results": breaches,
                     "total_emails": len(emails),
                     "emails_with_breaches": len([e for e,b in breaches.items() if b])}
        hunter_save_json(hdata, f"hunter_{make_safe_domain(domain)}.json")
        r["output"] = f"Found {len(emails)} emails"
    except Exception as e:
        r["status"] = "error"; r["output"] = str(e)
        print(f"  {red('✗')} Hunter error: {e}")
    return r

def scan_shodan(domain):
    r = base_result("shodan", domain)
    try:
        import shodan as _shodan
        api = _shodan.Shodan(get_key("shodan_api_key"))
        ip  = domain if sh_is_ip(domain) else sh_resolve_domain(domain)
        if not ip:
            r["status"] = "error"; r["output"] = "Could not resolve domain to IP"; return r
        host = api.host(ip)
        buf  = io.StringIO()
        with redirect_stdout(buf): sh_display_summary(host)
        r["data"] = host; r["output"] = buf.getvalue()
        sh_save_json(host, domain)
    except Exception as e:
        r["status"] = "error"; r["output"] = str(e)
    return r

def scan_cloud(domain):
    r = base_result("cloud_buckets", domain)
    try:
        r["data"] = scan_for_buckets_data(domain)
        r["output"] = "Scanned for cloud storage buckets"
    except Exception as e:
        r["status"] = "error"; r["output"] = str(e)
    return r

def scan_tech(domain):
    r = base_result("technologies", domain)
    try:
        data = fingerprint_site(domain)
        if isinstance(data, dict) and not data.get("error"):
            r["data"] = data; r["output"] = data.get("summary","")
        else:
            r["status"] = "error"
            r["output"] = (data.get("error","Fingerprinting failed") if isinstance(data,dict) else str(data))
    except Exception as e:
        r["status"] = "error"; r["output"] = str(e)
    return r

def scan_headers(domain):
    r = base_result("security_headers", domain)
    try:
        data = check_headers(domain)
        if isinstance(data, dict):
            r["data"] = data; r["output"] = f"Score: {data.get('score',0)}%"
    except Exception as e:
        r["status"] = "error"; r["output"] = str(e)
    return r

def scan_virustotal(domain):
    r = base_result("virustotal", domain)
    try:
        r["data"] = scan_url(domain, get_key("virustotal_api_key"))
    except Exception as e:
        r["status"] = "error"; r["output"] = str(e)
    return r

# ─────────────────────────────────────────────
#  HTML Report  (dark-navy / electric-blue)
# ─────────────────────────────────────────────
P = {
    "bg":       "#0D1117", "surface":  "#161B22", "surface2": "#1C2230",
    "border":   "#30363D", "accent":   "#58A6FF", "accent_d": "#1F6FEB",
    "text":     "#E6EDF3", "muted":    "#8B949E",
    "green":    "#3FB950", "yellow":   "#D29922", "red":      "#F85149",
}

def generate_html_report(orc) -> str:
    domain  = orc.domain
    results = orc.results
    ts      = datetime.now().strftime("%B %d, %Y at %H:%M:%S")

    def _e(v): return html.escape(str(v)) if v is not None else ""

    css = f"""
* {{margin:0;padding:0;box-sizing:border-box}}
body {{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
       background:{P['bg']};color:{P['text']};line-height:1.6}}
a {{color:{P['accent']};text-decoration:none}} a:hover {{text-decoration:underline}}
.header {{background:linear-gradient(135deg,{P['bg']} 0%,{P['surface']} 100%);
          border-bottom:2px solid {P['accent']};padding:56px 40px;text-align:center}}
.header h1 {{font-size:2.6em;font-weight:700;color:{P['text']}}}
.header h1 span {{color:{P['accent']}}}
.header .domain {{font-size:1.5em;color:{P['accent']};margin:10px 0;font-weight:300}}
.header .ts {{color:{P['muted']};font-size:.88em;margin-top:6px}}
.container {{max-width:1380px;margin:0 auto;padding:36px 20px}}
.tool-section {{background:{P['surface']};border:1px solid {P['border']};
                border-radius:12px;margin-bottom:26px;overflow:hidden;
                transition:box-shadow .25s}}
.tool-section:hover {{box-shadow:0 0 0 2px {P['accent_d']}}}
.tool-header {{background:linear-gradient(90deg,{P['surface2']} 0%,{P['bg']} 100%);
               border-bottom:1px solid {P['border']};padding:18px 26px;
               display:flex;justify-content:space-between;align-items:center;
               font-size:1.18em;font-weight:600;color:{P['accent']}}}
.status-badge {{font-size:.56em;padding:4px 13px;border-radius:20px;
                font-weight:700;text-transform:uppercase;letter-spacing:1px}}
.status-completed {{background:#163221;color:{P['green']};border:1px solid {P['green']}}}
.status-error     {{background:#2D1A1A;color:{P['red']};border:1px solid {P['red']}}}
.tool-content {{padding:26px}}
.data-table {{width:100%;border-collapse:collapse;margin:14px 0;font-size:.92em}}
.data-table th {{background:{P['surface2']};color:{P['accent']};padding:11px 15px;
                 text-align:left;font-weight:600;border-bottom:2px solid {P['border']}}}
.data-table td {{padding:10px 15px;border-bottom:1px solid {P['border']};
                 color:{P['text']};word-break:break-all}}
.data-table tr:hover td {{background:{P['surface2']}}}
.output-box {{background:#0A0E14;color:#A8D8A8;padding:18px;border-radius:8px;
              font-family:'Cascadia Code','Fira Code','Courier New',monospace;
              font-size:.84em;overflow-x:auto;white-space:pre-wrap;
              word-wrap:break-word;margin:14px 0;border:1px solid {P['border']}}}
.stats-grid {{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));
              gap:14px;margin:14px 0}}
.stat-card {{background:linear-gradient(135deg,{P['surface2']} 0%,{P['surface']} 100%);
             border:1px solid {P['accent_d']};border-radius:10px;padding:20px;text-align:center}}
.stat-card .number {{font-size:2em;font-weight:700;color:{P['accent']};display:block;margin-bottom:5px}}
.stat-card .label  {{font-size:.82em;color:{P['muted']}}}
.subdomain-list {{columns:3;column-gap:14px;margin:14px 0}}
.subdomain-item {{background:{P['surface2']};padding:5px 11px;margin:4px 0;border-radius:5px;
                  break-inside:avoid;font-family:'Courier New',monospace;font-size:.82em;
                  color:{P['text']};border-left:3px solid {P['accent_d']}}}
.tech-pill {{display:inline-block;background:{P['accent_d']};color:{P['text']};
             padding:2px 9px;border-radius:20px;font-size:.8em;margin:2px 2px 2px 0}}
.recon-iframe {{width:100%;height:680px;border:1px solid {P['border']};
                border-radius:8px;margin:14px 0;background:{P['bg']}}}
details {{margin-bottom:9px}}
summary {{cursor:pointer;padding:9px 13px;background:{P['surface2']};
          border:1px solid {P['border']};border-radius:6px;color:{P['accent']};
          font-weight:600;user-select:none}}
summary:hover {{background:{P['bg']}}}
.footer {{background:{P['surface']};border-top:1px solid {P['border']};
          text-align:center;padding:34px;margin-top:48px;color:{P['muted']}}}
.dl-btn {{display:inline-block;background:{P['accent_d']};color:{P['text']};
          padding:10px 26px;border-radius:8px;text-decoration:none;margin:7px;
          font-weight:600;transition:background .2s}}
.dl-btn:hover {{background:{P['accent']};color:#000;text-decoration:none}}
@media print {{body{{background:#fff;color:#000}}.tool-section{{box-shadow:none;page-break-inside:avoid}}}}
"""

    doc = [f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Recon Report – {domain}</title>
<style>{css}</style>
</head>
<body>
<div class="header">
  <h1>🔍 <span>Passive Recon</span> Report</h1>
  <div class="domain">{domain}</div>
  <div class="ts">Generated: {ts}</div>
</div>
<div class="container">
"""]

    for result in results:
        tool   = result["tool"]
        name   = tool.replace("_"," ").title()
        status = result.get("status","error")
        data   = result.get("data") or {}

        doc.append(f"""
<div class="tool-section">
  <div class="tool-header">
    <span>{name}</span>
    <span class="status-badge status-{status}">{status}</span>
  </div>
  <div class="tool-content">
""")

        # ── Wayback ───────────────────────────────────────────────────────────
        if tool == "wayback" and data.get("cdx_text_url"):
            doc.append(f'<h3>📊 Archived URLs</h3><iframe class="recon-iframe" src="{_e(data["cdx_text_url"])}"></iframe>')

        # ── DNS ───────────────────────────────────────────────────────────────
        elif tool == "dns" and data:
            rf = result.get("meta",{}).get("report_file","")
            jf = result.get("meta",{}).get("json_file","")
            a,mx,ns,txt = data.get("A",[]) or [],data.get("MX",[]) or [],data.get("NS",[]) or [],data.get("TXT",[]) or []
            doc.append(f"""
<div class="stats-grid">
  <div class="stat-card"><span class="number">{len(a)}</span><span class="label">A Records</span></div>
  <div class="stat-card"><span class="number">{len(mx)}</span><span class="label">MX Records</span></div>
  <div class="stat-card"><span class="number">{len(ns)}</span><span class="label">NS Records</span></div>
  <div class="stat-card"><span class="number">{len(txt)}</span><span class="label">TXT Records</span></div>
</div>
<table class="data-table">
  <tr><th>Type</th><th>Values</th></tr>
  <tr><td>A</td><td>{"<br>".join(a) or "—"}</td></tr>
  <tr><td>AAAA</td><td>{"<br>".join(data.get("AAAA",[]) or []) or "—"}</td></tr>
  <tr><td>MX</td><td>{"<br>".join([f"P{m['preference']}: {m['exchange']}" for m in mx]) or "—"}</td></tr>
  <tr><td>NS</td><td>{"<br>".join(ns) or "—"}</td></tr>
  <tr><td>CNAME</td><td>{"<br>".join(data.get("CNAME",[]) or []) or "—"}</td></tr>
  <tr><td>TXT</td><td>{"<br>".join(txt) or "—"}</td></tr>
</table>
""")
            if rf:
                doc.append(f'<a class="dl-btn" href="{_e(jf)}">⬇ DNS JSON</a>')
                doc.append(f'<iframe class="recon-iframe" src="{_e(rf)}"></iframe>')

        # ── WHOIS ─────────────────────────────────────────────────────────────
        elif tool == "whois" and data:
            ns_list = data.get("name_servers",[]) or []
            raw     = data.get("raw_whois","") or ""
            doc.append(f"""
<table class="data-table">
  <tr><th>Field</th><th>Value</th></tr>
  <tr><td>Domain</td><td>{_e(data.get("domain","N/A"))}</td></tr>
  <tr><td>Registrar</td><td>{_e(data.get("registrar","N/A"))}</td></tr>
  <tr><td>Created</td><td>{_e(data.get("creation_date","N/A"))}</td></tr>
  <tr><td>Expires</td><td>{_e(data.get("expiration_date","N/A"))}</td></tr>
  <tr><td>Updated</td><td>{_e(data.get("updated_date","N/A"))}</td></tr>
  <tr><td>DNSSEC</td><td>{_e(data.get("dnssec","N/A"))}</td></tr>
</table>
<h3 style="margin:14px 0 8px">🖥 Name Servers</h3>
<div class="output-box">{"&#10;".join(ns_list) or "None found"}</div>
<details>
  <summary>Raw WHOIS</summary>
  <div class="output-box" style="margin-top:8px">{_e(raw) or "Not available"}</div>
</details>
""")

        # ── Certificates ──────────────────────────────────────────────────────
        elif tool == "certificates" and data:
            stats  = data.get("statistics",{}) or {}
            subs   = (data.get("subdomains",{}) or {}).get("all",[]) or []
            certs  = data.get("certificates",[]) or []
            jf     = result.get("meta",{}).get("json_file","")
            doc.append(f"""
<div class="stats-grid">
  <div class="stat-card"><span class="number">{stats.get("total_subdomains",0)}</span><span class="label">Subdomains</span></div>
  <div class="stat-card"><span class="number">{stats.get("total_certificates",0)}</span><span class="label">Certificates</span></div>
</div>
<h3 style="margin:14px 0 8px">🌐 Discovered Subdomains</h3>
<div class="subdomain-list">
""")
            for sd in subs[:120]:
                doc.append(f'<div class="subdomain-item">• {_e(sd)}</div>')
            doc.append("</div>")
            if len(subs) > 120:
                doc.append(f'<p style="color:{P["muted"]};margin-top:8px">… and {len(subs)-120} more in JSON</p>')
            if jf:
                doc.append(f'<a class="dl-btn" href="{_e(jf)}" style="margin-top:10px;display:inline-block">⬇ Cert JSON</a>')
            if certs:
                doc.append('<h3 style="margin:14px 0 8px">📜 Certificates</h3>')
                doc.append('<table class="data-table"><tr><th>ID</th><th>Issuer</th><th>Valid Until</th><th>Days Left</th><th>Names</th></tr>')
                for cert in certs:
                    names = ", ".join(cert.get("names",[]))
                    doc.append(f'<tr><td>{cert.get("certificate_id","")}</td><td>{_e(cert.get("issuer",""))}</td><td>{_e(cert.get("not_after",""))}</td><td>{cert.get("days_remaining","")}</td><td>{_e(names)}</td></tr>')
                doc.append("</table>")

        # ── Hunter / Breach ───────────────────────────────────────────────────
        elif tool == "hunter_breach" and data:
            emails   = data.get("emails",[]) or []
            breaches = data.get("breach_results",{}) or {}
            doc.append(f"""
<div class="stats-grid">
  <div class="stat-card"><span class="number">{len(emails)}</span><span class="label">Emails Found</span></div>
  <div class="stat-card"><span class="number">{data.get("emails_with_breaches",0)}</span><span class="label">With Breaches</span></div>
</div>
<h3 style="margin:14px 0 8px">📧 Email Breach Analysis</h3>
""")
            if emails:
                doc.append('<table class="data-table"><tr><th>Email</th><th>Status</th><th>Breaches</th></tr>')
                for em in emails:
                    bl   = breaches.get(em,[]) or []
                    icon = "🚨" if bl else "✅"
                    tag  = f"{len(bl)} breach(es)" if bl else "Clean"
                    cells = "".join(f'<div>• {_e(b.get("database_name","Unknown"))}</div>' for b in bl[:3])
                    if len(bl) > 3: cells += f'<div style="color:{P["muted"]}">… +{len(bl)-3} more</div>'
                    cells = cells or "No breaches"
                    doc.append(f'<tr><td>{_e(em)}</td><td>{icon} {tag}</td><td>{cells}</td></tr>')
                doc.append("</table>")
            else:
                doc.append("<p>No emails found for this domain.</p>")

        # ── Google Dorks ──────────────────────────────────────────────────────
        elif tool == "google_dorks" and data:
            cats = data.get("results",{}) or {}
            doc.append(f"""
<div class="stats-grid">
  <div class="stat-card"><span class="number">{data.get("total_links",0)}</span><span class="label">Unique Links Found</span></div>
</div>
<h3 style="margin:14px 0 8px">🔎 Dork Results</h3>
""")
            for cat, links in cats.items():
                if not links: continue
                doc.append(f'<details><summary>{_e(cat)} ({len(links)})</summary><ol style="margin:10px 16px">')
                for lnk in links:
                    doc.append(f'<li><a href="{_e(lnk)}" target="_blank">{_e(lnk)}</a></li>')
                doc.append("</ol></details>")

        # ── GitHub ────────────────────────────────────────────────────────────
        elif tool == "github" and data:
            repos    = data.get("repositories",[]) or []
            findings = data.get("findings",[]) or []
            analysis = data.get("analysis") or {}
            doc.append(f"""
<div class="stats-grid">
  <div class="stat-card"><span class="number">{len(repos)}</span><span class="label">Repos Scanned</span></div>
  <div class="stat-card"><span class="number">{len(findings)}</span><span class="label">Findings</span></div>
</div>
""")
            if repos:
                doc.append('<details><summary>Repository List</summary><ol style="margin:10px 16px">')
                for repo in repos:
                    doc.append(f'<li><a href="{_e(repo.get("url",""))}" target="_blank">{_e(repo.get("name",""))}</a> — {_e(repo.get("description",""))}</li>')
                doc.append("</ol></details>")
            if findings:
                doc.append('<h3 style="margin:14px 0 8px">🧾 Findings</h3>')
                doc.append('<table class="data-table"><tr><th>Repo</th><th>File</th><th>Link</th><th>Risk</th></tr>')
                for f in findings:
                    doc.append(f'<tr><td>{_e(f.get("repo",""))}</td><td>{_e(f.get("file",f.get("path","")))}</td><td><a href="{_e(f.get("url",""))}" target="_blank">View</a></td><td>{_e(f.get("risk_level",""))}</td></tr>')
                doc.append("</table>")
            if analysis:
                doc.append('<table class="data-table"><tr><th>Risk Level</th><th>Count</th></tr>')
                for lvl in ("high_risk","medium_risk","low_risk"):
                    doc.append(f'<tr><td>{lvl.replace("_"," ").title()}</td><td>{len(analysis.get(lvl,[]))}</td></tr>')
                doc.append("</table>")

        # ── Security Headers ──────────────────────────────────────────────────
        elif tool == "security_headers" and data:
            score   = data.get("score",0)
            headers = data.get("headers",[]) or []
            s_col   = P["green"] if score>=75 else P["yellow"] if score>=50 else P["red"]
            doc.append(f"""
<h3 style="margin:0 0 12px">🔒 Security Headers</h3>
<div class="stat-card" style="max-width:200px;border-color:{s_col}">
  <span class="number" style="color:{s_col}">{score}%</span>
  <span class="label">Header Score</span>
</div>
<table class="data-table" style="margin-top:14px">
  <tr><th>Header</th><th>Present</th><th>Value</th></tr>
""")
            for h in headers:
                icon = "✅" if h.get("present") else "❌"
                doc.append(f'<tr><td>{_e(h.get("header",""))}</td><td>{icon}</td><td>{_e(h.get("value",""))}</td></tr>')
            doc.append("</table>")

        # ── VirusTotal ────────────────────────────────────────────────────────
        elif tool == "virustotal" and data:
            mal = data.get("malicious",0); sus = data.get("suspicious",0)
            tot = sum(data.values()) if isinstance(data,dict) else 0
            stat = "THREATS DETECTED" if (mal or sus) else "CLEAN"
            s_c  = P["red"] if (mal or sus) else P["green"]
            doc.append(f"""
<h3 style="margin:0 0 12px">🦠 VirusTotal</h3>
<div class="stat-card" style="max-width:320px;border-color:{s_c}">
  <span class="number" style="color:{s_c}">{stat}</span>
  <span class="label">Malicious:{mal} | Suspicious:{sus} | Total:{tot}</span>
</div>
<table class="data-table" style="margin-top:14px">
  <tr><th>Category</th><th>Count</th></tr>
""")
            for k,v in (data.items() if isinstance(data,dict) else []):
                doc.append(f'<tr><td>{_e(k)}</td><td>{v}</td></tr>')
            doc.append("</table>")

        # ── Shodan ────────────────────────────────────────────────────────────
        elif tool == "shodan" and data:
            ports = ", ".join(map(str, data.get("ports",[]))) or "—"
            doc.append(f"""
<h3 style="margin:0 0 12px">🔍 Shodan</h3>
<table class="data-table">
  <tr><th>IP</th><th>Org</th><th>ISP</th><th>ASN</th><th>Ports</th></tr>
  <tr><td>{_e(data.get("ip_str",""))}</td><td>{_e(data.get("org",""))}</td><td>{_e(data.get("isp",""))}</td><td>{_e(data.get("asn",""))}</td><td>{ports}</td></tr>
</table>
""")
            if data.get("vulns"):
                doc.append(f'<h4 style="margin:12px 0 8px;color:{P["red"]}">⚠ Vulnerabilities</h4><ul style="margin-left:20px">')
                for v in data["vulns"]: doc.append(f'<li>{_e(v)}</li>')
                doc.append("</ul>")

        # ── Cloud Buckets ─────────────────────────────────────────────────────
        elif tool == "cloud_buckets" and data:
            stats   = data.get("statistics",{}) or {}
            buckets = data.get("buckets_found",[]) or []
            doc.append(f"""
<div class="stats-grid">
  <div class="stat-card"><span class="number">{stats.get("total_buckets",0)}</span><span class="label">Buckets Found</span></div>
  <div class="stat-card"><span class="number">{stats.get("public_count",0)}</span><span class="label">Public</span></div>
</div>
""")
            if buckets:
                doc.append('<table class="data-table"><tr><th>Bucket</th><th>Provider</th><th>Status</th><th>URL</th></tr>')
                for b in buckets:
                    url = b.get("url") or "—"
                    lnk = f'<a href="{_e(url)}" target="_blank">Open</a>' if url!="—" else "—"
                    doc.append(f'<tr><td>{_e(b.get("name",""))}</td><td>{_e(b.get("provider",""))}</td><td>{_e(b.get("status",""))}</td><td>{lnk}</td></tr>')
                doc.append("</table>")

        # ── Tech Fingerprinting ────────────────────────────────────────────────
        elif tool == "technologies":
            import re as _re
            techs = (data.get("technologies",{}) if data else {}) or {}
            if techs:
                doc.append('<h3 style="margin:0 0 12px">🧩 Technologies</h3>')
                doc.append('<table class="data-table"><tr><th>Category</th><th>Detected</th></tr>')
                for cat, tlist in techs.items():
                    pills = " ".join(f'<span class="tech-pill">{_e(t)}</span>' for t in tlist)
                    doc.append(f'<tr><td>{_e(cat)}</td><td>{pills}</td></tr>')
                doc.append("</table>")
                if data and data.get("status_code"):
                    doc.append(f'<p style="color:{P["muted"]};margin-top:8px">HTTP Status: {data["status_code"]}</p>')
            elif result.get("output"):
                parsed_techs: dict = {}; cur = None
                for ln in result["output"].splitlines():
                    l = ln.strip()
                    if not l: continue
                    m = _re.match(r'📦\s*(.+):', l)
                    if m: cur = m.group(1).strip(); parsed_techs[cur] = []; continue
                    m2 = _re.match(r'^[\u2022\-\*\s]+(.+)', l)
                    if m2 and cur: parsed_techs[cur].append(m2.group(1).strip())
                if parsed_techs:
                    doc.append('<table class="data-table"><tr><th>Category</th><th>Detected</th></tr>')
                    for cat,tlist in parsed_techs.items():
                        pills = " ".join(f'<span class="tech-pill">{_e(t)}</span>' for t in tlist)
                        doc.append(f'<tr><td>{_e(cat)}</td><td>{pills}</td></tr>')
                    doc.append("</table>")
                else:
                    doc.append(f'<div class="output-box">{_e(result.get("output",""))}</div>')
            else:
                doc.append('<div class="output-box">No technologies detected.</div>')

        # ── Fallback ──────────────────────────────────────────────────────────
        else:
            if result.get("output"):
                doc.append(f'<div class="output-box">{_e(result["output"])}</div>')
            if data and tool not in ("wayback","whois","certificates","hunter_breach"):
                snippet = json.dumps(data, indent=2, default=str)[:2000]
                doc.append(f'<div class="output-box">{_e(snippet)}…</div>')

        doc.append("  </div>\n</div>")

    doc.append(f"""
</div>
<div class="footer">
  <h3 style="color:{P['text']};margin-bottom:14px">📦 Export Options</h3>
  <a class="dl-btn" href="recon_output.json">⬇ JSON Report</a>
  <p style="margin-top:18px;color:{P['muted']}">Passive Reconnaissance Framework v4.0 · Rudra Potghan</p>
</div>
</body>
</html>
""")

    out_file = f"{domain}_reconnaissance_report.html"
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("\n".join(doc))
    print(f"[{green('✓')}] HTML Report saved: {bold(out_file)}")
    return out_file

# ─────────────────────────────────────────────
#  Orchestrator  (logic unchanged from v3)
# ─────────────────────────────────────────────
class ReconOrchestratorV4:
    def __init__(self, target: str):
        self.domain     = normalize_domain(target)
        self.started_at = datetime.utcnow().isoformat()
        self.results: list = []
        self.pipeline = [
            scan_dns, scan_whois, scan_certificates, scan_wayback,
            scan_google_dorks, scan_github, scan_hunter, scan_shodan,
            scan_cloud, scan_tech, scan_headers, scan_virustotal,
        ]

    def run(self):
        print()
        print(bold(cyan("=" * 66)))
        print(bold(f"  🔍 RECON STARTED  →  {cyan(self.domain)}"))
        print(bold(cyan("=" * 66)))
        print()
        for idx, scan in enumerate(self.pipeline, 1):
            name = scan.__name__.replace("scan_","").replace("_"," ").title()
            print(f"  [{dim(str(idx).zfill(2))}/{len(self.pipeline)}]  {bold(name)} …")
            try:
                res = scan(self.domain)
                self.results.append(res)
                if res["status"] == "completed":
                    print(f"         {green('✅')} Completed")
                else:
                    print(f"         {yellow('⚠')}  Errors encountered")
            except Exception as e:
                print(f"         {red('❌')} Failed: {e}")
                err = base_result(scan.__name__.replace("scan_",""), self.domain)
                err["status"] = "error"; err["output"] = str(e)
                self.results.append(err)
        print()
        print(bold(cyan("=" * 66)))
        print(bold("  ✅  RECONNAISSANCE COMPLETE"))
        print(bold(cyan("=" * 66)))
        print()

    def export_json(self, filename: str = "recon_output") -> str:
        data = {
            "target": self.domain, "started_at": self.started_at,
            "completed_at": datetime.utcnow().isoformat(),
            "total_scans": len(self.results),
            "successful_scans": len([r for r in self.results if r["status"]=="completed"]),
            "results": self.results,
        }
        out = f"{filename}.json"
        with open(out, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        print(f"[{green('✓')}] JSON Report saved: {bold(out)}")
        return out

    def export_html(self) -> str:
        return generate_html_report(self)

# ─────────────────────────────────────────────
#  CLI entry point
# ─────────────────────────────────────────────
def _banner():
    art = [
        r" ██████╗ ██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗██╗      ",
        r"██╔════╝ ██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║██║      ",
        r"╚█████╗  ███████║███████║██║  ██║██║   ██║██║ █╗ ██║██║      ",
        r" ╚═══██╗ ██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║██║      ",
        r"██████╔╝ ██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝███████╗ ",
        r"╚═════╝  ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚══════╝ ",
    ]
    print()
    for line in art:
        print(bold(cyan(line)))
    print()
    print(bold(cyan("  ─────────────────────────────────────────────────────────")))
    print(bold(f"    {'Shadow Leads':^55}"))
    print(dim( f"    {'Passive Reconnaissance Framework  v4.0':^55}"))
    print(dim( f"    {'Author: Rudra Potghan  |  Authorized use only':^55}"))
    print(bold(cyan("  ─────────────────────────────────────────────────────────")))
    print()

def main():
    parser = argparse.ArgumentParser(
        prog="python main.py",
        description="Passive Reconnaissance Framework v4.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
COMMANDS
  run <domain>   Full passive recon scan
  configure      Interactive API key setup wizard
  status         Show configured API keys

EXAMPLES
  python main.py run example.com
  python main.py run example.com --output my_report
  python main.py run example.com --no-html
  python main.py configure
  python main.py status
        """,
    )
    sub = parser.add_subparsers(dest="command")

    run_p = sub.add_parser("run", help="Run a full recon scan")
    run_p.add_argument("domain", help="Target domain, e.g. example.com")
    run_p.add_argument("--no-html", action="store_true", help="Skip HTML report")
    run_p.add_argument("--output","-o", default="recon_output", metavar="FILE",
                       help="Base filename for output (default: recon_output)")

    sub.add_parser("configure", help="Set / update API keys")
    sub.add_parser("status",    help="Show API key status")

    # Back-compat: `python main.py example.com` still works
    raw = sys.argv[1:]
    if raw and raw[0] not in ("run","configure","status","-h","--help"):
        raw = ["run"] + raw

    args = parser.parse_args(raw)

    _banner()

    if args.command == "configure":
        configure_keys(force=True); show_key_status(); return
    if args.command == "status":
        show_key_status(); return
    if args.command == "run":
        configure_keys(force=False)
        domain = normalize_domain(args.domain)
        print(f"  {bold('Target :')} {cyan(domain)}\n")
        recon = ReconOrchestratorV4(domain)
        recon.run()
        jf = recon.export_json(args.output)
        hf = None if args.no_html else recon.export_html()
        ok  = len([r for r in recon.results if r["status"]=="completed"])
        err = len(recon.results) - ok
        print()
        print(bold("  SCAN SUMMARY"))
        print("  " + "─"*40)
        print(f"  Target   : {cyan(recon.domain)}")
        print(f"  Total    : {len(recon.results)}")
        print(f"  Success  : {green(str(ok))}")
        print(f"  Failed   : {(red(str(err)) if err else dim('0'))}")
        print(f"  JSON     : {bold(jf)}")
        if hf: print(f"  HTML     : {bold(hf)}")
        print()
        return
    parser.print_help()

if __name__ == "__main__":
    main()
