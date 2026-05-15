```
 ██████╗ ██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗██╗  
██╔════╝ ██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║██║  
╚█████╗  ███████║███████║██║  ██║██║   ██║██║ █╗ ██║██║  
 ╚═══██╗ ██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║██║  
██████╔╝ ██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝███████╗
╚═════╝  ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚══════╝

       S H A D O W L   —   Passive Recon Framework  v4.0
              Author: Rudra Potghan  |  For authorized use only
```

> **SHADOWL** — *Shadow Leads* — a passive reconnaissance framework that silently maps an organization's digital footprint without ever touching the target directly.

---

## 🔍 What is SHADOWL?

SHADOWL is a modular, CLI-first passive reconnaissance tool that aggregates intelligence from public sources to build a comprehensive picture of any domain target. It chains 12 independent scan modules, saves structured JSON output, and generates a polished dark-themed HTML report — all from a single command.

**No active scanning. No packets sent to the target. Pure OSINT.**

---

## ✨ Features

- **12-module pipeline** — DNS, WHOIS, Certificates, Wayback Machine, Google Dorks, GitHub secrets, Hunter.io breach check, Shodan, Cloud Buckets, Technology Fingerprinting, Security Headers, VirusTotal
- **First-run API key wizard** — interactive setup on first launch, keys stored securely in your OS config directory (no more editing source files)
- **Platform independent** — works on Windows, macOS, and Linux out of the box
- **Rich HTML report** — dark-navy UI with electric-blue accents, stat cards, collapsible sections, and inline iframes
- **Structured JSON output** — every scan result saved as machine-readable JSON for further processing
- **Full CLI** — `run`, `configure`, and `status` sub-commands with `--help` on everything

---

## 🛠 Requirements

- **Python 3.10+**
- Install dependencies:

```bash
pip install requests shodan dnspython tabulate tldextract colorama
```

> No virtual environment required — install globally or in any venv of your choice. The old `venv101/` folder is not needed.

---

## ⚙️ API Keys

SHADOWL uses several third-party APIs. On **first run** the wizard will prompt you for each key. Keys are saved to your OS config directory — you never need to edit source code.

| Key | Required | Where to get it |
|-----|----------|----------------|
| Shodan API Key | ✅ Required | https://account.shodan.io |
| Google Custom Search API Key | Optional | https://console.cloud.google.com |
| Google CSE ID | Optional | https://programmablesearchengine.google.com |
| GitHub Personal Access Token | Optional | https://github.com/settings/tokens |
| VirusTotal API Key | Optional | https://www.virustotal.com/gui/my-apikey |
| Hunter.io API Key | Optional | https://hunter.io/api-keys |
| LeakLookup API Key | Optional | https://leak-lookup.com/account/api |

Keys are stored at:
- **Windows:** `%APPDATA%\PassiveReconTool\api_keys.json`
- **macOS:** `~/Library/Application Support/PassiveReconTool/api_keys.json`
- **Linux:** `~/.config/PassiveReconTool/api_keys.json`

---

## 🚀 Usage

### Run a full scan
```bash
python main.py run example.com
```

### Run without generating the HTML report
```bash
python main.py run example.com --no-html
```

### Custom output filename
```bash
python main.py run example.com --output acme_recon
```

### Set up or update API keys
```bash
python main.py configure
```

### Check which keys are configured
```bash
python main.py status
```

### Old-style shorthand (backwards compatible)
```bash
python main.py example.com
```

---

## 📁 Output Layout

After a scan on `example.com`, you will find:

```
example.com_reconnaissance_report.html   ← rich HTML report (open in browser)
recon_output.json                        ← full consolidated JSON

example.com/
  ├── example.com_certsh.json            ← certificate transparency data
  ├── example.com_dns.json               ← DNS records
  ├── example.com_dns_report.html        ← DNS visual report
  ├── whois_<timestamp>.json             ← WHOIS data
  └── whois_summary_<timestamp>.txt      ← WHOIS summary

hunter_example.com.json                  ← Hunter.io email data
shodan_example.com_<timestamp>.json      ← Shodan host data
```

---

## 🧭 Scan Pipeline

```
DNS → WHOIS → Certificates → Wayback Machine → Google Dorks
  → GitHub Secrets → Hunter.io + Breach Check → Shodan
    → Cloud Buckets → Tech Fingerprinting → Security Headers → VirusTotal
```

Each module is fully independent — if one fails, the rest continue.

---

## 🗂 File Structure

```
PassiveReconTool/
  main.py                ← CLI entry point & orchestrator (v4)
  config_manager.py      ← API key wizard & storage (NEW in v4)
  dns_tool.py            ← DNS reconnaissance
  whois.py               ← WHOIS lookup
  certsh.py              ← Certificate transparency (crt.sh)
  wayback.py             ← Wayback Machine / CDX API
  dork.py                ← Google Custom Search dorking
  gitleaks.py            ← GitHub secrets scanning
  hunter_breachcheck.py  ← Hunter.io email + LeakLookup breach check
  shodan_scanner.py      ← Shodan host intelligence
  cloud_buckets.py       ← AWS/GCP/Azure bucket enumeration
  tech_fingerprinter.py  ← Technology stack detection
  security_headers.py    ← HTTP security header analysis
  virustotal.py          ← VirusTotal domain reputation
  README.md              ← This file
```

---

## 🛡️ Ethics & Legal

SHADOWL is designed exclusively for **authorized security testing, bug bounty research, and defensive OSINT**. All data is sourced from public APIs and archives — no packets are sent to the target.

**Only run this tool against domains you own or have explicit written permission to test. The author is not responsible for misuse.**

---

## 📄 License

MIT License — free to use, modify, and distribute with attribution.

---

## 📝 Changelog

### v4.0 (current)
- Renamed to **SHADOWL** with ASCII art banner
- Added `config_manager.py` — cross-platform API key wizard
- Full CLI with `run` / `configure` / `status` sub-commands
- HTML report redesigned: dark-navy + electric-blue palette
- Platform-independent paths (Windows, macOS, Linux)
- No hardcoded keys anywhere in source

### v3.0
- HTML report with color theme
- Integrated JSON file reading across all modules
- Orchestrator pattern with full pipeline

### v2.0 / v1.0
- Initial modular structure
- Per-module JSON output
