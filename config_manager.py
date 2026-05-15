"""
API Key Configuration Manager
Handles reading/writing API keys from a platform-independent config file.
On first run, guides the user through setting up all required API keys.
"""

import os
import sys
import json
import platform
from pathlib import Path

# ─────────────────────────────────────────────
#  Where we store keys (platform-independent)
# ─────────────────────────────────────────────

def get_config_path() -> Path:
    """Return a platform-appropriate path for the config file."""
    if platform.system() == "Windows":
        base = Path(os.environ.get("APPDATA", Path.home()))
    elif platform.system() == "Darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))

    config_dir = base / "PassiveReconTool"
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir / "api_keys.json"


CONFIG_PATH = get_config_path()

# ─────────────────────────────────────────────
#  Colour helpers (work on all platforms)
# ─────────────────────────────────────────────

def _supports_color() -> bool:
    if platform.system() == "Windows":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32          # type: ignore
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            return True
        except Exception:
            return False
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

USE_COLOR = _supports_color()

def c(text: str, code: str) -> str:
    if not USE_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"

def red(t):    return c(t, "91")
def green(t):  return c(t, "92")
def yellow(t): return c(t, "93")
def cyan(t):   return c(t, "96")
def bold(t):   return c(t, "1")
def dim(t):    return c(t, "2")


# ─────────────────────────────────────────────
#  Key definitions
# ─────────────────────────────────────────────

API_KEY_DEFINITIONS = [
    {
        "key":         "shodan_api_key",
        "label":       "Shodan API Key",
        "help":        "https://account.shodan.io → 'API Key'",
        "required":    True,
    },
    {
        "key":         "google_api_key",
        "label":       "Google Custom Search API Key",
        "help":        "https://console.cloud.google.com → 'Custom Search API'",
        "required":    False,
    },
    {
        "key":         "google_cse_id",
        "label":       "Google Custom Search Engine ID (CSE ID)",
        "help":        "https://programmablesearchengine.google.com",
        "required":    False,
    },
    {
        "key":         "github_token",
        "label":       "GitHub Personal Access Token",
        "help":        "https://github.com/settings/tokens → 'Generate new token'",
        "required":    False,
    },
    {
        "key":         "virustotal_api_key",
        "label":       "VirusTotal API Key",
        "help":        "https://www.virustotal.com/gui/my-apikey",
        "required":    False,
    },
    {
        "key":         "hunter_api_key",
        "label":       "Hunter.io API Key",
        "help":        "https://hunter.io/api-keys",
        "required":    False,
    },
    {
        "key":         "leaklookup_api_key",
        "label":       "LeakLookup API Key",
        "help":        "https://leak-lookup.com/account/api",
        "required":    False,
    },
]


# ─────────────────────────────────────────────
#  Load / save
# ─────────────────────────────────────────────

def load_keys() -> dict:
    """Load API keys from config file. Returns empty dict if not found."""
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_keys(keys: dict) -> None:
    """Persist API keys to the config file."""
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(keys, f, indent=2)


def get_key(name: str) -> str:
    """Return a single API key value (empty string if not set)."""
    return load_keys().get(name, "")


# ─────────────────────────────────────────────
#  Configuration wizard
# ─────────────────────────────────────────────

def _print_banner():
    print()
    print(bold(cyan("╔══════════════════════════════════════════════════════════╗")))
    print(bold(cyan("║    ▓  SHADOWL  —  Shadow Leads Recon Framework  v4.0  ▓ ║")))
    print(bold(cyan("║                   API Key Configuration                  ║")))
    print(bold(cyan("╚══════════════════════════════════════════════════════════╝")))
    print()


def configure_keys(force: bool = False) -> dict:
    """
    Interactive wizard to set up API keys.
    If force=False only runs when keys are missing or user explicitly calls it.
    Returns the loaded/updated key dict.
    """
    existing = load_keys()

    # Check if any required key is missing
    missing_required = [
        d for d in API_KEY_DEFINITIONS
        if d["required"] and not existing.get(d["key"])
    ]

    if not force and not missing_required:
        return existing  # All required keys present – skip wizard

    _print_banner()

    if missing_required:
        print(yellow("⚠  Some required API keys are not configured yet."))
    else:
        print(cyan("ℹ  Reconfiguring API keys."))

    print(f"{dim('Keys will be saved to:')} {dim(str(CONFIG_PATH))}")
    print()

    updated = dict(existing)

    for defn in API_KEY_DEFINITIONS:
        key     = defn["key"]
        label   = defn["label"]
        help_   = defn["help"]
        req     = defn["required"]

        current = updated.get(key, "")
        tag     = bold(red("[required]")) if req else dim("[optional]")
        hint    = f"  {dim('→')} {dim(help_)}"

        print(f"  {bold(label)}  {tag}")
        print(hint)

        if current:
            masked = current[:6] + "..." + current[-4:] if len(current) > 10 else "***"
            print(f"  {dim('Current:')} {dim(masked)}")
            answer = input(f"  {cyan('Keep current? [Y/n]:')} ").strip().lower()
            if answer not in ("n", "no"):
                print()
                continue

        placeholder = "(leave blank to skip)" if not req else "(required)"
        value = input(f"  {cyan(f'Enter {label} {placeholder}:')} ").strip()

        if value:
            updated[key] = value
        elif req and not current:
            print(f"  {yellow('⚠  Skipped required key. Tool may fail for some scans.')}")

        print()

    save_keys(updated)
    print(green("✅  API keys saved successfully!"))
    print(f"   {dim('Config file:')} {str(CONFIG_PATH)}")
    print()
    return updated


def show_key_status():
    """Print a status table of all configured keys."""
    keys = load_keys()
    print()
    print(bold("  API KEY STATUS"))
    print("  " + "─" * 50)
    for defn in API_KEY_DEFINITIONS:
        val  = keys.get(defn["key"], "")
        tag  = bold(red("[REQUIRED]")) if defn["required"] else dim("[optional]")
        if val:
            masked = val[:6] + "..." + val[-4:] if len(val) > 10 else "***"
            status = green("✓  " + masked)
        else:
            status = yellow("✗  Not set")
        print(f"  {tag:20}  {defn['label']:<35} {status}")
    print("  " + "─" * 50)
    print(f"  {dim('Config file:')} {str(CONFIG_PATH)}")
    print()


# ─────────────────────────────────────────────
#  Standalone entry point for testing
# ─────────────────────────────────────────────

if __name__ == "__main__":
    configure_keys(force=True)
    show_key_status()
