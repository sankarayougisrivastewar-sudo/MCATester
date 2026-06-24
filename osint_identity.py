#!/usr/bin/env python3
"""
MCATester - osint_identity.py
People & Identity OSINT modules for osint_agent.py

Modules:
  1. HaveIBeenPwned  — check emails against breach databases
  2. Holehe          — check email registration across 120+ sites
  3. Sherlock        — find username across 400+ social platforms
  4. ipinfo.io       — enhanced IP intelligence (geo, ASN, privacy)
  5. Censys          — certificate & service search (Shodan alternative)
  6. PhoneInfoga    — phone number OSINT (if numbers found)

Setup:
  pip install holehe
  pip install sherlock-project    # or: git clone https://github.com/sherlock-project/sherlock
  pip install phoneinfoga         # optional

  .env keys:
    HIBP_API_KEY=...             # haveibeenpwned.com/API/Key (paid, ~$3.50/month)
    IPINFO_TOKEN=...             # ipinfo.io (free tier: 50k requests/month)
    CENSYS_API_ID=...            # censys.io (free tier: 250 queries/day)
    CENSYS_API_SECRET=...
    IP2LOCATION_API_KEY=...      # optional

Usage:
  # Standalone
  python osint_identity.py --email jsmtih@altoromutual.com
  python osint_identity.py --username admin
  python osint_identity.py --ip 65.61.137.117
  python osint_identity.py --phone "+1234567890"

  # Integration (add to osint_agent.py):
  from osint_identity import run_identity_osint
  identity_results = run_identity_osint(emails=["user@target.com"],
                                         usernames=["admin"],
                                         ips=["65.61.137.117"])
"""

import os
import re
import sys
import time
import json
import subprocess
import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv
from osint_patches_v6 import holehe_check_v2, sherlock_search_v2

# Replace holehe_check() calls with holehe_check_v2()
# Replace sherlock_search() calls with sherlock_search_v2()

load_dotenv()
urllib3.disable_warnings()

# ─────────────────────────────────────────────
# API KEYS
# ─────────────────────────────────────────────

HIBP_API_KEY        = os.getenv("HIBP_API_KEY", "")
IPINFO_TOKEN        = os.getenv("IPINFO_TOKEN", "")
CENSYS_API_ID       = os.getenv("CENSYS_API_ID", "")
CENSYS_API_SECRET   = os.getenv("CENSYS_API_SECRET", "")
IP2LOCATION_KEY     = os.getenv("IP2LOCATION_API_KEY", "")

def identity_api_status():
    apis = {
        "HaveIBeenPwned": HIBP_API_KEY,
        "ipinfo.io": IPINFO_TOKEN,
        "Censys": CENSYS_API_ID,
        "ip2location": IP2LOCATION_KEY,
    }
    # These don't need API keys
    free_tools = ["Holehe", "Sherlock"]
    active = [k for k, v in apis.items() if v] + free_tools
    missing = [k for k, v in apis.items() if not v]
    return active, missing


# ═════════════════════════════════════════════
# 1. HAVE I BEEN PWNED
# ═════════════════════════════════════════════

def hibp_check_email(email):
    """
    Check if an email appears in known data breaches.
    Requires HIBP_API_KEY (paid, ~$3.50/month).
    Returns list of breaches.
    """
    if not HIBP_API_KEY:
        return {"email": email, "error": "HIBP_API_KEY not set", "breaches": []}

    try:
        r = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            headers={
                "hibp-api-key": HIBP_API_KEY,
                "user-agent": "MCATester-OSINT-Agent",
            },
            params={"truncateResponse": "false"},
            timeout=10,
        )

        if r.status_code == 200:
            breaches = r.json()
            return {
                "email": email,
                "breached": True,
                "breach_count": len(breaches),
                "breaches": [
                    {
                        "name": b.get("Name", ""),
                        "domain": b.get("Domain", ""),
                        "date": b.get("BreachDate", ""),
                        "count": b.get("PwnCount", 0),
                        "data_classes": b.get("DataClasses", []),
                    }
                    for b in breaches
                ],
            }
        elif r.status_code == 404:
            return {"email": email, "breached": False, "breach_count": 0, "breaches": []}
        elif r.status_code == 401:
            return {"email": email, "error": "Invalid HIBP API key", "breaches": []}
        elif r.status_code == 429:
            return {"email": email, "error": "Rate limited — wait and retry", "breaches": []}
        else:
            return {"email": email, "error": f"HTTP {r.status_code}", "breaches": []}

    except Exception as e:
        return {"email": email, "error": str(e)[:80], "breaches": []}


def hibp_check_paste(email):
    """Check if an email appears in paste dumps (pastebin etc)."""
    if not HIBP_API_KEY:
        return []
    try:
        r = requests.get(
            f"https://haveibeenpwned.com/api/v3/pasteaccount/{email}",
            headers={"hibp-api-key": HIBP_API_KEY, "user-agent": "MCATester-OSINT-Agent"},
            timeout=10,
        )
        if r.status_code == 200:
            return r.json()
        return []
    except:
        return []


def run_hibp(emails):
    """Run HIBP checks on a list of emails."""
    if not emails:
        return []
    print(f"  Checking {len(emails)} email(s) against breach databases...")
    results = []
    for email in emails[:10]:  # HIBP rate limit: 1 req per 1.5s
        result = hibp_check_email(email)
        if result.get("error"):
            print(f"    {email}: {result['error']}")
        elif result.get("breached"):
            print(f"    [!] {email}: FOUND in {result['breach_count']} breaches!")
            for b in result["breaches"][:3]:
                print(f"        → {b['name']} ({b['date']}) — {b['count']:,} accounts")
        else:
            print(f"    {email}: clean (not in any known breaches)")
        results.append(result)
        time.sleep(1.6)  # HIBP rate limit

    # Also check pastes
    for email in emails[:5]:
        pastes = hibp_check_paste(email)
        if pastes:
            print(f"    [!] {email}: found in {len(pastes)} paste(s)")
        time.sleep(1.6)

    return results


# ═════════════════════════════════════════════
# 2. HOLEHE — Email Registration Check
# ═════════════════════════════════════════════
def holehe_check(email):
    """
    Check which websites an email is registered on.
    Uses holehe's native module engine directly to completely eliminate terminal parsing bugs.
    """
    try:
        import asyncio
        import importlib
        from holehe.modules import __all__ as modules_list

        async def _run():
            out = []
            # Dynamically import and process using native modules
            for module_name in modules_list:
                try:
                    module = importlib.import_module(f"holehe.modules.{module_name}")
                    # Create the standard state tracker dictionary holehe expects
                    req = {"exists": False, "email": email, "rateLimit": False, "error": False}
                    
                    # Run the native module checker inside the async loop
                    await module.checker(email, req)
                    
                    if req["exists"]:
                        # Extract the human-readable clean site name from the module name
                        clean_name = module_name.replace("_", "").capitalize()
                        out.append(clean_name)
                except Exception:
                    continue
            return out

        # Safe async loop execution environment handler
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
        sites = loop.run_until_complete(_run())

        return {
            "email": email,
            "total_checked": len(modules_list),
            "registered_count": len(sites),
            "registered_sites": sites,
            "sample": sites[:10],
        }

    except Exception as library_error:
        # Emergency backup fallback to system CLI if library import breaks
        try:
            import subprocess
            import re
            result = subprocess.run(
                ["holehe", email, "--only-used", "--no-color"],
                capture_output=True, text=True, timeout=120,
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().splitlines()
                sites = []
                for l in lines:
                    l_str = l.strip()
                    # Strip raw ANSI text formatting fragments
                    l_str = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', l_str).strip()
                    
                    if not l_str or l_str.startswith(("[", "Email", "─", "★", "*")):
                        continue
                    
                    # Ignore the raw email, digits, summary sentences, and update strings
                    if email in l_str or l_str.isdigit() or "updated" in l_str.lower() or "holehe" in l_str.lower():
                        continue
                        
                    parts = l_str.split()
                    if parts:
                        site_candidate = parts[0].strip().replace(":", "")
                        if site_candidate.lower() not in ["for", "total", "rate", "error", "modules"]:
                            if site_candidate not in sites:
                                sites.append(site_candidate)

                return {
                    "email": email,
                    "total_checked": len(lines),
                    "registered_count": len(sites),
                    "registered_sites": sites,
                    "sample": sites[:10],
                }
            return {"email": email, "error": f"CLI failure: {library_error}", "registered_sites": []}
        except Exception as cli_error:
            return {"email": email, "error": f"Execution error: {str(cli_error)[:50]}", "registered_sites": []}


# Ensure this definition is aligned completely to the left margin (no leading spaces/tabs)
def run_holehe(emails):
    """Run holehe on discovered emails."""
    if not emails:
        return []
    print(f"  Checking {len(emails)} email(s) for site registrations...")
    results = []
    for email in emails[:5]:  # Limit to avoid rate limits / IP banning
        result = holehe_check(email)
        if result.get("error"):
            print(f"    {email}: {result['error']}")
        elif result.get("registered_count", 0) > 0:
            sites = result["registered_sites"][:5]
            print(f"    [!] {email}: registered on {result['registered_count']} sites")
            print(f"        → {', '.join(sites)}")
        else:
            print(f"    {email}: not found on any checked sites")
        results.append(result)
    return results
# ═════════════════════════════════════════════
# 3. SHERLOCK — Username Search
# ═════════════════════════════════════════════

def sherlock_search(username, timeout=120):
    """
    Search for a username across 400+ social platforms.
    Requires sherlock-project installed.
    """
    try:
        # Try sherlock CLI
        result = subprocess.run(
            ["sherlock", username, "--print-found", "--timeout", "10", "--no-color"],
            capture_output=True, text=True, timeout=timeout,
        )

        if result.returncode == 0 or result.stdout:
            found = []
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("http://") or line.startswith("https://"):
                    found.append(line)
                elif ": http" in line:
                    url = line.split(": ", 1)[-1].strip()
                    if url.startswith("http"):
                        found.append(url)

            return {
                "username": username,
                "found_count": len(found),
                "profiles": found[:20],
                "raw": result.stdout[:2000],
            }

        return {"username": username, "found_count": 0, "profiles": [],
                "error": result.stderr[:200] if result.stderr else "No results"}

    except FileNotFoundError:
        return {"username": username, "error": "sherlock not installed (pip install sherlock-project)",
                "found_count": 0, "profiles": []}
    except subprocess.TimeoutExpired:
        return {"username": username, "error": f"Timed out after {timeout}s",
                "found_count": 0, "profiles": []}
    except Exception as e:
        return {"username": username, "error": str(e)[:80],
                "found_count": 0, "profiles": []}


def extract_usernames_from_emails(emails):
    """Extract potential usernames from email addresses."""
    usernames = set()
    for email in emails:
        local = email.split("@")[0]
        # Clean up common patterns
        local = re.sub(r'[._+-]', '.', local)  # normalize separators
        usernames.add(local)
        # Also try without dots
        clean = local.replace(".", "")
        if clean != local:
            usernames.add(clean)
    return list(usernames)[:5]  # Limit to avoid very long scans


def run_sherlock(usernames):
    """Run sherlock on a list of usernames."""
    if not usernames:
        return []
    print(f"  Searching {len(usernames)} username(s) across social platforms...")
    results = []
    for username in usernames[:3]:  # Sherlock is slow, limit to 3
        print(f"    Checking: {username}...")
        result = sherlock_search(username)
        if result.get("error"):
            print(f"    {username}: {result['error']}")
        elif result.get("found_count", 0) > 0:
            print(f"    [!] {username}: found on {result['found_count']} platforms")
            for url in result["profiles"][:5]:
                print(f"        → {url}")
        else:
            print(f"    {username}: not found")
        results.append(result)
    return results

    


# ═════════════════════════════════════════════
# 4. IPINFO.IO — Enhanced IP Intelligence
# ═════════════════════════════════════════════

def ipinfo_lookup(ip):
    """
    Get detailed IP intelligence from ipinfo.io.
    Free tier: 50k requests/month.
    """
    try:
        url = f"https://ipinfo.io/{ip}/json"
        params = {}
        if IPINFO_TOKEN:
            params["token"] = IPINFO_TOKEN

        r = requests.get(url, params=params, timeout=10)
        if r.status_code != 200:
            return {"ip": ip, "error": f"HTTP {r.status_code}"}

        data = r.json()
        result = {
            "ip": ip,
            "hostname": data.get("hostname", ""),
            "city": data.get("city", ""),
            "region": data.get("region", ""),
            "country": data.get("country", ""),
            "loc": data.get("loc", ""),  # lat,lon
            "org": data.get("org", ""),  # ASN + org name
            "postal": data.get("postal", ""),
            "timezone": data.get("timezone", ""),
        }

        # Privacy detection (paid feature)
        privacy = data.get("privacy", {})
        if privacy:
            result["vpn"] = privacy.get("vpn", False)
            result["proxy"] = privacy.get("proxy", False)
            result["tor"] = privacy.get("tor", False)
            result["relay"] = privacy.get("relay", False)
            result["hosting"] = privacy.get("hosting", False)

        # Abuse contact (paid feature)
        abuse = data.get("abuse", {})
        if abuse:
            result["abuse_email"] = abuse.get("email", "")
            result["abuse_phone"] = abuse.get("phone", "")

        # Company info (paid feature)
        company = data.get("company", {})
        if company:
            result["company_name"] = company.get("name", "")
            result["company_domain"] = company.get("domain", "")
            result["company_type"] = company.get("type", "")

        return result

    except Exception as e:
        return {"ip": ip, "error": str(e)[:80]}


def ip2location_lookup(ip):
    """Fallback IP geo using ip2location API."""
    if not IP2LOCATION_KEY:
        return None
    try:
        r = requests.get(
            f"https://api.ip2location.io/?key={IP2LOCATION_KEY}&ip={ip}&format=json",
            timeout=10,
        )
        if r.status_code == 200:
            return r.json()
        return None
    except:
        return None


def run_ip_intel(ips):
    """Run IP intelligence on discovered IPs."""
    if not ips:
        return []
    print(f"  Analyzing {len(ips)} IP address(es)...")
    results = []
    for ip in ips[:5]:
        result = ipinfo_lookup(ip)
        if result.get("error"):
            print(f"    {ip}: {result['error']}")
        else:
            org = result.get("org", "N/A")
            loc = f"{result.get('city', '')}, {result.get('country', '')}"
            print(f"    {ip}: {org} | {loc}")
            if result.get("vpn"):
                print(f"      ⚠ VPN detected")
            if result.get("tor"):
                print(f"      ⚠ Tor exit node")
            if result.get("hosting"):
                print(f"      → Hosting/datacenter IP")

        # ip2location fallback
        if IP2LOCATION_KEY and result.get("error"):
            ip2l = ip2location_lookup(ip)
            if ip2l:
                result["ip2location"] = ip2l
                print(f"    {ip} (ip2location): {ip2l.get('country_name', 'N/A')}")

        results.append(result)
    return results


# ═════════════════════════════════════════════
# 5. CENSYS — Certificate & Service Search
# ═════════════════════════════════════════════

def censys_search_hosts(query, max_results=10):
    """
    Search Censys for hosts matching a query.
    Free tier: 250 queries/day.
    """
    if not CENSYS_API_ID or not CENSYS_API_SECRET:
        return {"error": "CENSYS_API_ID and CENSYS_API_SECRET not set", "hosts": []}

    try:
        r = requests.get(
            "https://search.censys.io/api/v2/hosts/search",
            params={"q": query, "per_page": max_results},
            auth=(CENSYS_API_ID, CENSYS_API_SECRET),
            timeout=15,
        )
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}", "hosts": []}

        data = r.json()
        hits = data.get("result", {}).get("hits", [])
        hosts = []
        for hit in hits:
            hosts.append({
                "ip": hit.get("ip", ""),
                "services": [
                    {"port": s.get("port"), "service_name": s.get("service_name", ""),
                     "transport_protocol": s.get("transport_protocol", "")}
                    for s in hit.get("services", [])
                ],
                "location": hit.get("location", {}),
                "autonomous_system": hit.get("autonomous_system", {}),
                "operating_system": hit.get("operating_system", {}).get("product", ""),
            })
        return {"query": query, "total": data.get("result", {}).get("total", 0),
                "hosts": hosts}

    except Exception as e:
        return {"error": str(e)[:80], "hosts": []}


def censys_search_certs(domain):
    """Search Censys certificate transparency for a domain."""
    if not CENSYS_API_ID or not CENSYS_API_SECRET:
        return {"error": "Censys API keys not set", "certs": []}

    try:
        r = requests.get(
            "https://search.censys.io/api/v2/certificates/search",
            params={"q": f"names: {domain}", "per_page": 20},
            auth=(CENSYS_API_ID, CENSYS_API_SECRET),
            timeout=15,
        )
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}", "certs": []}

        data = r.json()
        hits = data.get("result", {}).get("hits", [])
        certs = []
        subdomains = set()
        for hit in hits:
            names = hit.get("names", [])
            for name in names:
                if name.endswith(domain) and name != domain:
                    subdomains.add(name)
            certs.append({
                "fingerprint": hit.get("fingerprint_sha256", "")[:16],
                "names": names[:5],
                "issuer": hit.get("issuer_dn", "")[:80],
                "not_after": hit.get("not_after", ""),
            })

        return {"domain": domain, "total_certs": len(certs),
                "subdomains_from_certs": sorted(subdomains),
                "certs": certs[:10]}

    except Exception as e:
        return {"error": str(e)[:80], "certs": []}


def run_censys(domain, ips=None):
    """Run Censys searches for a domain."""
    results = {}

    # Host search
    print(f"  Censys host search: {domain}")
    host_result = censys_search_hosts(domain)
    if host_result.get("error"):
        print(f"    Error: {host_result['error']}")
    else:
        print(f"    Found {host_result.get('total', 0)} hosts")
        for h in host_result.get("hosts", [])[:3]:
            ports = [str(s["port"]) for s in h.get("services", [])]
            print(f"    {h['ip']}: ports {', '.join(ports)}")
    results["hosts"] = host_result

    # Certificate search (finds subdomains)
    print(f"  Censys certificate search: {domain}")
    cert_result = censys_search_certs(domain)
    if cert_result.get("error"):
        print(f"    Error: {cert_result['error']}")
    else:
        subs = cert_result.get("subdomains_from_certs", [])
        print(f"    {cert_result.get('total_certs', 0)} certificates, "
              f"{len(subs)} subdomains from cert transparency")
        for s in subs[:10]:
            print(f"      → {s}")
    results["certs"] = cert_result

    return results


# ═════════════════════════════════════════════
# 6. PHONEINFOGA — Phone Number OSINT
# ═════════════════════════════════════════════

def phoneinfoga_lookup(phone_number):
    """
    Run PhoneInfoga on a phone number.
    Requires phoneinfoga CLI installed.
    """
    try:
        result = subprocess.run(
            ["phoneinfoga", "scan", "-n", phone_number],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            return {
                "number": phone_number,
                "raw": result.stdout[:2000],
                "success": True,
            }
        return {"number": phone_number, "error": result.stderr[:200], "success": False}

    except FileNotFoundError:
        return {"number": phone_number,
                "error": "phoneinfoga not installed (go install github.com/sundowndev/phoneinfoga/v2/cmd/phoneinfoga@latest)",
                "success": False}
    except Exception as e:
        return {"number": phone_number, "error": str(e)[:80], "success": False}


# ═════════════════════════════════════════════
# UNIFIED RUNNER
# ═════════════════════════════════════════════

def run_identity_osint(emails=None, usernames=None, ips=None, domain=None,
                       phones=None, enable_sherlock=True):
    """
    Run all identity OSINT modules on discovered data.
    Call this from osint_agent.py after the main pipeline.

    Args:
        emails: list of discovered email addresses
        usernames: list of usernames (auto-extracted from emails if not provided)
        ips: list of IP addresses
        domain: target domain (for Censys)
        phones: list of phone numbers (rare in OSINT)
        enable_sherlock: whether to run sherlock (slow)

    Returns: dict with all results
    """
    emails = emails or []
    usernames = usernames or []
    ips = ips or []
    phones = phones or []
    results = {}

    print(f"\n{'═'*55}")
    print(f"  Identity & Exposure OSINT")
    print(f"{'═'*55}")

    active, missing = identity_api_status()
    print(f"  Active : {', '.join(active)}")
    if missing:
        print(f"  Missing: {', '.join(missing)}")

    # ── HIBP ────────────────────────────────────
    if emails:
        print(f"\n{'─'*55}")
        print(f"  Breach Check (HaveIBeenPwned)")
        print(f"{'─'*55}")
        results["hibp"] = run_hibp(emails)

    # ── Holehe ──────────────────────────────────
    if emails:
        print(f"\n{'─'*55}")
        print(f"  Email Registration Check (Holehe)")
        print(f"{'─'*55}")
        results["holehe"] = run_holehe(emails)

    # ── Sherlock ────────────────────────────────
    if enable_sherlock:
        if not usernames and emails:
            usernames = extract_usernames_from_emails(emails)
            print(f"\n  Extracted usernames from emails: {usernames}")

        if usernames:
            print(f"\n{'─'*55}")
            print(f"  Username Search (Sherlock)")
            print(f"{'─'*55}")
            results["sherlock"] = run_sherlock(usernames)

    # ── IP Intelligence ─────────────────────────
    if ips:
        print(f"\n{'─'*55}")
        print(f"  IP Intelligence (ipinfo.io)")
        print(f"{'─'*55}")
        results["ip_intel"] = run_ip_intel(ips)

    # ── Censys ──────────────────────────────────
    if domain and CENSYS_API_ID:
        print(f"\n{'─'*55}")
        print(f"  Censys Search")
        print(f"{'─'*55}")
        results["censys"] = run_censys(domain, ips)

    # ── PhoneInfoga ─────────────────────────────
    if phones:
        print(f"\n{'─'*55}")
        print(f"  Phone Number OSINT (PhoneInfoga)")
        print(f"{'─'*55}")
        for phone in phones[:3]:
            result = phoneinfoga_lookup(phone)
            if result.get("success"):
                print(f"    {phone}: data found")
            else:
                print(f"    {phone}: {result.get('error', 'no data')}")
        results["phones"] = [phoneinfoga_lookup(p) for p in phones[:3]]

    # ── Summary ─────────────────────────────────
    print(f"\n{'═'*55}")
    print(f"  Identity OSINT Summary")
    print(f"{'═'*55}")

    breached = sum(1 for r in results.get("hibp", []) if r.get("breached"))
    registered = sum(r.get("registered_count", 0) for r in results.get("holehe", []))
    profiles = sum(r.get("found_count", 0) for r in results.get("sherlock", []))

    if breached:
        print(f"  [!] {breached} email(s) found in data breaches")
    if registered:
        print(f"  [!] {registered} site registration(s) found")
    if profiles:
        print(f"  [!] {profiles} social media profile(s) found")
    if not (breached or registered or profiles):
        print(f"  No identity exposure found")

    return results


# ─────────────────────────────────────────────
# INTEGRATION HELPER
# ─────────────────────────────────────────────

def integrate_identity_osint(osint_result, domain, enable_sherlock=False):
    """
    Auto-extract emails, IPs, usernames from OSINT results and run identity checks.
    Call after run_osint() completes.

    Usage in osint_agent.py:
        result = run_osint(target)
        from osint_identity import integrate_identity_osint
        result = integrate_identity_osint(result, target)
    """
    # Extract emails from findings
    emails = list(set(osint_result.get("emails", [])))
    for f in osint_result.get("findings", []):
        for e in f.get("evidence", {}).get("email_list", []):
            if e not in emails:
                emails.append(e)

    # Extract IPs from recon
    ips = []
    dns = osint_result.get("recon", {}).get("dns", "")
    for line in dns.split("\n"):
        if line.startswith("A:"):
            for ip in re.findall(r'\d+\.\d+\.\d+\.\d+', line):
                if ip not in ips:
                    ips.append(ip)

    # Extract usernames from emails
    usernames = extract_usernames_from_emails(emails) if emails else []

    # Run identity OSINT
    identity = run_identity_osint(
        emails=emails,
        usernames=usernames,
        ips=ips,
        domain=domain,
        enable_sherlock=enable_sherlock,
    )

    osint_result["identity"] = identity
    return osint_result


# ─────────────────────────────────────────────
# STANDALONE CLI
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="MCATester Identity OSINT Module",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python osint_identity.py --email jsmtih@altoromutual.com
  python osint_identity.py --email user@test.com --sherlock
  python osint_identity.py --username johndoe
  python osint_identity.py --ip 65.61.137.117
  python osint_identity.py --domain demo.testfire.net
  python osint_identity.py --phone "+1234567890"
        """)
    parser.add_argument("--email", action="append", help="Email to investigate (can repeat)")
    parser.add_argument("--username", action="append", help="Username to search (can repeat)")
    parser.add_argument("--ip", action="append", help="IP to analyze (can repeat)")
    parser.add_argument("--domain", help="Domain for Censys search")
    parser.add_argument("--phone", action="append", help="Phone number to investigate")
    parser.add_argument("--sherlock", action="store_true", help="Enable Sherlock username search")
    parser.add_argument("--all", action="store_true", help="Run all modules")
    args = parser.parse_args()

    if not any([args.email, args.username, args.ip, args.domain, args.phone]):
        parser.print_help()
        sys.exit(0)

    results = run_identity_osint(
        emails=args.email or [],
        usernames=args.username or [],
        ips=args.ip or [],
        domain=args.domain,
        phones=args.phone or [],
        enable_sherlock=args.sherlock or args.all,
    )

    # Print JSON summary
    print(f"\n{'─'*55}")
    print("Raw results (JSON):")
    # Only print non-empty results
    for key, val in results.items():
        if val:
            print(f"\n  {key}:")
            if isinstance(val, list):
                for item in val[:3]:
                    print(f"    {json.dumps(item, indent=2)[:200]}")
            elif isinstance(val, dict):
                print(f"    {json.dumps(val, indent=2)[:500]}")