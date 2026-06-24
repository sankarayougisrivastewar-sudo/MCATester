#!/usr/bin/env python3
"""
MCATester - osint_agent.py (v4 — Integrated Features)
Complete OSINT Pipeline + 3 Advanced Features:

NEW IN v4:
  [FEATURE 1] Recursive Asset Discovery — feeds every discovered subdomain
               back into DNS + port scanning. Catches 4th/5th tier domains.
  [FEATURE 2] AI Context Injector — Gemini mid-pipeline tactical decisions.
               Uses detected tech stack to generate targeted probe paths.
  [FEATURE 3] Delta Detection + Webhooks — compares each scan against
               previous scan for same host. Alerts on drift via Slack/
               Discord/Telegram.

All previous fixes retained:
  FIX A — open_ports enriched after tech detection (8080 added when Tomcat detected)
  FIX B — Active probe probes ALL reachable bases
  FIX C — JS analysis prioritises non-standard ports
  FIX D — Swagger UI confirmed in fetch stage via URL path match
  FIX E — crt.sh timeout raised to 25s with retry
  FIX F — VT subdomain parsing uses data[].id
  FIX G — Claude Haiku model string corrected
  FIX H — Response diffing tests login.jsp POST for SQLi
  FIX I — recon_emails Serper fallback when theHarvester missing
"""

import os
import re
import sys
import time
import socket
import subprocess
import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv
from output_formatter import fmt, format_final_report

# Patch output_formatter with clean_excerpt so osint_patches_v6 can import it
# (osint_patches_v6 imports clean_excerpt from output_formatter at probe time)
import output_formatter as _ofmt
import re as _re_patch
if not hasattr(_ofmt, 'clean_excerpt'):
    def _clean_excerpt_patch(content, max_len=300):
        text = _re_patch.sub(r'<[^>]+>', ' ', content[:800])
        text = _re_patch.sub(r'\s+', ' ', text).strip()
        return text[:max_len]
    _ofmt.clean_excerpt = _clean_excerpt_patch

from osint_patches_v6 import detect_waf_catchall, probe_single_waf_aware
from osint_patches_v6 import infer_passive_tech

# ── Feature imports ────────────────────────────────────────────────────────────
from recursive_discovery import run_recursive_discovery, RecursiveDiscovery

# Email filtering is now handled in recursive_discovery.py directly
from ai_context_injector  import inject_ai_context, ai_classify_finding
from delta_detection      import compute_delta, format_drift_for_dashboard
from orchestrator         import Orchestrator
from webhooks             import send_alert, send_scan_summary, send_drift_alert
try:
    from payload_injector import run_payload_injection
    PAYLOAD_INJECTOR_AVAILABLE = True
except ImportError:
    PAYLOAD_INJECTOR_AVAILABLE = False

try:
    from subdomain_takeover import run_subdomain_takeover, format_takeover_findings
    TAKEOVER_AVAILABLE = True
except ImportError:
    TAKEOVER_AVAILABLE = False
try:
    from cve_correlation import run_cve_correlation, format_cve_report
    CVE_CORRELATION_AVAILABLE = True
except ImportError:
    CVE_CORRELATION_AVAILABLE = False

try:
    from ai_decision_engine import run_ai_decisions
    AI_DECISIONS_AVAILABLE = True
except ImportError:
    AI_DECISIONS_AVAILABLE = False

load_dotenv()
urllib3.disable_warnings()

# ─────────────────────────────────────────────
# TARGET TYPE DETECTION
# ─────────────────────────────────────────────

def is_local_target(domain):
    d = domain.lower().strip()
    if d in ("localhost", "127.0.0.1", "::1"):
        return True
    try:
        ip = socket.gethostbyname(d)
        p = ip.split(".")
        if p[0] == "127": return True
        if p[0] == "10": return True
        if p[0] == "192" and p[1] == "168": return True
        if p[0] == "172" and 16 <= int(p[1]) <= 31: return True
    except Exception:
        pass
    return False


GEMINI_MODEL       = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
SHODAN_API_KEY     = os.getenv("SHODAN_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
SERPER_API_KEY     = os.getenv("SERPER_API_KEY", "")
LEAKIX_API_KEY     = os.getenv("LEAKIX_API_KEY", "")
URLSCAN_API_KEY    = os.getenv("URLSCAN_API_KEY", "")
ABUSEIPDB_API_KEY  = os.getenv("ABUSEIPDB_API_KEY", "")
OTX_API_KEY        = os.getenv("OTX_API_KEY", "")


def api_status():
    apis = {
        "Shodan":     SHODAN_API_KEY,
        "VirusTotal": VIRUSTOTAL_API_KEY,
        "Serper":     SERPER_API_KEY,
        "LeakIX":     LEAKIX_API_KEY,
        "urlscan":    URLSCAN_API_KEY,
        "AbuseIPDB":  ABUSEIPDB_API_KEY,
        "OTX":        OTX_API_KEY,
        "Gemini":     os.getenv("GEMINI_API_KEY",""),
        "Slack":      os.getenv("SLACK_WEBHOOK_URL",""),
        "Discord":    os.getenv("DISCORD_WEBHOOK_URL",""),
        "Telegram":   os.getenv("TELEGRAM_BOT_TOKEN",""),
    }
    active  = [k for k, v in apis.items() if v]
    missing = [k for k, v in apis.items() if not v]
    if active:  print(f"  APIs active  : {', '.join(active)}")
    if missing: print(f"  APIs missing : {', '.join(missing)} (add to .env for better results)")


def run_cmd(command, timeout=60):
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        out = result.stdout.strip()
        err = result.stderr.strip()
        ansi = re.compile(r'\x1b\[[0-9;]*m')
        if out:   return ansi.sub('', out)[:2000]
        elif err: return ansi.sub('', err)[:2000]
        return "[!] No output"
    except subprocess.TimeoutExpired:
        return f"[!] Timed out after {timeout}s"
    except FileNotFoundError:
        return f"[!] Tool not found: {command[0]}"
    except Exception as e:
        return f"[!] Error: {e}"


def banner(title):
    print(f"\n{'─'*55}\n  {title}\n{'─'*55}")


def http_get(url, timeout=8, max_bytes=50000, referer="https://www.google.com/"):
    try:
        r = requests.get(
            url, timeout=timeout, verify=False, stream=True,
            allow_redirects=True,
            headers={
                "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                   "AppleWebKit/537.36 (KHTML, like Gecko) "
                                   "Chrome/124.0.0.0 Safari/537.36",
                "Accept":          "text/html,application/xhtml+xml,application/json,text/plain,*/*",
                "Accept-Language": "en-US,en;q=0.9",
                "Referer":         referer,
                "Connection":      "keep-alive",
            },
        )
        content = b""
        for chunk in r.iter_content(4096):
            content += chunk
            if len(content) >= max_bytes:
                break
        return {"status": r.status_code, "content": content.decode("utf-8", errors="ignore"),
                "headers": dict(r.headers), "url": r.url, "error": None}
    except requests.exceptions.Timeout:
        return {"status": 0, "content": "", "headers": {}, "url": url, "error": "Timeout"}
    except requests.exceptions.ConnectionError:
        return {"status": 0, "content": "", "headers": {}, "url": url, "error": "Connection refused"}
    except Exception as e:
        return {"status": 0, "content": "", "headers": {}, "url": url, "error": str(e)[:80]}


def is_target_url(url, domain):
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        netloc = parsed.netloc.lower().lstrip("www.").split(":")[0]
        base   = domain.lower().lstrip("www.").split(":")[0]
        return netloc == base or netloc.endswith("." + base)
    except Exception:
        return False


# ─────────────────────────────────────────────
# PHASE 1 APIs  (unchanged from v3)
# ─────────────────────────────────────────────

def shodan_lookup(domain):
    ip = run_cmd(["dig", "+short", "A", domain], timeout=10)
    if not ip or "[!]" in ip:
        return None, [], {}
    ip = ip.strip().splitlines()[0]

    if SHODAN_API_KEY:
        try:
            r = requests.get(f"https://api.shodan.io/shodan/host/{ip}",
                             params={"key": SHODAN_API_KEY}, timeout=15)
            if r.status_code == 200:
                data       = r.json()
                open_ports = sorted(set(item["port"] for item in data.get("data", [])))
                vulns      = data.get("vulns", {})
                lines = [f"Shodan — {ip}",
                         f"  Org   : {data.get('org', 'N/A')}",
                         f"  OS    : {data.get('os', 'N/A')}",
                         f"  Ports : {open_ports}",
                         f"  Hosts : {', '.join(data.get('hostnames', [])) or 'None'}"]
                if vulns:
                    lines.append(f"  CVEs ({len(vulns)}): {', '.join(list(vulns.keys())[:5])}")
                    print(f"  Shodan CVEs: {', '.join(list(vulns.keys())[:5])}")
                for item in data.get("data", [])[:5]:
                    svc = f"{item.get('product','')} {item.get('version','')}".strip()
                    if svc: lines.append(f"  Port {item['port']}: {svc}")
                print(f"  Shodan: {len(open_ports)} ports, {len(vulns)} CVEs")
                return "\n".join(lines), open_ports, dict(vulns)
            else:
                print(f"  Shodan API HTTP {r.status_code} — trying InternetDB (free)")
        except Exception as e:
            print(f"  Shodan API error ({e}) — trying InternetDB")

    try:
        print(f"  Querying InternetDB for {ip}...")
        r = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=10,
                         headers={"User-Agent": "Mozilla/5.0"})
        if r.status_code == 200:
            data       = r.json()
            open_ports = sorted(data.get("ports", []))
            vulns_list = data.get("vulns", [])
            lines = [f"InternetDB (Shodan free) — {ip}",
                     f"  Ports : {open_ports}",
                     f"  Hosts : {', '.join(data.get('hostnames', [])) or 'None'}",
                     f"  Tags  : {', '.join(data.get('tags', [])) or 'None'}",
                     f"  CPEs  : {', '.join(data.get('cpes', [])[:3]) or 'None'}"]
            if vulns_list:
                lines.append(f"  CVEs ({len(vulns_list)}): {', '.join(vulns_list[:5])}")
                print(f"  InternetDB CVEs: {', '.join(vulns_list[:5])}")
            print(f"  InternetDB: {len(open_ports)} ports, {len(vulns_list)} CVEs")
            return "\n".join(lines), open_ports, {v: {} for v in vulns_list}
        elif r.status_code == 404:
            print(f"  InternetDB: no data for {ip}")
            return None, [], {}
        else:
            print(f"  InternetDB: HTTP {r.status_code}")
            return None, [], {}
    except Exception as e:
        print(f"  InternetDB error: {e}")
        return None, [], {}


def virustotal_subdomains(domain):
    if not VIRUSTOTAL_API_KEY:
        return []
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            params={"limit": 40}, timeout=15)
        if r.status_code != 200:
            print(f"  VirusTotal: HTTP {r.status_code}")
            return []
        data = r.json()
        subs = [item["id"] for item in data.get("data", [])
                if item.get("id", "").endswith(domain) and item["id"] != domain]
        print(f"  VirusTotal: {len(subs)} subdomains")
        return sorted(set(subs))
    except Exception as e:
        print(f"  VirusTotal error: {e}")
        return []


def serper_search(query, max_results=10):
    if not SERPER_API_KEY:
        return []
    try:
        r = requests.post("https://google.serper.dev/search",
                          headers={"X-API-KEY": SERPER_API_KEY, "Content-Type": "application/json"},
                          json={"q": query, "num": max_results}, timeout=10)
        if r.status_code != 200:
            return []
        return [{"href": item.get("link", ""), "body": item.get("snippet", "")}
                for item in r.json().get("organic", [])]
    except Exception:
        return []


def leakix_lookup(domain):
    if not LEAKIX_API_KEY:
        return ""
    try:
        r = requests.get(f"https://leakix.net/domain/{domain}",
                         headers={"api-key": LEAKIX_API_KEY, "Accept": "application/json"},
                         timeout=15)
        if r.status_code != 200:
            print(f"  LeakIX: HTTP {r.status_code}")
            return ""
        data   = r.json()
        events = data.get("Events", []) or []
        leaks  = data.get("Leaks",  []) or []
        lines  = [f"LeakIX — {domain}"]
        if events:
            lines.append(f"  Exposed services ({len(events)}):")
            for e in events[:5]:
                lines.append(f"    [{e.get('event_source','')}] {e.get('summary','')[:80]}")
        if leaks:
            lines.append(f"  Leaks found ({len(leaks)}):")
            for l in leaks[:3]:
                lines.append(f"    {l.get('summary','')[:80]}")
        if events or leaks:
            print(f"  LeakIX: {len(events)} services, {len(leaks)} leaks")
            return "\n".join(lines)
        return "LeakIX: no findings"
    except Exception as e:
        print(f"  LeakIX error: {e}")
        return ""


# ─────────────────────────────────────────────
# THREAT INTELLIGENCE  (unchanged from v3)
# ─────────────────────────────────────────────

def urlscan_lookup(domain):
    headers = {"User-Agent": "Mozilla/5.0"}
    if URLSCAN_API_KEY:
        headers["API-Key"] = URLSCAN_API_KEY
    try:
        r = requests.get("https://urlscan.io/api/v1/search/",
                         params={"q": f"domain:{domain}", "size": 5},
                         headers=headers, timeout=15)
        if r.status_code == 429:
            print("  urlscan: rate limited"); return ""
        if r.status_code != 200:
            print(f"  urlscan: HTTP {r.status_code}"); return ""
        results = r.json().get("results", [])
        if not results:
            print(f"  urlscan: no prior scans found for {domain}"); return ""
        lines        = [f"urlscan.io — {domain}"]
        malicious_ct = 0
        for scan in results[:3]:
            page    = scan.get("page", {})
            task    = scan.get("task", {})
            stats   = scan.get("stats", {})
            verdict = scan.get("verdicts", {}).get("overall", {})
            date    = task.get("time", "")[:10]
            ip      = page.get("ip", "?")
            server  = page.get("server", "?")
            is_mal  = verdict.get("malicious", False)
            mal_res = stats.get("malicious", 0)
            lines.append(f"  [{date}] IP: {ip} | Server: {server} | "
                         f"Malicious: {is_mal} | Malicious resources: {mal_res}")
            if is_mal:
                malicious_ct += 1
                lines.append(f"    [!] MALICIOUS — score: {verdict.get('score',0)} | "
                              f"categories: {', '.join(verdict.get('categories',[]))}")
            ss = task.get("screenshotURL", "")
            if ss:
                lines.append(f"    Screenshot: {ss}")
        status_str = f"MALICIOUS ({malicious_ct} scans)" if malicious_ct else "clean"
        print(f"  urlscan: {len(results)} scans — {status_str}")
        return "\n".join(lines)
    except Exception as e:
        print(f"  urlscan error: {e}"); return ""


def abuseipdb_lookup(domain):
    if not ABUSEIPDB_API_KEY:
        print("  AbuseIPDB: no API key"); return ""
    try:
        ip = run_cmd(["dig", "+short", "A", domain], timeout=10)
        if not ip or "[!]" in ip: return ""
        ip = ip.strip().splitlines()[0]
        r = requests.get("https://api.abuseipdb.com/api/v2/check",
                         headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
                         params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
                         timeout=15)
        if r.status_code != 200:
            print(f"  AbuseIPDB: HTTP {r.status_code}"); return ""
        data   = r.json().get("data", {})
        score  = data.get("abuseConfidenceScore", 0)
        reports= data.get("totalReports", 0)
        lines  = [f"AbuseIPDB — {ip}",
                  f"  Abuse score : {score}/100",
                  f"  Reports     : {reports} (last 90 days)",
                  f"  Last report : {data.get('lastReportedAt','N/A')}",
                  f"  ISP         : {data.get('isp','N/A')}",
                  f"  Country     : {data.get('countryCode','N/A')}",
                  f"  Usage type  : {data.get('usageType','N/A')}",
                  f"  Domain      : {data.get('domain','N/A')}"]
        if score >= 75:
            lines.append("  [!!!] CRITICAL — IP widely flagged as malicious")
            print(f"  AbuseIPDB: CRITICAL score {score}/100, {reports} reports")
        elif score >= 25:
            lines.append("  [!] SUSPICIOUS — moderate abuse reports")
            print(f"  AbuseIPDB: SUSPICIOUS score {score}/100, {reports} reports")
        else:
            print(f"  AbuseIPDB: score {score}/100, {reports} reports (clean)")
        for rep in data.get("reports", [])[:3]:
            cats    = ", ".join(str(c) for c in rep.get("categories", []))
            comment = rep.get("comment", "")[:80]
            date    = rep.get("reportedAt", "")[:10]
            lines.append(f"    [{date}] categories: {cats} — {comment}")
        return "\n".join(lines)
    except Exception as e:
        print(f"  AbuseIPDB error: {e}"); return ""


def otx_lookup(domain):
    headers = {}
    if OTX_API_KEY:
        headers["X-OTX-API-KEY"] = OTX_API_KEY
    base  = "https://otx.alienvault.com/api/v1/indicators"
    lines = [f"OTX AlienVault — {domain}"]
    found = False
    try:
        r = requests.get(f"{base}/domain/{domain}/general", headers=headers, timeout=15)
        if r.status_code == 200:
            data       = r.json()
            pulse_info = data.get("pulse_info", {})
            pulse_count= pulse_info.get("count", 0)
            lines.append(f"  Pulse count    : {pulse_count} threat reports")
            if pulse_count > 0:
                found = True
                print(f"  OTX: {pulse_count} threat pulses for {domain}")
                for p in pulse_info.get("pulses", [])[:5]:
                    line = f"    [{p.get('created','')[:10]}] {p.get('name','')[:80]}"
                    adv  = p.get("adversary", "")
                    tags = ", ".join(p.get("tags", [])[:4])
                    if adv: line += f" | Adversary: {adv}"
                    if tags: line += f" | Tags: {tags}"
                    lines.append(line)
        ip = run_cmd(["dig", "+short", "A", domain], timeout=10)
        if ip and "[!]" not in ip:
            ip = ip.strip().splitlines()[0]
            r4 = requests.get(f"{base}/IPv4/{ip}/general", headers=headers, timeout=15)
            if r4.status_code == 200:
                d4 = r4.json()
                ip_pulse = d4.get("pulse_info", {}).get("count", 0)
                rep = d4.get("reputation", 0)
                asn = d4.get("asn", "N/A")
                cty = d4.get("country_name", "N/A")
                lines.append(f"  IP {ip}: pulses={ip_pulse} | reputation={rep} | ASN={asn} | country={cty}")
                if ip_pulse > 0:
                    found = True
                    print(f"  OTX: {ip_pulse} threat pulses for IP {ip}")
        if not found:
            print(f"  OTX: no threat data for {domain}")
            lines.append("  No threat intelligence found")
        return "\n".join(lines)
    except Exception as e:
        print(f"  OTX error: {e}"); return ""


# ─────────────────────────────────────────────
# TECH-SPECIFIC PROBE PATHS  (unchanged)
# ─────────────────────────────────────────────

TECH_PROBE_PATHS = {
    "Tomcat": [
        "/WEB-INF/web.xml", "/WEB-INF/web.xml.bak",
        "/META-INF/context.xml", "/WEB-INF/applicationContext.xml",
        "/manager/html", "/manager/status", "/host-manager/html",
        "/WEB-INF/classes/application.properties",
        "/WEB-INF/classes/database.properties",
        "/console/", "/jmx-console/", "/web-console/",
        "/server-status",
        "/bank/", "/bank/login.jsp", "/bank/accounts.aspx",
        "/bank/transaction.aspx", "/bank/transfer.aspx",
        "/swagger/index.html", "/swagger/", "/swagger-ui.html",
    ],
    "WordPress": [
        "/wp-config.php", "/wp-config.php.bak", "/wp-config.php~",
        "/wp-content/debug.log", "/wp-content/uploads/",
        "/xmlrpc.php", "/wp-json/wp/v2/users",
        "/wp-includes/version.php", "/wp-cron.php",
    ],
    "Laravel": [
        "/.env", "/.env.backup", "/.env.production",
        "/storage/logs/laravel.log", "/vendor/autoload.php",
        "/_debugbar/", "/telescope/", "/api/user",
    ],
    "Django": [
        "/admin/", "/manage.py", "/__debug__/",
        "/static/admin/", "/api/schema/", "/api/docs/",
    ],
    "Node.js": [
        "/package.json", "/package-lock.json", "/.npmrc",
        "/node_modules/.bin/", "/.env", "/config/default.json",
    ],
    "PHP": [
        "/phpinfo.php", "/info.php", "/test.php",
        "/adminer.php", "/phpmyadmin/", "/.htaccess",
        "/.htpasswd", "/config.php", "/database.php",
        "/composer.json", "/composer.lock",
    ],
    "Apache": [
        "/server-status", "/server-info", "/.htaccess",
        "/.htpasswd", "/cgi-bin/", "/icons/",
    ],
    "Spring": [
        "/actuator", "/actuator/env", "/actuator/health",
        "/actuator/beans", "/actuator/mappings",
        "/v2/api-docs", "/swagger-ui.html", "/h2-console/",
    ],
    "IIS": [
        "/web.config", "/Web.config", "/_vti_bin/",
        "/trace.axd", "/elmah.axd",
    ],
}


def get_tech_paths(technologies):
    paths = set()
    for tech in technologies:
        for key, tech_paths in TECH_PROBE_PATHS.items():
            if key.lower() in tech.lower() or tech.lower() in key.lower():
                paths.update(tech_paths)
    return list(paths)


# ─────────────────────────────────────────────
# CONTENT VALIDATION  (unchanged)
# ─────────────────────────────────────────────

CONTENT_SIGNATURES = {
    "backup_file":      [b"PK\x03\x04", b"-- MySQL dump", b"mysqldump",
                         b"pg_dump", b"\x1f\x8b\x08", b"Rar!"],
    "login_page":       ['type="password"', "type='password'", 'name="password"',
                         'name="username"', 'id="loginForm"'],
    "error_disclosure": ["SQL syntax", "mysql_fetch", "ORA-", "Stack Trace",
                         "at java.lang.", "javax.servlet", "org.apache.catalina",
                         "Traceback (most recent", "Warning: include(", "Fatal error:"],
    "config_file":      ["DB_PASSWORD", "database_password", "connectionString",
                         "jdbc:mysql", "jdbc:postgresql", "SECRET_KEY", "APP_KEY="],
    "directory_listing":["Index of /", "Parent Directory", "[DIR]", "[TXT]"],
    "git_repository":   ["[core]", "repositoryformatversion",
                         '[remote "origin"]', "filemode = "],
    "env_file":         ["APP_ENV=", "DB_HOST=", "DB_PASSWORD=",
                         "REDIS_URL=", "AWS_ACCESS_KEY"],
    "swagger_content":  ["swagger", "openapi", "Swagger UI", "swagger-ui",
                         "/v2/api-docs", "/v3/api-docs"],
}


def validate_content(content, path):
    path_lower    = path.lower()
    content_lower = content.lower()

    if any(ext in path_lower for ext in (".zip", ".sql", ".bak", ".tar", ".gz", ".rar")):
        for sig in CONTENT_SIGNATURES["backup_file"]:
            if isinstance(sig, bytes):
                if sig in content.encode("utf-8", errors="ignore"):
                    return True, "Real backup file", [f"Binary signature detected"]
            elif sig.lower() in content_lower:
                return True, "Real backup/dump file", [sig]

    if any(x in path_lower for x in ("login", "signin", "auth")):
        matches = [s for s in CONTENT_SIGNATURES["login_page"] if s in content]
        if matches:
            return True, "Real login page", matches[:2]

    matches = [s for s in CONTENT_SIGNATURES["error_disclosure"] if s.lower() in content_lower]
    if matches:
        return True, "Error/stack trace disclosure", matches[:2]

    if any(ext in path_lower for ext in (".env", "config", "properties", "settings")):
        matches = [s for s in CONTENT_SIGNATURES["config_file"] if s in content]
        if matches:
            return True, "Real config file with sensitive data", matches[:2]

    matches = [s for s in CONTENT_SIGNATURES["directory_listing"] if s in content]
    if matches:
        return True, "Directory listing exposed", matches[:1]

    if ".git" in path_lower:
        matches = [s for s in CONTENT_SIGNATURES["git_repository"] if s in content]
        if matches:
            return True, "Real git repository exposed", matches[:2]

    if ".env" in path_lower:
        matches = [s for s in CONTENT_SIGNATURES["env_file"] if s in content]
        if matches:
            return True, "Real .env file with credentials", matches[:2]

    if any(x in path_lower for x in ("swagger", "api-docs", "openapi")):
        matches = [s for s in CONTENT_SIGNATURES["swagger_content"] if s.lower() in content_lower]
        if matches and len(content) > 500:
            return True, "Swagger/OpenAPI UI publicly accessible", matches[:2]

    return False, "", []


# ─────────────────────────────────────────────
# EVIDENCE EXTRACTION  (unchanged)
# ─────────────────────────────────────────────

EVIDENCE_PATTERNS = {
    "db_password":   r'(?:DB_PASSWORD|db_password|database_password)\s*[=:]\s*["\']?([^\s"\'<\n]{3,50})',
    "db_user":       r'(?:DB_USER|db_user|DB_USERNAME)\s*[=:]\s*["\']?([^\s"\'<\n]{2,30})',
    "db_host":       r'(?:DB_HOST|db_host)\s*[=:]\s*["\']?([^\s"\'<\n]{3,50})',
    "db_name":       r'(?:DB_NAME|db_name)\s*[=:]\s*["\']?([^\s"\'<\n]{2,30})',
    "app_key":       r'(?:APP_KEY|app_key)\s*[=:]\s*["\']?([^\s"\'<\n]{8,100})',
    "api_key":       r'(?:API_KEY|api_key|APIKEY)\s*[=:]\s*["\']?([^\s"\'<\n]{8,60})',
    "secret_key":    r'(?:SECRET_KEY|secret_key|SECRET)\s*[=:]\s*["\']?([^\s"\'<\n]{8,60})',
    "access_token":  r'(?:ACCESS_TOKEN|access_token)\s*[=:]\s*["\']?([^\s"\'<\n]{8,100})',
    "jwt_token":     r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
    "aws_key":       r'(?:AKIA|ASIA)[A-Z0-9]{16}',
    "aws_secret":    r'(?:aws_secret|AWS_SECRET)[_a-zA-Z]*\s*[=:]\s*["\']?([a-zA-Z0-9/+=]{30,50})',
    "private_key":   r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
    "oauth_secret":  r'(?:client_secret|clientSecret)\s*[=:]\s*["\']?([^\s"\'<\n]{8,60})',
    "smtp_password": r'(?:SMTP_PASSWORD|MAIL_PASSWORD|smtp_pass)\s*[=:]\s*["\']?([^\s"\'<\n]{3,50})',
    "ftp_password":  r'PWD\s*=\s*([^\s\n]{3,30})',
    "basic_auth":    r'Authorization:\s*Basic\s+([a-zA-Z0-9+/=]{10,})',
    "sql_dump":      r'(?:CREATE TABLE|INSERT INTO|DROP TABLE|ALTER TABLE)',
    "sql_error":     r'(?:You have an error in your SQL syntax|mysql_fetch_array\(\)|ORA-\d{4,5}|Warning: mysql_|Unclosed quotation mark|SQLSTATE\[|pg_query\(\): Query failed)',
    "sqli_result":   r'(?:information_schema\.tables|information_schema\.columns)',
    "php_version":   r'PHP Version\s+([\d.]+)',
    "server_info":   r'(?:Apache|nginx|IIS)[\s/]+([\d.]+)',
    "doc_root":      r'DOCUMENT_ROOT\s*</td><td[^>]*>([^<]+)',
    "git_config":    r'\[core\]\s*repositoryformatversion',
    "git_remote":    r'url\s*=\s*(https?://(?:github|gitlab|bitbucket|gogs)[^\s]+)',
    "git_author":    r'(?:email)\s*=\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
    "dir_listing":   r'Index of /[^\n<]{0,50}',
    "listed_files":  r'href="([^"]+\.(?:sql|env|bak|zip|tar|gz|config|conf|log|key|pem))"',
    "xss_reflected": r'<script>alert\([^\)]{0,20}\)</script>',
    "password_hash": r'\$(?:2[aby]|1|5|6)\$[a-zA-Z0-9./]{20,}',
    "wp_config":     r'define\s*\(\s*[\'"](?:DB_NAME|DB_USER|DB_PASSWORD)',
    "email_list":    r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    "swagger_ui":    r'swagger-ui|swagger\.json|openapi\.json|Swagger\s*UI|SwaggerUI|swagger-ui-bundle|swagger-ui\.css',
    "api_endpoint":  r'"(?:paths|basePath|host)"\s*:\s*"([^"]{3,60})"',
    "jsp_error":     r'(?:javax\.servlet|java\.lang\.|org\.apache\.)',
    "internal_ip":   r'(?:10\.|192\.168\.|172\.1[6-9]\.|172\.2\d\.|172\.3[0-1]\.)\d+\.\d+',
}

CRITICAL_PATTERNS = {
    "db_password", "app_key", "api_key", "secret_key", "jwt_token",
    "aws_key", "private_key", "oauth_secret", "sql_dump", "wp_config",
}
HIGH_PATTERNS = {
    "git_config", "git_remote", "php_version", "sql_error",
    "sqli_result", "ftp_password", "smtp_password", "listed_files",
    "swagger_ui", "api_endpoint", "jsp_error", "internal_ip",
}


def extract_evidence(content):
    findings = {}
    for name, pattern in EVIDENCE_PATTERNS.items():
        matches = re.findall(pattern, content, re.I | re.MULTILINE)
        if matches:
            clean = []
            for m in matches[:3]:
                val = m if isinstance(m, str) else (m[0] if isinstance(m, tuple) and m else "")
                val = val.strip()[:120]
                if val and val not in clean:
                    clean.append(val)
            if clean:
                findings[name] = clean
    return findings


def format_evidence(evidence):
    if not evidence:
        return ""
    lines = []
    for k, vals in list(evidence.items())[:8]:
        label = k.replace("_", " ").upper()
        for v in vals[:2]:
            display = v if len(v) <= 80 else v[:55] + "...[truncated]"
            lines.append(f"    [{label}] {display}")
    return "\n".join(lines)


def severity_from_evidence(evidence, base_severity):
    sev_rank = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    current  = sev_rank.get(base_severity, 2)
    if any(p in evidence for p in CRITICAL_PATTERNS): current = max(current, 4)
    elif any(p in evidence for p in HIGH_PATTERNS):   current = max(current, 3)
    return ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"][current]


def clean_excerpt(content, max_len=300):
    text = re.sub(r'<[^>]+>', ' ', content[:800])
    text = re.sub(r'\s+', ' ', text).strip()
    return text[:max_len]


# ─────────────────────────────────────────────
# SQLi VERIFICATION  (unchanged)
# ─────────────────────────────────────────────

REAL_DB_ERROR_PATTERNS = [
    r"You have an error in your SQL syntax",
    r"mysql_fetch_array\(\)", r"mysql_fetch_row\(\)", r"mysql_num_rows\(\)",
    r"ORA-\d{4,5}", r"Warning: mysql_", r"Warning: pg_",
    r"Unclosed quotation mark", r"SQLSTATE\[", r"pg_query\(\): Query failed",
    r"supplied argument is not a valid MySQL", r"Column count doesn't match",
    r"on MySQL result index",
]


def verify_sqli_on_target(url):
    result = http_get(url, timeout=10)
    if result["status"] in (0, 404):
        return {"confirmed": False, "error": result.get("error"), "status": result["status"]}
    content = result["content"]
    for pat in REAL_DB_ERROR_PATTERNS:
        m = re.search(pat, content, re.I)
        if m:
            return {"confirmed": True, "status": result["status"],
                    "error_text": m.group()[:120], "excerpt": clean_excerpt(content)}
    if re.search(r'information_schema\.tables|information_schema\.columns', content, re.I):
        return {"confirmed": True, "status": result["status"],
                "error_text": "information_schema data disclosed", "excerpt": clean_excerpt(content)}
    return {"confirmed": False, "status": result["status"]}


# ─────────────────────────────────────────────
# STAGE 1 — RECON
# ─────────────────────────────────────────────

def recon_dns(domain):
    banner("1a  DNS Reconnaissance")
    if is_local_target(domain):
        print(f"  Local target: 127.0.0.1")
        return "A: 127.0.0.1 (local)"
    lines = []
    for rtype in ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]:
        out = run_cmd(["dig", "+short", rtype, domain], timeout=10)
        if out and "[!]" not in out and out.strip():
            lines.append(f"{rtype}: {out.strip()[:200]}")
            print(f"  {rtype}: {out.strip()[:80]}")
    a = run_cmd(["dig", "+short", "A", domain], timeout=10)
    if a and "[!]" not in a:
        ip = a.strip().splitlines()[0]
        ptr = run_cmd(["dig", "+short", "-x", ip], timeout=10)
        lines.append(f"Reverse DNS {ip}: {ptr.strip()[:80]}")
    return "\n".join(lines) or "No DNS records found"


def recon_whois(domain):
    banner("1b  Whois Lookup")
    out = run_cmd(["whois", domain], timeout=30)
    important = []
    for line in out.splitlines():
        for field in ["Registrar:", "Registrant", "Created", "Updated",
                      "Expires", "Name Server", "Admin Email", "Status:"]:
            if field.lower() in line.lower():
                important.append(line.strip())
    print(f"  {len(important)} key fields extracted")
    return "\n".join(important[:20]) or out[:400]


def recon_ports(domain):
    banner("1c  Port Scan")
    if SHODAN_API_KEY and not is_local_target(domain):
        print("  Shodan API active — querying passively...")
        shodan_raw, shodan_ports, shodan_cves = shodan_lookup(domain)
        if shodan_raw and shodan_ports:
            return shodan_raw, shodan_ports
        print("  Shodan returned no data — falling back to nmap")

    ip = run_cmd(["dig", "+short", "A", domain], timeout=10)
    if not ip or "[!]" in ip:
        return f"Could not resolve {domain}", []
    ip = ip.strip().splitlines()[0]
    print(f"  Target IP: {ip}")
    nmap = run_cmd(["nmap", "-sT", "-sV", "-Pn", "-T3", "--top-ports", "100", domain], timeout=120)

    open_ports = []
    for line in nmap.splitlines():
        m = re.match(r"(\d+)/tcp\s+open", line)
        if m: open_ports.append(int(m.group(1)))

    if not open_ports:
        print("  Nmap found nothing — trying direct socket scan...")
        def check_port(port):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                result = s.connect_ex((ip, port))
                s.close()
                return port if result == 0 else None
            except Exception:
                return None
        with ThreadPoolExecutor(max_workers=10) as ex:
            for r in ex.map(check_port, [80, 443, 8080, 8443, 8000, 3000, 5000, 9090]):
                if r:
                    open_ports.append(r)
                    print(f"  Socket: port {r} OPEN")

    print(f"  Open ports: {open_ports or 'none detected'}")
    return f"IP: {ip}\n{nmap[:1500]}", open_ports


def recon_subdomains_passive(domain):
    subs = set()

    if VIRUSTOTAL_API_KEY:
        for sub in virustotal_subdomains(domain):
            subs.add(sub)
        if subs:
            print(f"  VirusTotal: {len(subs)} found, continuing to crt.sh...")

    try:
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}",
                         timeout=15, headers={"User-Agent": "Mozilla/5.0"})
        if r.status_code == 200 and "error" not in r.text.lower()[:30]:
            before = len(subs)
            for line in r.text.strip().splitlines():
                parts = line.split(",")
                if parts:
                    sub = parts[0].strip()
                    if sub.endswith(domain) and sub != domain:
                        subs.add(sub)
            print(f"  HackerTarget: {len(subs) - before} new subdomains")
    except Exception as e:
        print(f"  HackerTarget error: {e}")

    try:
        for attempt in range(2):
            try:
                r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json",
                                 timeout=25,
                                 headers={"Accept": "application/json", "User-Agent": "Mozilla/5.0"})
                if r.status_code == 200:
                    before = len(subs)
                    for entry in r.json():
                        name = entry.get("name_value", "")
                        for sub in name.splitlines():
                            sub = sub.strip().lstrip("*.")
                            if sub.endswith(domain) and sub != domain:
                                subs.add(sub)
                    print(f"  crt.sh: {len(subs) - before} new subdomains")
                    break
            except Exception as e:
                if attempt == 0:
                    print(f"  crt.sh attempt 1 failed ({e}) — retrying...")
                    time.sleep(3)
                else:
                    print(f"  crt.sh error: {e}")
    except Exception:
        pass

    if not subs:
        try:
            r = requests.get(f"https://rapiddns.io/subdomain/{domain}?full=1",
                             timeout=15, headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code == 200:
                for sub in re.findall(r'([a-zA-Z0-9_-]+\.' + re.escape(domain) + r')', r.text):
                    if sub != domain: subs.add(sub)
                print(f"  RapidDNS: {len(subs)} subdomains")
        except Exception as e:
            print(f"  RapidDNS error: {e}")

    return sorted(subs)

from osint_patches_v6 import clean_subdomain

def recon_subdomains(domain):
    banner("1d  Subdomain Enumeration")
    subdomains = []

    try:
        import sublist3r, io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            subs = sublist3r.main(domain, 40, None, None, False, False, False, None)
        if subs:
            for s in subs[:30]:
                cleaned = clean_subdomain(s, domain)
                if cleaned and cleaned not in subdomains:
                    subdomains.append(cleaned)
            print(f"  sublist3r: {len(subdomains)} subdomains found")
        else:
            print("  sublist3r: 0 results")
    except Exception as e:
        print(f"  sublist3r unavailable ({type(e).__name__}) — using passive sources")

    for sub in recon_subdomains_passive(domain):
        cleaned = clean_subdomain(sub, domain)
        if cleaned and cleaned not in subdomains:
            subdomains.append(cleaned)

    for sub in ["www","mail","ftp","admin","api","dev","staging","test",
                "vpn","remote","portal","shop","beta","cdn","static","app"]:
        out = run_cmd(["dig", "+short", f"{sub}.{domain}"], timeout=5)
        if out and "[!]" not in out and out.strip():
            fqdn = f"{sub}.{domain}"
            cleaned = clean_subdomain(fqdn, domain)
            if cleaned and cleaned not in subdomains:
                subdomains.append(cleaned)
                print(f"  Found: {cleaned}")

    print(f"  Total: {len(subdomains)} subdomains")
    return subdomains


def detect_tech_from_headers(domain, open_ports=None):
    candidates = [f"https://{domain}", f"http://{domain}"]
    for port in (open_ports or []):
        if port not in (80, 443):
            candidates.append(f"http://{domain}:{port}")

    result = {"status": 0, "headers": {}, "content": ""}
    for url in candidates:
        r = http_get(url, timeout=8)
        if r["status"] not in (0,):
            result = r; break

    h       = {k.lower(): v.lower() for k, v in result.get("headers", {}).items()}
    content = result.get("content", "").lower()
    detected = []

    checks = {
        "PHP":        lambda: "php" in h.get("x-powered-by", ""),
        "WordPress":  lambda: "wp-content" in content or "wp-json" in content,
        "Drupal":     lambda: "drupal" in content or "x-drupal-cache" in h,
        "Joomla":     lambda: "joomla" in content,
        "Laravel":    lambda: "xsrf-token" in str(h) or "laravel" in content,
        "Django":     lambda: "csrfmiddlewaretoken" in content,
        "React":      lambda: "__next_data__" in content or "react" in content,
        "Node.js":    lambda: "node" in h.get("x-powered-by", "") or "express" in h.get("x-powered-by", ""),
        "Python":     lambda: "python" in h.get("x-powered-by", "") or "flask" in h.get("server", ""),
        "Apache":     lambda: "apache" in h.get("server", ""),
        "Nginx":      lambda: "nginx" in h.get("server", ""),
        "Tomcat":     lambda: "coyote" in h.get("server", "") or "tomcat" in h.get("server", ""),
        "IIS":        lambda: "microsoft-iis" in h.get("server", ""),
        "Cloudflare": lambda: bool(h.get("cf-ray")),
        "ASP.NET":    lambda: "asp.net" in h.get("x-powered-by", "") or "aspnet" in str(h),
        "Java":       lambda: "jsessionid" in str(h) or "j_spring" in content,
    }
    for tech, fn in checks.items():
        try:
            if fn(): detected.append(tech)
        except Exception:
            pass

    server  = h.get("server", "")
    powered = h.get("x-powered-by", "")
    return detected, f"Server: {server} | X-Powered-By: {powered}" if (server or powered) else "No server headers"


def recon_tech(domain, open_ports=None):
    banner("1e  Tech Stack Detection")
    scan_url = f"http://{domain}"
    for port in (open_ports or []):
        if port not in (80, 443):
            scan_url = f"http://{domain}:{port}"; break

    whatweb = run_cmd(["whatweb", scan_url], timeout=20)
    if "[!] Tool not found" in whatweb or "Traceback" in whatweb or not whatweb.strip():
        whatweb = run_cmd(["whatweb", "-a", "3", "--open-timeout", "10", scan_url], timeout=20)

    tech_patterns = {
        "WordPress": r"wordpress|wp-content", "Drupal": r"drupal", "Joomla": r"joomla",
        "Laravel": r"laravel|XSRF-TOKEN", "Django": r"csrfmiddlewaretoken",
        "React": r"react|__NEXT_DATA__", "PHP": r"php", "Python": r"python|flask|django",
        "Node.js": r"node\.js|express", "Apache": r"apache", "Nginx": r"nginx",
        "Tomcat": r"tomcat|coyote|jsp", "IIS": r"microsoft-iis",
        "Cloudflare": r"cloudflare|cf-ray", "Java": r"java|jsessionid|j_spring",
        "jQuery": r"jquery",
    }
    detected = [t for t, p in tech_patterns.items() if re.search(p, whatweb, re.I)]

    if not detected or "[!] Tool not found" in whatweb:
        print("  WhatWeb unavailable or empty — using header-based detection")
        detected, raw_info = detect_tech_from_headers(domain, open_ports)
        raw = f"Technologies (header-based): {', '.join(detected) or 'None'}\n{raw_info}"
    else:
        print(f"  WhatWeb: {whatweb[:120]}")
        raw = f"Technologies: {', '.join(detected) or 'None'}\n\nWhatWeb: {whatweb[:500]}"

    if not detected:
        dns_text = run_cmd(["dig", "+short", "TXT", domain], timeout=10)
        mx_text = run_cmd(["dig", "+short", "MX", domain], timeout=10)
        ns_text = run_cmd(["dig", "+short", "NS", domain], timeout=10)
        all_dns = f"{dns_text}\n{mx_text}\n{ns_text}"
        passive = infer_passive_tech(all_dns)
        if passive:
            detected.extend(passive)
            print(f"  Passive inference: {', '.join(passive)}")
            raw += f"\nPassive (DNS-inferred): {', '.join(passive)}"

    print(f"  Detected: {detected or 'None'}")
    return {"technologies": detected, "raw": raw}


def recon_emails(domain):
    emails = []
    out = run_cmd(["theHarvester", "-d", domain, "-b", "bing,yahoo,duckduckgo", "-l", "50"], timeout=60)
    if out and "[!]" not in out:
        emails = list(set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', out)))
        if emails:
            print(f"  theHarvester: {len(emails)} emails")
            return emails
    if SERPER_API_KEY:
        results = serper_search(f'site:{domain} "@{domain}"', max_results=10)
        for r in results:
            found = re.findall(r'[a-zA-Z0-9._%+-]+@' + re.escape(domain), r.get("body", ""))
            emails.extend(found)
        emails = list(set(emails))
        if emails:
            print(f"  Emails via Serper: {len(emails)}")
    if not emails:
        print("  No emails found (theHarvester missing, Serper returned nothing)")
    return emails


def recon_github(domain):
    banner("1f  GitHub Recon")
    base    = domain.split(".")[0]
    results = []
    seen    = set()
    try:
        hdrs  = {"Accept": "application/vnd.github.v3+json"}
        token = os.getenv("GITHUB_TOKEN", "")
        if token: hdrs["Authorization"] = f"token {token}"
        r = requests.get("https://api.github.com/search/repositories",
                         params={"q": domain, "sort": "updated", "per_page": 10},
                         headers=hdrs, timeout=15)
        if r.status_code == 200:
            for repo in r.json().get("items", []):
                full = repo["full_name"]
                desc = (repo.get("description") or "").lower()
                name = repo["name"].lower()
                if (domain.lower() in name or domain.lower() in desc or base.lower() in name):
                    if full not in seen:
                        seen.add(full)
                        line = f"  {full} (updated {repo['updated_at'][:10]})"
                        results.append(line)
                        print(line)
        time.sleep(1)
        if not results: print(f"  No repos found mentioning {domain}")
        if token:
            for sq in [f"{domain} password", f"{domain} api_key", f"{domain} secret"]:
                cr = requests.get("https://api.github.com/search/code",
                                  params={"q": sq, "per_page": 3}, headers=hdrs, timeout=15)
                if cr.status_code == 200:
                    items = cr.json().get("items", [])
                    if items:
                        results.append(f"  Secret search '{sq}':")
                        for item in items[:3]:
                            results.append(f"    FOUND: {item['html_url']}")
                            print(f"    [!] Secret hit: {item['html_url']}")
                time.sleep(1)
    except Exception as e:
        results.append(f"GitHub error: {e}")
    return "\n".join(results) or "No relevant GitHub repos found"


# ─────────────────────────────────────────────
# STAGE 2 — GOOGLE DORKING  (unchanged)
# ─────────────────────────────────────────────

DORK_CATEGORIES = [
    ("CRITICAL", "Exposed env/config files",
     ['site:{d} ext:env', 'site:{d} ext:sql', 'site:{d} ext:bak', 'site:{d} "wp-config.php"']),
    ("CRITICAL", "Exposed credentials",
     ['site:{d} intext:"db_password"', 'site:{d} intext:"api_key"',
      'site:{d} intext:"secret_key"', 'site:{d} intext:password filetype:txt']),
    ("HIGH",  "Exposed git repositories",  ['site:{d} inurl:.git', 'site:{d} ".git/config"']),
    ("HIGH",  "Exposed admin panels",      ['site:{d} inurl:admin', 'site:{d} inurl:phpmyadmin', 'site:{d} inurl:cpanel']),
    ("HIGH",  "Backup files",              ['site:{d} inurl:backup', 'site:{d} ext:zip', 'site:{d} inurl:old']),
    ("HIGH",  "Tech disclosure",           ['site:{d} inurl:phpinfo', 'site:{d} intitle:"Apache HTTP Server"']),
    ("MEDIUM","Directory listings",        ['site:{d} "index of /"', 'site:{d} intitle:"index of"']),
    ("MEDIUM","Error messages",            ['site:{d} "SQL syntax"', 'site:{d} "Fatal error"', 'site:{d} "stack trace"']),
    ("MEDIUM","Login pages",               ['site:{d} inurl:login', 'site:{d} inurl:signin', 'site:{d} inurl:dashboard']),
    ("INFO",  "Subdomains",                ['site:*.{d} -www']),
    ("MEDIUM","Sensitive documents",       ['site:{d} filetype:pdf', 'site:{d} filetype:xlsx']),
    ("HIGH",  "Paste/leak sites",          ['site:pastebin.com "{d}"', 'site:github.com "{d}"']),
]


def dork_search(query, max_results=5):
    if SERPER_API_KEY:
        results = serper_search(query, max_results=max_results)
        if results: return results
    try:
        from ddgs import DDGS
        with DDGS() as ddgs:
            results = list(ddgs.text(query, max_results=max_results))
            time.sleep(1.2)
            return results
    except Exception:
        return []


def run_dorking(domain, extra_dorks=None):
    banner("2  Google Dorking")
    found_urls = {}
    for severity, category, dork_templates in DORK_CATEGORIES:
        print(f"  [{severity}] {category}")
        for template in dork_templates[:2]:
            dork = template.replace("{d}", domain)
            for r in dork_search(dork, max_results=5):
                url = r.get("href", "")
                if not url: continue
                skip = ["bing.com/aclick","google.com/aclk","doubleclick",
                        "googleadservices","ryrob.com","medium.com",
                        "hostinger.com","localhost.co","localhost8000"]
                if any(s in url for s in skip): continue
                if url not in found_urls:
                    found_urls[url] = {"severity": severity, "category": category,
                                       "snippet": r.get("body","")[:200], "dork": dork,
                                       "on_target": is_target_url(url, domain)}
                    marker = "✓" if found_urls[url]["on_target"] else "~"
                    print(f"    [{marker}] {url[:70]}")

    # ── FEATURE 2: Add AI-generated extra dorks ──────────────────────────────
    if extra_dorks:
        banner("2b  AI-Generated Dorks (Context Injector)")
        print(f"  Running {len(extra_dorks)} AI-targeted dorks...")
        for dork in extra_dorks[:10]:
            for r in dork_search(dork, max_results=5):
                url = r.get("href", "")
                if url and url not in found_urls:
                    found_urls[url] = {"severity": "HIGH", "category": "AI-Targeted Dork",
                                       "snippet": r.get("body","")[:200], "dork": dork,
                                       "on_target": is_target_url(url, domain)}
                    marker = "✓" if found_urls[url]["on_target"] else "~"
                    print(f"    [AI][{marker}] {url[:70]}")

    print(f"\n  Total unique URLs : {len(found_urls)}")
    print(f"  On-target URLs    : {sum(1 for v in found_urls.values() if v['on_target'])}")
    print(f"  Off-target (intel): {sum(1 for v in found_urls.values() if not v['on_target'])}")
    return found_urls


# ─────────────────────────────────────────────
# STAGE 3 — FETCH & EXTRACT  (unchanged)
# ─────────────────────────────────────────────

SPA_INDICATORS = [
    "<!doctype html", "<title>owasp juice shop</title>", "<title>juice shop</title>",
    "ng-app", "__next_data__", "window.__remixcontext", "react-root",
    'id="root"', 'id="app"',
]


def is_spa_catchall(content, path):
    if not content: return False
    cl = content.lower()
    if "<html" in cl or "<!doctype" in cl:
        if any(ind in cl for ind in SPA_INDICATORS): return True
        sensitive = (".env",".sql",".bak",".zip",".log",".config","/.git","/id_rsa")
        if any(path.lower().endswith(e) or e in path.lower() for e in sensitive):
            return True
    return False


def fetch_and_analyze(url, meta, open_ports=None):
    result = http_get(url)
    if result["status"] == 0 and open_ports:
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(url)
        for port in open_ports:
            if port not in (80, 443):
                retry_url = urlunparse(parsed._replace(netloc=f"{parsed.hostname}:{port}"))
                r2 = http_get(retry_url)
                if r2["status"] not in (0,):
                    result = r2; url = retry_url; break

    severity = meta["severity"]
    category = meta["category"]
    finding  = {
        "url": url, "category": category, "severity": severity,
        "status": result["status"], "evidence": {}, "confirmed": False,
        "vuln_type": "", "summary": "", "excerpt": "",
        "error": result["error"],
        "source": "on_target" if meta.get("on_target") else "intel_reference",
    }

    if result["error"] or result["status"] == 0:
        finding["summary"] = f"Fetch failed: {result['error']}"; return finding

    content   = result["content"]
    status    = result["status"]
    url_lower = url.lower()

    if status == 200 and meta.get("on_target") and is_spa_catchall(content, url):
        finding["summary"] = "SPA catch-all (not a real file)"; return finding

    if status == 403:
        # 403 = server is CORRECTLY protecting this path.
        # This is NOT a vulnerability — the path may exist but is blocked.
        # Only report as INFO so it doesn't pollute the findings list.
        finding.update(
            confirmed = False,
            severity  = "INFO",
            vuln_type = "Access controlled (403)",
            summary   = "Path exists but server is blocking access — not a vulnerability",
        )
        return finding

    if status == 404:
        finding["summary"] = "Not found (404)"; return finding
    if status not in (200, 206):
        finding["summary"] = f"HTTP {status}"; return finding

    # ── Infrastructure detection for 200 responses ────────────────────────
    # URLs that return 200 but contain no sensitive content patterns
    # are still valuable intelligence — categorize as infrastructure findings
    # Dedup check — skip if base URL already confirmed as infra
    url_base = url.split('?')[0]
    if hasattr(fetch_and_analyze, '_infra_seen'):
        if url_base in fetch_and_analyze._infra_seen:
            # Don't re-confirm same endpoint
            pass
    else:
        fetch_and_analyze._infra_seen = set()

    INFRA_SIGNALS = [
        # VPN / remote access
        (["vpn", "remote/login", "forticlient", "ssl-vpn", "sslvpn",
          "remote_login", "dana-na"],
         "HIGH", "VPN/Remote Access Portal Exposed",
         "Remote access portal publicly accessible — credential stuffing risk"),
        # Webmail
        (["webmail", "gw/webaccess", "/owa/", "zimbra", "roundcube",
          "groupwise", "webaccess"],
         "HIGH", "Webmail Portal Exposed",
         "Webmail portal accessible — authentication attack surface"),
        # Lotus Notes / Domino
        ([".nsf/", "names.nsf", "mail.nsf", "domino", "groupwise"],
         "HIGH", "Lotus Notes/Domino Database Accessible",
         "Legacy mail database endpoint exposed — potential user enumeration"),
        # Login portals
        (["login.do", "login.action", "signin", "fologin", "/login/"],
         "MEDIUM", "Login Portal Discovered",
         "Authentication endpoint discovered — note for credential testing"),
        # API endpoints
        (["mca-api", "/api/", "swagger", "openapi", "api-docs"],
         "HIGH", "API Endpoint Accessible",
         "API endpoint returning 200 — review for unauthenticated access"),
        # File serving APIs with path parameters
        (["get-file-by-path", "getdocument", "cdn?path", "file?path"],
         "HIGH", "File-Serving API Endpoint",
         "File API with path parameter — test for directory traversal"),
    ]

    url_lower_check = url.lower()
    for signals, infra_sev, infra_type, infra_summary in INFRA_SIGNALS:
        if any(sig in url_lower_check for sig in signals):
            if meta.get("on_target") and len(content) > 50:
                # Real infrastructure finding — mark confirmed
                # Skip if already confirmed this base URL
                if url_base in fetch_and_analyze._infra_seen:
                    break
                fetch_and_analyze._infra_seen.add(url_base)
                finding.update(
                    confirmed  = True,
                    severity   = infra_sev,
                    vuln_type  = infra_type,
                    summary    = infra_summary,
                    category   = "Infrastructure",
                    source     = "infrastructure",
                )
                print(f"  [INFRA] CONFIRMED: {infra_type}")
                print(f"    URL: {url[:80]}")
                # Still run content confirmation — may find secrets inside
                break

    evidence = extract_evidence(content)
    finding["evidence"] = evidence
    finding["excerpt"]  = clean_excerpt(content)

    is_real, real_type, real_ev = validate_content(content, url_lower)

    if ".env" in url_lower:
        finding.update(vuln_type="Exposed .env file",
                       confirmed=bool(meta.get("on_target")))
    elif ".git/config" in url_lower or evidence.get("git_config") or evidence.get("git_remote"):
        finding.update(vuln_type="Exposed git repository",
                       confirmed=bool(meta.get("on_target")))
    elif "phpinfo" in url_lower or "php version" in content.lower():
        finding.update(vuln_type="PHP info disclosure",
                       confirmed=bool(meta.get("on_target")))
    elif evidence.get("sql_dump") and meta.get("on_target"):
        finding.update(vuln_type="SQL database dump exposed", confirmed=True)
    elif evidence.get("dir_listing") or (
        "index of /" in content.lower() and "parent directory" in content.lower()
    ):
        finding.update(vuln_type="Directory listing enabled",
                       confirmed=bool(meta.get("on_target")))
        if meta.get("on_target"):
            evidence["dir_listing"] = ["Directory contents publicly listed"]
    elif evidence.get("sql_error") or evidence.get("sqli_result"):
        if meta.get("on_target"):
            finding.update(vuln_type="SQL error / injection point", confirmed=True)
        else:
            finding.update(vuln_type="SQLi payload reference (off-target)",
                           confirmed=False, severity="INFO",
                           summary="Mentioned SQLi payloads — not a direct finding")
    elif any(x in url_lower for x in ("swagger","api-docs","openapi")) and meta.get("on_target"):
        if is_real or evidence.get("swagger_ui"):
            finding.update(vuln_type="Swagger/OpenAPI UI publicly accessible",
                           confirmed=True, severity="HIGH")
    elif is_real and meta.get("on_target"):
        finding.update(vuln_type=real_type, confirmed=True)
        if real_ev:
            evidence["content_signature"] = real_ev
    elif evidence and meta.get("on_target"):
        finding.update(vuln_type=f"Sensitive data exposed ({', '.join(list(evidence.keys())[:3])})",
                       confirmed=True)
    elif (len(content) > 100 and
          url_lower.endswith((".env",".sql",".bak",".config",".log",".xml")) and
          meta.get("on_target")):
        finding.update(vuln_type="Sensitive file accessible", confirmed=True)

    if finding["confirmed"] and evidence:
        finding["severity"] = severity_from_evidence(evidence, severity)

    if finding["confirmed"]:
        finding["summary"] = (
            f"{finding['vuln_type']} — contains: {', '.join(list(evidence.keys())[:3])}"
            if evidence else finding["vuln_type"]
        )

    return finding


def run_fetch_stage(domain, dork_urls, open_ports=None):
    banner("3  Fetch & Extract Evidence")
    on_target  = {u:m for u,m in dork_urls.items() if m["on_target"]}
    off_target = {u:m for u,m in dork_urls.items() if not m["on_target"]}
    print(f"  On-target URLs    : {len(on_target)}  ← these are real findings")
    print(f"  Off-target (intel): {len(off_target)}  ← pastebin/github refs, not target vulns\n")

    sev_rank       = {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1,"INFO":0}
    sqli_indicators= ["union+select","union%20select","union select","order+by",
                      "information_schema","sleep(","benchmark("]
    findings       = []

    print("  [ON-TARGET] Fetching and analyzing...")
    for url, meta in sorted(on_target.items(), key=lambda x: sev_rank.get(x[1]["severity"],0), reverse=True):
        url_lower = url.lower()
        if any(ind in url_lower for ind in sqli_indicators):
            sqli = verify_sqli_on_target(url)
            if sqli["confirmed"]:
                findings.append({"url": url, "category": meta["category"], "severity": "HIGH",
                                  "status": sqli["status"], "evidence": {"sql_error": [sqli["error_text"]]},
                                  "confirmed": True, "vuln_type": "SQL Injection confirmed (live response)",
                                  "summary": f"DB error: {sqli['error_text']}",
                                  "excerpt": sqli.get("excerpt",""), "source": "on_target"})
                print(f"  [HIGH] CONFIRMED SQLi: {url[:70]}\n    DB error: {sqli['error_text']}")
            else:
                print(f"  [~] SQLi not confirmed (HTTP {sqli.get('status','?')}): {url[:60]}")
            time.sleep(0.5); continue

        finding = fetch_and_analyze(url, meta, open_ports)
        time.sleep(0.5)
        if finding["confirmed"]:
            print(f"  [{finding['severity']}] CONFIRMED: {finding['vuln_type']}\n    URL: {url[:75]}")
            ev_str = format_evidence(finding["evidence"])
            if ev_str: print(ev_str)
            findings.append(finding)
        elif finding["status"] == 200 and finding["summary"]:
            print(f"  [~] {finding['status']} {url[:65]}")

    print(f"\n  [INTEL REFS] Scanning off-target mentions (not counted as findings)...")
    intel_refs = []
    for url, meta in list(off_target.items())[:15]:
        finding = fetch_and_analyze(url, meta)
        if finding.get("evidence"):
            finding.update(source="intel_reference", severity="INFO", confirmed=False)
            intel_refs.append(finding)
            print(f"  [INTEL] {url[:65]}")
        time.sleep(0.3)

    confirmed = [f for f in findings if f["confirmed"]]
    print(f"\n  Confirmed on-target findings : {len(confirmed)}")
    print(f"  Intel references (off-target): {len(intel_refs)}")
    return findings, intel_refs


# ─────────────────────────────────────────────
# STAGE 4 — ACTIVE PROBING
# FEATURE 2: Uses AI-targeted paths when available
# ─────────────────────────────────────────────

PROBE_PATHS = {
    "CRITICAL": [
        "/.env", "/.env.local", "/.env.backup", "/.env.prod",
        "/config.php", "/wp-config.php", "/configuration.php",
        "/config/database.php", "/database.sql", "/db.sql", "/backup.sql",
        "/.git/config", "/.git/HEAD", "/id_rsa", "/.ssh/id_rsa",
    ],
    "HIGH": [
        "/phpinfo.php", "/info.php", "/test.php",
        "/phpmyadmin/", "/phpmyadmin/index.php", "/adminer.php",
        "/admin/", "/administrator/", "/wp-admin/", "/wp-login.php",
        "/backup/", "/backup.zip", "/backup.tar.gz",
        "/error.log", "/access.log", "/debug.log",
        "/WS_FTP.LOG", "/WS_FTP.ini", "/web.config",
    ],
    "MEDIUM": [
        "/robots.txt", "/sitemap.xml", "/.htaccess", "/.htpasswd",
        "/server-status", "/server-info",
        "/swagger/", "/swagger/index.html", "/swagger-ui.html",
        "/swagger.json", "/openapi.json",
        "/api-docs/", "/graphql", "/graphiql",
        "/actuator/", "/actuator/env", "/actuator/health",
        "/api/v1/", "/api/v2/", "/console/",
    ],
    "LOW": [
        "/login", "/login.php", "/login.jsp", "/signin", "/dashboard", "/portal",
        "/CHANGELOG.md", "/README.md", "/VERSION",
        "/package.json", "/composer.json", "/requirements.txt",
    ],
}


def probe_single(base_url, path, severity):
    url     = base_url.rstrip("/") + path
    result  = http_get(url, timeout=5)
    status  = result["status"]
    content = result["content"]

    if status in (0, 404): return None
    if status == 200 and is_spa_catchall(content, path): return None

    evidence   = extract_evidence(content) if content else {}
    is_finding = False
    reason     = ""
    sev        = severity

    if status == 200:
        is_real, real_type, real_ev = validate_content(content, path)
        if evidence:
            is_finding = True
            reason = "Accessible with sensitive content"
            sev    = severity_from_evidence(evidence, severity)
        elif is_real:
            is_finding = True
            reason = real_type
            if real_ev: evidence["content_signature"] = real_ev
        elif path in ("/.env","/.git/config","/wp-config.php","/config.php",
                      "/database.sql","/WEB-INF/web.xml") and len(content) > 20:
            is_finding = True
            reason = f"Sensitive file accessible ({len(content)} bytes)"
        elif path.endswith((".log",".sql",".bak",".zip")) and len(content) > 50:
            is_finding = True
            reason = "Sensitive file type accessible"
        elif any(p in path.lower() for p in ("phpmyadmin","adminer","/backup",
                                              "/manager","/host-manager",
                                              "/jmx-console","/web-console",
                                              "/jolokia")) and len(content) > 20:
            is_finding = True
            reason = f"Sensitive path accessible (HTTP 200, {len(content)} bytes)"
        elif "index of /" in content.lower() and "parent directory" in content.lower():
            is_finding = True
            reason = "Directory listing enabled"
            evidence["dir_listing"] = ["Directory contents exposed"]
    elif status == 403:
        # 403 = server is blocking access — not a confirmed vulnerability
        # Never report 403 as a finding; it just means the path is protected
        is_finding = False

    if not is_finding: return None
    return {"url": url, "path": path, "status": status, "severity": sev,
            "vuln_type": reason, "evidence": evidence, "summary": f"{reason} — {path}",
            "excerpt": clean_excerpt(content), "confirmed": False,
            "category": "Active Probe", "source": "on_target"}


def run_active_probe(domain, open_ports=None, technologies=None, ai_paths=None):
    banner("4  Active Probing")
    technologies = technologies or []

    # FIX A: enrich ports for Tomcat/Java
    enriched_ports = list(open_ports or [])
    if any("tomcat" in t.lower() or "java" in t.lower() or "apache" in t.lower()
           for t in technologies):
        for p in [8080, 8443, 8009]:
            if p not in enriched_ports:
                enriched_ports.append(p)
                print(f"  [FIX A] Added port {p} based on Tomcat/Java detection")

    # FIX B: discover ALL reachable base URLs
    candidates = []
    for port in enriched_ports:
        if port not in (80, 443):
            candidates.append(f"http://{domain}:{port}")
    candidates += [f"https://{domain}", f"http://{domain}"]

    reachable_bases = []
    for url_attempt in candidates:
        result = http_get(url_attempt, timeout=10)
        status = result["status"]
        if status == 503:
            print(f"  [{url_attempt}] HTTP 503 — waking up (15s)...")
            time.sleep(15)
            result = http_get(url_attempt, timeout=15)
            status = result["status"]
        if status not in (0,):
            server = result["headers"].get("Server", "")
            print(f"  Base: {url_attempt} — HTTP {status}" + (f" ({server})" if server else ""))
            reachable_bases.append(url_attempt)
        else:
            print(f"  [{url_attempt}] no response ({result.get('error','timeout')})")

    if not reachable_bases:
        print("  [!] Target unreachable on all ports")
        return []

    # ── FEATURE 2: Use AI-generated paths if available ─────────────────────
    if ai_paths:
        banner("4b  AI-Targeted Probe Paths (Context Injector)")
        print(f"  Using {len(ai_paths)} AI-generated paths instead of generic list")
        ai_base_paths = ai_paths  # list of (path, severity) tuples
        tech_specific = []        # skip generic tech paths when AI is providing them
    else:
        tech_specific = get_tech_paths(technologies)
        ai_base_paths = []

    base_paths  = [(path, sev) for sev, paths in PROBE_PATHS.items() for path in paths]
    extra_paths = [(p, "HIGH") for p in tech_specific
                   if p not in [x[0] for x in base_paths]]
    ai_extra    = [(p, s) for p, s in ai_base_paths
                   if p not in [x[0] for x in base_paths + extra_paths]]
    all_paths   = base_paths + extra_paths + ai_extra
    print(f"  Probing {len(all_paths)} paths × {len(reachable_bases)} base(s)...\n")

    findings  = []
    seen_keys = set()

    for base_url in reachable_bases:
        waf, waf_name, waf_hash, waf_len = detect_waf_catchall(base_url, http_get)

        with ThreadPoolExecutor(max_workers=15) as executor:
            futures = {executor.submit(
                probe_single_waf_aware,
                base_url, path, sev, http_get,
                waf_catch_all=waf,
                baseline_hash=waf_hash,
                baseline_length=waf_len,
                extract_evidence_fn=extract_evidence,
                is_spa_catchall_fn=is_spa_catchall,
            ): path for path, sev in all_paths}
            for future in as_completed(futures):
                r = future.result()
                if r:
                    dedup = r["path"] + str(r["status"])
                    if dedup not in seen_keys:
                        seen_keys.add(dedup)
                        findings.append(r)
                        print(f"  [{r['severity']}] {r['path']} (HTTP {r['status']}) via {base_url}")
                        print(f"    {r['vuln_type']}")
                        ev = format_evidence(r["evidence"])
                        if ev: print(ev)

        # ── FEATURE 2: AI classify ambiguous responses ──────────────────────
        if os.getenv("GEMINI_API_KEY"):
            for finding in findings:
                if finding.get("severity") in ("MEDIUM", "LOW") and not finding.get("ai_reviewed"):
                    ai_result = ai_classify_finding(
                        finding["url"],
                        finding.get("excerpt", ""),
                        finding.get("status", 0),
                        technologies
                    )
                    if ai_result.get("is_vulnerability") and ai_result.get("confidence", 0) > 70:
                        finding["severity"]   = ai_result.get("severity", finding["severity"])
                        finding["vuln_type"]  = ai_result.get("vuln_type", finding["vuln_type"])
                        finding["ai_reviewed"] = True
                        finding["ai_confidence"] = ai_result.get("confidence")
                        print(f"  [AI-RECLASSIFIED] {finding['path']} → {finding['severity']} "
                              f"(confidence: {ai_result.get('confidence')}%)")

    sev_rank = {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1,"INFO":0}
    findings.sort(key=lambda x: sev_rank.get(x["severity"],0), reverse=True)
    print(f"\n  Active probe findings: {len(findings)}")
    return findings


# ─────────────────────────────────────────────
# STAGE 5 — GEMINI REPORT  (unchanged)
# ─────────────────────────────────────────────

REMEDIATION = {
    "Missing security header: Strict-Transport-Security":
        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    "Missing security header: Content-Security-Policy":
        "Add CSP: Content-Security-Policy: default-src 'self'; script-src 'self'",
    "Missing security header: X-Frame-Options":
        "Add: X-Frame-Options: DENY",
    "Missing security header: X-Content-Type-Options":
        "Add: X-Content-Type-Options: nosniff",
    "Missing security header: Referrer-Policy":
        "Add: Referrer-Policy: strict-origin-when-cross-origin",
    "Missing security header: Permissions-Policy":
        "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
    "Insecure cookie":
        "Add Secure; HttpOnly; SameSite=Strict flags to all session cookies",
    "Info disclosure via header: Server":
        "Tomcat: remove Server header in server.xml",
    "Swagger/OpenAPI UI publicly accessible":
        "Restrict Swagger UI to internal networks or remove from production",
}

def get_remediation(vuln_type):
    if vuln_type in REMEDIATION: return REMEDIATION[vuln_type]
    for key, fix in REMEDIATION.items():
        if any(w in vuln_type.lower() for w in key.lower().split()[:3]):
            return fix
    return "Review OWASP guidelines: https://owasp.org/www-project-top-ten/"


def _format_identity(identity):
    lines = []
    for ip_data in identity.get("ip_intel", []):
        if not ip_data.get("error"):
            lines.append(f"IP {ip_data.get('ip','')}: {ip_data.get('org','')} | {ip_data.get('city','')}, {ip_data.get('country','')}")
    for h in identity.get("holehe", []):
        if h.get("registered_count", 0) > 0:
            sites = ", ".join(h.get("registered_sites", [])[:5])
            lines.append(f"Email {h.get('email','')}: registered on {h.get('registered_count',0)} sites ({sites})")
    for s in identity.get("sherlock", []):
        if s.get("found_count", 0) > 0:
            lines.append(f"Username {s.get('username','')}: found on {s.get('found_count',0)} platforms")
    return "\n".join(lines) if lines else "No identity exposure found"


def build_report_prompt(target, recon, all_findings, intel_refs=None):
    sev_rank = {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1,"INFO":0}
    all_findings.sort(key=lambda x: sev_rank.get(x.get("severity","INFO"),0), reverse=True)
    by_sev = {"CRITICAL":[],"HIGH":[],"MEDIUM":[],"LOW":[],"INFO":[]}
    for f in all_findings:
        by_sev.get(f.get("severity","INFO"), by_sev["INFO"]).append(f)

    finding_lines = []
    for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
        for f in by_sev[sev]:
            ev_str = " | ".join(
                f"{k}: {str(vals[0])[:80]}" if isinstance(vals, (list, tuple))
                else f"{k}: {str(vals)[:80]}"
                for k, vals in list(f.get("evidence",{}).items())[:4]
            )
            finding_lines.append(
                f"[{sev}] {f.get('vuln_type','Finding')} | URL: {f.get('url','')} | "
                f"Status: {f.get('status','')} | Evidence: {ev_str or f.get('summary','')[:100]}"
            )

    intel_lines = [f"  INTEL: {r.get('url','')} — {r.get('summary','')[:80]}"
                   for r in (intel_refs or [])[:5]]

    threat_intel_section = ""
    for key, label in [("urlscan","urlscan.io"),("abuseipdb","AbuseIPDB"),("otx","OTX AlienVault")]:
        if recon.get(key):
            threat_intel_section += f"\n{label}:\n{recon[key][:400]}\n"

    # Include recursive discovery summary if available
    recursive_section = ""
    if recon.get("recursive_discovery"):
        rd = recon["recursive_discovery"]
        summary = rd.get("summary", {})
        recursive_section = f"\nRECURSIVE ASSET DISCOVERY:\n"
        recursive_section += f"  Total assets: {summary.get('total_assets', 0)}\n"
        recursive_section += f"  Assets with open ports: {summary.get('assets_with_ports', 0)}\n"
        deep = summary.get("deepest_finds", [])
        if deep:
            recursive_section += f"  Deep targets: {', '.join(a['domain'] for a in deep[:5])}\n"

    context = f"""TARGET: {target}

=== INFRASTRUCTURE ===
DNS:\n{recon.get('dns','')}
PORTS:\n{recon.get('ports','')}
SUBDOMAINS ({len(recon.get('subdomains',[]))}):\n{', '.join(recon.get('subdomains',[])) or 'None'}
TECH STACK:\n{recon.get('tech_raw','')}
WHOIS:\n{recon.get('whois','')}
EMAILS:\n{', '.join(recon.get('emails',[])) or 'None'}
GITHUB:\n{recon.get('github','')}
{recursive_section}
{threat_intel_section}
=== CONFIRMED VULNERABILITY FINDINGS ({len(all_findings)} total on target) ===
CRITICAL: {len(by_sev['CRITICAL'])} | HIGH: {len(by_sev['HIGH'])} | MEDIUM: {len(by_sev['MEDIUM'])} | LOW: {len(by_sev['LOW'])}
{chr(10).join(finding_lines) if finding_lines else 'No confirmed vulnerabilities found.'}

=== INTEL REFERENCES (off-target — context only) ===
{chr(10).join(intel_lines) if intel_lines else 'None'}""".strip()[:7000]

    return f"""You are a senior penetration tester. Write a professional OSINT vulnerability report.
Use ONLY confirmed on-target findings for the vulnerability section.
Intel references are background context only.
Include threat intelligence in a dedicated section.
No invented findings. If a section has no data say "None found."

{context}

## Executive Summary
## Confirmed Vulnerabilities (each: [SEVERITY] Finding, URL, Status, Evidence, Impact)
## Infrastructure Summary
## Digital Footprint
## Threat Intelligence
## Intelligence References
## Attack Vectors (only confirmed on-target findings)"""


def write_report(target, recon, all_findings, intel_refs=None):
    banner("5  Generating Report with Gemini")
    api_key = os.getenv("GEMINI_API_KEY", "")
    if not api_key:
        print("  [!] GEMINI_API_KEY not found — plain text report")
        return build_plain_report(target, recon, all_findings)
    print(f"  API key loaded: {api_key[:12]}...")
    prompt = build_report_prompt(target, recon, all_findings, intel_refs)

    models = ["gemini-2.5-flash", "gemini-2.0-flash", "gemini-1.5-flash"]
    if GEMINI_MODEL not in models: models.insert(0, GEMINI_MODEL)
    payload = {"contents": [{"parts": [{"text": prompt}]}],
               "generationConfig": {"maxOutputTokens": 8192, "temperature": 0.3}}

    for attempt, model in enumerate(models):
        print(f"  Trying {model}...")
        url = (f"https://generativelanguage.googleapis.com/v1beta/models/"
               f"{model}:generateContent?key={api_key}")
        try:
            r = requests.post(url, json=payload, timeout=120)
            if r.status_code == 200:
                text = r.json()["candidates"][0]["content"]["parts"][0]["text"]
                print(f"  [{model}] Report generated OK")
                return text
            elif r.status_code == 429:
                msg  = r.json().get("error", {}).get("message", "")
                m    = re.search(r"retry[_ ]after[^0-9]*([0-9]+)", msg, re.I) or re.search(r"([0-9]+)\s*s", msg)
                wait = min(int(m.group(1)) + 5 if m else 60 * (attempt+1), 120)
                print(f"  [{model}] Rate limited — waiting {wait}s...")
                time.sleep(wait)
                r2 = requests.post(url, json=payload, timeout=120)
                if r2.status_code == 200:
                    text = r2.json()["candidates"][0]["content"]["parts"][0]["text"]
                    print(f"  [{model}] Report generated OK (after retry)")
                    return text
                print(f"  [{model}] Still rate limited — next model...")
            elif r.status_code == 503:
                print(f"  [{model}] Service unavailable — waiting {20*(attempt+1)}s...")
                time.sleep(20 * (attempt+1))
            elif r.status_code == 404:
                print(f"  [{model}] Not available — next...")
            else:
                print(f"  [{model}] HTTP {r.status_code} — next...")
        except Exception as e:
            print(f"  [{model}] Error: {str(e)[:60]} — next...")

    anthropic_key = os.getenv("ANTHROPIC_API_KEY", "")
    if anthropic_key:
        print("  Trying Anthropic Claude API as fallback...")
        try:
            r = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers={"x-api-key": anthropic_key, "anthropic-version": "2023-06-01",
                         "content-type": "application/json"},
                json={"model": "claude-haiku-4-5", "max_tokens": 4096,
                      "messages": [{"role": "user", "content": prompt}]},
                timeout=120)
            if r.status_code == 200:
                print("  [Claude Haiku] Report generated OK")
                return r.json()["content"][0]["text"]
            print(f"  [Claude] HTTP {r.status_code}")
        except Exception as e:
            print(f"  [Claude] Error: {e}")

    print("  [!] All AI models failed — plain text report")
    return build_plain_report(target, recon, all_findings)


def build_plain_report(target, recon, all_findings):
    sev_rank = {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1,"INFO":0}
    all_findings.sort(key=lambda x: sev_rank.get(x.get("severity","INFO"),0), reverse=True)
    by_sev = {"CRITICAL":[],"HIGH":[],"MEDIUM":[],"LOW":[],"INFO":[]}
    for f in all_findings:
        by_sev.get(f.get("severity","INFO"), by_sev["INFO"]).append(f)

    lines = [f"OSINT REPORT — {target}", "="*55,
             f"CRITICAL: {len(by_sev['CRITICAL'])} | HIGH: {len(by_sev['HIGH'])} | "
             f"MEDIUM: {len(by_sev['MEDIUM'])} | LOW: {len(by_sev['LOW'])}",
             "", "─── CONFIRMED VULNERABILITIES ───────────────────────"]
    for f in [f for f in all_findings if f.get("source") != "intel_reference"]:
        lines += [f"\n[{f.get('severity','?')}] {f.get('vuln_type','Finding')}",
                  f"  URL      : {f.get('url','')}",
                  f"  Status   : HTTP {f.get('status','')}",
                  f"  Category : {f.get('category','')}",
                  f"  Fix      : {get_remediation(f.get('vuln_type',''))}"]
        ev = format_evidence(f.get("evidence",{}))
        if ev: lines += ["  Evidence :", ev]
        elif f.get("summary"): lines.append(f"  Summary  : {f['summary'][:200]}")
    for key, label in [("urlscan","urlscan.io"),("abuseipdb","AbuseIPDB"),("otx","OTX")]:
        if recon.get(key):
            lines += ["", f"─── {label.upper()} ─────────────────────────────────────", recon[key][:400]]
    lines += ["", "─── INFRASTRUCTURE ──────────────────────────────────",
              recon.get("dns",""), f"\nSubdomains: {', '.join(recon.get('subdomains',[])) or 'None'}",
              "", recon.get("ports",""), "", "─── TECH / EMAILS / GITHUB ──────────────────────────",
              recon.get("tech_raw",""), f"\nEmails: {', '.join(recon.get('emails',[])) or 'None'}",
              "", recon.get("github",""), "", "─── WHOIS ───────────────────────────────────────────",
              recon.get("whois","")]

    identity = recon.get("identity", {})
    if identity:
        lines.append("")
        lines.append("─── IDENTITY OSINT ──────────────────────────────────")
        lines.append(_format_identity(identity))

    return "\n".join(lines)


# ─────────────────────────────────────────────
# STAGES 6-8  (unchanged from v3)
# ─────────────────────────────────────────────

JS_PATTERNS = {
    "aws_key":      r"(?:AKIA|ASIA)[A-Z0-9]{16}",
    "jwt_token":    r"eyJ[A-Za-z0-9_-]+[.]eyJ[A-Za-z0-9_-]+[.][A-Za-z0-9_-]+",
    "api_key":      r"api.?key.{0,5}[A-Za-z0-9_-]{16,60}",
    "s3_bucket":    r"s3[.]amazonaws[.]com/[A-Za-z0-9_.-]+",
    "private_path": r"/(admin|internal|private|debug|config|backup)/",
    "hardcoded_ip": r"(?:[0-9]{1,3}[.]){3}[0-9]{1,3}:[0-9]{2,5}",
    "firebase":     r"firebaseapp[.]com|firebaseio[.]com",
}


def extract_js_urls(html_content, base_url):
    from urllib.parse import urljoin, urlparse
    js_urls = []
    for m in re.finditer(r'<script[^>]+src=["\'"]([^"\']+)["\']', html_content, re.I):
        url = m.group(1)
        if url.startswith("http"):
            js_urls.append(url)
        elif url.startswith("//"):
            js_urls.append("https:" + url)
        elif url.startswith("/"):
            p = urlparse(base_url)
            js_urls.append(f"{p.scheme}://{p.netloc}{url}")
        else:
            js_urls.append(urljoin(base_url, url))
    return list(set(js_urls))


def analyze_js_file(url):
    result = http_get(url, timeout=8, max_bytes=200000)
    if result["status"] != 200 or not result["content"]: return None
    content  = result["content"]
    findings = {}
    for name, pattern in JS_PATTERNS.items():
        matches = re.findall(pattern, content, re.I)
        if matches:
            clean = list(set((m if isinstance(m, str) else m[0]).strip()[:100]
                             for m in matches[:3]))
            if clean: findings[name] = clean
    return {"url": url, "size": len(content), "findings": findings} if findings else None


def run_js_analysis(domain, open_ports=None):
    banner("6  JavaScript Analysis")

    candidates = []
    for port in (open_ports or []):
        if port not in (80, 443):
            candidates.append(f"http://{domain}:{port}")
    candidates += [f"https://{domain}", f"http://{domain}"]

    html_content, base_url = "", ""
    for url in candidates:
        r = http_get(url, timeout=8)
        if r["status"] == 200 and r["content"]:
            if "<script" in r["content"].lower():
                html_content, base_url = r["content"], url
                print(f"  HTML source from: {url}")
                break
            elif not html_content:
                html_content, base_url = r["content"], url

    if not html_content:
        print("  Could not fetch page for JS extraction"); return []

    js_urls = extract_js_urls(html_content, base_url)

    if not js_urls:
        from urllib.parse import urlparse
        p = urlparse(base_url)
        for path in ["/scripts/main.js", "/static/js/main.js", "/js/app.js",
                     "/app.js", "/main.js", "/bundle.js", "/dist/app.js"]:
            test_url = f"{p.scheme}://{p.netloc}{path}"
            r = http_get(test_url, timeout=5)
            if r["status"] == 200 and "function" in r["content"]:
                js_urls.append(test_url)
                print(f"  Found JS at: {test_url}")

    print(f"  Found {len(js_urls)} JS files")
    if not js_urls: return []

    findings = []
    with ThreadPoolExecutor(max_workers=5) as ex:
        for r in ex.map(analyze_js_file, js_urls[:20]):
            if r and r["findings"]:
                sev = "CRITICAL" if any(k in r["findings"] for k in ("aws_key","jwt_token")) else "HIGH"
                print(f"  [{sev}] {r['url'][:65]}")
                for k, vals in r["findings"].items():
                    print(f"    [{k.upper()}] {str(vals[0] if isinstance(vals, (list,tuple)) else vals)[:80]}")
                findings.append({
                    "url": r["url"], "category": "JS Analysis", "severity": sev,
                    "status": 200, "evidence": r["findings"], "confirmed": True,
                    "vuln_type": f"Sensitive data in JS ({', '.join(r['findings'].keys())})",
                    "summary": f"JS file leaks: {', '.join(r['findings'].keys())}",
                    "excerpt": "", "source": "on_target"})
    print(f"  JS findings: {len(findings)}")
    return findings


SECURITY_HEADERS = {
    "Strict-Transport-Security": ("HIGH",   "Missing HSTS — SSL stripping possible"),
    "Content-Security-Policy":   ("HIGH",   "Missing CSP — XSS not browser-mitigated"),
    "X-Frame-Options":           ("MEDIUM", "Missing X-Frame-Options — clickjacking possible"),
    "X-Content-Type-Options":    ("MEDIUM", "Missing X-Content-Type-Options — MIME sniffing"),
    "Referrer-Policy":           ("LOW",    "Missing Referrer-Policy — data leakage"),
    "Permissions-Policy":        ("LOW",    "Missing Permissions-Policy"),
}
LEAKY_HEADERS = {
    "Server": "Server software version disclosed",
    "X-Powered-By": "Backend technology disclosed",
    "X-AspNet-Version": "ASP.NET version disclosed",
    "X-Generator": "CMS/generator disclosed",
}


def run_header_analysis(domain, open_ports=None):
    banner("7  Header Security Analysis")
    candidates = [f"https://{domain}", f"http://{domain}"]
    for port in (open_ports or []):
        if port not in (80, 443):
            candidates.append(f"http://{domain}:{port}")

    headers, base_url = {}, ""
    for url in candidates:
        r = http_get(url, timeout=8)
        if r["status"] not in (0,):
            headers, base_url = r.get("headers", {}), url
            print(f"  Analyzing: {url} (HTTP {r['status']})"); break

    if not headers:
        print("  Could not fetch headers"); return []

    findings = []
    h_lower  = {k.lower(): v for k, v in headers.items()}

    print("\n  Security Headers:")
    for header, (sev, desc) in SECURITY_HEADERS.items():
        present = header.lower() in h_lower
        print(f"  {'OK' if present else 'MISSING':7} {header}")
        if not present:
            findings.append({"url": base_url, "category": "Header Analysis", "severity": sev,
                              "status": 200, "evidence": {"missing_header": [header]},
                              "confirmed": True, "vuln_type": f"Missing security header: {header}",
                              "summary": desc, "excerpt": "", "source": "on_target"})

    print("\n  Information Disclosure:")
    for header, desc in LEAKY_HEADERS.items():
        value = headers.get(header) or headers.get(header.lower(), "")
        if value:
            print(f"  LEAKS  {header}: {value[:60]}")
            findings.append({"url": base_url, "category": "Header Analysis", "severity": "MEDIUM",
                              "status": 200, "evidence": {"info_disclosure": [f"{header}: {value}"]},
                              "confirmed": True, "vuln_type": f"Info disclosure via header: {header}",
                              "summary": f"{desc} — {value[:80]}", "excerpt": "", "source": "on_target"})

    print("\n  Cookie Security:")
    for k, v in headers.items():
        if k.lower() == "set-cookie":
            issues = []
            if "httponly" not in v.lower(): issues.append("no HttpOnly")
            if "secure"   not in v.lower(): issues.append("no Secure")
            if "samesite" not in v.lower(): issues.append("no SameSite")
            if issues:
                name = v.split("=")[0]
                print(f"  WEAK   Cookie {name}: {', '.join(issues)}")
                findings.append({"url": base_url, "category": "Header Analysis", "severity": "MEDIUM",
                                  "status": 200, "evidence": {"insecure_cookie": [f"{name}: {', '.join(issues)}"]},
                                  "confirmed": True, "vuln_type": f"Insecure cookie: {name}",
                                  "summary": f"Cookie {name} has {', '.join(issues)}", "excerpt": "", "source": "on_target"})

    print(f"\n  Header findings: {len(findings)}")
    return findings


def run_response_diffing(domain, open_ports=None):
    banner("8  Response Diffing")
    base = f"https://{domain}"
    for port in (open_ports or []):
        if port not in (80, 443):
            base = f"http://{domain}:{port}"; break

    tests = [
        ("SQL error detection (GET)",
         f"{base}/", f"{base}/search?query=%27",
         ["sql syntax","mysql_fetch","ORA-","SQLSTATE","syntax error",
          "You have an error","Warning: mysql","unclosed quotation"]),
        ("Stack trace disclosure",
         f"{base}/", f"{base}/this_path_does_not_exist_xyz",
         ["stack trace","at org.","at com.","at java.","NullPointerException",
          "javax.servlet","org.apache.catalina","java.lang.Exception"]),
        ("Path traversal",
         f"{base}/", f"{base}/../../etc/passwd",
         ["root:","daemon:","nobody:"]),
        ("Verbose 500 errors",
         f"{base}/", f"{base}/index?id=99999999999",
         ["internal server error details","debug","traceback","ServletException"]),
    ]

    findings = []
    print(f"  Running diff tests...\n")

    for desc, url_a, url_b, leak_patterns in tests:
        r_a = http_get(url_a, timeout=6)
        r_b = http_get(url_b, timeout=6)
        if r_a["status"] == 0 or r_b["status"] == 0:
            print(f"  [-] {desc}: unreachable"); continue
        content_b = r_b["content"].lower()
        matched   = [p for p in leak_patterns if p.lower() in content_b]
        if matched:
            print(f"  [HIGH] {desc}: leaks {matched}")
            findings.append({"url": url_b, "category": "Response Diffing", "severity": "HIGH",
                              "status": r_b["status"], "evidence": {"verbose_error": matched},
                              "confirmed": True, "vuln_type": f"Verbose error: {desc}",
                              "summary": f"Response leaks: {', '.join(matched)}",
                              "excerpt": clean_excerpt(r_b["content"]), "source": "on_target"})
        elif r_a["status"] != r_b["status"]:
            print(f"  [~] {desc}: {r_a['status']} vs {r_b['status']}")
        else:
            print(f"  [-] {desc}: no difference")

    # FIX H: POST-based SQLi test against login form
    login_url = f"{base}/login.jsp"
    sqli_payloads = [
        ("uid=admin'--&passw=x&btnSubmit=Login", "login SQLi (comment)"),
        ("uid=' OR '1'='1&passw=x&btnSubmit=Login", "login SQLi (OR 1=1)"),
    ]
    sqli_patterns = ["sql syntax","mysql_fetch","ORA-","SQLSTATE","syntax error",
                     "You have an error","Warning: mysql","unclosed quotation",
                     "javax.servlet.ServletException","java.sql"]
    for payload, desc in sqli_payloads:
        try:
            r = requests.post(login_url, data=dict(p.split("=",1) for p in payload.split("&")),
                              timeout=8, verify=False,
                              headers={"User-Agent": "Mozilla/5.0",
                                       "Content-Type": "application/x-www-form-urlencoded"})
            content_lower = r.text.lower()
            matched = [p for p in sqli_patterns if p.lower() in content_lower]
            if matched:
                print(f"  [HIGH] {desc}: SQL error in response — {matched}")
                findings.append({"url": login_url, "category": "Response Diffing",
                                  "severity": "HIGH", "status": r.status_code,
                                  "evidence": {"sql_error": matched}, "confirmed": True,
                                  "vuln_type": f"SQL Injection via login form: {desc}",
                                  "summary": f"Login form returns SQL error: {', '.join(matched)}",
                                  "excerpt": clean_excerpt(r.text), "source": "on_target"})
            else:
                print(f"  [~] {desc}: no SQL error (HTTP {r.status_code})")
        except Exception as e:
            print(f"  [-] {desc}: {e}")

    print(f"\n  Diff findings: {len(findings)}")
    return findings


# ─────────────────────────────────────────────
# MAIN PIPELINE — v4 with all 3 features
# ─────────────────────────────────────────────

def run_osint(target, passive=False):
    import time as _time
    _scan_start = _time.time()  # track duration internally

    print(f"\n{'='*55}")
    print(f"  MCATester OSINT Pipeline v4")
    print(f"  Target : {target}")
    print(f"  Model  : {GEMINI_MODEL}")
    print(f"{'='*55}")
    api_status()

    recon = {
        "dns":        recon_dns(target),
        "whois":      recon_whois(target),
        "subdomains": recon_subdomains(target),
        "emails":     recon_emails(target),
        "github":     recon_github(target),
    }

    if LEAKIX_API_KEY and not is_local_target(target):
        banner("1g  LeakIX Passive Exposure")
        leakix_data = leakix_lookup(target)
        recon["leakix"] = leakix_data
        if leakix_data and "no findings" not in leakix_data:
            print(leakix_data[:300])

    if not is_local_target(target):
        banner("1h  Threat Intelligence (urlscan / AbuseIPDB / OTX)")
        recon["urlscan"]  = urlscan_lookup(target)
        recon["abuseipdb"]= abuseipdb_lookup(target)
        recon["otx"]      = otx_lookup(target)
        for key in ("urlscan","abuseipdb","otx"):
            if recon[key]: print(recon[key][:300])

    ports_raw, open_ports = recon_ports(target)
    recon["ports"]      = ports_raw
    recon["open_ports"] = open_ports

    shodan_cve_findings = []
    cve_matches = re.findall(r'CVE-\d{4}-\d+', ports_raw)
    for cve_id in cve_matches[:10]:
        shodan_cve_findings.append({
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "category": "Shodan CVE", "severity": "HIGH", "status": 200,
            "evidence": {"shodan_cve": [cve_id]}, "confirmed": True,
            "vuln_type": f"Known CVE detected by Shodan: {cve_id}",
            "summary": f"Shodan identified {cve_id} on target infrastructure",
            "excerpt": "", "source": "shodan_passive"})
    if shodan_cve_findings:
        print(f"  Shodan CVEs added as findings: {len(shodan_cve_findings)}")

    tech_result           = recon_tech(target, open_ports)
    recon["tech_raw"]     = tech_result["raw"]
    recon["technologies"] = tech_result["technologies"]

    # FIX A: enrich open_ports before subsequent stages
    enriched_ports = list(open_ports)
    if any("tomcat" in t.lower() or "java" in t.lower() or "apache" in t.lower()
           for t in recon["technologies"]):
        for p in [8080, 8443]:
            if p not in enriched_ports:
                enriched_ports.append(p)
                print(f"  Port {p} added to scan list (Tomcat/Java detected)")
    recon["open_ports"] = enriched_ports

    # ═══════════════════════════════════════════════════════════════════════
    # FEATURE 1: RECURSIVE ASSET DISCOVERY
    # Feeds every discovered subdomain back through DNS + port scanning
    # ═══════════════════════════════════════════════════════════════════════
    if not is_local_target(target):
        banner("1i  Recursive Asset Discovery [FEATURE 1]")
        print(f"  Starting recursive discovery — feeds new subdomains back into scanner...")

        # Clean emails out of subdomains list only — keep valid subdomains intact
        # Emails get mixed in from Serper/theHarvester and break DNS resolution
        recon["subdomains"] = [
            s for s in recon["subdomains"]
            if "@" not in s          # remove email addresses
            and " " not in s         # remove garbage with spaces
            and len(s) < 100         # remove absurdly long strings
        ]
        # Note: recursive_discovery.py discovers subdomains independently —
        # we clean the pre-existing list only, not its internal discovery

        recursive_result = run_recursive_discovery(
            root_domain         = target,
            max_depth           = 3,
            max_assets          = 100,
            progress_cb         = print,
            known_subdomains    = recon["subdomains"],  # pass stage 1d results
        )
        recon["recursive_assets"] = recursive_result.get("dashboard_assets", [])

        # Merge newly discovered subdomains into existing list
        existing_subs = set(recon["subdomains"])
        new_subs = [s for s in recursive_result["all_subdomains"] if s not in existing_subs]
        recon["subdomains"].extend(new_subs)
        recon["recursive_discovery"] = recursive_result

        summary = recursive_result.get("summary", {})
        print(f"\n  [RECURSIVE] Total assets: {summary.get('total_assets', 0)}")
        print(f"  [RECURSIVE] Assets with ports: {summary.get('assets_with_ports', 0)}")
        print(f"  [RECURSIVE] New subdomains: {len(new_subs)}")

        # Deep targets = high-value: port-open, depth >= 2
        deep_targets = recursive_result.get("new_scan_targets", [])
        if deep_targets:
            print(f"  [RECURSIVE] HIGH-VALUE deep targets: {deep_targets[:5]}")
            recon["deep_targets"] = deep_targets
    else:
        recursive_result = {}

    # ── Subdomain Takeover Detection ─────────────────────────────────────
    if TAKEOVER_AVAILABLE and recon.get("subdomains"):
        banner("1k  Subdomain Takeover Detection")
        all_subs = list(set(
            recon.get("subdomains", []) +
            recursive_result.get("all_subdomains", [])
        ))
        takeover_raw = run_subdomain_takeover(all_subs)
        takeover_findings = format_takeover_findings(takeover_raw)
        if takeover_findings:
            print(f"\n  [!] {len(takeover_findings)} takeover vulnerability(s) found!")
            for f in takeover_findings:
                print(f"    [{f['severity']}] {f['url']}")
        recon["takeover_findings"] = takeover_findings

    # ═══════════════════════════════════════════════════════════════════════
    # FEATURE 2: AI CONTEXT INJECTOR
    # Uses Gemini mid-pipeline to generate targeted paths
    # ═══════════════════════════════════════════════════════════════════════
    ai_context = {}
    if not passive and recon["technologies"]:
        banner("1j  AI Context Injector [FEATURE 2]")
        ai_context = inject_ai_context(
            technologies    = recon["technologies"],
            domain          = target,
            open_ports      = enriched_ports,
            initial_findings= [],
            verbose         = True
        )
        if ai_context:
            print(f"  [AI] Generated {len(ai_context.get('ai_paths', []))} targeted paths")
            print(f"  [AI] Extra dorks: {len(ai_context.get('extra_dorks', []))}")
    else:
        if passive:
            print("  [AI Context Injector] Skipped in passive mode")

    # Dork stage — passes AI-generated extra dorks
    dork_urls = run_dorking(target, extra_dorks=ai_context.get("extra_dorks", []))
    recon["dork_urls"] = dork_urls  # store for CVE correlation stage
    dork_findings, intel_refs = run_fetch_stage(target, dork_urls, enriched_ports)

    # Active probe — passes AI-generated paths
    probe_findings = (run_active_probe(
        target,
        enriched_ports,
        technologies = recon["technologies"],
        ai_paths     = ai_context.get("ai_paths", [])
    ) if not passive else [])

    js_findings     = run_js_analysis(target, enriched_ports)     if not passive else []
    header_findings = run_header_analysis(target, enriched_ports) if not passive else []
    diff_findings   = run_response_diffing(target, enriched_ports) if not passive else []

    all_findings = [f for f in
        dork_findings + probe_findings + shodan_cve_findings +
        js_findings + header_findings + diff_findings
        if f.get("confirmed")]

    # Log infrastructure findings separately for visibility
    infra_findings = [f for f in dork_findings if f.get("source") == "infrastructure"]
    if infra_findings:
        print(f"\n  [Infrastructure] {len(infra_findings)} asset(s) discovered:")
        for f in infra_findings:
            print(f"    [{f['severity']}] {f['vuln_type']}")
            print(f"      {f['url'][:80]}")

    # ═══════════════════════════════════════════════════════════════════════
    # FEATURE 4: ATTACK CHAIN ORCHESTRATOR
    # Pivots on confirmed findings to discover chained vulnerabilities
    # ═══════════════════════════════════════════════════════════════════════
    if not passive and all_findings:
        banner("4c  Attack Chain Orchestrator [FEATURE 4]")
        try:
            # Build seed list: confirmed findings + dork URLs as lightweight seeds
            # Dork URLs (e.g. swagger/index.html) may not pass confirmed=True
            # but still contain trigger patterns the orchestrator needs
            orc_seeds = list(all_findings)

            # Add dork URLs as seed findings if they contain trigger keywords
            TRIGGER_KEYWORDS = [
                # Web app frameworks / tools
                "swagger", "admin", ".git", "phpinfo", "wp-login",
                "manager", "actuator", "jenkins", "backup", ".env",
                "api-docs", "openapi", "laravel", "telescope", "horizon",
                # API patterns — catches /mca-api/, /api/, /v1/, /v2/
                "/api/", "mca-api", "get-file", "getdocument", "getfile",
                # VPN / remote access
                "vpn", "remote/login", "webaccess", "webmail",
                # File serving endpoints — high value for traversal
                "file-by-path", "file?path", "download?", "cdn?path",
                # Login portals
                "login.do", "login.action", "fologin", "webmail",
            ]
            for url, meta in dork_urls.items():
                if not meta.get("on_target"):
                    continue
                url_lower = url.lower()
                if any(kw in url_lower for kw in TRIGGER_KEYWORDS):
                    # Only add if not already in seeds
                    if not any(f.get("url") == url for f in orc_seeds):
                        orc_seeds.append({
                            "url":       url,
                            "severity":  "MEDIUM",
                            "vuln_type": meta.get("category", "Dork finding"),
                            "confirmed": True,
                            "summary":   f"Dork URL — potential trigger: {url}",
                            "evidence":  {},
                            "source":    "dork_seed",
                        })

            print(f"  Seeds: {len(all_findings)} confirmed + "
                  f"{len(orc_seeds)-len(all_findings)} dork trigger URLs")

            orc = Orchestrator(
                target       = target,
                open_ports   = enriched_ports,
                technologies = recon["technologies"],
                max_depth    = 3,
            )
            orchestrated = orc.run(orc_seeds, http_get)
            if orchestrated:
                existing_urls = {f["url"] for f in all_findings}
                new_orc = [f for f in orchestrated if f["url"] not in existing_urls]
                all_findings.extend(new_orc)
                print(f"  [Orchestrator] Added {len(new_orc)} chained findings to results")
        except Exception as e:
            print(f"  [Orchestrator] Error: {e}")

    # Identity OSINT
    identity_data = {}
    if not is_local_target(target):
        try:
            from osint_identity import run_ip_intel, run_holehe, run_hibp

            ips = []
            dns = recon.get("dns", "")
            for line in dns.split("\n"):
                for ip in re.findall(r'\d+\.\d+\.\d+\.\d+', line):
                    if ip not in ips:
                        ips.append(ip)
            if ips:
                identity_data["ip_intel"] = run_ip_intel(ips)

            emails = list(set(recon.get("emails", []) or []))
            for f in all_findings:
                for e in f.get("evidence", {}).get("email_list", []):
                    if e not in emails:
                        emails.append(e)

            if emails:
                banner("9b  Email Registration Check (Holehe)")
                identity_data["holehe"] = run_holehe(emails)

        except ImportError:
            print("  [!] osint_identity.py not found — skipping")

    recon["identity"] = identity_data

    # ── Payload Injection Stage ──────────────────────────────────────────
    if PAYLOAD_INJECTOR_AVAILABLE and not passive:
        banner("9z  Payload Injection Testing")
        print("  Testing login pages and API endpoints for injection vulnerabilities...")
        injection_findings = run_payload_injection(
            findings  = all_findings,
            dork_urls = recon.get("dork_urls", {}),
        )
        if injection_findings:
            print(f"\n  [!] {len(injection_findings)} injection vulnerability(s) confirmed!")
            for f in injection_findings:
                print(f"    [{f['severity']}] {f['vuln_type']}")
                print(f"          {f['url'][:80]}")
            all_findings.extend(injection_findings)
        else:
            print("  [✓] No injection vulnerabilities confirmed on tested targets")

    # ── CVE Correlation Stage ─────────────────────────────────────────────
    cve_matches = []
    if CVE_CORRELATION_AVAILABLE:
        banner("5a  CVE Correlation")

        # Build extended findings list — include recursive assets and
        # dork URLs as synthetic findings so CVE keywords can match
        # vpnv3.mca.gov.in, names.nsf etc even if not in all_findings
        extended_findings = list(all_findings)

        # Add recursive assets as synthetic findings
        for asset in recon.get("recursive_assets", []):
            domain = asset.get("domain", "")
            server = asset.get("server", "")
            title  = asset.get("title", "")
            if domain:
                extended_findings.append({
                    "url":       f"https://{domain}",
                    "vuln_type": f"Recursive asset: {server} {title}".strip(),
                    "summary":   f"Discovered subdomain: {domain}",
                    "severity":  "INFO",
                    "confirmed": True,
                    "source":    "recursive",
                })

        # Also add dork findings that weren't confirmed but contain
        # infrastructure keywords (VPN, NSF, GroupWise etc)
        INFRA_KEYWORDS = ["vpn", "remote/login", "nsf", "groupwise",
                          "webaccess", "tomcat", "phpinfo", "actuator",
                          "jenkins", "swagger", "fortinet"]
        for url in list(recon.get("dork_urls", {}).keys()):
            url_lower = url.lower()
            if any(kw in url_lower for kw in INFRA_KEYWORDS):
                extended_findings.append({
                    "url":       url,
                    "vuln_type": "Dork discovered URL",
                    "summary":   url,
                    "severity":  "INFO",
                    "confirmed": False,
                    "source":    "dork",
                })

        print(f"  Cross-referencing {len(extended_findings)} findings + assets...")
        cve_matches = run_cve_correlation(
            findings     = extended_findings,
            technologies = recon.get("technologies", []),
            enrich_nvd   = True,
        )
        if cve_matches:
            print(f"\n  [CVE] {len(cve_matches)} CVE(s) correlated:")
            for m in cve_matches:
                print(f"    [{m['severity']}] {m['cve_id']} CVSS {m['cvss']} — {m['title'][:55]}")
            # Add CVE findings to all_findings as CRITICAL/HIGH findings
            for m in cve_matches:
                if m["cvss"] >= 7.0:
                    all_findings.append({
                        "url":       m.get("finding_url") or f"https://{target}",
                        "severity":  m["severity"],
                        "vuln_type": f"CVE Correlation: {m['cve_id']}",
                        "summary":   m["title"],
                        "confirmed": True,
                        "source":    "cve_correlation",
                        "category":  "CVE Intelligence",
                        "evidence":  {
                            # All values must be strings or lists — never floats
                            # PDF/report generators do vals[0][:80] on these
                            "cve_id":   [m["cve_id"]],
                            "cvss":     [str(m["cvss"])],
                            "impact":   [m["impact"]],
                            "affected": [m["affected"]],
                            "poc_url":  [m["poc_url"]],
                        },
                        "fix": f"Apply vendor patch: {m['patch_url']}",
                    })
            # Recount severities
            by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
            for f in all_findings:
                by_sev[f.get("severity", "INFO")] = \
                    by_sev.get(f.get("severity", "INFO"), 0) + 1
        else:
            print("  [CVE] No CVE correlations found for this target")
        recon["cve_matches"] = cve_matches

    # ── AI Decision Engine ───────────────────────────────────────────────
    ai_decisions = {}
    if AI_DECISIONS_AVAILABLE:
        banner("5b  AI Decision Engine (Groq)")
        try:
            ai_decisions = run_ai_decisions(
                target    = target,
                recon     = recon,
                findings  = all_findings,
                cve_matches = recon.get("cve_matches", []),
            )
            recon["ai_decisions"] = ai_decisions

            # Add AI risk assessment to findings for report
            final = ai_decisions.get("final_assessment", {})
            if final.get("executive_summary"):
                recon["ai_executive_summary"] = final["executive_summary"]
            if final.get("technical_summary"):
                recon["ai_technical_summary"] = final["technical_summary"]
            if final.get("immediate_actions"):
                recon["ai_immediate_actions"] = final["immediate_actions"]
        except Exception as e:
            print(f"  [AI-Agent] Decision engine error: {e}")

    report = write_report(target, recon, all_findings, intel_refs)

    by_sev = {"CRITICAL":[],"HIGH":[],"MEDIUM":[],"LOW":[],"INFO":[]}
    for f in all_findings:
        by_sev.get(f.get("severity","INFO"), by_sev["INFO"]).append(f)

    # ═══════════════════════════════════════════════════════════════════════
    # FEATURE 3: DELTA DETECTION + WEBHOOKS
    # Compare against previous scan, alert on regressions
    # ═══════════════════════════════════════════════════════════════════════
    current_result = {
        "target":       target,
        "subdomains":   recon["subdomains"],
        "technologies": recon["technologies"],
        "findings":     all_findings,
        "intel_refs":   intel_refs,
        "report":       report,
        "recon":        recon,
        "recursive_summary": recursive_result.get("summary", {}),
    }

    # Suppress verbose INFO logs from search.py DDG during pipeline
    import logging as _logging
    _logging.getLogger("mcatester.search").setLevel(_logging.WARNING)

    # Webhook: alert on High/Critical findings
    try:
        duration_s = _time.time() - _scan_start
        send_scan_summary(target, by_sev, duration_s=duration_s)
        for f in all_findings:
            send_alert(f, target)
        print(f"\n  [Webhooks] Alerts sent for {len([f for f in all_findings if f.get('severity') in ('CRITICAL','HIGH')])} High+ findings")
    except Exception as e:
        print(f"  [Webhooks] Error: {e}")

    print(f"\n{'='*55}")
    print(f"  OSINT Complete — {target}")
    print(f"  CRITICAL : {len(by_sev['CRITICAL'])}")
    print(f"  HIGH     : {len(by_sev['HIGH'])}")
    print(f"  MEDIUM   : {len(by_sev['MEDIUM'])}")
    print(f"  LOW      : {len(by_sev['LOW'])}")
    print(f"  Subdomains  : {len(recon['subdomains'])}")
    print(f"  Technologies: {recon['technologies']}")
    if recursive_result:
        rd_sum = recursive_result.get("summary", {})
        print(f"  Assets (recursive): {rd_sum.get('total_assets', 0)}")
    print(f"{'='*55}")

    return current_result


def run_osint_crew(target):
    return run_osint(target)


def osint_to_scan_targets(osint_result, base_domain):
    targets = [base_domain]
    for sub in osint_result.get("subdomains", []):
        if sub not in targets: targets.append(sub)
    return targets[:10]


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    from datetime import datetime

    parser = argparse.ArgumentParser(description="MCATester OSINT Agent v4")
    parser.add_argument("domain", nargs="?", help="Target domain")
    parser.add_argument("--passive", action="store_true",
                        help="Passive mode: skip Stage 4 active probing")
    parser.add_argument("--no-save", action="store_true",
                        help="Do not save report to file")
    parser.add_argument("--no-recursive", action="store_true",
                        help="Skip recursive asset discovery")
    parser.add_argument("--no-ai-context", action="store_true",
                        help="Skip AI context injector")
    args = parser.parse_args()

    print("MCATester OSINT Agent v4")
    print("="*55)
    print("WARNING: Only use on domains you own or have permission to test")
    print("="*55)

    key = os.getenv("GEMINI_API_KEY", "")
    print(f"\nGemini key : {'set (' + key[:10] + '...)' if key else 'NOT SET'}")
    print(f"Model      : {GEMINI_MODEL}")
    if args.passive:    print("Mode       : PASSIVE (Stage 4 active probing disabled)")
    if not args.no_recursive: print("Recursive  : ENABLED (3 levels deep)")
    if not args.no_ai_context and key: print("AI Context : ENABLED (Gemini mid-pipeline)")

    target = args.domain or input("\nEnter domain (e.g. testphp.vulnweb.com): ").strip()
    if not target: target = "vulnweb.com"

    result = run_osint(target, passive=args.passive)

    # 403 bypass
    try:
        from bypass_403 import run_403_bypass_stage
        bypass = run_403_bypass_stage(result.get("findings", []))
        if bypass:
            result["findings"].extend(bypass)
    except ImportError:
        print("  [!] bypass_403.py not found — skipping 403 bypass")

    # PDF report
    try:
        from osint_features import generate_pdf_report
        generate_pdf_report(result, target)
    except ImportError:
        print("  [!] osint_features.py not found — skipping PDF")

    # Clean structured output
    try:
        from output_formatter import format_final_report, fmt
        fmt.summary(target, result.get("findings", []), result.get("recon", {}))
        format_final_report(result, target)
    except ImportError:
        print("\n" + "="*55 + "\nINTELLIGENCE REPORT\n" + "="*55)
        print(result["report"])

    if not args.no_save:
        ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"report_{target.replace('.','_')}_{ts}.md"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(f"# OSINT Report — {target}\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Mode:** {'Passive' if args.passive else 'Full'}\n\n---\n\n")
            f.write(result["report"])
        print(f"\n  Report saved → {filename}")