#!/usr/bin/env python3
"""
MCATester - subdomain_takeover.py
Subdomain Takeover Detection

Checks discovered subdomains for dangling CNAME records pointing
to unclaimed services — a direct path to full subdomain control.

How it works:
  1. Resolve each subdomain's CNAME chain
  2. Check if the CNAME target matches a known takeover-vulnerable service
  3. Probe the CNAME target to see if it returns a "not found" fingerprint
  4. If fingerprint matches — subdomain is takeable

Services checked: GitHub Pages, Heroku, Netlify, Vercel, Fastly,
Shopify, Tumblr, WordPress.com, Squarespace, HubSpot, AWS S3,
Azure, Zendesk, Surge.sh, Readme.io and more.
"""

import re
import socket
import requests
import urllib3
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings()
logger = logging.getLogger("mcatester.takeover")
logger.setLevel(logging.WARNING)

# ─────────────────────────────────────────────────────────────────────────────
# FINGERPRINT DATABASE
# Each entry: service name, CNAME pattern, response fingerprint,
# severity, and description
# ─────────────────────────────────────────────────────────────────────────────

TAKEOVER_FINGERPRINTS = [
    {
        "service":     "GitHub Pages",
        "cname":       ["github.io", "github.com"],
        "fingerprint": ["there isn't a github pages site here",
                        "for root url (/)"],
        "severity":    "HIGH",
        "description": "CNAME points to GitHub Pages — claim by creating repo at username/subdomain",
        "difficulty":  "Easy",
    },
    {
        "service":     "Heroku",
        "cname":       ["herokuapp.com", "herokussl.com", "herokudns.com"],
        "fingerprint": ["no such app", "herokucdn.com/error-pages/no-such-app"],
        "severity":    "HIGH",
        "description": "CNAME points to unclaimed Heroku app — register the app name",
        "difficulty":  "Easy",
    },
    {
        "service":     "Netlify",
        "cname":       ["netlify.app", "netlify.com"],
        "fingerprint": ["not found - request id", "netlify"],
        "severity":    "HIGH",
        "description": "CNAME points to unclaimed Netlify site",
        "difficulty":  "Easy",
    },
    {
        "service":     "Vercel",
        "cname":       ["vercel.app", "vercel.io", "now.sh"],
        "fingerprint": ["the deployment could not be found",
                        "vercel.com/404"],
        "severity":    "HIGH",
        "description": "CNAME points to unclaimed Vercel deployment",
        "difficulty":  "Easy",
    },
    {
        "service":     "Fastly",
        "cname":       ["fastly.net"],
        "fingerprint": ["fastly error: unknown domain",
                        "please check that this domain"],
        "severity":    "HIGH",
        "description": "CNAME points to Fastly CDN — claim via Fastly dashboard",
        "difficulty":  "Medium",
    },
    {
        "service":     "AWS S3",
        "cname":       ["s3.amazonaws.com", "s3-website"],
        "fingerprint": ["nosuchbucket", "the specified bucket does not exist",
                        "no such bucket"],
        "severity":    "CRITICAL",
        "description": "CNAME points to deleted/unclaimed S3 bucket — create bucket with same name",
        "difficulty":  "Easy",
    },
    {
        "service":     "AWS CloudFront",
        "cname":       ["cloudfront.net"],
        "fingerprint": ["bad request", "error 403: forbidden",
                        "the request could not be satisfied"],
        "severity":    "MEDIUM",
        "description": "CNAME points to CloudFront distribution",
        "difficulty":  "Hard",
    },
    {
        "service":     "Azure",
        "cname":       ["azurewebsites.net", "cloudapp.net",
                        "blob.core.windows.net", "azure-api.net"],
        "fingerprint": ["404 web site not found",
                        "the resource you are looking for has been removed"],
        "severity":    "HIGH",
        "description": "CNAME points to unclaimed Azure resource",
        "difficulty":  "Medium",
    },
    {
        "service":     "Shopify",
        "cname":       ["myshopify.com", "shopify.com"],
        "fingerprint": ["sorry, this shop is currently unavailable",
                        "only if you want to"],
        "severity":    "HIGH",
        "description": "CNAME points to unclaimed Shopify store",
        "difficulty":  "Easy",
    },
    {
        "service":     "Tumblr",
        "cname":       ["domains.tumblr.com"],
        "fingerprint": ["whatever you were looking for doesn't currently exist",
                        "there's nothing here"],
        "severity":    "HIGH",
        "description": "CNAME points to unclaimed Tumblr blog",
        "difficulty":  "Easy",
    },
    {
        "service":     "WordPress.com",
        "cname":       ["wordpress.com"],
        "fingerprint": ["do you want to register"],
        "severity":    "MEDIUM",
        "description": "CNAME points to unclaimed WordPress.com site",
        "difficulty":  "Easy",
    },
    {
        "service":     "HubSpot",
        "cname":       ["hs-sites.com", "hubspot.com", "hubspotpagebuilder.com"],
        "fingerprint": ["this page no longer exists or has moved",
                        "domain not found"],
        "severity":    "HIGH",
        "description": "CNAME points to unclaimed HubSpot landing page",
        "difficulty":  "Medium",
    },
    {
        "service":     "Zendesk",
        "cname":       ["zendesk.com"],
        "fingerprint": ["help center closed", "this help center no longer exists"],
        "severity":    "HIGH",
        "description": "CNAME points to unclaimed Zendesk help center",
        "difficulty":  "Medium",
    },
    {
        "service":     "Surge.sh",
        "cname":       ["surge.sh"],
        "fingerprint": ["project not found", "surge.sh"],
        "severity":    "HIGH",
        "description": "CNAME points to unclaimed Surge.sh project",
        "difficulty":  "Easy",
    },
    {
        "service":     "Readme.io",
        "cname":       ["readme.io", "readmessl.com"],
        "fingerprint": ["project doesnt exist", "this page does not exist"],
        "severity":    "HIGH",
        "description": "CNAME points to unclaimed Readme.io docs site",
        "difficulty":  "Easy",
    },
    {
        "service":     "Squarespace",
        "cname":       ["squarespace.com"],
        "fingerprint": ["no such account", "this domain has not been connected"],
        "severity":    "HIGH",
        "description": "CNAME points to unclaimed Squarespace site",
        "difficulty":  "Hard",
    },
    {
        "service":     "Ghost",
        "cname":       ["ghost.io"],
        "fingerprint": ["the thing you were looking for is no longer here"],
        "severity":    "HIGH",
        "description": "CNAME points to unclaimed Ghost blog",
        "difficulty":  "Easy",
    },
    {
        "service":     "Bitbucket",
        "cname":       ["bitbucket.io"],
        "fingerprint": ["repository not found"],
        "severity":    "HIGH",
        "description": "CNAME points to unclaimed Bitbucket Pages",
        "difficulty":  "Easy",
    },
    {
        "service":     "Webflow",
        "cname":       ["webflow.io"],
        "fingerprint": ["the page you are looking for doesn't exist"],
        "severity":    "HIGH",
        "description": "CNAME points to unclaimed Webflow site",
        "difficulty":  "Medium",
    },
    {
        "service":     "Pantheon",
        "cname":       ["pantheonsite.io"],
        "fingerprint": ["404 error unknown site"],
        "severity":    "HIGH",
        "description": "CNAME points to unclaimed Pantheon site",
        "difficulty":  "Medium",
    },
]

# ─────────────────────────────────────────────────────────────────────────────
# DNS CNAME RESOLUTION
# ─────────────────────────────────────────────────────────────────────────────

def resolve_cname(domain: str) -> list:
    """
    Resolve full CNAME chain for a domain.
    Returns list of CNAMEs in order.
    """
    try:
        import subprocess
        result = subprocess.run(
            ["dig", "+short", "CNAME", domain],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            cnames = [c.rstrip(".") for c in result.stdout.strip().splitlines()]
            return [c for c in cnames if c]
    except Exception:
        pass

    # Fallback: socket-based resolution
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, 'CNAME')
        return [str(r.target).rstrip(".") for r in answers]
    except Exception:
        pass

    return []


def resolve_cname_simple(domain: str) -> str:
    """
    Simple CNAME check using socket.getaddrinfo and comparing
    resolved hostname to expected patterns.
    """
    try:
        result = socket.getaddrinfo(domain, None)
        return domain  # resolved — not dangling
    except socket.gaierror:
        return ""  # unresolvable — potentially dangling


# ─────────────────────────────────────────────────────────────────────────────
# TAKEOVER CHECK
# ─────────────────────────────────────────────────────────────────────────────

def check_subdomain(subdomain: str) -> dict | None:
    """
    Check a single subdomain for takeover vulnerability.

    Returns finding dict if vulnerable, None if safe.
    """
    subdomain = subdomain.strip().lower()

    # Step 1: Try to resolve
    try:
        ip = socket.gethostbyname(subdomain)
    except socket.gaierror:
        # Unresolvable — check if it has a CNAME pointing somewhere
        cnames = resolve_cname(subdomain)
        if not cnames:
            return None  # truly dangling — no CNAME either
        # Has CNAME but no A record — classic takeover pattern
        for cname in cnames:
            for fp in TAKEOVER_FINGERPRINTS:
                if any(pattern in cname for pattern in fp["cname"]):
                    return {
                        "subdomain": subdomain,
                        "cname":     cnames[0],
                        "service":   fp["service"],
                        "severity":  fp["severity"],
                        "type":      "Subdomain Takeover — Dangling CNAME",
                        "reason":    f"CNAME {cnames[0]} → {fp['service']} (unresolvable)",
                        "description": fp["description"],
                        "difficulty": fp["difficulty"],
                    }
        return None

    # Step 2: Get CNAME chain
    cnames = resolve_cname(subdomain)

    # Step 3: Check if CNAME points to vulnerable service
    all_cnames = cnames + [subdomain]
    matched_service = None
    matched_fp = None

    for cname in all_cnames:
        for fp in TAKEOVER_FINGERPRINTS:
            if any(pattern in cname for pattern in fp["cname"]):
                matched_service = fp
                matched_fp = cname
                break
        if matched_service:
            break

    if not matched_service:
        return None

    # Step 4: Probe the subdomain and check response fingerprint
    try:
        for scheme in ("https", "http"):
            try:
                r = requests.get(
                    f"{scheme}://{subdomain}",
                    timeout=8,
                    verify=False,
                    allow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0"},
                )
                text_lower = r.text.lower()

                for fingerprint in matched_service["fingerprint"]:
                    if fingerprint.lower() in text_lower:
                        return {
                            "subdomain":   subdomain,
                            "cname":       matched_fp or cnames[0] if cnames else subdomain,
                            "service":     matched_service["service"],
                            "severity":    matched_service["severity"],
                            "type":        "Subdomain Takeover — Confirmed",
                            "reason":      f"Response contains '{fingerprint}' fingerprint",
                            "description": matched_service["description"],
                            "difficulty":  matched_service["difficulty"],
                            "status":      r.status_code,
                            "url":         r.url,
                        }
                break  # Got a response — no need to try other scheme
            except requests.ConnectionError:
                continue

    except Exception:
        pass

    # CNAME matches but couldn't confirm via fingerprint
    # Still worth reporting as POTENTIAL
    if matched_service and cnames:
        return {
            "subdomain":   subdomain,
            "cname":       cnames[0],
            "service":     matched_service["service"],
            "severity":    "MEDIUM",
            "type":        "Subdomain Takeover — Potential (unconfirmed)",
            "reason":      f"CNAME points to {matched_service['service']} — fingerprint check inconclusive",
            "description": matched_service["description"],
            "difficulty":  matched_service["difficulty"],
        }

    return None


# ─────────────────────────────────────────────────────────────────────────────
# MAIN RUNNER
# ─────────────────────────────────────────────────────────────────────────────

def run_subdomain_takeover(subdomains: list,
                           progress_cb=None) -> list:
    """
    Check all subdomains for takeover vulnerabilities in parallel.

    Args:
        subdomains: list of subdomain strings
        progress_cb: optional callback for progress updates

    Returns:
        list of confirmed/potential takeover findings
    """
    log = progress_cb or print

    # Filter out already-known infrastructure
    clean_subs = [
        s for s in subdomains
        if "@" not in s
        and " " not in s
        and len(s) < 100
        and "." in s
    ]

    if not clean_subs:
        return []

    log(f"  [Takeover] Checking {len(clean_subs)} subdomains for dangling CNAMEs...")
    findings = []

    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(check_subdomain, sub): sub
                   for sub in clean_subs}

        for future in as_completed(futures, timeout=120):
            sub = futures[future]
            try:
                result = future.result(timeout=15)
                if result:
                    findings.append(result)
                    sev = result["severity"]
                    svc = result["service"]
                    print(f"  [{sev}] TAKEOVER: {sub} → {svc}")
                    print(f"         {result['reason']}")
            except Exception:
                pass

    if not findings:
        log(f"  [Takeover] No takeover vulnerabilities found")
    else:
        log(f"  [Takeover] {len(findings)} takeover vulnerability(s) found!")

    return findings


def format_takeover_findings(findings: list) -> list:
    """Convert takeover findings to standard MCATester finding format."""
    formatted = []
    for f in findings:
        formatted.append({
            "url":       f"https://{f['subdomain']}",
            "severity":  f["severity"],
            "vuln_type": f["type"],
            "summary":   f"{f['service']} — {f['description']}",
            "confirmed": f["type"] == "Subdomain Takeover — Confirmed",
            "source":    "subdomain_takeover",
            "category":  "Subdomain Takeover",
            "status":    f.get("status", 0),
            "evidence":  {
                "subdomain":  [f["subdomain"]],
                "cname":      [f.get("cname", "")],
                "service":    [f["service"]],
                "difficulty": [f["difficulty"]],
                "reason":     [f["reason"]],
            },
            "fix": f"Remove the CNAME record for {f['subdomain']} or claim the {f['service']} resource.",
        })
    return formatted


# ─────────────────────────────────────────────────────────────────────────────
# STANDALONE TEST
# python subdomain_takeover.py
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 55)
    print("  Subdomain Takeover — Standalone Test")
    print("=" * 55)

    # Test with known vulnerable patterns + real mca.gov.in subdomains
    test_subs = [
        # Known dangling patterns (synthetic test)
        "nonexistent-test-12345.github.io",
        "nonexistent-test-12345.herokuapp.com",
        # Real mca.gov.in subdomains from scan
        "vpnv3.mca.gov.in",
        "webmail.mca.gov.in",
        "mail.mca.gov.in",
        "pminternship.mca.gov.in",
        "app.mca.gov.in",
        "reports.mca.gov.in",
        "servicedesk.mca.gov.in",
        "uat.mca.gov.in",
        "est.mca.gov.in",
        "etaal.mca.gov.in",
    ]

    results = run_subdomain_takeover(test_subs)
    formatted = format_takeover_findings(results)

    print(f"\n{'='*55}")
    print(f"  Results: {len(results)} finding(s)")
    print(f"{'='*55}")

    if formatted:
        for f in formatted:
            print(f"\n  [{f['severity']}] {f['vuln_type']}")
            print(f"  URL    : {f['url']}")
            print(f"  Summary: {f['summary']}")
            print(f"  Fix    : {f['fix']}")
    else:
        print("  No takeover vulnerabilities found")
        print("  (All subdomains resolve correctly or have no known patterns)")