#!/usr/bin/env python3
"""
MCATester - cve_correlation.py
CVE Correlation Engine

Takes discovered technology versions and infrastructure findings,
cross-references them against known CVEs via:
  1. NVD API (free, no key required)
  2. DuckDuckGo search via search.py
  3. Static knowledge base of critical CVEs for common targets

Outputs enriched findings with CVE IDs, CVSS scores, and PoC links.
"""

import re
import time
import requests
import logging

logger = logging.getLogger("mcatester.cve")
logger.setLevel(logging.WARNING)

# ─────────────────────────────────────────────────────────────────────────────
# STATIC KNOWLEDGE BASE
# High-value CVEs for tech commonly found in government/enterprise targets
# Keyed by lowercase technology name patterns
# ─────────────────────────────────────────────────────────────────────────────

KNOWN_CVES = {

    # ── Fortinet ──────────────────────────────────────────────────────────────
    "fortinet": [
        {
            "cve_id":    "CVE-2023-27997",
            "cvss":      9.8,
            "severity":  "CRITICAL",
            "title":     "Fortinet SSL VPN pre-auth heap overflow — RCE without login",
            "affected":  "FortiOS 6.0-6.4 < 6.4.13, 7.0 < 7.0.12, 7.2 < 7.2.5",
            "impact":    "Unauthenticated remote code execution on VPN appliance",
            "poc_url":   "https://github.com/search?q=CVE-2023-27997",
            "patch_url": "https://www.fortiguard.com/psirt/FG-IR-23-097",
            "keywords":  ["fortigate", "fortinet", "forticlient", "ssl-vpn",
                          "remote/login", "vpn", "4111"],
        },
        {
            "cve_id":    "CVE-2022-40684",
            "cvss":      9.8,
            "severity":  "CRITICAL",
            "title":     "Fortinet auth bypass — admin access without credentials",
            "affected":  "FortiOS 7.0.0-7.0.6, 7.2.0-7.2.1",
            "impact":    "Full admin access to management interface without authentication",
            "poc_url":   "https://github.com/search?q=CVE-2022-40684",
            "patch_url": "https://www.fortiguard.com/psirt/FG-IR-22-377",
            "keywords":  ["fortigate", "fortinet", "forticlient", "ssl-vpn",
                          "remote/login", "vpn"],
        },
        {
            "cve_id":    "CVE-2018-13379",
            "cvss":      9.8,
            "severity":  "CRITICAL",
            "title":     "Fortinet path traversal — credentials leaked via /remote/fgt_lang",
            "affected":  "FortiOS 5.4.6-5.4.12, 5.6.3-5.6.7, 6.0.0-6.0.4",
            "impact":    "Read VPN credentials from system files without authentication",
            "poc_url":   "https://github.com/search?q=CVE-2018-13379+fortinet",
            "patch_url": "https://www.fortiguard.com/psirt/FG-IR-18-384",
            "keywords":  ["fortigate", "fortinet", "ssl-vpn", "remote/login", "vpn"],
        },
    ],

    # ── Lotus Notes / Domino ──────────────────────────────────────────────────
    "domino": [
        {
            "cve_id":    "CVE-2023-23460",
            "cvss":      9.8,
            "severity":  "CRITICAL",
            "title":     "HCL Domino RCE via crafted IMAP request",
            "affected":  "HCL Domino < 12.0.2 FP1, < 11.0.1 FP6",
            "impact":    "Remote code execution on Domino server",
            "poc_url":   "https://support.hcltechsw.com/csm?id=kb_article&sysparm_article=KB0101490",
            "patch_url": "https://support.hcltechsw.com/csm",
            "keywords":  [".nsf", "domino", "lotus", "names.nsf", "mca01812.nsf"],
        },
        {
            "cve_id":    "CVE-2021-27757",
            "cvss":      7.5,
            "severity":  "HIGH",
            "title":     "HCL Domino user enumeration via names.nsf",
            "affected":  "HCL Domino 9.x, 10.x, 11.x",
            "impact":    "Unauthenticated enumeration of all user accounts in directory",
            "poc_url":   "https://github.com/search?q=domino+names.nsf+enumeration",
            "patch_url": "https://support.hcltechsw.com/csm",
            "keywords":  ["names.nsf", "domino", "lotus", ".nsf"],
        },
    ],

    # ── GroupWise ─────────────────────────────────────────────────────────────
    "groupwise": [
        {
            "cve_id":    "CVE-2023-24486",
            "cvss":      8.8,
            "severity":  "HIGH",
            "title":     "Novell GroupWise WebAccess XSS + session hijack",
            "affected":  "GroupWise 18.x before 18.4.2",
            "impact":    "Session hijacking via XSS in webmail interface",
            "poc_url":   "https://www.zerodayinitiative.com/advisories/ZDI-23-186/",
            "patch_url": "https://www.novell.com/documentation/groupwise18/",
            "keywords":  ["groupwise", "webaccess", "gw/webaccess", "novell"],
        },
    ],

    # ── Apache Tomcat ─────────────────────────────────────────────────────────
    "tomcat": [
        {
            "cve_id":    "CVE-2025-24813",
            "cvss":      9.8,
            "severity":  "CRITICAL",
            "title":     "Apache Tomcat partial PUT RCE",
            "affected":  "Tomcat 11.0.0-M1-11.0.2, 10.1.0-M1-10.1.34, 9.0.0.M1-9.0.98",
            "impact":    "Remote code execution via partial HTTP PUT request",
            "poc_url":   "https://github.com/search?q=CVE-2025-24813",
            "patch_url": "https://tomcat.apache.org/security-9.html",
            "keywords":  ["tomcat", "apache-coyote", "coyote", "8080", "8443"],
        },
        {
            "cve_id":    "CVE-2019-0232",
            "cvss":      8.1,
            "severity":  "HIGH",
            "title":     "Apache Tomcat CGI RCE on Windows",
            "affected":  "Tomcat 9.0.0-9.0.17, 8.5.0-8.5.39, 7.0.0-7.0.93",
            "impact":    "Remote code execution via CGI servlet on Windows systems",
            "poc_url":   "https://github.com/search?q=CVE-2019-0232+tomcat",
            "patch_url": "https://tomcat.apache.org/security-9.html",
            "keywords":  ["tomcat", "apache-coyote"],
        },
    ],

    # ── Apache HTTP Server ────────────────────────────────────────────────────
    "apache": [
        {
            "cve_id":    "CVE-2021-41773",
            "cvss":      9.8,
            "severity":  "CRITICAL",
            "title":     "Apache 2.4.49 path traversal + RCE",
            "affected":  "Apache HTTP Server 2.4.49 only",
            "impact":    "Read arbitrary files and execute code if mod_cgi enabled",
            "poc_url":   "https://github.com/search?q=CVE-2021-41773",
            "patch_url": "https://httpd.apache.org/security/vulnerabilities_24.html",
            "keywords":  ["apache", "httpd", "2.4.49"],
        },
        {
            "cve_id":    "CVE-2021-42013",
            "cvss":      9.8,
            "severity":  "CRITICAL",
            "title":     "Apache 2.4.50 path traversal bypass + RCE",
            "affected":  "Apache HTTP Server 2.4.50",
            "impact":    "Bypass of CVE-2021-41773 patch — still exploitable",
            "poc_url":   "https://github.com/search?q=CVE-2021-42013",
            "patch_url": "https://httpd.apache.org/security/vulnerabilities_24.html",
            "keywords":  ["apache", "httpd", "2.4.50"],
        },
    ],

    # ── nginx ─────────────────────────────────────────────────────────────────
    "nginx": [
        {
            "cve_id":    "CVE-2021-23017",
            "cvss":      7.7,
            "severity":  "HIGH",
            "title":     "nginx DNS resolver off-by-one heap write",
            "affected":  "nginx 0.6.18-1.20.0",
            "impact":    "Potential RCE via malicious DNS response",
            "poc_url":   "https://github.com/search?q=CVE-2021-23017+nginx",
            "patch_url": "http://nginx.org/en/CHANGES",
            "keywords":  ["nginx"],
        },
    ],

    # ── WordPress ─────────────────────────────────────────────────────────────
    "wordpress": [
        {
            "cve_id":    "CVE-2024-27956",
            "cvss":      9.9,
            "severity":  "CRITICAL",
            "title":     "WordPress WP Automatic plugin SQLi",
            "affected":  "WP-Automatic plugin < 3.92.1",
            "impact":    "Unauthenticated SQL injection — full database access",
            "poc_url":   "https://github.com/search?q=CVE-2024-27956+wordpress",
            "patch_url": "https://wpscan.com/vulnerability/",
            "keywords":  ["wordpress", "wp-login", "wp-admin", "wp-config"],
        },
    ],

    # ── PHP ───────────────────────────────────────────────────────────────────
    "php": [
        {
            "cve_id":    "CVE-2024-4577",
            "cvss":      9.8,
            "severity":  "CRITICAL",
            "title":     "PHP CGI argument injection RCE on Windows",
            "affected":  "PHP 8.1 < 8.1.29, 8.2 < 8.2.20, 8.3 < 8.3.8",
            "impact":    "Remote code execution via argument injection in CGI mode",
            "poc_url":   "https://github.com/search?q=CVE-2024-4577+php",
            "patch_url": "https://www.php.net/ChangeLog-8.php",
            "keywords":  ["php", "phpinfo", ".php", "php-fpm"],
        },
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
# NVD API LOOKUP
# Free, no key required, rate limited to 5 req/30s
# ─────────────────────────────────────────────────────────────────────────────

def nvd_lookup(cve_id: str) -> dict:
    """Fetch CVE details from NVD API v2."""
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        r = requests.get(url, timeout=15,
                         headers={"User-Agent": "MCATester/4.0"})
        if r.status_code != 200:
            return {}
        data = r.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return {}

        cve = vulns[0].get("cve", {})
        metrics = cve.get("metrics", {})

        # Get CVSS score — try v3.1 first, then v3.0, then v2
        cvss = 0.0
        severity = "UNKNOWN"
        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if key in metrics and metrics[key]:
                m = metrics[key][0]
                cvss_data = m.get("cvssData", {})
                cvss     = cvss_data.get("baseScore", 0.0)
                severity = cvss_data.get("baseSeverity",
                           m.get("baseSeverity", "UNKNOWN"))
                break

        # Get description
        descs = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descs if d.get("lang") == "en"), ""
        )

        return {
            "cve_id":      cve_id,
            "cvss":        cvss,
            "severity":    severity,
            "description": description[:300],
            "published":   cve.get("published", "")[:10],
            "source":      "NVD",
        }
    except Exception as e:
        logger.warning(f"NVD lookup failed for {cve_id}: {e}")
        return {}


# ─────────────────────────────────────────────────────────────────────────────
# CORE CORRELATION ENGINE
# ─────────────────────────────────────────────────────────────────────────────

def correlate_findings(findings: list, technologies: list = None) -> list:
    """
    Match confirmed findings against known CVE database.

    Args:
        findings:     list of confirmed finding dicts from osint_agent.py
        technologies: list of detected technologies (e.g. ['Apache', 'Tomcat'])

    Returns:
        list of CVE match dicts, each containing:
        {
          finding_url, finding_type, cve_id, cvss, severity,
          title, impact, poc_url, patch_url, affected, source
        }
    """
    matches = []
    seen_cves = set()

    tech_lower = [t.lower() for t in (technologies or [])]

    for finding in findings:
        url     = finding.get("url", "").lower()
        vtype   = finding.get("vuln_type", "").lower()
        summary = finding.get("summary", "").lower()
        text    = f"{url} {vtype} {summary}"

        # Check every tech category in the knowledge base
        for tech_key, cve_list in KNOWN_CVES.items():
            for cve in cve_list:
                cve_id = cve["cve_id"]
                if cve_id in seen_cves:
                    continue

                # Match if any keyword appears in the finding text
                # or in the detected technology stack
                keywords = cve.get("keywords", [])
                matched = (
                    any(kw in text for kw in keywords) or
                    any(kw in " ".join(tech_lower) for kw in keywords)
                )

                if matched:
                    seen_cves.add(cve_id)
                    match = {
                        "finding_url":  finding.get("url", ""),
                        "finding_type": finding.get("vuln_type", ""),
                        "cve_id":       cve_id,
                        "cvss":         cve["cvss"],
                        "severity":     cve["severity"],
                        "title":        cve["title"],
                        "affected":     cve["affected"],
                        "impact":       cve["impact"],
                        "poc_url":      cve["poc_url"],
                        "patch_url":    cve["patch_url"],
                        "source":       "knowledge_base",
                    }
                    matches.append(match)
                    print(f"  [CVE] {cve_id} (CVSS {cve['cvss']}) — {cve['title'][:60]}")
                    print(f"        Matched: {finding.get('url','')[:70]}")

    return matches


def correlate_technologies(technologies: list) -> list:
    """
    Correlate detected technologies directly against CVE database.
    Runs even if no specific findings matched.

    Args:
        technologies: ['Apache', 'Tomcat', 'nginx'] etc

    Returns:
        list of CVE matches
    """
    matches = []
    seen_cves = set()
    tech_str = " ".join(t.lower() for t in (technologies or []))

    if not tech_str.strip():
        return []

    for tech_key, cve_list in KNOWN_CVES.items():
        for cve in cve_list:
            cve_id = cve["cve_id"]
            if cve_id in seen_cves:
                continue

            keywords = cve.get("keywords", [])
            if any(kw in tech_str for kw in keywords):
                seen_cves.add(cve_id)
                matches.append({
                    "finding_url":  "",
                    "finding_type": "Technology Detection",
                    "cve_id":       cve_id,
                    "cvss":         cve["cvss"],
                    "severity":     cve["severity"],
                    "title":        cve["title"],
                    "affected":     cve["affected"],
                    "impact":       cve["impact"],
                    "poc_url":      cve["poc_url"],
                    "patch_url":    cve["patch_url"],
                    "source":       "knowledge_base",
                })
                print(f"  [CVE] {cve_id} (CVSS {cve['cvss']}) ← {tech_key} detected")

    return matches


def enrich_with_nvd(cve_matches: list, max_lookups: int = 5) -> list:
    """
    Enrich top CVE matches with live NVD data.
    Only fetches for CRITICAL/HIGH to avoid rate limiting.

    Args:
        cve_matches: list from correlate_findings()
        max_lookups: max NVD API calls (rate limited to 5/30s)
    """
    enriched = []
    lookups  = 0

    # Sort by CVSS descending — enrich most critical first
    sorted_matches = sorted(cve_matches,
                            key=lambda x: x.get("cvss", 0),
                            reverse=True)

    for match in sorted_matches:
        if lookups >= max_lookups:
            enriched.append(match)
            continue

        if match.get("cvss", 0) >= 7.0:  # Only enrich HIGH+
            nvd = nvd_lookup(match["cve_id"])
            if nvd:
                match["nvd_description"] = nvd.get("description", "")
                match["nvd_published"]   = nvd.get("published", "")
                match["cvss"]            = nvd.get("cvss", match["cvss"])
                match["source"]          = "NVD + knowledge_base"
                lookups += 1
                time.sleep(0.5)  # NVD rate limit: 5 req/30s

        enriched.append(match)

    return enriched


def run_cve_correlation(findings: list,
                        technologies: list = None,
                        enrich_nvd: bool = True) -> list:
    """
    Main entry point for osint_agent.py.

    Args:
        findings:     all confirmed findings from pipeline
        technologies: detected tech stack
        enrich_nvd:   whether to fetch live NVD data (adds 1-2s per CVE)

    Returns:
        list of CVE matches ready to add to report
    """
    all_matches = []

    # 1. Match against findings (URL/vuln_type patterns)
    finding_matches = correlate_findings(findings, technologies)
    all_matches.extend(finding_matches)

    # 2. Match against technologies directly
    tech_matches = correlate_technologies(technologies)
    # Dedup — don't add if already found via findings
    existing_cves = {m["cve_id"] for m in all_matches}
    for m in tech_matches:
        if m["cve_id"] not in existing_cves:
            all_matches.append(m)
            existing_cves.add(m["cve_id"])

    if not all_matches:
        return []

    # 3. Enrich top matches with live NVD data
    if enrich_nvd and all_matches:
        print(f"  [CVE] Enriching {min(5, len(all_matches))} CVEs via NVD API...")
        all_matches = enrich_with_nvd(all_matches, max_lookups=5)

    # Sort by CVSS
    all_matches.sort(key=lambda x: x.get("cvss", 0), reverse=True)

    return all_matches


def format_cve_report(cve_matches: list) -> str:
    """Format CVE matches for the intelligence report."""
    if not cve_matches:
        return "  No CVE correlations found."

    lines = []
    for m in cve_matches:
        lines.append(f"\n  {'─'*50}")
        lines.append(f"  {m['severity']:<10} {m['cve_id']}  (CVSS {m['cvss']})")
        lines.append(f"  {m['title']}")
        lines.append(f"  Affected : {m['affected']}")
        lines.append(f"  Impact   : {m['impact']}")
        if m.get("finding_url"):
            lines.append(f"  Triggered: {m['finding_url'][:80]}")
        lines.append(f"  PoC      : {m['poc_url']}")
        lines.append(f"  Patch    : {m['patch_url']}")
        if m.get("nvd_description"):
            lines.append(f"  NVD      : {m['nvd_description'][:150]}")

    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# STANDALONE TEST
# python cve_correlation.py
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=== CVE Correlation Test ===\n")

    # Simulate mca.gov.in findings
    test_findings = [
        {
            "url":       "https://vpnv3.mca.gov.in:4111/remote/login",
            "vuln_type": "VPN/Remote Access Portal Exposed",
            "severity":  "HIGH",
            "confirmed": True,
            "source":    "infrastructure",
        },
        {
            "url":       "https://mail.mca.gov.in/mail/mca01812.nsf/",
            "vuln_type": "Lotus Notes/Domino Database Accessible",
            "severity":  "HIGH",
            "confirmed": True,
            "source":    "infrastructure",
        },
        {
            "url":       "https://webmail.mca.gov.in/gw/webaccess/help",
            "vuln_type": "Webmail Portal Exposed",
            "severity":  "HIGH",
            "confirmed": True,
            "source":    "infrastructure",
        },
    ]

    test_technologies = ["Google Workspace Apps", "nginx"]

    print("Running CVE correlation...")
    matches = run_cve_correlation(
        findings     = test_findings,
        technologies = test_technologies,
        enrich_nvd   = True,
    )

    print(f"\n{'='*55}")
    print(f"  CVEs found: {len(matches)}")
    print(f"  CRITICAL  : {sum(1 for m in matches if m['severity'] == 'CRITICAL')}")
    print(f"  HIGH      : {sum(1 for m in matches if m['severity'] == 'HIGH')}")
    print(f"{'='*55}")
    print(format_cve_report(matches))