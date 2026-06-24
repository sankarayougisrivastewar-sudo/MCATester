#!/usr/bin/env python3
"""
MCATester - ai_decision_engine.py
AI Decision Engine powered by Groq (llama-3.3-70b-versatile)

Transforms MCATester from a fixed pipeline into an adaptive agent.
The LLM makes real decisions at key points:

  1. TRIAGE     — after DNS/subdomains, prioritize what to scan
  2. DORK FOCUS — generate target-specific dork queries
  3. URL RANK   — rank discovered URLs by exploitation potential
  4. INJECT?    — decide which pages are worth injection testing
  5. CVE ASSESS — evaluate if correlated CVEs are likely exploitable
  6. RISK RANK  — final prioritization of all findings

All decisions are JSON-structured so the pipeline can act on them.
Falls back to Gemini or rule-based logic if Groq is unavailable.
"""

import os
import json
import time
import logging
import re

# Load .env file so standalone test picks up API keys
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

logger = logging.getLogger("mcatester.ai_decision")
logger.setLevel(logging.WARNING)

# ─────────────────────────────────────────────────────────────────────────────
# LLM CLIENT
# ─────────────────────────────────────────────────────────────────────────────

def _call_groq(prompt: str, max_tokens: int = 800) -> str:
    """Call Groq API with llama-3.3-70b-versatile."""
    try:
        from groq import Groq
        client = Groq(api_key=os.getenv("GROQ_API_KEY"))
        r = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a senior penetration tester analyzing security scan results. "
                        "You give concise, technical, actionable decisions in JSON format only. "
                        "Never include explanation outside the JSON. "
                        "Never refuse — always give the best assessment with available data."
                    )
                },
                {"role": "user", "content": prompt}
            ],
            max_tokens=max_tokens,
            temperature=0.1,  # low temperature = consistent decisions
        )
        return r.choices[0].message.content.strip()
    except Exception as e:
        print(f"  [AI-Agent] Groq error: {e}")
        return ""


def _call_gemini(prompt: str) -> str:
    """Fallback to Gemini if Groq unavailable."""
    try:
        import google.generativeai as genai
        key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        if not key:
            return ""
        genai.configure(api_key=key)
        model = genai.GenerativeModel("gemini-2.5-flash")
        r = model.generate_content(prompt)
        return r.text.strip()
    except Exception as e:
        logger.warning(f"Gemini fallback failed: {e}")
        return ""


def call_llm(prompt: str, max_tokens: int = 800) -> str:
    """Call LLM with Groq primary, Gemini fallback."""
    # Try Groq first
    if os.getenv("GROQ_API_KEY"):
        result = _call_groq(prompt, max_tokens)
        if result:
            return result

    # Gemini fallback
    result = _call_gemini(prompt)
    if result:
        return result

    return ""


def parse_json_response(text: str) -> dict:
    """Safely parse JSON from LLM response."""
    if not text:
        return {}
    try:
        # Strip markdown code blocks if present
        text = re.sub(r'```json\s*', '', text)
        text = re.sub(r'```\s*', '', text)
        text = text.strip()
        return json.loads(text)
    except Exception:
        # Try to extract JSON object from mixed text
        match = re.search(r'\{.*\}', text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except Exception:
                pass
    return {}


# ─────────────────────────────────────────────────────────────────────────────
# DECISION 1: TRIAGE — what to focus on after initial recon
# ─────────────────────────────────────────────────────────────────────────────

def decide_scan_focus(target: str, dns_info: dict,
                      subdomains: list, technologies: list) -> dict:
    """
    After DNS + subdomain enumeration, decide what to prioritize.

    Returns:
    {
      "target_type": "government|enterprise|saas|startup",
      "high_value_subdomains": ["vpnv3.mca.gov.in", "mail.mca.gov.in"],
      "skip_subdomains": ["dcv2avmail1.mca.gov.in"],
      "focus_areas": ["vpn", "webmail", "api"],
      "risk_level": "high|medium|low",
      "reasoning": "brief explanation"
    }
    """
    # Build context
    interesting_subs = [s for s in subdomains if any(
        kw in s.lower() for kw in
        ["vpn", "mail", "admin", "api", "dev", "staging", "test",
         "portal", "login", "app", "web", "secure", "internal"]
    )][:10]

    prompt = f"""Analyze this target and decide scan priorities.

Target: {target}
DNS A records: {dns_info.get('a_records', [])}
MX records: {dns_info.get('mx', '')}
Total subdomains: {len(subdomains)}
Interesting subdomains: {interesting_subs}
Detected technologies: {technologies}

Return JSON only:
{{
  "target_type": "government",
  "high_value_subdomains": ["list the 5 most interesting subdomains"],
  "skip_subdomains": ["list obviously useless ones like DNS servers"],
  "focus_areas": ["vpn", "webmail", "api"],
  "risk_level": "high",
  "reasoning": "one sentence"
}}"""

    result = parse_json_response(call_llm(prompt))
    if not result:
        # Rule-based fallback
        return {
            "target_type": "unknown",
            "high_value_subdomains": interesting_subs[:5],
            "skip_subdomains": [],
            "focus_areas": ["login", "api", "admin"],
            "risk_level": "medium",
            "reasoning": "LLM unavailable — rule-based fallback",
        }
    return result


# ─────────────────────────────────────────────────────────────────────────────
# DECISION 2: URL RANKING — prioritize discovered URLs
# ─────────────────────────────────────────────────────────────────────────────

def rank_urls_by_risk(urls: list, target: str) -> dict:
    """
    After dorking, rank discovered URLs by exploitation potential.

    Returns:
    {
      "critical_priority": ["url1", "url2"],
      "high_priority": ["url3"],
      "skip": ["url4"],
      "reasoning": "brief"
    }
    """
    if not urls:
        return {"critical_priority": [], "high_priority": [], "skip": []}

    # Limit to 20 most interesting URLs for the prompt
    sample = urls[:20]

    prompt = f"""Rank these URLs by security risk for target {target}.

URLs found:
{chr(10).join(f'- {u}' for u in sample)}

Criteria:
- CRITICAL: file APIs with path params, VPN login pages, admin panels, .env/.sql files
- HIGH: login pages, webmail, API endpoints, backup files
- SKIP: static pages, PDFs, search results, off-domain URLs

Return JSON only:
{{
  "critical_priority": ["highest risk URLs — test these first"],
  "high_priority": ["worth testing"],
  "skip": ["not worth testing"],
  "reasoning": "one sentence"
}}"""

    result = parse_json_response(call_llm(prompt))
    if not result:
        # Rule-based fallback
        critical = [u for u in urls if any(
            kw in u.lower() for kw in
            ["get-file", "file?path", "vpn", "remote/login", ".env", "admin"]
        )]
        high = [u for u in urls if any(
            kw in u.lower() for kw in ["login", "signin", "api", "swagger"]
        )]
        return {
            "critical_priority": critical[:5],
            "high_priority": high[:5],
            "skip": [],
            "reasoning": "LLM unavailable — rule-based fallback",
        }
    return result


# ─────────────────────────────────────────────────────────────────────────────
# DECISION 3: INJECTION TARGETING — which pages to test
# ─────────────────────────────────────────────────────────────────────────────

def decide_injection_targets(findings: list, target: str) -> dict:
    """
    Decide which confirmed pages are worth injection testing.

    Returns:
    {
      "inject_these": [
        {"url": "...", "reason": "login form", "priority": "high"},
      ],
      "skip_these": ["url1"],
      "expected_vulns": ["sqli", "xss"],
      "reasoning": "brief"
    }
    """
    if not findings:
        return {"inject_these": [], "skip_these": [], "expected_vulns": []}

    # Extract relevant findings
    login_pages = [f for f in findings if any(
        kw in (f.get("url","")).lower() for kw in
        ["login", "signin", ".jsp", ".php", ".do", "portal"]
    )]
    api_pages = [f for f in findings if any(
        kw in (f.get("url","")).lower() for kw in
        ["api", "file?path", "get-file", "search", "query"]
    )]

    candidates = (login_pages + api_pages)[:10]
    if not candidates:
        return {"inject_these": [], "skip_these": [], "expected_vulns": []}

    prompt = f"""Decide which pages to test for injection vulnerabilities on {target}.

Candidate pages:
{chr(10).join(f'- [{f.get("severity","?")}] {f.get("url","")} ({f.get("vuln_type","")})' for f in candidates)}

Consider:
- WAF presence (if all pages returned 403, skip injection)
- Technology stack (PHP/JSP = SQLi likely, React/Next.js = less likely)
- File APIs with path params = path traversal priority
- Login forms = SQLi + credential bypass priority

Return JSON only:
{{
  "inject_these": [
    {{"url": "full URL", "test_types": ["sqli", "xss", "traversal"], "priority": "high"}}
  ],
  "skip_these": ["URLs not worth testing"],
  "expected_vulns": ["sqli"],
  "reasoning": "one sentence"
}}"""

    result = parse_json_response(call_llm(prompt))
    if not result:
        return {
            "inject_these": [
                {"url": f.get("url",""), "test_types": ["sqli","xss"],
                 "priority": "medium"}
                for f in candidates[:3]
            ],
            "skip_these": [],
            "expected_vulns": ["sqli", "xss"],
            "reasoning": "LLM unavailable — rule-based fallback",
        }
    return result


# ─────────────────────────────────────────────────────────────────────────────
# DECISION 4: CVE ASSESSMENT — are these CVEs likely exploitable?
# ─────────────────────────────────────────────────────────────────────────────

def assess_cve_exploitability(cve_matches: list,
                               target: str,
                               recursive_assets: list) -> dict:
    """
    Evaluate whether correlated CVEs are likely exploitable in this context.

    Returns:
    {
      "likely_exploitable": [
        {
          "cve_id": "CVE-2023-27997",
          "confidence": "high",
          "reason": "VPN panel is publicly accessible on port 4111",
          "immediate_action": "Check FortiOS version via banner",
        }
      ],
      "unlikely": ["CVE-2021-23017"],
      "overall_risk": "critical",
      "recommended_next_steps": ["step1", "step2"]
    }
    """
    if not cve_matches:
        return {"likely_exploitable": [], "unlikely": [], "overall_risk": "low"}

    # Build CVE context
    cve_context = []
    for c in cve_matches[:8]:
        cve_context.append(
            f"  {c['cve_id']} CVSS {c['cvss']} — {c['title']}\n"
            f"    Matched on: {c.get('finding_url','')}\n"
            f"    Affected: {c.get('affected','')}"
        )

    # Build asset context
    accessible = [a for a in recursive_assets
                  if a.get("ports") and len(a.get("ports",[])) > 0][:5]

    prompt = f"""Assess CVE exploitability for {target}.

CVEs correlated:
{chr(10).join(cve_context)}

Accessible assets:
{chr(10).join(f'  {a.get("domain","")} ports:{a.get("ports",[])} server:{a.get("server","")}' for a in accessible)}

For each CVE, assess:
1. Is the vulnerable service publicly accessible?
2. Does the version range match what's visible?
3. Is there a known public PoC?
4. What's the confidence level?

Return JSON only:
{{
  "likely_exploitable": [
    {{
      "cve_id": "CVE-2023-27997",
      "confidence": "high",
      "reason": "Fortinet VPN publicly accessible on port 4111",
      "immediate_action": "Run nuclei template or check version banner"
    }}
  ],
  "unlikely": ["CVE-id"],
  "overall_risk": "critical",
  "recommended_next_steps": ["action1", "action2", "action3"]
}}"""

    result = parse_json_response(call_llm(prompt, max_tokens=1000))
    if not result:
        return {
            "likely_exploitable": [
                {
                    "cve_id": c["cve_id"],
                    "confidence": "medium",
                    "reason": "Service accessible — version unconfirmed",
                    "immediate_action": f"Verify version against {c.get('affected','')}"
                }
                for c in cve_matches if c.get("cvss", 0) >= 9.0
            ],
            "unlikely": [c["cve_id"] for c in cve_matches if c.get("cvss", 0) < 7.0],
            "overall_risk": "high",
            "recommended_next_steps": ["Verify FortiOS version", "Check patch status"],
        }
    return result


# ─────────────────────────────────────────────────────────────────────────────
# DECISION 5: FINAL RISK RANKING
# ─────────────────────────────────────────────────────────────────────────────

def rank_final_findings(findings: list, target: str,
                        cve_assessment: dict = None) -> dict:
    """
    Final LLM pass — prioritize all findings and generate executive summary.

    Returns:
    {
      "top_3_findings": [...],
      "executive_summary": "2-3 sentence summary for non-technical audience",
      "technical_summary": "2-3 sentence summary for security team",
      "immediate_actions": ["action1", "action2"],
      "overall_risk_score": 8.5,
      "risk_label": "CRITICAL"
    }
    """
    if not findings:
        return {
            "top_3_findings": [],
            "executive_summary": "No significant vulnerabilities found.",
            "technical_summary": "Scan completed with no confirmed findings.",
            "immediate_actions": [],
            "overall_risk_score": 0,
            "risk_label": "LOW",
        }

    # Summarize findings for prompt
    finding_summary = []
    for f in sorted(findings,
                    key=lambda x: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}.get(
                        x.get("severity","LOW"), 3))[:15]:
        finding_summary.append(
            f"  [{f.get('severity','?')}] {f.get('vuln_type','')} — {f.get('url','')}"
        )

    cve_context = ""
    if cve_assessment and cve_assessment.get("likely_exploitable"):
        cve_context = f"\nLikely exploitable CVEs: {[c['cve_id'] for c in cve_assessment['likely_exploitable']]}"

    prompt = f"""Final risk assessment for {target}.

Confirmed findings:
{chr(10).join(finding_summary)}
{cve_context}

Generate executive and technical summaries. Be specific about the target.
Focus on business impact for executive summary.
Focus on attack vectors for technical summary.

Return JSON only:
{{
  "top_3_findings": [
    {{"rank": 1, "finding": "CVE-2023-27997 on Fortinet VPN", "why": "pre-auth RCE means no credentials needed"}}
  ],
  "executive_summary": "2-3 sentences for CTO/management",
  "technical_summary": "2-3 sentences for security team",
  "immediate_actions": ["Patch FortiOS immediately", "..."],
  "overall_risk_score": 9.2,
  "risk_label": "CRITICAL"
}}"""

    result = parse_json_response(call_llm(prompt, max_tokens=1000))
    if not result:
        critical = [f for f in findings if f.get("severity") == "CRITICAL"]
        return {
            "top_3_findings": [
                {"rank": i+1, "finding": f.get("vuln_type",""),
                 "why": f.get("summary","")[:80]}
                for i, f in enumerate(critical[:3])
            ],
            "executive_summary": f"Critical vulnerabilities found on {target} requiring immediate attention.",
            "technical_summary": f"{len(critical)} critical findings confirmed including CVE correlations.",
            "immediate_actions": ["Review and patch critical CVEs", "Implement missing security headers"],
            "overall_risk_score": 9.0 if critical else 5.0,
            "risk_label": "CRITICAL" if critical else "MEDIUM",
        }
    return result


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def run_ai_decisions(target: str, recon: dict,
                     findings: list, cve_matches: list) -> dict:
    """
    Run all AI decision points and return structured intelligence.
    Called from osint_agent.py after all stages complete.

    Returns enriched intelligence dict added to recon["ai_decisions"]
    """
    print(f"\n  [AI-Agent] Running Groq decision engine...")
    decisions = {}

    # Decision 1: Triage
    print(f"  [AI-Agent] Assessing target profile...")
    decisions["triage"] = decide_scan_focus(
        target=target,
        dns_info={"a_records": recon.get("a_records", []),
                  "mx": recon.get("dns","")},
        subdomains=recon.get("subdomains", []),
        technologies=recon.get("technologies", []),
    )
    time.sleep(0.5)  # Rate limit

    # Decision 2: URL ranking
    all_urls = list(recon.get("dork_urls", {}).keys())
    if all_urls:
        print(f"  [AI-Agent] Ranking {len(all_urls)} URLs by risk...")
        decisions["url_ranking"] = rank_urls_by_risk(all_urls, target)
        time.sleep(0.5)

    # Decision 3: Injection targeting
    print(f"  [AI-Agent] Deciding injection targets...")
    decisions["injection_targets"] = decide_injection_targets(findings, target)
    time.sleep(0.5)

    # Decision 4: CVE assessment
    if cve_matches:
        print(f"  [AI-Agent] Assessing {len(cve_matches)} CVE exploitability...")
        recursive_assets = recon.get("recursive_assets", [])
        decisions["cve_assessment"] = assess_cve_exploitability(
            cve_matches, target, recursive_assets
        )
        time.sleep(0.5)

    # Decision 5: Final risk ranking
    print(f"  [AI-Agent] Generating final risk assessment...")
    decisions["final_assessment"] = rank_final_findings(
        findings, target,
        cve_assessment=decisions.get("cve_assessment")
    )

    # Print key outputs
    final = decisions.get("final_assessment", {})
    if final:
        print(f"\n  [AI-Agent] ─────────────────────────────────")
        print(f"  [AI-Agent] Risk: {final.get('risk_label','?')} "
              f"(score: {final.get('overall_risk_score','?')}/10)")
        print(f"  [AI-Agent] Executive: {final.get('executive_summary','')[:120]}")
        if final.get("immediate_actions"):
            print(f"  [AI-Agent] Actions:")
            for a in final["immediate_actions"][:3]:
                print(f"    → {a}")
        print(f"  [AI-Agent] ─────────────────────────────────")

    cve_assess = decisions.get("cve_assessment", {})
    if cve_assess.get("likely_exploitable"):
        print(f"\n  [AI-Agent] ⚠ Likely exploitable CVEs:")
        for c in cve_assess["likely_exploitable"]:
            print(f"    [{c.get('confidence','?').upper()}] "
                  f"{c.get('cve_id','')} — {c.get('reason','')[:80]}")

    return decisions


# ─────────────────────────────────────────────────────────────────────────────
# STANDALONE TEST
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 55)
    print("  AI Decision Engine — Standalone Test")
    print("=" * 55)

    # Simulate mca.gov.in scan data
    test_recon = {
        "a_records": ["115.108.8.26", "182.79.28.26"],
        "subdomains": ["vpnv3.mca.gov.in", "mail.mca.gov.in",
                       "pminternship.mca.gov.in", "webmail.mca.gov.in",
                       "app.mca.gov.in"],
        "technologies": ["Google Workspace Apps", "nginx"],
        "recursive_assets": [
            {"domain": "vpnv3.mca.gov.in", "ports": [4111], "server": "Fortinet"},
            {"domain": "mail.mca.gov.in", "ports": [80,443], "server": "nginx"},
            {"domain": "pminternship.mca.gov.in", "ports": [80,443], "server": "nginx"},
        ],
        "dork_urls": {
            "https://vpnv3.mca.gov.in:4111/remote/login": {},
            "https://pminternship.mca.gov.in/mca-api/files/get-file-by-path?path=test": {},
            "https://webmail.mca.gov.in/login": {},
            "http://www.mca.gov.in/mcafoportal/login.do": {},
        }
    }

    test_findings = [
        {"severity": "CRITICAL", "vuln_type": "CVE Correlation: CVE-2023-27997",
         "url": "https://vpnv3.mca.gov.in", "source": "cve_correlation",
         "summary": "Fortinet pre-auth RCE"},
        {"severity": "HIGH", "vuln_type": "API Endpoint Accessible",
         "url": "https://pminternship.mca.gov.in/mca-api/files/get-file-by-path",
         "source": "infrastructure", "summary": "File API accessible"},
        {"severity": "HIGH", "vuln_type": "Missing HSTS",
         "url": "https://mca.gov.in", "source": "on_target",
         "summary": "Missing security header"},
    ]

    test_cves = [
        {"cve_id": "CVE-2023-27997", "cvss": 9.8,
         "title": "Fortinet SSL VPN pre-auth heap overflow",
         "finding_url": "https://vpnv3.mca.gov.in",
         "affected": "FortiOS 6.0-7.2"},
        {"cve_id": "CVE-2022-40684", "cvss": 9.8,
         "title": "Fortinet auth bypass",
         "finding_url": "https://vpnv3.mca.gov.in",
         "affected": "FortiOS 7.0-7.2"},
    ]

    result = run_ai_decisions("mca.gov.in", test_recon,
                              test_findings, test_cves)

    print(f"\n{'='*55}")
    print(f"  Decisions generated: {len(result)}")
    for key, val in result.items():
        print(f"\n  [{key.upper()}]")
        if isinstance(val, dict):
            for k, v in list(val.items())[:4]:
                print(f"    {k}: {str(v)[:80]}")
    print(f"{'='*55}")