#!/usr/bin/env python3
"""
MCATester - ai_context_injector.py
Uses Gemini MID-PIPELINE to make tactical scanning decisions.

Instead of running generic paths against every target, this module:
1. Takes the detected tech stack from Stage 1e
2. Asks Gemini: "Given this stack, what paths should we fuzz?"
3. Returns a hyper-targeted path list
4. Active probe uses THIS list instead of the generic one

Result: fewer requests, higher hit rate, faster scans.

FIXES in this version:
  FIX A — Duplicate dorks: extra_dorks was being appended to itself
           (extra_dorks + strategy.get("extra_dorks", []) when extra_dorks
           was already set from strategy)
  FIX B — Path dedup: strategy priority_paths could re-add paths already
           returned by get_ai_probe_paths, producing duplicates in ai_paths
  FIX C — is_saas/has_onprem recalculated once and reused consistently
"""

import os
import re
import json
import requests
from dotenv import load_dotenv
load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL   = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
GROQ_API_KEY   = os.getenv("GROQ_API_KEY", "")

GEMINI_FALLBACK_MODELS = [
    GEMINI_MODEL,
    "gemini-1.5-flash",
    "gemini-1.5-flash-8b",
]

# SaaS vs On-Prem detection keyword lists
SAAS_KEYWORDS = [
    "google workspace", "google apps", "gmail", "office 365",
    "microsoft 365", "azure", "sharepoint", "zoho", "salesforce",
    "hubspot", "slack", "dropbox", "notion",
]
ONPREM_KEYWORDS = [
    "apache", "nginx", "tomcat", "iis", "php", "wordpress",
    "drupal", "django", "express", "node.js", "java", "asp.net",
]


def _classify_target(technologies: list) -> tuple:
    """
    Returns (is_saas, has_onprem) booleans.
    Centralised here so the same logic isn't duplicated across functions.
    """
    tech_lower = ", ".join(technologies).lower()
    is_saas    = any(kw in tech_lower for kw in SAAS_KEYWORDS)
    has_onprem = any(kw in tech_lower for kw in ONPREM_KEYWORDS)
    return is_saas, has_onprem


# ─────────────────────────────────────────────
# GEMINI CALLER (mid-pipeline, low token usage)
# ─────────────────────────────────────────────

def _ask_gemini(prompt: str, max_tokens: int = 1000) -> str:
    """
    Multi-provider AI caller — Groq first (14400/day free),
    Gemini fallback chain, silent fail if all exhausted.
    """
    # ── Groq (primary — highest free quota) ───────────────
    if GROQ_API_KEY:
        try:
            r = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {GROQ_API_KEY}",
                         "Content-Type": "application/json"},
                json={"model": "llama-3.3-70b-versatile",
                      "messages": [{"role": "user", "content": prompt}],
                      "max_tokens": max_tokens,
                      "temperature": 0.2},
                timeout=30)
            if r.status_code == 200:
                return r.json()["choices"][0]["message"]["content"]
            elif r.status_code == 429:
                print("  [AI] Groq rate limited — trying Gemini...")
        except Exception:
            pass

    # ── Gemini fallback chain ──────────────────────────────
    if GEMINI_API_KEY:
        for model in GEMINI_FALLBACK_MODELS:
            url = (f"https://generativelanguage.googleapis.com/v1beta/models/"
                   f"{model}:generateContent?key={GEMINI_API_KEY}")
            try:
                r = requests.post(url,
                    json={"contents": [{"parts": [{"text": prompt}]}],
                          "generationConfig": {"maxOutputTokens": max_tokens,
                                               "temperature": 0.2}},
                    timeout=30)
                if r.status_code == 200:
                    return r.json()["candidates"][0]["content"]["parts"][0]["text"]
                elif r.status_code == 429:
                    print(f"  [AI] {model} quota exhausted — trying next...")
                    continue
            except Exception:
                continue

    return ""


# ─────────────────────────────────────────────
# CORE: AI-GENERATED PATH LIST
# ─────────────────────────────────────────────

def get_ai_probe_paths(technologies: list, domain: str,
                        existing_findings: list = None) -> list:
    """
    Ask Gemini to generate a targeted path list based on detected tech stack.
    For SaaS targets, generates Google dorks instead of paths.
    """
    if not technologies:
        return []

    tech_str            = ", ".join(technologies)
    is_saas, has_onprem = _classify_target(technologies)  # FIX C: use shared helper

    # Build context from existing findings
    findings_context = ""
    if existing_findings:
        confirmed = [f for f in existing_findings if f.get("confirmed")][:5]
        if confirmed:
            findings_context = "\n\nAlready confirmed findings:\n"
            for f in confirmed:
                findings_context += f"- {f.get('vuln_type','')} at {f.get('url','')}\n"

    if is_saas and not has_onprem:
        prompt = f"""You are an OSINT investigator. The target {domain} uses: {tech_str}
This is a cloud/SaaS organization — there are NO on-premise directories to fuzz.{findings_context}

Generate targeted Google dork queries to find:
1. Public Google Drive/Docs/Sheets shared by {domain} employees
2. Exposed cloud storage or misconfigured sharing
3. Cached/indexed internal documents on third-party sites
4. Public Trello/Notion/Confluence boards mentioning {domain}
5. Exposed credentials or API keys in GitHub

Return ONLY a JSON array (no explanation):
[
  {{"dork": "site:docs.google.com \\"{domain}\\"", "severity": "HIGH", "reason": "public docs"}},
  {{"dork": "site:drive.google.com \\"{domain}\\"", "severity": "HIGH", "reason": "shared files"}},
  {{"dork": "site:trello.com \\"{domain}\\"", "severity": "MEDIUM", "reason": "public boards"}}
]

Generate at least 12 dorks. Severity: CRITICAL, HIGH, MEDIUM, LOW"""

    else:
        prompt = f"""You are a penetration tester. A target is running: {tech_str}
Target domain: {domain}{findings_context}

Generate a JSON array of the TOP 25 most likely vulnerable paths to probe for this exact tech stack.
Focus on paths that are:
- Specific to the detected technologies (not generic)
- Known to expose sensitive data or admin interfaces
- Ordered by likelihood of finding a vulnerability

Return ONLY a JSON array like this (no explanation, no markdown):
[
  {{"path": "/manager/html", "severity": "HIGH", "reason": "Tomcat manager"}},
  {{"path": "/WEB-INF/web.xml", "severity": "HIGH", "reason": "Tomcat config"}}
]

Severity must be one of: CRITICAL, HIGH, MEDIUM, LOW"""

    response = _ask_gemini(prompt, max_tokens=1500)
    if not response:
        return []

    try:
        clean = re.sub(r'```(?:json)?\s*', '', response).strip()
        match = re.search(r'\[.*\]', clean, re.DOTALL)
        if not match:
            return []
        data    = json.loads(match.group())
        results = []
        for item in data:
            if is_saas and not has_onprem:
                dork = item.get("dork", "").strip()
                sev  = item.get("severity", "MEDIUM").upper()
                if dork and sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                    results.append((dork, sev))
            else:
                path = item.get("path", "").strip()
                sev  = item.get("severity", "MEDIUM").upper()
                if path and sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                    results.append((path, sev))
        return results
    except Exception:
        return []


# ─────────────────────────────────────────────
# CORE: AI SCAN STRATEGY ADVISOR
# ─────────────────────────────────────────────

def get_ai_scan_strategy(technologies: list, domain: str,
                          open_ports: list,
                          initial_findings: list) -> dict:
    """
    After passive recon, ask Gemini for a full tactical scan strategy.
    """
    if not GEMINI_API_KEY:
        return {}

    tech_str     = ", ".join(technologies) or "Unknown"
    ports_str    = str(open_ports) if open_ports else "Unknown"
    findings_str = "\n".join(
        f"- {f.get('vuln_type','')} at {f.get('url','')}"
        for f in initial_findings[:10] if f.get("confirmed")
    ) or "None yet"

    prompt = f"""You are a senior penetration tester planning an attack.

Target: {domain}
Tech stack: {tech_str}
Open ports: {ports_str}
Confirmed findings so far:
{findings_str}

Based on this intelligence, provide a tactical scan strategy as JSON:
{{
  "priority_paths": [
    {{"path": "/path", "severity": "HIGH", "reason": "why"}}
  ],
  "extra_dorks": [
    "site:{domain} inurl:specific-thing"
  ],
  "sqli_targets": [
    "specific URL patterns likely vulnerable to SQLi"
  ],
  "skip_stages": [
    "any stages that are unlikely to yield results given this stack"
  ],
  "reasoning": "brief explanation of strategy"
}}

Return ONLY valid JSON, no markdown."""

    response = _ask_gemini(prompt, max_tokens=2000)
    if not response:
        return {}

    try:
        clean = re.sub(r'```(?:json)?\s*', '', response).strip()
        match = re.search(r'\{.*\}', clean, re.DOTALL)
        if not match:
            return {}
        return json.loads(match.group())
    except Exception:
        return {}


# ─────────────────────────────────────────────
# CORE: AI FINDING CLASSIFIER
# ─────────────────────────────────────────────

def ai_classify_finding(url: str, content: str,
                         status: int, tech_stack: list) -> dict:
    """
    For ambiguous responses (200 but unclear if sensitive),
    ask Gemini to classify whether this is a real vulnerability.
    """
    if not GEMINI_API_KEY or not content:
        return {}

    content_preview = content[:1000]
    tech_str        = ", ".join(tech_stack) or "Unknown"

    prompt = f"""You are a security analyst. Determine if this HTTP response contains a vulnerability.

URL: {url}
HTTP Status: {status}
Tech stack: {tech_str}
Response content (first 1000 chars):
---
{content_preview}
---

Respond with JSON only:
{{
  "is_vulnerability": true/false,
  "severity": "CRITICAL/HIGH/MEDIUM/LOW/INFO",
  "vuln_type": "specific vulnerability name",
  "confidence": 0-100,
  "reasoning": "one sentence explanation"
}}"""

    response = _ask_gemini(prompt, max_tokens=300)
    if not response:
        return {}

    try:
        clean = re.sub(r'```(?:json)?\s*', '', response).strip()
        match = re.search(r'\{.*\}', clean, re.DOTALL)
        if not match:
            return {}
        return json.loads(match.group())
    except Exception:
        return {}


# ─────────────────────────────────────────────
# INTEGRATION FUNCTION for osint_agent.py
# ─────────────────────────────────────────────

def inject_ai_context(technologies: list, domain: str,
                       open_ports: list, initial_findings: list,
                       verbose: bool = True) -> dict:
    """
    Main entry point called from osint_agent.py between Stage 1e and Stage 4.

    Returns enriched context for the active probe stage:
    {
      "ai_paths":     [(path, severity), ...],
      "extra_dorks":  [...],
      "sqli_targets": [...],
      "strategy":     {...},
      "mode":         "paths" | "dorks"
    }
    """
    if not GEMINI_API_KEY:
        if verbose:
            print("  [AI Injector] No Gemini key — using generic paths")
        return {}

    if verbose:
        print(f"  [AI Injector] Querying Gemini for {', '.join(technologies)} strategy...")

    # FIX C: classify once, reuse everywhere — no divergence between functions
    is_saas, has_onprem = _classify_target(technologies)

    # Two Gemini calls: targeted paths + full strategy
    ai_paths = get_ai_probe_paths(technologies, domain, initial_findings)
    strategy = get_ai_scan_strategy(technologies, domain, open_ports, initial_findings)

    if is_saas and not has_onprem:
        # SaaS mode: ai_paths contains dorks not filesystem paths
        extra_dorks = [item[0] for item in ai_paths]
        ai_paths    = []
        if verbose:
            print(f"  [AI Injector] SaaS target — generated {len(extra_dorks)} dorks (no paths)")
            for d in extra_dorks[:3]:
                print(f"    → {d}")
    else:
        # On-prem mode: merge strategy priority_paths into ai_paths, deduped
        # FIX B: track seen paths to avoid duplicates from the two Gemini calls
        seen_paths = {path for path, _ in ai_paths}
        for item in strategy.get("priority_paths", []):
            path = item.get("path", "").strip()
            sev  = item.get("severity", "MEDIUM").upper()
            if path and path not in seen_paths and sev in ("CRITICAL","HIGH","MEDIUM","LOW"):
                ai_paths.append((path, sev))
                seen_paths.add(path)

        # FIX A: extra_dorks comes ONLY from strategy — don't double-append
        extra_dorks = list(dict.fromkeys(strategy.get("extra_dorks", [])))  # deduped

    if verbose:
        print(f"  [AI Injector] Generated {len(ai_paths)} targeted paths")
        if strategy.get("reasoning"):
            print(f"  [AI Injector] Strategy: {strategy['reasoning'][:120]}")

    return {
        "ai_paths":     ai_paths,
        "extra_dorks":  extra_dorks,       # FIX A: no more doubling
        "sqli_targets": strategy.get("sqli_targets", []),
        "strategy":     strategy,
        "mode":         "dorks" if (is_saas and not has_onprem) else "paths",
    }