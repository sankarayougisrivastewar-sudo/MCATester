#!/usr/bin/env python3

import requests
import re
from bs4 import BeautifulSoup
from ddgs import DDGS
from agent.logger import logger


HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"
}


# ─────────────────────────────────────────────
# SAFE REQUEST
# ─────────────────────────────────────────────

def safe_get(url, timeout=10):
    try:
        resp = requests.get(url, headers=HEADERS, timeout=timeout)
        resp.raise_for_status()
        return resp.text
    except Exception as e:
        logger.warning(f"Request failed: {url} | {e}")
        return None


# ─────────────────────────────────────────────
# WEB SEARCH
# ─────────────────────────────────────────────

def web_search(query: str, max_results: int = 5) -> str:
    print(f"  [*] Searching: {query}")

    try:
        with DDGS() as ddgs:
            results = list(ddgs.text(query, max_results=max_results))

        if not results:
            return "[!] No results."

        output = f"[SEARCH: {query}]\n"
        output += "─" * 40 + "\n"

        for i, r in enumerate(results, 1):
            title = r.get("title", "")[:120]
            url = r.get("href", "")
            snippet = r.get("body", "")[:200]

            output += f"\n[{i}] {title}\n"
            output += f"URL: {url}\n"
            output += f"{snippet}\n"

        return output

    except Exception as e:
        logger.error(f"Search error: {e}")
        return f"[!] Search failed: {e}"


# ─────────────────────────────────────────────
# CVE SEARCH
# ─────────────────────────────────────────────

def search_cve(cve_id: str) -> str:
    print(f"  [*] CVE Lookup: {cve_id}")

    ddg = web_search(f"{cve_id} exploit vulnerability details", 3)

    mitre_url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
    mitre_data = fetch_page(mitre_url, 1500)

    return f"{ddg}\n\n[MITRE]\n{mitre_data}"


# ─────────────────────────────────────────────
# EXPLOIT SEARCH
# ─────────────────────────────────────────────

def search_exploit(service: str, version: str = "") -> str:
    query = f"{service} {version} exploit CVE poc github"
    return web_search(query, 5)


# ─────────────────────────────────────────────
# FIX SEARCH
# ─────────────────────────────────────────────

def search_fix(vuln: str) -> str:
    query = f"{vuln} fix patch mitigation security"
    return web_search(query, 3)


# ─────────────────────────────────────────────
# PAGE FETCH
# ─────────────────────────────────────────────

def fetch_page(url: str, max_chars: int = 2000) -> str:
    html = safe_get(url)
    if not html:
        return "[!] Failed to fetch page."

    try:
        soup = BeautifulSoup(html, "html.parser")

        # remove junk
        for tag in soup(["script", "style", "nav", "footer", "header", "aside"]):
            tag.decompose()

        text = soup.get_text("\n", strip=True)

        lines = [l.strip() for l in text.splitlines() if len(l.strip()) > 30]
        clean = "\n".join(lines)

        return clean[:max_chars] + ("\n...truncated" if len(clean) > max_chars else "")

    except Exception as e:
        logger.error(f"Parsing error: {e}")
        return "[!] Parsing failed."


# ─────────────────────────────────────────────
# SMART DISPATCH
# ─────────────────────────────────────────────

def handle_search_dispatch(query: str) -> str:
    query = query.strip()
    logger.info(f"Search dispatch: {query}")

    # CVE detection
    cve_match = re.search(r"CVE-\d{4}-\d{4,7}", query, re.I)
    if cve_match:
        return search_cve(cve_match.group())

    q = query.lower()

    # exploit intent
    if any(k in q for k in ["exploit", "poc", "payload", "rce", "lfi", "sqli"]):
        return web_search(query + " exploit github", 5)

    # fix intent
    if any(k in q for k in ["fix", "patch", "mitigate", "secure"]):
        return search_fix(query)

    return web_search(query, 5)


# ─────────────────────────────────────────────
# TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("[ search.py test ]")

    q = input("Query: ")
    print(handle_search_dispatch(q))