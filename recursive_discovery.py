#!/usr/bin/env python3
"""
MCATester - recursive_discovery.py
Recursive asset discovery — feeds discovered subdomains back into
DNS + port scanning engines until no new assets are found.

Logic:
  1. Start with root domain
  2. Enumerate subdomains (crt.sh, VT, HackerTarget)
  3. For each NEW subdomain found, recurse:
     - DNS resolve it
     - Port scan it
     - Enumerate ITS subdomains
  4. Stop when no new assets discovered (or max depth/breadth reached)

This catches the "4th tier subdomain with open /admin" pattern that
manual one-level scans always miss.
"""

import os
import re
import time
import socket
import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

# ─────────────────────────────────────────────
# SINGLE-DOMAIN SUBDOMAIN SOURCES
# ─────────────────────────────────────────────

def _crtsh(domain: str) -> set:
    """Query crt.sh with 2 retries and exponential backoff."""
    for attempt in range(3):
        try:
            timeout = 20 + attempt * 10  # 20s, 30s, 40s
            r = requests.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=timeout,
                headers={"Accept": "application/json", "User-Agent": "Mozilla/5.0"},
            )
            if r.status_code != 200:
                if attempt < 2:
                    time.sleep(3 * (attempt + 1))
                    continue
                return set()
            subs = set()
            for entry in r.json():
                for name in entry.get("name_value", "").splitlines():
                    name = name.strip().lstrip("*.")
                    if name.endswith(domain) and name != domain:
                        subs.add(name)
            return subs
        except Exception:
            if attempt < 2:
                time.sleep(3 * (attempt + 1))
                continue
    return set()


def _hackertarget(domain: str) -> set:
    try:
        r = requests.get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            timeout=15,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if r.status_code != 200 or "error" in r.text.lower()[:30]:
            return set()
        subs = set()
        for line in r.text.strip().splitlines():
            parts = line.split(",")
            if parts:
                sub = parts[0].strip()
                if sub.endswith(domain) and sub != domain:
                    subs.add(sub)
        return subs
    except Exception:
        return set()


def _virustotal(domain: str) -> set:
    if not VIRUSTOTAL_API_KEY:
        return set()
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            params={"limit": 40},
            timeout=15,
        )
        if r.status_code != 200:
            return set()
        return {
            item["id"] for item in r.json().get("data", [])
            if item.get("id", "").endswith(domain) and item["id"] != domain
        }
    except Exception:
        return set()


def enumerate_subdomains_for(domain: str) -> set:
    """Enumerate subdomains using all passive sources in parallel.
    Each source has its own internal timeout — we never block here."""
    subs = set()
    with ThreadPoolExecutor(max_workers=3) as ex:
        futures = {ex.submit(fn, domain): fn.__name__
                   for fn in [_crtsh, _hackertarget, _virustotal]}
        # No timeout on as_completed — each source handles its own timeout
        # crt.sh retries up to 40s × 3 = 120s max, but that's fine
        # because we already seeded known_subdomains from stage 1d
        for future in as_completed(futures):
            try:
                found = future.result(timeout=120)  # per-future safety cap
                subs.update(found)
            except Exception:
                pass  # source failed or timed out — skip it
    return subs


# ─────────────────────────────────────────────
# DNS RESOLVE + PORT PROBE
# ─────────────────────────────────────────────

def resolve_domain(domain: str) -> str | None:
    """Resolve domain to IP. Returns None if unresolvable."""
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


def quick_port_probe(domain: str, ports=(80, 443, 8080, 8443, 8000)) -> list:
    """Fast socket scan of common ports. Returns list of open ports."""
    ip = resolve_domain(domain)
    if not ip:
        return []
    open_ports = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
            s.close()
        except Exception:
            pass
    return open_ports


def grab_http_info(domain: str, ports: list) -> dict:
    """Grab server header and title from first responding port."""
    for port in ports:
        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{domain}:{port}" if port not in (80, 443) else f"{scheme}://{domain}"
        try:
            r = requests.get(url, timeout=4, verify=False,
                             headers={"User-Agent": "Mozilla/5.0"},
                             allow_redirects=True)
            server = r.headers.get("Server", "")
            title  = re.search(r"<title[^>]*>([^<]{1,100})</title>", r.text, re.I)
            return {
                "url":    url,
                "status": r.status_code,
                "server": server,
                "title":  title.group(1).strip() if title else "",
            }
        except Exception:
            continue
    return {}


# ─────────────────────────────────────────────
# RECURSIVE DISCOVERY ENGINE
# ─────────────────────────────────────────────

class RecursiveDiscovery:
    """
    Recursively discovers the full asset tree of an organization.

    Parameters:
        root_domain   : starting domain (e.g. "mca.gov.in")
        max_depth     : how many levels deep to recurse (default 3)
        max_assets    : hard cap on total assets to prevent runaway (default 200)
        delay         : seconds between API calls (default 0.5)
        progress_cb   : optional callback(message) for real-time UI updates
    """

    def __init__(self, root_domain: str, max_depth: int = 3,
                 max_assets: int = 200, delay: float = 0.2,
                 progress_cb=None):
        self.root_domain  = root_domain
        self.max_depth    = max_depth
        self.max_assets   = max_assets
        self.delay        = delay  # between batches, not per-domain
        self.progress_cb  = progress_cb or print

        self.visited      = set()   # domains already processed
        self.asset_tree   = {}      # domain → asset info dict
        self.queue        = []      # (domain, depth) pairs to process

    def _log(self, msg: str):
        self.progress_cb(f"  [recursive] {msg}")

    def _process_domain(self, domain: str, depth: int):
        """Process one domain: resolve, port scan, enumerate subdomains."""
        if domain in self.visited:
            return []
        if len(self.asset_tree) >= self.max_assets:
            self._log(f"Max assets ({self.max_assets}) reached — stopping")
            return []

        self.visited.add(domain)
        self._log(f"[depth {depth}] Scanning: {domain}")

        # Resolve
        ip = resolve_domain(domain)
        if not ip:
            self._log(f"  Unresolvable: {domain}")
            return []

        # Port probe
        open_ports = quick_port_probe(domain)

        # HTTP info
        http_info = grab_http_info(domain, open_ports) if open_ports else {}

        # Store asset
        asset = {
            "domain":     domain,
            "ip":         ip,
            "depth":      depth,
            "open_ports": open_ports,
            "http":       http_info,
            "subdomains": [],
        }
        self.asset_tree[domain] = asset

        if open_ports:
            self._log(f"  {domain} → {ip} | ports: {open_ports} | "
                      f"{http_info.get('server','?')} | {http_info.get('title','')[:40]}")

        # Don't recurse beyond max depth
        if depth >= self.max_depth:
            return []

        # Enumerate subdomains of this domain
        time.sleep(self.delay)
        new_subs = enumerate_subdomains_for(domain)
        asset["subdomains"] = list(new_subs)

        # Filter out emails and garbage before queuing
        # crt.sh and other sources sometimes return email addresses
        # like richard.henry@mca.gov.in which can't be DNS-resolved as hostnames
        new_domains = [
            s for s in new_subs
            if s not in self.visited
            and "@" not in s           # skip emails
            and " " not in s           # skip garbage with spaces
            and len(s) < 100           # skip absurdly long strings
            and "." in s               # must have at least one dot
        ]
        if new_domains:
            self._log(f"  Found {len(new_domains)} new subdomains under {domain}")
        return new_domains

    def run(self, known_subdomains: list = None) -> dict:
        """
        Run the recursive discovery.

        Args:
            known_subdomains: pre-discovered subdomains from osint_agent.py
                              stage 1d — used as additional seeds so recursive
                              discovery doesn't start from scratch.
        Returns full asset tree dict.
        """
        self._log(f"Starting recursive discovery from: {self.root_domain}")
        self._log(f"Max depth: {self.max_depth} | Max assets: {self.max_assets}")

        # Seed with root domain
        self.queue = [(self.root_domain, 0)]

        # Also seed with already-discovered subdomains from stage 1d
        # This prevents crt.sh timeout from killing the whole discovery
        if known_subdomains:
            clean = [
                s for s in known_subdomains
                if "@" not in s and " " not in s
                and len(s) < 100 and "." in s
                and s != self.root_domain
            ]
            for sub in clean:
                if sub not in self.visited:
                    self.queue.append((sub, 1))
            if clean:
                self._log(f"Seeded {len(clean)} known subdomains from stage 1d")

        while self.queue and len(self.asset_tree) < self.max_assets:
            # Grab a batch of domains at the same depth level
            # and scan them in parallel — much faster than sequential
            current_depth = self.queue[0][1]
            batch = []
            while (self.queue and
                   self.queue[0][1] == current_depth and
                   len(batch) < 15):  # max 15 parallel scans
                domain, depth = self.queue.pop(0)
                if domain not in self.visited:
                    batch.append((domain, depth))

            if not batch:
                continue

            # Scan the batch in parallel
            with ThreadPoolExecutor(max_workers=10) as ex:
                futures = {
                    ex.submit(self._process_domain, domain, depth): (domain, depth)
                    for domain, depth in batch
                }
                for future in as_completed(futures):
                    try:
                        new_domains = future.result(timeout=30)
                        # Feed new domains back into queue at depth+1
                        for new_domain in new_domains:
                            if (new_domain not in self.visited
                                    and "@" not in new_domain
                                    and len(new_domain) < 100):
                                self.queue.append((new_domain, depth + 1))
                    except Exception:
                        pass

            time.sleep(self.delay)

        self._log(f"Discovery complete: {len(self.asset_tree)} assets found")
        return self.asset_tree

    def summary(self) -> dict:
        """Return summary stats for the dashboard."""
        all_assets   = list(self.asset_tree.values())
        total        = len(all_assets)
        with_ports   = [a for a in all_assets if a["open_ports"]]
        by_depth     = {}
        for a in all_assets:
            d = a["depth"]
            by_depth[d] = by_depth.get(d, 0) + 1

        return {
            "total_assets":       total,
            "assets_with_ports":  len(with_ports),
            "depth_distribution": by_depth,
            "all_ips":            list(set(a["ip"] for a in all_assets if a["ip"])),
            "all_domains":        list(self.asset_tree.keys()),
            "deepest_finds":      [
                a for a in all_assets
                if a["depth"] >= 2 and a["open_ports"]
            ],
        }
    def to_dashboard_json(self) -> list:
        """Convert asset tree to structured JSON for the dashboard."""
        assets = []
        for domain, asset in self.asset_tree.items():
            http = asset.get("http", {})
            server = (http.get("server", "") or "").lower()
            title = (http.get("title", "") or "").lower()

            # Infer engine
            engine = "unknown"
            if "nginx" in server: engine = "nginx"
            elif "apache" in server: engine = "apache"
            elif "tomcat" in server or "coyote" in server: engine = "tomcat"
            elif "iis" in server: engine = "iis"
            elif server: engine = server.split("/")[0]

            # Detect service
            service = ""
            if "groupwise" in title: service = "GroupWise (Email)"
            elif "outlook" in title or "owa" in title: service = "Outlook Web Access"
            elif "login" in title or "sign in" in title: service = "Login Portal"
            elif "internship" in title: service = "PM Internship Portal"
            elif title: service = http.get("title", "")[:40]

            # Risk tags
            tags = []
            ports = asset.get("open_ports", [])
            if any(p in [21, 22, 23, 25, 3306, 5432, 6379, 27017] for p in ports):
                tags.append("exposed-service")
            if "vpn" in domain: tags.append("vpn-endpoint")
            if "mail" in domain or "smtp" in domain: tags.append("mail-server")
            if "admin" in domain or "mgmt" in domain: tags.append("admin-interface")
            if "dev" in domain or "staging" in domain or "test" in domain:
                tags.append("non-production")

            assets.append({
                "domain": domain,
                "ip": asset.get("ip", ""),
                "ports": ports,
                "engine": engine,
                "service": service,
                "title": http.get("title", ""),
                "server": http.get("server", ""),
                "depth": asset.get("depth", 0),
                "tags": tags,
            })
        return assets


# ─────────────────────────────────────────────
# INTEGRATION FUNCTION for osint_agent.py
# ─────────────────────────────────────────────

def run_recursive_discovery(root_domain: str, max_depth: int = 3,
                             max_assets: int = 100,
                             progress_cb=None,
                             known_subdomains: list = None) -> dict:
    """
    Drop-in function for osint_agent.py.
    Call after recon_subdomains() to get the full asset tree.

    Args:
        known_subdomains: pass recon["subdomains"] from stage 1d so
                          recursive discovery uses them as seeds even
                          if crt.sh times out during internal enumeration.

    Returns:
        {
          "asset_tree": {...},
          "summary": {...},
          "all_subdomains": [...],   ← flat list for existing pipeline
          "new_scan_targets": [...]  ← enriched targets to re-scan
        }
    """
    engine = RecursiveDiscovery(
        root_domain  = root_domain,
        max_depth    = max_depth,
        max_assets   = max_assets,
        progress_cb  = progress_cb or print,
    )
    asset_tree = engine.run(known_subdomains=known_subdomains)
    summary    = engine.summary()
    dashboard_assets = engine.to_dashboard_json()

    # Flat list of all discovered subdomains (compatible with existing pipeline)
    all_subdomains = [d for d in asset_tree.keys() if d != root_domain]

    # Prioritised re-scan targets — assets with open ports at deep levels
    new_scan_targets = [
        a["domain"] for a in asset_tree.values()
        if a["open_ports"] and a["depth"] >= 2
    ]

    return {
        "asset_tree":       asset_tree,
        "summary":          summary,
        "all_subdomains":   all_subdomains,
        "new_scan_targets": new_scan_targets,
        "dashboard_assets": dashboard_assets,
    }