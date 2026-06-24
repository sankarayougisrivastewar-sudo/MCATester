#!/usr/bin/env python3
"""
MCATester - content_confirmation.py
Content-based finding confirmation — replaces status-code-only logic.

Core idea: HTTP 200 alone means nothing. We read the response body
and check for patterns that prove sensitive content is actually exposed.

Severity is determined by WHAT is in the response, not HOW it was found.
403 responses are downgraded to INFO — path exists but is protected.
"""

import re

# ─────────────────────────────────────────────
# CONTENT SIGNATURE TABLE
# Maps pattern keys → (regex, severity, vuln_type, description)
# ─────────────────────────────────────────────

CONTENT_SIGNATURES = [

    # ── Credentials / Secrets ─────────────────────────────────────────────
    ("cred_env_password",   "CRITICAL",
     r'(?:DB_PASSWORD|database_password|MYSQL_PASSWORD|POSTGRES_PASSWORD)'
     r'\s*[=:]\s*["\']?([^\s"\'<\n]{3,})',
     "Database password exposed in config file"),

    ("cred_app_key",        "CRITICAL",
     r'(?:APP_KEY|APPLICATION_KEY)\s*[=:]\s*["\']?(base64:[a-zA-Z0-9+/=]{20,})',
     "Laravel/framework application key exposed"),

    ("cred_aws_key",        "CRITICAL",
     r'(?:AKIA|ASIA)[A-Z0-9]{16}',
     "AWS access key ID exposed"),

    ("cred_aws_secret",     "CRITICAL",
     r'(?:aws_secret_access_key|AWS_SECRET)\s*[=:]\s*["\']?([a-zA-Z0-9/+=]{30,})',
     "AWS secret access key exposed"),

    ("cred_private_key",    "CRITICAL",
     r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
     "Private key exposed"),

    ("cred_jwt",            "CRITICAL",
     r'eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}',
     "JWT token exposed"),

    ("cred_api_key",        "HIGH",
     r'(?:api_key|API_KEY|APIKEY|x-api-key)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{16,})',
     "API key exposed"),

    ("cred_oauth",          "HIGH",
     r'(?:client_secret|clientSecret|OAUTH_SECRET)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{8,})',
     "OAuth client secret exposed"),

    ("cred_smtp",           "HIGH",
     r'(?:MAIL_PASSWORD|SMTP_PASSWORD|SMTP_PASS)\s*[=:]\s*["\']?([^\s"\'<\n]{3,})',
     "SMTP/mail password exposed"),

    ("cred_password_hash",  "HIGH",
     r'\$(?:2[aby]|1|5|6)\$[a-zA-Z0-9./]{20,}',
     "Password hash exposed"),

    # ── Database / SQL ────────────────────────────────────────────────────
    ("db_sql_dump",         "CRITICAL",
     r'(?:CREATE TABLE\s+[`"\[]?\w|INSERT INTO\s+[`"\[]?\w|mysqldump)',
     "SQL database dump exposed"),

    ("db_sql_error",        "HIGH",
     r'(?:You have an error in your SQL syntax|mysql_fetch_array\(\)|'
     r'ORA-\d{4,5}|Warning: mysql_|Unclosed quotation mark|'
     r'SQLSTATE\[|pg_query\(\): Query failed|'
     r'supplied argument is not a valid MySQL)',
     "SQL error — potential injection point"),

    ("db_sqli_data",        "CRITICAL",
     r'information_schema\.(?:tables|columns)',
     "SQL injection confirmed — schema data returned"),

    ("db_connection_str",   "CRITICAL",
     r'(?:Server=.*;Database=.*;|mysql://\w+:\w+@|'
     r'postgresql://\w+:\w+@|mongodb://\w+:\w+@)',
     "Database connection string exposed"),

    # ── PHP / Server config ───────────────────────────────────────────────
    ("php_phpinfo",         "HIGH",
     r'PHP Version\s+(\d+\.\d+[\.\d]*)',
     "PHP configuration (phpinfo) exposed"),

    ("php_wp_config",       "CRITICAL",
     r"define\s*\(\s*['\"](?:DB_NAME|DB_USER|DB_PASSWORD)",
     "WordPress configuration file exposed"),

    ("php_laravel_env",     "CRITICAL",
     r'APP_ENV\s*=\s*\w+.*(?:DB_PASSWORD|APP_KEY)',
     "Laravel .env file exposed"),

    ("server_version",      "MEDIUM",
     r'(?:Apache|nginx|IIS|Tomcat|LiteSpeed)/(\d+\.\d+[\.\d]*)',
     "Server version disclosure"),

    ("php_error",           "MEDIUM",
     r'(?:Fatal error|Parse error|Warning):\s+\w+.*in\s+/.+\.php on line \d+',
     "PHP error — stack trace / path disclosure"),

    # ── Git ───────────────────────────────────────────────────────────────
    ("git_config",          "HIGH",
     r'\[core\]\s*repositoryformatversion',
     "Git repository config exposed"),

    ("git_remote",          "HIGH",
     r'url\s*=\s*(https?://(?:github|gitlab|bitbucket)[^\s]+)',
     "Git remote URL exposed"),

    ("git_commit",          "MEDIUM",
     r'ref:\s*refs/heads/\w+',
     "Git HEAD reference exposed"),

    # ── Directory listing ─────────────────────────────────────────────────
    ("dir_listing",         "HIGH",
     r'Index of\s*/[^\n<]{0,60}',
     "Directory listing enabled"),

    ("dir_parent",          "HIGH",
     r'Parent Directory',
     "Directory listing — parent link visible"),

    # ── API / Swagger ─────────────────────────────────────────────────────
    ("swagger_spec",        "HIGH",
     r'"(?:swagger|openapi)"\s*:\s*"[\d.]+"|swagger-ui-bundle',
     "Swagger/OpenAPI spec publicly accessible"),

    ("api_paths",           "MEDIUM",
     r'"paths"\s*:\s*\{[^}]{20,}',
     "API endpoint paths disclosed"),

    # ── Java / Spring ─────────────────────────────────────────────────────
    ("java_stacktrace",     "MEDIUM",
     r'(?:javax\.servlet\.|java\.lang\.|org\.apache\.tomcat\.)',
     "Java stack trace — technology disclosure"),

    ("spring_actuator",     "HIGH",
     r'"activeProfiles"|"systemProperties"|"applicationConfig"',
     "Spring Boot actuator data exposed"),

    # ── Network / Infrastructure ──────────────────────────────────────────
    ("internal_ip",         "MEDIUM",
     r'\b(?:10\.\d+|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d+\.\d+\b',
     "Internal IP address disclosed"),

    ("cloud_metadata",      "CRITICAL",
     r'(?:169\.254\.169\.254|metadata\.google\.internal)',
     "Cloud metadata endpoint accessible"),

    # ── Sensitive files ───────────────────────────────────────────────────
    ("sensitive_files",     "HIGH",
     r'href="[^"]+\.(?:sql|env|bak|key|pem|p12|pfx|backup|dump)"',
     "Links to sensitive files in directory listing"),

    ("xss_confirmed",       "HIGH",
     r'<script>\s*(?:alert|confirm|prompt)\s*\([^)]{0,30}\)\s*</script>',
     "Cross-site scripting (XSS) confirmed"),
]

# Map severity string to rank for comparison
_SEV_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_RANK_SEV = {v: k for k, v in _SEV_RANK.items()}


# ─────────────────────────────────────────────
# CORE FUNCTION
# ─────────────────────────────────────────────

def confirm_finding(url: str, content: str, status: int,
                    category: str = "", on_target: bool = True) -> dict:
    """
    Content-based finding confirmation.

    Args:
        url:        The URL that was fetched
        content:    The response body (string)
        status:     HTTP status code
        category:   Dork category from Google dorking stage
        on_target:  Whether this URL belongs to the target domain

    Returns:
        {
          "confirmed": bool,
          "severity":  "CRITICAL"|"HIGH"|"MEDIUM"|"LOW"|"INFO",
          "vuln_type": str,
          "summary":   str,
          "evidence":  {pattern_key: [matched_values]},
          "reason":    str   ← why this was confirmed/rejected
        }
    """
    result = {
        "confirmed": False,
        "severity":  "INFO",
        "vuln_type": "",
        "summary":   "",
        "evidence":  {},
        "reason":    "",
    }

    if not on_target:
        result["reason"] = "off-target URL"
        return result

    # ── 403: path exists but is protected ────────────────────────────────
    # Only report as INFO — the server is blocking it correctly
    if status == 403:
        result["confirmed"] = False
        result["severity"]  = "INFO"
        result["reason"]    = "HTTP 403 — path blocked, server is protecting it"
        result["summary"]   = "Path exists but access-controlled (HTTP 403)"
        result["vuln_type"] = "Access controlled path"
        return result

    # ── 404 / unreachable: not a finding ─────────────────────────────────
    if status in (0, 404):
        result["reason"] = f"HTTP {status} — path does not exist"
        return result

    # ── Non-200 redirects ─────────────────────────────────────────────────
    if status in (301, 302):
        result["severity"] = "INFO"
        result["reason"]   = f"HTTP {status} redirect"
        return result

    # ── 200: check content ────────────────────────────────────────────────
    if status not in (200, 206):
        result["reason"] = f"HTTP {status} — not a success response"
        return result

    if not content or len(content) < 20:
        result["reason"] = "Response body too small to analyze"
        return result

    # False positive: custom 404 pages that return 200
    fp_signals = [
        "page not found", "404 not found", "does not exist",
        "no page found", "error 404", "couldn't find",
        "the page you requested", "we couldn't find that page",
        "page doesn't exist",
    ]
    content_lower = content.lower()
    if any(sig in content_lower[:600] for sig in fp_signals):
        result["reason"] = "Custom 404 page returning HTTP 200"
        return result

    # ── Scan content for sensitive patterns ───────────────────────────────
    best_severity = "INFO"
    best_vuln_type = ""
    best_summary = ""
    matched_evidence = {}

    url_lower = url.lower()

    for sig_key, severity, pattern, description in CONTENT_SIGNATURES:
        matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
        if matches:
            # Store evidence — clean and cap values
            clean_matches = []
            for m in matches[:3]:
                val = m if isinstance(m, str) else (m if not isinstance(m, tuple) else m[0])
                val = str(val).strip()[:100]
                if val and val not in clean_matches:
                    clean_matches.append(val)
            if clean_matches:
                matched_evidence[sig_key] = clean_matches

            # Track highest severity found
            if _SEV_RANK.get(severity, 0) > _SEV_RANK.get(best_severity, 0):
                best_severity = severity
                best_vuln_type = description
                best_summary = f"{description} — pattern: {sig_key}"

    # ── URL-based type hints (content-confirmed) ──────────────────────────
    # These override the generic description with a more specific vuln type
    if matched_evidence:
        url_type_map = [
            (".env",          "Environment file exposed (.env)"),
            ("phpinfo",       "PHP configuration exposed (phpinfo)"),
            (".git/config",   "Git repository exposed"),
            ("wp-config",     "WordPress config exposed"),
            ("swagger",       "Swagger/OpenAPI UI accessible"),
            ("actuator",      "Spring Boot actuator exposed"),
            ("/backup",       "Backup file accessible"),
            (".sql",          "SQL dump accessible"),
            ("/admin",        "Admin panel accessible"),
        ]
        for url_fragment, specific_type in url_type_map:
            if url_fragment in url_lower:
                best_vuln_type = specific_type
                break

    # ── Extension-based confirmation for sensitive files ──────────────────
    # Even without pattern matches, some file types are inherently sensitive
    # when they return 200 with meaningful content
    if not matched_evidence:
        sensitive_ext_map = {
            ".env":    ("CRITICAL", "Environment file exposed"),
            ".sql":    ("CRITICAL", "SQL file exposed"),
            ".key":    ("CRITICAL", "Private key file exposed"),
            ".pem":    ("CRITICAL", "Certificate/key file exposed"),
            ".bak":    ("HIGH",     "Backup file exposed"),
            ".config": ("HIGH",     "Config file exposed"),
            ".log":    ("HIGH",     "Log file exposed"),
        }
        for ext, (ext_sev, ext_type) in sensitive_ext_map.items():
            if url_lower.endswith(ext) and len(content) > 50:
                if _SEV_RANK.get(ext_sev, 0) > _SEV_RANK.get(best_severity, 0):
                    best_severity  = ext_sev
                    best_vuln_type = ext_type
                    best_summary   = f"{ext_type} — URL ends with {ext}"
                matched_evidence[f"file_type_{ext[1:]}"] = [f"File returned HTTP 200 with content"]
                break

    # ── Category-based confirmation ───────────────────────────────────────
    # For dork results that match known sensitive categories
    if not matched_evidence and category:
        cat_sev_map = {
            "Exposed env/config files": ("HIGH",   "Configuration file accessible"),
            "Exposed credentials":       ("HIGH",   "Potential credential exposure"),
            "Exposed git repositories":  ("HIGH",   "Git repository accessible"),
            "Backup files":              ("MEDIUM", "Backup/archive accessible"),
        }
        if category in cat_sev_map:
            cat_sev, cat_type = cat_sev_map[category]
            # Only confirm if content is substantial (not just HTML boilerplate)
            html_ratio = content_lower.count('<') / max(len(content), 1)
            if html_ratio < 0.15 and len(content) > 100:
                # Low HTML ratio = likely file content, not a webpage
                best_severity  = cat_sev
                best_vuln_type = cat_type
                best_summary   = f"{cat_type} — non-HTML content returned"
                matched_evidence["file_content"] = ["Non-HTML content returned for sensitive path"]

    # ── Final decision ────────────────────────────────────────────────────
    if matched_evidence or (best_severity not in ("INFO", "") and best_vuln_type):
        result["confirmed"] = True
        result["severity"]  = best_severity
        result["vuln_type"] = best_vuln_type or "Sensitive content exposed"
        result["evidence"]  = matched_evidence
        result["reason"]    = f"Content match: {', '.join(list(matched_evidence.keys())[:4])}"
        result["summary"]   = (
            f"{best_vuln_type} — "
            f"contains: {', '.join(list(matched_evidence.keys())[:3])}"
            if matched_evidence else best_summary
        )
    else:
        result["confirmed"] = False
        result["severity"]  = "INFO"
        result["reason"]    = "HTTP 200 but no sensitive content patterns found"
        result["summary"]   = "URL accessible but no sensitive content detected"

    return result


# ─────────────────────────────────────────────
# BATCH CONFIRMATION  (for fetch stage)
# ─────────────────────────────────────────────

def confirm_findings_batch(raw_findings: list) -> list:
    """
    Re-confirm a list of findings using content-based logic.
    Each finding dict needs: url, content, status, category, on_target.

    Returns the same list with updated confirmed/severity/vuln_type fields.
    Downgraded findings (403s that were MEDIUM) get severity=INFO.
    """
    for f in raw_findings:
        if not f.get("on_target", True):
            continue

        confirmation = confirm_finding(
            url       = f.get("url", ""),
            content   = f.get("content", f.get("excerpt", "")),
            status    = f.get("status", 0),
            category  = f.get("category", ""),
            on_target = f.get("on_target", True),
        )

        # Only update if content confirmation gives us something better
        # OR if it downgrades a 403 that was incorrectly marked as MEDIUM+
        if f.get("status") == 403:
            # 403s should never be MEDIUM or higher — downgrade to INFO
            f["confirmed"] = False
            f["severity"]  = "INFO"
            f["vuln_type"] = "Access controlled path (403)"
            f["summary"]   = "Path exists but server is blocking access correctly"

        elif confirmation["confirmed"]:
            f["confirmed"] = True
            f["severity"]  = confirmation["severity"]
            f["vuln_type"] = confirmation["vuln_type"] or f.get("vuln_type", "")
            f["summary"]   = confirmation["summary"]
            if confirmation["evidence"]:
                # Merge with existing evidence
                existing = f.get("evidence", {})
                existing.update(confirmation["evidence"])
                f["evidence"] = existing

        else:
            # 200 but no sensitive content — not a confirmed finding
            f["confirmed"] = False
            f["severity"]  = "INFO"
            f["summary"]   = confirmation["reason"]

    return raw_findings


# ─────────────────────────────────────────────
# STANDALONE TEST
# python content_confirmation.py
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("=== Content Confirmation Tests ===\n")

    tests = [
        # (url, content, status, expected_confirmed, expected_severity)
        ("/.env",
         "APP_KEY=base64:SomeRandomKey\nDB_PASSWORD=supersecret\nDB_HOST=localhost",
         200, True, "CRITICAL"),

        ("/phpinfo.php",
         "<html>PHP Version 8.1.2 - Linux<br>Configuration File /etc/php/php.ini</html>",
         200, True, "HIGH"),

        ("/.git/config",
         "[core]\n\trepositoryformatversion = 0\nurl = https://github.com/user/repo",
         200, True, "HIGH"),

        ("/login.php",
         "<html><body><form><input name='user'/><input name='pass'/></form></body></html>",
         200, False, "INFO"),

        ("/admin/",
         "<html>Page not found</html>",
         200, False, "INFO"),

        ("/config.php",
         "File/path exists but access-controlled.",
         403, False, "INFO"),

        ("/backup.sql",
         "CREATE TABLE users (\n  id INT,\n  username VARCHAR(50),\n  password VARCHAR(255)\n);",
         200, True, "CRITICAL"),

        ("/swagger/index.html",
         '{"swagger":"2.0","info":{"title":"API"},"paths":{"/api/users":{}}}',
         200, True, "HIGH"),

        ("/random-page",
         "<html><body>Page not found — 404</body></html>",
         200, False, "INFO"),
    ]

    passed = 0
    for url, content, status, exp_confirmed, exp_sev in tests:
        r = confirm_finding(url, content, status, on_target=True)
        ok = (r["confirmed"] == exp_confirmed and r["severity"] == exp_sev)
        passed += ok
        icon = "✓" if ok else "✗"
        print(f"  {icon} {url:<30} confirmed={r['confirmed']} sev={r['severity']:<10} "
              f"(expected {exp_confirmed}/{exp_sev})")
        if not ok:
            print(f"      reason: {r['reason']}")
        if r["evidence"]:
            print(f"      evidence: {list(r['evidence'].keys())}")

    print(f"\n  {passed}/{len(tests)} tests passed")