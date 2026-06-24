#!/usr/bin/env python3
"""
MCATester - delta_detection.py
Security drift detection — compares current scan against previous scan
and flags changes that matter: new ports, dropped headers, new subdomains,
new findings, disappeared assets.

Integrates with FastAPI backend — reads/writes scan JSON from your DB.
"""

import json
from datetime import datetime
from typing import Any


# ─────────────────────────────────────────────
# DRIFT EVENT TYPES
# ─────────────────────────────────────────────

DRIFT_SEVERITY = {
    "new_critical_finding":     "CRITICAL",
    "new_high_finding":         "HIGH",
    "port_opened":              "HIGH",
    "security_header_dropped":  "HIGH",
    "new_subdomain":            "MEDIUM",
    "finding_resolved":         "LOW",
    "port_closed":              "LOW",
    "subdomain_disappeared":    "LOW",
    "tech_stack_changed":       "MEDIUM",
    "new_cve":                  "CRITICAL",
    "cookie_security_weakened": "HIGH",
}


# ─────────────────────────────────────────────
# COMPARISON HELPERS
# ─────────────────────────────────────────────

def _findings_key(finding: dict) -> str:
    """Unique key for a finding — url + vuln_type."""
    return f"{finding.get('url','')}::{finding.get('vuln_type','')}"


def _compare_findings(prev_findings: list, curr_findings: list) -> list:
    """Detect new and resolved findings between scans."""
    events = []
    prev_keys = {_findings_key(f) for f in prev_findings}
    curr_keys = {_findings_key(f) for f in curr_findings}

    # New findings
    new_keys = curr_keys - prev_keys
    for f in curr_findings:
        if _findings_key(f) in new_keys:
            sev = f.get("severity", "INFO")
            events.append({
                "change_type": f"new_{sev.lower()}_finding",
                "severity":    DRIFT_SEVERITY.get(f"new_{sev.lower()}_finding", "MEDIUM"),
                "field":       "finding",
                "new_value":   f.get("vuln_type", ""),
                "url":         f.get("url", ""),
                "detail":      f.get("summary", "")[:200],
            })

    # Resolved findings (was there before, gone now)
    resolved_keys = prev_keys - curr_keys
    for f in prev_findings:
        if _findings_key(f) in resolved_keys:
            events.append({
                "change_type": "finding_resolved",
                "severity":    "LOW",
                "field":       "finding",
                "old_value":   f.get("vuln_type", ""),
                "url":         f.get("url", ""),
                "detail":      f"Previously: {f.get('summary','')[:100]}",
            })

    return events


def _compare_ports(prev_ports: list, curr_ports: list) -> list:
    """Detect newly opened and closed ports."""
    events = []
    prev_set = set(prev_ports or [])
    curr_set = set(curr_ports or [])

    for port in curr_set - prev_set:
        events.append({
            "change_type": "port_opened",
            "severity":    "HIGH",
            "field":       "open_ports",
            "new_value":   str(port),
            "detail":      f"Port {port} is now open — was not seen in previous scan",
        })

    for port in prev_set - curr_set:
        events.append({
            "change_type": "port_closed",
            "severity":    "LOW",
            "field":       "open_ports",
            "old_value":   str(port),
            "detail":      f"Port {port} closed since last scan",
        })

    return events


def _compare_subdomains(prev_subs: list, curr_subs: list) -> list:
    """Detect new and disappeared subdomains."""
    events = []
    prev_set = set(prev_subs or [])
    curr_set = set(curr_subs or [])

    for sub in curr_set - prev_set:
        events.append({
            "change_type": "new_subdomain",
            "severity":    "MEDIUM",
            "field":       "subdomains",
            "new_value":   sub,
            "detail":      f"New subdomain discovered: {sub}",
        })

    for sub in prev_set - curr_set:
        events.append({
            "change_type": "subdomain_disappeared",
            "severity":    "LOW",
            "field":       "subdomains",
            "old_value":   sub,
            "detail":      f"Subdomain no longer resolving: {sub}",
        })

    return events


def _compare_headers(prev_findings: list, curr_findings: list) -> list:
    """Detect security headers that were present before but dropped now."""
    events = []

    def _get_missing_headers(findings):
        return {
            f.get("evidence", {}).get("missing_header", [None])[0]
            for f in findings
            if f.get("vuln_type", "").startswith("Missing security header")
            and f.get("evidence", {}).get("missing_header")
        }

    prev_missing = _get_missing_headers(prev_findings)
    curr_missing = _get_missing_headers(curr_findings)

    # Header was present (not missing) before, now missing
    newly_dropped = curr_missing - prev_missing
    for header in newly_dropped:
        if header:
            events.append({
                "change_type": "security_header_dropped",
                "severity":    "HIGH",
                "field":       "security_headers",
                "new_value":   header,
                "detail":      f"Security header {header} was present in last scan but is now MISSING",
            })

    return events


def _compare_technologies(prev_techs: list, curr_techs: list) -> list:
    """Detect tech stack changes."""
    events = []
    prev_set = set(prev_techs or [])
    curr_set = set(curr_techs or [])

    new_techs = curr_set - prev_set
    if new_techs:
        events.append({
            "change_type": "tech_stack_changed",
            "severity":    "MEDIUM",
            "field":       "technologies",
            "new_value":   ", ".join(new_techs),
            "detail":      f"New technologies detected: {', '.join(new_techs)}",
        })

    return events


def _compare_cookies(prev_findings: list, curr_findings: list) -> list:
    """Detect cookie security regressions."""
    events = []

    def _get_cookie_issues(findings):
        issues = {}
        for f in findings:
            if "Insecure cookie" in f.get("vuln_type", ""):
                cookie_name = f.get("vuln_type", "").replace("Insecure cookie: ", "")
                ev = f.get("evidence", {}).get("insecure_cookie", [""])[0]
                issues[cookie_name] = ev
        return issues

    prev_cookies = _get_cookie_issues(prev_findings)
    curr_cookies = _get_cookie_issues(curr_findings)

    # Cookie that was secure before is now insecure
    for name, issues in curr_cookies.items():
        if name not in prev_cookies:
            events.append({
                "change_type": "cookie_security_weakened",
                "severity":    "HIGH",
                "field":       "cookies",
                "new_value":   f"{name}: {issues}",
                "detail":      f"Cookie {name} security weakened since last scan: {issues}",
            })

    return events


# ─────────────────────────────────────────────
# MAIN DELTA PARSER
# ─────────────────────────────────────────────

def compute_delta(prev_scan: dict, curr_scan: dict) -> dict:
    """
    Compare two scan result dicts and return all drift events.

    Args:
        prev_scan: previous scan result from your DB
        curr_scan: current scan result just completed

    Returns:
        {
          "target":       str,
          "prev_scan_at": str,
          "curr_scan_at": str,
          "drift_events": [...],
          "summary": {
            "total_drifts":    int,
            "critical_drifts": int,
            "high_drifts":     int,
            "has_regressions": bool,
          }
        }
    """
    target = curr_scan.get("target", prev_scan.get("target", "unknown"))

    prev_findings = prev_scan.get("findings", [])
    curr_findings = curr_scan.get("findings", [])
    prev_recon    = prev_scan.get("recon", {})
    curr_recon    = curr_scan.get("recon", {})

    all_events = []

    # Run all comparisons
    all_events += _compare_findings(prev_findings, curr_findings)
    all_events += _compare_ports(
        prev_recon.get("open_ports", []),
        curr_recon.get("open_ports", [])
    )
    all_events += _compare_subdomains(
        prev_scan.get("subdomains", []),
        curr_scan.get("subdomains", [])
    )
    all_events += _compare_headers(prev_findings, curr_findings)
    all_events += _compare_technologies(
        prev_scan.get("technologies", []),
        curr_scan.get("technologies", [])
    )
    all_events += _compare_cookies(prev_findings, curr_findings)

    # Sort by severity
    sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    all_events.sort(key=lambda e: sev_rank.get(e.get("severity", "INFO"), 0), reverse=True)

    # Add timestamps
    for event in all_events:
        event["detected_at"] = datetime.utcnow().isoformat()

    critical = [e for e in all_events if e["severity"] == "CRITICAL"]
    high     = [e for e in all_events if e["severity"] == "HIGH"]

    # Regressions = things getting WORSE (new findings, dropped headers, opened ports)
    regression_types = {"new_critical_finding", "new_high_finding", "port_opened",
                        "security_header_dropped", "cookie_security_weakened", "new_cve"}
    has_regressions = any(e["change_type"] in regression_types for e in all_events)

    return {
        "target":         target,
        "prev_scan_at":   prev_scan.get("created_at", "unknown"),
        "curr_scan_at":   curr_scan.get("created_at", datetime.utcnow().isoformat()),
        "drift_events":   all_events,
        "summary": {
            "total_drifts":    len(all_events),
            "critical_drifts": len(critical),
            "high_drifts":     len(high),
            "has_regressions": has_regressions,
            "regression_count": sum(1 for e in all_events if e["change_type"] in regression_types),
        }
    }


def format_drift_for_dashboard(delta: dict) -> list:
    """
    Format drift events for your FastAPI /dashboard endpoint.
    Returns list of cards to display in the UI.
    """
    cards = []
    for event in delta.get("drift_events", [])[:20]:
        sev = event.get("severity", "INFO")
        cards.append({
            "type":        "drift_event",
            "severity":    sev,
            "change_type": event.get("change_type", ""),
            "title":       event.get("field", "").replace("_", " ").title(),
            "description": event.get("detail", ""),
            "value":       event.get("new_value") or event.get("old_value", ""),
            "url":         event.get("url", ""),
            "detected_at": event.get("detected_at", ""),
            "badge":       f"+ New Drift Event" if "new" in event.get("change_type","") else "Changed",
        })
    return cards