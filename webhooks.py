#!/usr/bin/env python3
"""
MCATester - webhooks.py
Slack / Discord / Telegram alerting for High+ findings.
Add to .env:
    SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
    DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
    TELEGRAM_BOT_TOKEN=...
    TELEGRAM_CHAT_ID=...
"""

import os
import requests
from dotenv import load_dotenv
load_dotenv()

SLACK_WEBHOOK    = os.getenv("SLACK_WEBHOOK_URL", "")
DISCORD_WEBHOOK  = os.getenv("DISCORD_WEBHOOK_URL", "")
TELEGRAM_TOKEN   = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

SEVERITY_EMOJI = {
    "CRITICAL": "🚨",
    "HIGH":     "🔴",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "INFO":     "ℹ️",
}

ALERT_SEVERITIES = {"CRITICAL", "HIGH"}  # only alert on these


def _send_slack(message: str):
    if not SLACK_WEBHOOK:
        return
    try:
        requests.post(SLACK_WEBHOOK,
                      json={"text": message},
                      timeout=8)
    except Exception as e:
        print(f"  [webhook] Slack error: {e}")


def _send_discord(message: str):
    if not DISCORD_WEBHOOK:
        return
    try:
        # Discord has 2000 char limit
        requests.post(DISCORD_WEBHOOK,
                      json={"content": message[:1990]},
                      timeout=8)
    except Exception as e:
        print(f"  [webhook] Discord error: {e}")


def _send_telegram(message: str):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            json={"chat_id": TELEGRAM_CHAT_ID,
                  "text": message[:4000],
                  "parse_mode": "Markdown"},
            timeout=8)
    except Exception as e:
        print(f"  [webhook] Telegram error: {e}")


def send_alert(finding: dict, target: str):
    """Send alert for a single High/Critical finding."""
    sev = finding.get("severity", "")
    if sev not in ALERT_SEVERITIES:
        return

    emoji    = SEVERITY_EMOJI.get(sev, "⚠️")
    vuln     = finding.get("vuln_type", "Finding")
    url      = finding.get("url", "")
    summary  = finding.get("summary", "")[:200]
    category = finding.get("category", "")

    message = (
        f"{emoji} *MCATester Alert*\n"
        f"*Target:* `{target}`\n"
        f"*Severity:* {sev}\n"
        f"*Finding:* {vuln}\n"
        f"*URL:* {url}\n"
        f"*Category:* {category}\n"
        f"*Detail:* {summary}"
    )

    _send_slack(message)
    _send_discord(message)
    _send_telegram(message)


def send_scan_summary(target: str, by_sev: dict, duration_s: float = 0):
    """Send scan completion summary."""
    total = sum(len(v) for v in by_sev.values())
    has_critical = len(by_sev.get("CRITICAL", [])) > 0
    has_high     = len(by_sev.get("HIGH", [])) > 0

    if not (has_critical or has_high):
        return  # Only alert if there's something worth knowing

    emoji = "🚨" if has_critical else "🔴"
    message = (
        f"{emoji} *MCATester Scan Complete*\n"
        f"*Target:* `{target}`\n"
        f"*Duration:* {duration_s:.0f}s\n"
        f"*Findings:* {total} total\n"
        f"  🚨 Critical: {len(by_sev.get('CRITICAL', []))}\n"
        f"  🔴 High: {len(by_sev.get('HIGH', []))}\n"
        f"  🟡 Medium: {len(by_sev.get('MEDIUM', []))}\n"
        f"  🟢 Low: {len(by_sev.get('LOW', []))}"
    )

    _send_slack(message)
    _send_discord(message)
    _send_telegram(message)


def send_drift_alert(target: str, drift_events: list):
    """Alert on security drift detected between scans."""
    if not drift_events:
        return

    critical_drifts = [d for d in drift_events if d.get("severity") in ALERT_SEVERITIES]
    if not critical_drifts:
        return

    lines = [f"📡 *Security Drift Detected — `{target}`*\n"]
    for d in critical_drifts[:5]:
        change = d.get("change_type", "changed")
        field  = d.get("field", "")
        val    = d.get("new_value", "")[:80]
        lines.append(f"  • *{change.upper()}* `{field}`: {val}")

    message = "\n".join(lines)
    _send_slack(message)
    _send_discord(message)
    _send_telegram(message)