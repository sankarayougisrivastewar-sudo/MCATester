#!/usr/bin/env python3
"""
MCATester Dashboard — server.py v2
FastAPI backend with:
  - REST API for scans, findings, targets
  - SSE (Server-Sent Events) for real-time log streaming
  - SQLite scan history
  - Scan mode routing (full / passive / quick)
  - stdout capture → SSE pipe

Usage:
  cd MCATester && python server.py
  Open http://localhost:8000

Requirements:
  pip install fastapi uvicorn aiosqlite python-multipart sse-starlette
"""

import os, sys, io, json, time, queue, sqlite3, asyncio, threading, re
from datetime import datetime
from pathlib import Path
from contextlib import contextmanager

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional

# SSE support — falls back gracefully if not installed
try:
    from sse_starlette.sse import EventSourceResponse
    HAS_SSE = True
except ImportError:
    HAS_SSE = False
    print("  ⚠ sse-starlette not installed — SSE disabled (pip install sse-starlette)")

# ─────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────

DB_PATH = "mcatester.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL,
        mode TEXT DEFAULT 'full', status TEXT DEFAULT 'pending',
        started_at TEXT, completed_at TEXT, duration_seconds REAL,
        critical INTEGER DEFAULT 0, high INTEGER DEFAULT 0,
        medium INTEGER DEFAULT 0, low INTEGER DEFAULT 0, info INTEGER DEFAULT 0,
        total_findings INTEGER DEFAULT 0, subdomains INTEGER DEFAULT 0,
        technologies TEXT DEFAULT '[]', report_md TEXT, report_pdf TEXT,
        findings_json TEXT DEFAULT '[]', recon_json TEXT DEFAULT '{}', error TEXT
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL,
        severity TEXT, vuln_type TEXT, url TEXT, status INTEGER,
        category TEXT, evidence TEXT DEFAULT '{}', summary TEXT,
        fix TEXT DEFAULT '', source TEXT DEFAULT 'on_target',
        FOREIGN KEY (scan_id) REFERENCES scans(id)
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS targets (
        id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT UNIQUE NOT NULL,
        label TEXT, last_scanned TEXT, scan_count INTEGER DEFAULT 0,
        last_critical INTEGER DEFAULT 0, last_high INTEGER DEFAULT 0,
        last_medium INTEGER DEFAULT 0, last_low INTEGER DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )""")
    # Delta detection — stores drift events between consecutive scans
    conn.execute("""CREATE TABLE IF NOT EXISTS scan_deltas (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        prev_scan_id INTEGER,
        target TEXT NOT NULL,
        computed_at TEXT,
        total_drifts INTEGER DEFAULT 0,
        critical_drifts INTEGER DEFAULT 0,
        high_drifts INTEGER DEFAULT 0,
        has_regressions INTEGER DEFAULT 0,
        drift_json TEXT DEFAULT '[]',
        FOREIGN KEY (scan_id) REFERENCES scans(id)
    )""")
    conn.commit(); conn.close()

@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH); conn.row_factory = sqlite3.Row
    try: yield conn; conn.commit()
    finally: conn.close()


# ─────────────────────────────────────────────
# LOG CAPTURE — pipes stdout to SSE clients
# ─────────────────────────────────────────────

scan_logs = {}       # scan_id -> queue.Queue of log lines
scan_complete = {}   # scan_id -> threading.Event

class LogCapture(io.TextIOBase):
    """Captures print() output and sends to both terminal and SSE queue."""
    def __init__(self, scan_id, original_stdout):
        self.scan_id = scan_id
        self.original = original_stdout
        self.q = scan_logs.get(scan_id)

    def write(self, text):
        if text and text.strip():
            self.original.write(text)
            self.original.flush()
            if self.q:
                # Strip ANSI codes for the web client
                clean = re.sub(r'\x1b\[[0-9;]*m', '', text).strip()
                if clean:
                    self.q.put(clean)
        elif text:
            self.original.write(text)
        return len(text) if text else 0

    def flush(self):
        self.original.flush()


# ─────────────────────────────────────────────
# APP
# ─────────────────────────────────────────────

app = FastAPI(title="MCATester Dashboard", version="2.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])

class ScanRequest(BaseModel):
    target: str
    mode: str = "full"  # full, passive, quick

active_scans = {}


# ─────────────────────────────────────────────
# SCAN EXECUTION
# ─────────────────────────────────────────────

def get_previous_scan(target: str, current_scan_id: int) -> dict:
    """Fetch the most recent completed scan for target (excluding current)."""
    with get_db() as db:
        row = db.execute("""
            SELECT id, findings_json, recon_json, technologies
            FROM scans
            WHERE target=? AND status='completed' AND id != ?
            ORDER BY id DESC LIMIT 1
        """, (target, current_scan_id)).fetchone()
    if not row:
        return {}
    try:
        findings = json.loads(row["findings_json"] or "[]")
        recon    = json.loads(row["recon_json"]    or "{}")
        techs    = json.loads(row["technologies"]  or "[]")
    except Exception:
        return {}
    return {
        "id":           row["id"],
        "target":       target,
        "findings":     findings,
        "recon":        recon,
        "technologies": techs,
        "subdomains":   recon.get("subdomains", []),
        "created_at":   str(row["id"]),  # used as timestamp fallback
    }


def run_scan_background(scan_id: int, target: str, mode: str):
    start_time = time.time()

    with get_db() as db:
        db.execute("UPDATE scans SET status='running', started_at=? WHERE id=?",
                   (datetime.now().isoformat(), scan_id))

    active_scans[scan_id] = {"status": "running", "target": target}

    # Set up log capture
    scan_logs[scan_id] = queue.Queue(maxsize=500)
    scan_complete[scan_id] = threading.Event()
    original_stdout = sys.stdout
    sys.stdout = LogCapture(scan_id, original_stdout)

    try:
        from osint_agent import run_osint
        passive = mode in ("passive", "quick")
        result = run_osint(target, passive=passive)

        duration = time.time() - start_time
        findings = result.get("findings", [])
        recon = result.get("recon", {})

        sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev[f.get("severity", "INFO")] = sev.get(f.get("severity", "INFO"), 0) + 1

        with get_db() as db:
            db.execute("""UPDATE scans SET
                status='completed', completed_at=?, duration_seconds=?,
                critical=?, high=?, medium=?, low=?, info=?,
                total_findings=?, subdomains=?, technologies=?,
                report_md=?, findings_json=?, recon_json=?
                WHERE id=?""", (
                datetime.now().isoformat(), round(duration, 1),
                sev["CRITICAL"], sev["HIGH"], sev["MEDIUM"], sev["LOW"], sev["INFO"],
                len(findings), len(result.get("subdomains", [])),
                json.dumps(result.get("technologies", [])),
                result.get("report", ""),
                json.dumps(findings, default=str),
                json.dumps(recon, default=str), scan_id))

            for f in findings:
                db.execute("""INSERT INTO findings
                    (scan_id,severity,vuln_type,url,status,category,evidence,summary,fix,source)
                    VALUES (?,?,?,?,?,?,?,?,?,?)""", (
                    scan_id, f.get("severity"), f.get("vuln_type"),
                    f.get("url"), f.get("status"), f.get("category"),
                    json.dumps(f.get("evidence", {})),
                    f.get("summary"), f.get("fix", ""),
                    f.get("source", "on_target")))

            db.execute("""INSERT INTO targets (domain, last_scanned, scan_count,
                last_critical, last_high, last_medium, last_low)
                VALUES (?,?,1,?,?,?,?) ON CONFLICT(domain) DO UPDATE SET
                last_scanned=?, scan_count=scan_count+1,
                last_critical=?, last_high=?, last_medium=?, last_low=?""", (
                target, datetime.now().isoformat(),
                sev["CRITICAL"], sev["HIGH"], sev["MEDIUM"], sev["LOW"],
                datetime.now().isoformat(),
                sev["CRITICAL"], sev["HIGH"], sev["MEDIUM"], sev["LOW"]))

        active_scans[scan_id] = {"status": "completed", "target": target}

        # ── DELTA DETECTION ─────────────────────────────────────────────
        # Compare this scan against the previous one for the same target.
        # Runs AFTER the scan is saved so get_previous_scan finds it.
        try:
            from delta_detection import compute_delta
            from webhooks import send_drift_alert

            prev_scan = get_previous_scan(target, scan_id)
            if prev_scan:
                # Build current scan dict in the shape compute_delta expects
                curr_scan = {
                    "target":       target,
                    "findings":     findings,
                    "recon":        recon,
                    "subdomains":   recon.get("subdomains", []),
                    "technologies": result.get("technologies", []),
                    "created_at":   datetime.now().isoformat(),
                }
                delta = compute_delta(prev_scan, curr_scan)
                summary = delta.get("summary", {})

                # Save delta to DB
                with get_db() as db:
                    db.execute("""INSERT INTO scan_deltas
                        (scan_id, prev_scan_id, target, computed_at,
                         total_drifts, critical_drifts, high_drifts,
                         has_regressions, drift_json)
                        VALUES (?,?,?,?,?,?,?,?,?)""", (
                        scan_id, prev_scan["id"], target,
                        datetime.now().isoformat(),
                        summary.get("total_drifts", 0),
                        summary.get("critical_drifts", 0),
                        summary.get("high_drifts", 0),
                        1 if summary.get("has_regressions") else 0,
                        json.dumps(delta.get("drift_events", [])),
                    ))

                # Fire webhook alerts for regressions
                if summary.get("has_regressions"):
                    send_drift_alert(target, delta.get("drift_events", []))

                print(f"  [Delta] {summary.get('total_drifts', 0)} drift events vs scan #{prev_scan['id']}")
                if summary.get("critical_drifts", 0) > 0:
                    print(f"  [Delta] ⚠ {summary['critical_drifts']} CRITICAL regressions detected")
            else:
                print(f"  [Delta] No previous scan found — baseline established")
        except Exception as e:
            print(f"  [Delta] Error: {e}")

    except Exception as e:
        duration = time.time() - start_time
        with get_db() as db:
            db.execute("UPDATE scans SET status='failed', error=?, duration_seconds=? WHERE id=?",
                       (str(e)[:500], round(duration, 1), scan_id))
        active_scans[scan_id] = {"status": "failed", "error": str(e)[:200]}

    finally:
        sys.stdout = original_stdout
        scan_complete[scan_id].set()
        # Keep logs for 5 min then cleanup
        def cleanup():
            time.sleep(300)
            scan_logs.pop(scan_id, None)
            scan_complete.pop(scan_id, None)
        threading.Thread(target=cleanup, daemon=True).start()


# ─────────────────────────────────────────────
# API ENDPOINTS
# ─────────────────────────────────────────────

@app.post("/api/scans")
async def start_scan(req: ScanRequest):
    # Prevent duplicate scans on same target
    for sid, info in active_scans.items():
        if info.get("status") == "running" and info.get("target") == req.target:
            raise HTTPException(409, f"Scan already running for {req.target}")

    with get_db() as db:
        cursor = db.execute("INSERT INTO scans (target,mode,status,started_at) VALUES (?,?,?,?)",
                            (req.target, req.mode, 'pending', datetime.now().isoformat()))
        scan_id = cursor.lastrowid

    thread = threading.Thread(target=run_scan_background,
                              args=(scan_id, req.target, req.mode), daemon=True)
    thread.start()
    return {"id": scan_id, "status": "started", "target": req.target}


@app.get("/api/scans")
async def list_scans(limit: int = Query(50, ge=1, le=200), target: Optional[str] = None):
    with get_db() as db:
        if target:
            rows = db.execute("SELECT * FROM scans WHERE target=? ORDER BY id DESC LIMIT ?",
                              (target, limit)).fetchall()
        else:
            rows = db.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: int):
    with get_db() as db:
        scan = db.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not scan: raise HTTPException(404)
        findings = db.execute("""SELECT * FROM findings WHERE scan_id=? ORDER BY
            CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1
            WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END""",
            (scan_id,)).fetchall()
    result = dict(scan)
    result["findings"] = [dict(f) for f in findings]
    return result


@app.get("/api/scans/{scan_id}/status")
async def scan_status(scan_id: int):
    if scan_id in active_scans:
        return active_scans[scan_id]
    with get_db() as db:
        scan = db.execute("SELECT status,error FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not scan: raise HTTPException(404)
        return {"status": scan["status"], "error": scan["error"]}


@app.get("/api/scans/{scan_id}/delta")
async def get_scan_delta(scan_id: int):
    """Return drift events for a scan vs its previous scan."""
    with get_db() as db:
        row = db.execute("""SELECT * FROM scan_deltas WHERE scan_id=?
                            ORDER BY id DESC LIMIT 1""", (scan_id,)).fetchone()
    if not row:
        return {"scan_id": scan_id, "status": "no_delta",
                "message": "No previous scan to compare against (first scan for this target)"}
    delta = dict(row)
    try:
        delta["drift_events"] = json.loads(delta.get("drift_json") or "[]")
    except Exception:
        delta["drift_events"] = []
    delta.pop("drift_json", None)  # don't send raw JSON string
    return delta


@app.get("/api/targets/{domain}/drift")
async def get_target_drift(domain: str, limit: int = Query(10, ge=1, le=50)):
    """Return recent drift history for a target — useful for trend charts."""
    with get_db() as db:
        rows = db.execute("""
            SELECT sd.scan_id, sd.prev_scan_id, sd.computed_at,
                   sd.total_drifts, sd.critical_drifts, sd.high_drifts,
                   sd.has_regressions, sd.drift_json
            FROM scan_deltas sd
            WHERE sd.target=?
            ORDER BY sd.id DESC LIMIT ?
        """, (domain, limit)).fetchall()
    results = []
    for row in rows:
        r = dict(row)
        try:
            r["drift_events"] = json.loads(r.get("drift_json") or "[]")
        except Exception:
            r["drift_events"] = []
        r.pop("drift_json", None)
        results.append(r)
    return results


@app.delete("/api/scans/{scan_id}")
async def delete_scan(scan_id: int):
    with get_db() as db:
        db.execute("DELETE FROM findings WHERE scan_id=?", (scan_id,))
        db.execute("DELETE FROM scans WHERE id=?", (scan_id,))
    return {"deleted": True}


# ── SSE LIVE LOG STREAM ─────────────────────

@app.get("/api/scans/{scan_id}/logs")
async def stream_logs(scan_id: int, request: Request):
    """SSE endpoint — streams live log lines from a running scan."""
    if not HAS_SSE:
        return JSONResponse({"error": "SSE not available. pip install sse-starlette"}, 501)

    async def event_generator():
        q = scan_logs.get(scan_id)
        done_event = scan_complete.get(scan_id)

        if not q:
            yield {"event": "log", "data": "Waiting for scan to start..."}
            for _ in range(30):
                await asyncio.sleep(1)
                q = scan_logs.get(scan_id)
                if q: break
            if not q:
                yield {"event": "done", "data": "Scan not found or already completed"}
                return

        while True:
            if await request.is_disconnected():
                break
            try:
                line = q.get_nowait()
                yield {"event": "log", "data": line}
            except queue.Empty:
                if done_event and done_event.is_set() and q.empty():
                    yield {"event": "done", "data": "Scan completed"}
                    break
                await asyncio.sleep(0.3)

    return EventSourceResponse(event_generator())


@app.get("/api/targets")
async def list_targets():
    with get_db() as db:
        rows = db.execute("SELECT * FROM targets ORDER BY last_scanned DESC").fetchall()
    return [dict(r) for r in rows]


@app.get("/api/dashboard")
async def dashboard_stats():
    with get_db() as db:
        ts = db.execute("SELECT COUNT(*) as c FROM scans").fetchone()["c"]
        tt = db.execute("SELECT COUNT(*) as c FROM targets").fetchone()["c"]
        tf = db.execute("SELECT COUNT(*) as c FROM findings").fetchone()["c"]
        sc = db.execute("""SELECT severity, COUNT(*) as count FROM findings
            GROUP BY severity""").fetchall()
        recent = db.execute("""SELECT id,target,status,started_at,critical,high,medium,low,
            total_findings,duration_seconds,mode,subdomains,technologies,recon_json
            FROM scans ORDER BY id DESC LIMIT 8""").fetchall()

        # Aggregate stats from latest completed scan
        latest = db.execute("""SELECT subdomains, recon_json, technologies
            FROM scans WHERE status='completed' ORDER BY id DESC LIMIT 1""").fetchone()

        # Trend data — severity totals per scan over time
        trend = db.execute("""SELECT id, target, started_at, critical, high, medium, low,
            total_findings FROM scans WHERE status='completed'
            ORDER BY id ASC LIMIT 20""").fetchall()

    # Extract aggregate counts from latest scan
    total_subs = 0; total_ports = 0; total_emails = 0; total_cves = 0
    if latest:
        total_subs = latest["subdomains"] or 0
        try:
            recon = json.loads(latest["recon_json"] or "{}")
            total_ports = len(recon.get("open_ports", []))
            total_emails = len(recon.get("emails", []))
            # Count CVEs from Shodan data if present
            ports_text = recon.get("ports", "")
            total_cves = len(re.findall(r'CVE-\d{4}-\d+', ports_text))
        except: pass

    # Count chain findings, CVE findings, injection findings, takeover findings
    with get_db() as db:
        # Check columns exist before querying
        cols = [r[1] for r in db.execute("PRAGMA table_info(findings)").fetchall()]
        has_source   = "source"   in cols
        has_category = "category" in cols

        def count_findings(conditions):
            try:
                return db.execute(f"SELECT COUNT(*) as c FROM findings WHERE {conditions}").fetchone()["c"]
            except Exception:
                return 0

        if has_source and has_category:
            chain_count     = count_findings(
                "source='Attack Chain' OR source='attack_chain' OR "
                "category='Attack Chain' OR trigger != '' OR chain_depth > 0"
            )
            cve_count       = count_findings(
                "source='cve_correlation' OR category='CVE Intelligence' OR "
                "vuln_type LIKE 'CVE Correlation%'"
            )
            injection_count = count_findings(
                "source='payload_injection' OR source='Active Exploitation' OR "
                "category='Active Exploitation' OR vuln_type LIKE '%SQL Injection%' OR "
                "vuln_type LIKE '%XSS%'"
            )
            takeover_count  = count_findings(
                "source='subdomain_takeover' OR category='Subdomain Takeover' OR "
                "vuln_type LIKE '%Takeover%'"
            )
        elif has_source:
            chain_count     = count_findings("chain_depth > 0 OR trigger != ''")
            cve_count       = count_findings("source='cve_correlation' OR vuln_type LIKE 'CVE%'")
            injection_count = count_findings("source='payload_injection'")
            takeover_count  = count_findings("source='subdomain_takeover'")
        else:
            chain_count = cve_count = injection_count = takeover_count = 0

    # Better CVE count — from recon_json cve_matches
    if total_cves == 0:
        try:
            with get_db() as db:
                latest_cve = db.execute(
                    "SELECT recon_json FROM scans WHERE status='completed' ORDER BY id DESC LIMIT 1"
                ).fetchone()
            if latest_cve:
                recon_data = json.loads(latest_cve["recon_json"] or "{}")
                cve_matches = recon_data.get("cve_matches", [])
                total_cves = len(cve_matches) if cve_matches else total_cves
        except: pass

    return {
        "total_scans": ts, "total_targets": tt, "total_findings": tf,
        "severity_breakdown": {r["severity"]: r["count"] for r in sc},
        "recent_scans": [dict(r) for r in recent],
        "total_subdomains": total_subs, "total_ports": total_ports,
        "total_emails": total_emails, "total_cves": total_cves,
        "chain_findings": chain_count,
        "cve_findings": cve_count,
        "injection_findings": injection_count,
        "takeover_findings": takeover_count,
        "trend": [dict(r) for r in trend],
    }


# ── ALERTS API ─────────────────────────────

@app.get("/api/alerts")
async def get_alerts(limit: int = Query(20, ge=1, le=100)):
    """Return recent high/critical findings as alerts across all scans."""
    with get_db() as db:
        # Check which columns exist in findings table
        cols = [r[1] for r in db.execute("PRAGMA table_info(findings)").fetchall()]
        confirmed_clause = "AND f.confirmed = 1" if "confirmed" in cols else ""
        category_col = "f.category," if "category" in cols else ""
        source_col = "f.source," if "source" in cols else ""

        rows = db.execute(f"""
            SELECT f.id, f.scan_id, f.severity, f.vuln_type, f.url,
                   f.summary, {source_col} {category_col}
                   s.target, s.started_at
            FROM findings f
            JOIN scans s ON f.scan_id = s.id
            WHERE f.severity IN ('CRITICAL','HIGH')
            {confirmed_clause}
            ORDER BY f.id DESC
            LIMIT ?
        """, (limit,)).fetchall()
    return [dict(r) for r in rows]


@app.get("/api/scans/{scan_id}/chains")
async def get_scan_chains(scan_id: int):
    """Return attack chain findings grouped by trigger type."""
    with get_db() as db:
        rows = db.execute("""
            SELECT * FROM findings
            WHERE scan_id=?
            AND (source='Attack Chain' OR category='Attack Chain'
                 OR vuln_type LIKE '%chain%' OR trigger IS NOT NULL)
            ORDER BY CASE severity
                WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1
                WHEN 'MEDIUM' THEN 2 ELSE 3 END
        """, (scan_id,)).fetchall()
    findings = [dict(r) for r in rows]
    # Group by trigger type
    chains = {}
    for f in findings:
        trigger = f.get("trigger") or f.get("vuln_type") or "unknown"
        if trigger not in chains:
            chains[trigger] = []
        chains[trigger].append(f)
    return {"chains": chains, "total": len(findings)}


# ── FRONTEND ────────────────────────────────

@app.get("/")
async def index():
    p = Path("static/index.html")
    if p.exists(): return HTMLResponse(p.read_text())
    return HTMLResponse("<h1>MCATester</h1><p>Place index.html in static/</p>")

if Path("static").exists():
    app.mount("/static", StaticFiles(directory="static"), name="static")

@app.on_event("startup")
async def startup():
    init_db()
    print("  MCATester Dashboard v2 ready → http://localhost:8000")

if __name__ == "__main__":
    import uvicorn
    print("\n" + "=" * 55)
    print("  MCATester Web Dashboard v2")
    print("=" * 55)
    init_db()
    print(f"  Database : {DB_PATH}")
    print(f"  Server   : http://localhost:8000")
    print(f"  SSE      : {'enabled' if HAS_SSE else 'disabled (pip install sse-starlette)'}")
    print("=" * 55 + "\n")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")