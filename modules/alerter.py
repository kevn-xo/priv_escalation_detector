# -*- coding: utf-8 -*-
"""
alerter.py - Alert output for privilege escalation detector.
Destinations: CSV, Windows Event Log, Teams webhook.
"""

import csv, json, os, logging
from datetime import datetime

log = logging.getLogger("detector.alerter")

CSV_HEADERS = [
    "detected_at",  "severity",     "pid",
    "process_name", "exe_path",     "username",
    "parent_name",  "parent_pid",   "cmdline",
    "privileges",   "is_elevated",  "flags",
    "whitelist_note",
]

EVENTID_PRIV_ALERT = 3000


def alert_csv(detection: dict, report_dir: str) -> str:
    """Append detection to daily CSV. Returns filepath."""
    os.makedirs(report_dir, exist_ok=True)
    today  = datetime.now().strftime("%Y%m%d")
    fpath  = os.path.join(report_dir, f"privesc_{today}.csv")
    exists = os.path.exists(fpath)

    ctx  = detection.get("context",   {})
    tok  = detection.get("token",     {})
    wl   = detection.get("whitelist", {})

    row = {
        "detected_at":   detection.get("detected_at", ""),
        "severity":      detection.get("severity", ""),
        "pid":           ctx.get("pid", ""),
        "process_name":  ctx.get("name", ""),
        "exe_path":      ctx.get("exe", ""),
        "username":      ctx.get("username", ""),
        "parent_name":   ctx.get("parent_name", ""),
        "parent_pid":    ctx.get("parent_pid", ""),
        "cmdline":       ctx.get("cmdline", "")[:100],
        "privileges":    "|".join(tok.get("matches", [])),
        "is_elevated":   tok.get("is_elevated", False),
        "flags":         "|".join(ctx.get("flags", [])),
        "whitelist_note":wl.get("reason", ""),
    }

    with open(fpath, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
        if not exists:
            writer.writeheader()
        writer.writerow(row)

    log.debug(f"CSV alert written: {fpath}")
    return fpath


def alert_eventlog(detection: dict) -> bool:
    """Write detection to Windows Application event log."""
    try:
        import win32evtlogutil
        import win32evtlog

        ctx      = detection.get("context", {})
        tok      = detection.get("token",   {})
        severity = detection.get("severity","HIGH")

        etype = (win32evtlog.EVENTLOG_ERROR_TYPE
                 if severity == "CRITICAL"
                 else win32evtlog.EVENTLOG_WARNING_TYPE)

        privs = ", ".join(tok.get("matches", []))
        msg   = (
            f"PRIVILEGE ESCALATION DETECTED\n"
            f"Process  : {ctx.get('name','')} (PID={ctx.get('pid','')})"
            f"\nPath     : {ctx.get('exe','')}\n"
            f"User     : {ctx.get('username','')}\n"
            f"Parent   : {ctx.get('parent_name','')}\n"
            f"Elevated : {tok.get('is_elevated','')}\n"
            f"Privileges: {privs}\n"
            f"Detected : {detection.get('detected_at','')}"
        )

        win32evtlogutil.ReportEvent(
            "PrivEscDetector",
            eventID   = EVENTID_PRIV_ALERT,
            eventType = etype,
            strings   = [msg],
            data      = b"privesc_detection",
        )
        log.info("Event log entry written.")
        return True

    except Exception as e:
        log.error(f"Event log write failed: {e}")
        return False


def alert_teams(detection: dict, webhook_url: str) -> bool:
    """Send Teams card for privilege escalation detection."""
    if not webhook_url:
        return False
    try:
        import requests
    except ImportError:
        log.error("requests not installed.")
        return False

    ctx      = detection.get("context", {})
    tok      = detection.get("token",   {})
    severity = detection.get("severity","HIGH")

    color = {"CRITICAL":"FF0000","HIGH":"FF8C00",
             "MEDIUM":"FFA500"}.get(severity, "FF8C00")

    payload = {
        "@type":    "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": color,
        "summary":  f"Priv Esc Detected: {ctx.get('name','')}",
        "sections": [{
            "activityTitle":
                f"[{severity}] Privilege Escalation: {ctx.get('name','')}",
            "activitySubtitle":
                detection.get("detected_at",""),
            "facts": [
                {"name":"Process",    "value":ctx.get("name","")},
                {"name":"PID",        "value":str(ctx.get("pid",""))},
                {"name":"Path",       "value":ctx.get("exe","")},
                {"name":"User",       "value":ctx.get("username","")},
                {"name":"Parent",     "value":ctx.get("parent_name","")},
                {"name":"Elevated",   "value":str(tok.get("is_elevated",""))},
                {"name":"Privileges", "value":", ".join(tok.get("matches",[]))},
                {"name":"Flags",      "value":", ".join(ctx.get("flags",[]))},
            ],
            "markdown": True
        }]
    }

    try:
        resp = requests.post(
            webhook_url,
            data    = json.dumps(payload),
            headers = {"Content-Type":"application/json"},
            timeout = 10,
        )
        return resp.status_code == 200
    except Exception as e:
        log.error(f"Teams alert failed: {e}")
        return False


def dispatch(detection: dict, destinations: list,
             report_dir:  str = "data/reports",
             webhook_url: str = "") -> dict:
    """Route one detection to all configured destinations."""
    results  = {}
    ctx      = detection.get("context", {})
    tok      = detection.get("token",   {})
    severity = detection.get("severity","HIGH")

    log.warning(
        f"PRIV ESC ALERT | {ctx.get('name','')} "
        f"PID={ctx.get('pid','')} | "
        f"severity={severity} | "
        f"privs={tok.get('matches',[])} | "
        f"elevated={tok.get('is_elevated','')} | "
        f"path={ctx.get('exe','')}"
    )

    if "csv" in destinations:
        results["csv"] = alert_csv(detection, report_dir)

    if "eventlog" in destinations:
        results["eventlog"] = alert_eventlog(detection)

    if "teams" in destinations and webhook_url:
        results["teams"] = alert_teams(detection, webhook_url)

    return results
