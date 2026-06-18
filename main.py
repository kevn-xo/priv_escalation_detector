# -*- coding: utf-8 -*-
"""
main.py - Privilege Escalation Detector
Usage:
  python main.py                          # Run with config defaults
  python main.py --output csv             # CSV alerts only
  python main.py --output all             # CSV + event log + Teams
  python main.py --webhook-url URL        # Add Teams destination
  python main.py --dry-run                # Detect, print, no alerts
  python main.py --privilege SeDebug,...  # Watch specific privs only
  python main.py --duration 60            # Run for 60s then exit
  python main.py --config custom.json
"""

import argparse, json, os, sys, time, signal, queue
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from modules.logger      import get_logger
from modules.wmi_watcher import ProcessWatcher
from modules.token_reader import get_high_risk_enabled
from modules.enricher    import enrich
from modules.whitelist   import load as load_whitelist, is_whitelisted
from modules.alerter     import dispatch


def load_config(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def compute_severity(matched_privs: list,
                     privilege_severity: dict,
                     is_elevated: bool,
                     masquerading: bool) -> str:
    """
    Determine alert severity from matched privileges.
    Escalates to CRITICAL if masquerading detected or elevated token.
    """
    if masquerading:
        return "CRITICAL"

    severities = [privilege_severity.get(p, "MEDIUM")
                  for p in matched_privs]

    if "CRITICAL" in severities:
        return "CRITICAL"
    if is_elevated and "HIGH" in severities:
        return "CRITICAL"
    if "HIGH" in severities:
        return "HIGH"
    return "MEDIUM"


def process_event(event: dict, cfg: dict,
                  wl_rules: list, log,
                  dry_run: bool,
                  destinations: list,
                  webhook_url: str,
                  report_dir: str,
                  watch_privs: list):
    """
    Handle one new process event from the watcher queue.

    Steps:
    1. Enrich with context (path, parent, cmdline, user)
    2. Check whitelist
    3. Read token privileges
    4. Cross-reference against high-risk privilege list
    5. If matches found and not whitelisted -> alert
    """
    pid       = event["pid"]
    wmi_event = event.get("wmi_event")

    # Step 1: Enrich
    context = enrich(pid, wmi_event, cfg["suspicious_paths"])
    name    = context["name"]
    exe     = context["exe"]

    # Step 2: Whitelist check
    wl_result = is_whitelisted(name, exe, wl_rules)

    if wl_result["whitelisted"]:
        log.debug(f"Whitelisted: {name} PID={pid}")
        return

    masquerading = wl_result.get("masquerading", False)
    if masquerading:
        log.warning(
            f"MASQUERADING DETECTED: {name} PID={pid} "
            f"path={exe} | {wl_result['reason']}"
        )

    # Step 3: Read token
    tok = get_high_risk_enabled(pid, watch_privs)

    if tok["error"] and not masquerading:
        # Access denied on protected processes is normal - skip silently
        log.debug(f"Token read error PID={pid}: {tok['error']}")
        return

    # Step 4: Check for matches
    matched = tok.get("matches", [])

    if not matched and not masquerading:
        return   # Clean process - no high-risk privs enabled

    # Step 5: Build detection and alert
    severity = compute_severity(
        matched,
        cfg["privilege_severity"],
        tok.get("is_elevated", False),
        masquerading,
    )

    detection = {
        "detected_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "severity":    severity,
        "context":     context,
        "token":       tok,
        "whitelist":   wl_result,
        "masquerading":masquerading,
    }

    log.warning(
        f"DETECTION | {name} PID={pid} | "
        f"severity={severity} | "
        f"privs={matched} | elevated={tok.get('is_elevated',False)}"
    )

    if dry_run:
        log.info("DRY-RUN: alert suppressed.")
        print(f"\n[DRY-RUN] Detection:")
        print(json.dumps({
            "severity":   severity,
            "process":    name,
            "pid":        pid,
            "exe":        exe,
            "privileges": matched,
            "elevated":   tok.get("is_elevated"),
            "flags":      context["flags"],
        }, indent=2))
        return

    result = dispatch(
        detection,
        destinations,
        report_dir  = report_dir,
        webhook_url = webhook_url,
    )
    log.info(f"Alert dispatched: {result}")


def run_detector(args, cfg, log):
    report_dir  = os.path.join(BASE_DIR, cfg["report_dir"])
    webhook_url = args.webhook_url or cfg.get("teams_webhook_url","")
    wl_path     = os.path.join(BASE_DIR, "whitelist.json")
    wl_rules    = load_whitelist(wl_path)

    # Privilege list to watch
    watch_privs = cfg["high_risk_privileges"]
    if args.privilege:
        watch_privs = [p.strip() for p in args.privilege.split(",")]

    # Alert destinations
    if args.output == "all":
        destinations = ["csv","eventlog","teams"]
    elif args.output:
        destinations = [args.output]
    else:
        destinations = cfg["alert_destinations"]

    log.info("=" * 60)
    log.info("PRIVILEGE ESCALATION DETECTOR STARTED")
    log.info(f"Watching privs : {watch_privs}")
    log.info(f"Whitelist rules: {len(wl_rules)}")
    log.info(f"Destinations   : {destinations}")
    log.info(f"Dry-run        : {args.dry_run}")
    log.info("=" * 60)

    # Event queue - watcher puts, main thread reads
    event_queue = queue.Queue(maxsize=500)

    # Start watcher thread
    watcher = ProcessWatcher(
        event_queue   = event_queue,
        poll_interval = cfg["watch_interval_seconds"],
    )
    watcher.start()
    log.info("Watcher thread started.")

    # Graceful shutdown
    running    = [True]
    start_time = time.time()

    def _stop(sig, frame):
        log.info("Shutdown signal received.")
        running[0] = False
    signal.signal(signal.SIGINT, _stop)

    processed = 0

    while running[0]:
        # Check duration limit
        if args.duration and (time.time() - start_time) >= args.duration:
            log.info(f"Duration limit ({args.duration}s) reached.")
            break

        try:
            event = event_queue.get(timeout=1)
            processed += 1
            process_event(
                event, cfg, wl_rules, log,
                args.dry_run, destinations,
                webhook_url, report_dir, watch_privs,
            )
        except queue.Empty:
            continue
        except Exception as e:
            log.error(f"Event processing error: {e}", exc_info=True)

    watcher.stop()
    log.info(f"Detector stopped. Events processed: {processed}")


def main():
    parser = argparse.ArgumentParser(
        description="Privilege Escalation Detector - real-time token monitoring."
    )
    parser.add_argument("--output",
                        choices=["csv","eventlog","teams","all"],
                        default=None)
    parser.add_argument("--webhook-url",  default="")
    parser.add_argument("--privilege",    default=None,
                        help="Comma-separated privilege names to watch")
    parser.add_argument("--dry-run",      action="store_true")
    parser.add_argument("--duration",     type=int, default=None,
                        help="Stop after N seconds (for testing)")
    parser.add_argument("--config",
                        default=os.path.join(BASE_DIR, "config.json"))
    args   = parser.parse_args()
    cfg    = load_config(args.config)
    log    = get_logger(
        "detector",
        os.path.join(BASE_DIR, cfg["log_file"])
    )
    run_detector(args, cfg, log)


if __name__ == "__main__":
    main()
