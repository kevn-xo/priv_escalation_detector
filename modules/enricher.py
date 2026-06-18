# -*- coding: utf-8 -*-
"""
enricher.py - Enriches a new process event with full context.

Raw WMI Creation event gives us: PID, Name, ExecutablePath, CommandLine.
We add: parent process name, owner, is path suspicious, exists on disk.
"""

import psutil
import os
import logging
from datetime import datetime

log = logging.getLogger("detector.enricher")


def enrich(pid: int, wmi_event=None,
           suspicious_paths: list = None) -> dict:
    """
    Build a full context dict for a newly detected process.

    Args:
        pid:              process ID
        wmi_event:        raw WMI Win32_Process object (optional)
        suspicious_paths: list of path substrings to flag

    Returns:
        enriched process context dict
    """
    suspicious_paths = suspicious_paths or []

    context = {
        "pid":          pid,
        "name":         "",
        "exe":          "",
        "cmdline":      "",
        "username":     "",
        "parent_pid":   None,
        "parent_name":  "",
        "create_time":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "exe_exists":   False,
        "flags":        [],
    }

    # Prefer WMI event data - it is captured at creation time
    # and won't disappear if the process exits fast
    if wmi_event:
        context["name"]   = getattr(wmi_event, "Name",            "") or ""
        context["exe"]    = getattr(wmi_event, "ExecutablePath",   "") or ""
        context["cmdline"]= getattr(wmi_event, "CommandLine",      "") or ""

    # Fill gaps with psutil - may fail if process already exited
    try:
        proc = psutil.Process(pid)
        if not context["name"]:
            context["name"] = proc.name()
        if not context["exe"]:
            context["exe"]  = proc.exe()
        if not context["cmdline"]:
            context["cmdline"] = " ".join(proc.cmdline())

        context["username"]   = proc.username()
        context["parent_pid"] = proc.ppid()

        try:
            parent = psutil.Process(proc.ppid())
            context["parent_name"] = parent.name()
        except Exception:
            context["parent_name"] = "unknown"

        context["create_time"] = datetime.fromtimestamp(
            proc.create_time()
        ).strftime("%Y-%m-%d %H:%M:%S")

    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        log.debug(f"psutil enrichment limited for PID {pid}: {e}")

    # Existence check
    exe = context["exe"]
    context["exe_exists"] = os.path.exists(exe) if exe else False

    # Flag suspicious paths
    for sp in suspicious_paths:
        if sp.lower() in exe.lower():
            context["flags"].append("SUSPICIOUS_PATH")
            break

    if exe and not context["exe_exists"]:
        context["flags"].append("EXE_NOT_ON_DISK")

    return context
