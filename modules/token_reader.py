# -*- coding: utf-8 -*-
"""
token_reader.py - Reads enabled privileges from a process token.

DEFENSIVE USE: Detects unexpected privilege escalation by inspecting
the security token of newly created processes in real time.

Flow per new process:
  1. OpenProcess(PROCESS_QUERY_INFORMATION, pid)
  2. OpenProcessToken(handle, TOKEN_QUERY)
  3. GetTokenInformation(token, TokenPrivileges)
  4. Filter for SE_PRIVILEGE_ENABLED
  5. LookupPrivilegeName for each enabled LUID
  6. Return list of enabled privilege names
"""

import win32api
import win32con
import win32security
import logging

log = logging.getLogger("detector.token_reader")

# Token access flag needed - query only, not modify
TOKEN_QUERY = win32con.TOKEN_QUERY


def read_enabled_privileges(pid: int) -> dict:
    """
    Read all ENABLED privileges from the token of a process.

    Args:
        pid: Target process ID

    Returns:
        dict with keys:
          "enabled_privileges": list of privilege name strings
          "all_privileges":     list of all privileges (enabled + disabled)
          "error":              error string if failed, else None
          "is_elevated":        True if token is elevated
    """
    result = {
        "enabled_privileges": [],
        "all_privileges":     [],
        "is_elevated":        False,
        "error":              None,
    }

    proc_handle  = None
    token_handle = None

    try:
        # Step 1: Open the process - PROCESS_QUERY_INFORMATION is enough
        # We do NOT need PROCESS_ALL_ACCESS - minimal privilege principle
        proc_handle = win32api.OpenProcess(
            win32con.PROCESS_QUERY_INFORMATION,
            False,
            pid
        )

        # Step 2: Open its token - TOKEN_QUERY only
        token_handle = win32security.OpenProcessToken(
            proc_handle,
            TOKEN_QUERY
        )

        # Step 3: Read all privileges from the token
        raw_privs = win32security.GetTokenInformation(
            token_handle,
            win32security.TokenPrivileges
        )
        # raw_privs = list of (LUID, flags) tuples

        # Step 4: Filter and name them
        for luid, flags in raw_privs:
            try:
                name = win32security.LookupPrivilegeName(None, luid)
            except Exception:
                name = str(luid)

            result["all_privileges"].append(name)

            # SE_PRIVILEGE_ENABLED = bit 2 set in flags
            if flags & win32security.SE_PRIVILEGE_ENABLED:
                result["enabled_privileges"].append(name)

        # Step 5: Check elevation type
        try:
            elev = win32security.GetTokenInformation(
                token_handle,
                win32security.TokenElevation
            )
            result["is_elevated"] = bool(elev)
        except Exception:
            pass

    except win32api.error as e:
        # Common errors:
        # 5  = Access Denied (protected process like lsass)
        # 87 = Invalid parameter (PID gone - process exited before we read it)
        result["error"] = f"win32 error {e.winerror}: {e.strerror}"
        log.debug(f"PID {pid}: {result['error']}")

    except Exception as e:
        result["error"] = str(e)
        log.debug(f"PID {pid} token read failed: {e}")

    finally:
        if token_handle:
            try:
                token_handle.Close()
            except Exception:
                pass
        if proc_handle:
            try:
                proc_handle.Close()
            except Exception:
                pass

    return result


def get_high_risk_enabled(pid: int,
                           high_risk_list: list) -> dict:
    """
    Convenience wrapper - returns only the high-risk enabled privileges
    for a given PID, along with context.

    Args:
        pid:            target process ID
        high_risk_list: list of privilege names to watch for

    Returns:
        dict with "matches" (list), "all_enabled", "is_elevated", "error"
    """
    token_info = read_enabled_privileges(pid)

    matches = [
        p for p in token_info["enabled_privileges"]
        if p in high_risk_list
    ]

    return {
        "matches":     matches,
        "all_enabled": token_info["enabled_privileges"],
        "is_elevated": token_info["is_elevated"],
        "error":       token_info["error"],
    }
