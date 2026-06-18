# -*- coding: utf-8 -*-
"""
whitelist.py - Path-based process whitelist.

Name-only whitelisting is bypassed trivially by renaming malware.
Path-based whitelisting requires BOTH name AND path to match.
If either is wrong -> not whitelisted -> alert.
"""

import json
import os
import logging

log = logging.getLogger("detector.whitelist")


def load(whitelist_path: str) -> list:
    """Load whitelist rules from JSON file."""
    try:
        with open(whitelist_path, encoding="utf-8") as f:
            data = json.load(f)
        rules = data.get("rules", [])
        log.debug(f"Loaded {len(rules)} whitelist rules.")
        return rules
    except Exception as e:
        log.error(f"Whitelist load failed: {e}")
        return []


def is_whitelisted(process_name: str,
                   exe_path:     str,
                   rules:        list) -> dict:
    """
    Check if a process is whitelisted.

    Logic:
      - Find a rule where process_name matches (case-insensitive)
      - AND exe_path contains path_must_contain (case-insensitive)
      - Both must match for whitelist to apply

    Returns:
      dict with "whitelisted" bool and "reason" string
    """
    name_lower = process_name.lower()
    path_lower = exe_path.lower()

    for rule in rules:
        rule_name = rule.get("name", "").lower()
        rule_path = rule.get("path_must_contain", "").lower()

        if name_lower == rule_name:
            # Name matches - now check path
            if rule_path and rule_path in path_lower:
                return {
                    "whitelisted": True,
                    "reason":      rule.get("reason", "whitelisted"),
                    "matched_rule":rule,
                }
            elif rule_path and rule_path not in path_lower:
                # Name matches but path is WRONG
                # This is a masquerading indicator
                return {
                    "whitelisted": False,
                    "reason":      (
                        f"Name '{process_name}' matches whitelist but "
                        f"path '{exe_path}' does not contain "
                        f"'{rule['path_must_contain']}' - possible masquerading"
                    ),
                    "masquerading": True,
                    "matched_rule": rule,
                }

    return {
        "whitelisted":  False,
        "reason":       "No matching whitelist rule",
        "masquerading": False,
    }
