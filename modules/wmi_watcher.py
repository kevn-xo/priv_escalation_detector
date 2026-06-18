# -*- coding: utf-8 -*-
"""
wmi_watcher.py - Real-time process creation watcher via WMI.

Uses Win32_Process.watch_for(Creation) which blocks until
a new process is created, then returns the WMI event object.

Runs in its own thread - puts detected events onto a queue
so the main thread can handle alerting without blocking the watcher.
"""

import wmi
import pythoncom
import threading
import queue
import logging
import time

log = logging.getLogger("detector.wmi_watcher")


class ProcessWatcher(threading.Thread):
    """
    Background thread that watches for new process creation via WMI.
    Puts each new process event onto an output queue.
    Main thread reads from the queue and handles token inspection + alerting.

    Why a separate thread?
      - WMI watcher blocks until an event fires
      - We need the main thread free to handle alerting, logging, shutdown
      - Queue decouples detection from response
    """

    def __init__(self, event_queue: queue.Queue,
                 poll_interval: int = 1):
        super().__init__(daemon=True)
        self.event_queue   = event_queue
        self.poll_interval = poll_interval
        self._stop_event   = threading.Event()
        self.name          = "ProcessWatcherThread"

    def stop(self):
        """Signal the watcher thread to stop."""
        self._stop_event.set()

    def run(self):
        """
        Thread entry point.
        pythoncom.CoInitialize() MUST be called in the thread that uses WMI.
        Each thread needs its own COM initialization.
        """
        log.info("WMI watcher thread starting...")

        try:
            # CoInitialize in THIS thread - mandatory for COM/WMI
            pythoncom.CoInitialize()
            c = wmi.WMI()

            # watch_for returns a watcher object
            # Calling the watcher blocks until a process is created
            watcher = c.Win32_Process.watch_for(
                notification_type = "Creation",
                delay_secs        = self.poll_interval,
            )

            log.info("WMI watcher active - watching for new processes...")

            while not self._stop_event.is_set():
                try:
                    # Blocks here until a new process fires
                    # wmi library raises wmi.x_wmi_timed_out on timeout
                    new_proc = watcher()

                    if new_proc is None:
                        continue

                    pid  = new_proc.ProcessId
                    name = new_proc.Name or ""

                    log.debug(f"New process detected: {name} PID={pid}")

                    # Put on queue for main thread to handle
                    self.event_queue.put({
                        "pid":       pid,
                        "name":      name,
                        "wmi_event": new_proc,
                    })

                except wmi.x_wmi_timed_out:
                    # Normal timeout - loop back and check stop event
                    continue
                except Exception as e:
                    if not self._stop_event.is_set():
                        log.error(f"Watcher error: {e}")
                    time.sleep(1)

        except Exception as e:
            log.error(f"WMI watcher thread fatal error: {e}")

        finally:
            try:
                pythoncom.CoUninitialize()
            except Exception:
                pass
            log.info("WMI watcher thread stopped.")
