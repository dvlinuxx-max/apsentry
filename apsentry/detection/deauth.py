"""Optional monitor-mode detector for 802.11 deauth/disassoc floods.

Requires scapy and a wireless interface in monitor mode (Linux). A deauth flood
is a denial-of-service that knocks clients off an AP and is also the setup phase
of many evil-twin attacks, so detecting it complements the scan-based engine.

This module is import-safe without scapy: available() returns False and the rest
of the tool keeps working.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from typing import Callable, Optional

try:
    from scapy.all import sniff, Dot11, Dot11Deauth, Dot11Disas  # type: ignore
    _HAVE_SCAPY = True
except Exception:
    _HAVE_SCAPY = False


class DeauthMonitor:
    """Sniff management frames and flag deauth/disassoc bursts over a threshold."""

    def __init__(self, iface: str, window: float = 5.0, threshold: int = 20,
                 on_alert: Optional[Callable[[dict], None]] = None):
        self.iface = iface
        self.window = window
        self.threshold = threshold
        self.on_alert = on_alert
        self.events: deque = deque()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.total_deauth = 0

    @staticmethod
    def available() -> bool:
        return _HAVE_SCAPY

    def _handle(self, pkt) -> None:
        if not pkt.haslayer(Dot11):
            return
        if not (pkt.haslayer(Dot11Deauth) or pkt.haslayer(Dot11Disas)):
            return
        now = time.time()
        d = pkt.getlayer(Dot11)
        self.events.append((now, d.addr2, d.addr1))
        self.total_deauth += 1
        while self.events and now - self.events[0][0] > self.window:
            self.events.popleft()
        if len(self.events) >= self.threshold and self.on_alert:
            srcs = {e[1] for e in self.events}
            self.on_alert({
                "count": len(self.events), "window_s": self.window,
                "sources": sorted(s for s in srcs if s), "ts": now,
            })

    def _run(self) -> None:
        sniff(iface=self.iface, prn=self._handle, store=False,
              stop_filter=lambda _: self._stop.is_set())

    def start(self) -> None:
        if not _HAVE_SCAPY:
            raise RuntimeError("scapy is not installed; deauth monitoring unavailable")
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
