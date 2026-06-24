"""Rolling monitor state: AP inventory, signal history, and the alert log."""
from __future__ import annotations

import time
from collections import deque
from typing import Optional

from .models import AccessPoint, Detection, ScanResult, Severity


class MonitorState:
    def __init__(self, alert_cap: int = 500, history_per_ap: int = 60,
                 alert_cooldown: float = 30.0, prune_after: float = 600.0):
        self.aps: dict[str, AccessPoint] = {}
        self.prune_after = prune_after
        self.signal_history: dict[str, deque] = {}
        self.alerts: list[Detection] = []
        self.alert_cap = alert_cap
        self.history_per_ap = history_per_ap
        self.alert_cooldown = alert_cooldown
        self.scan_count = 0
        self.started = time.time()
        self.last_scan_ts = 0.0
        self.current_detections: list[Detection] = []
        self.current_risk = 0
        self._alert_index: dict[str, Detection] = {}

    def ingest_scan(self, scan: ScanResult) -> None:
        self.scan_count += 1
        self.last_scan_ts = scan.timestamp
        for ap in scan.aps:
            existing = self.aps.get(ap.bssid)
            if existing:
                existing.last_seen = scan.timestamp
                existing.times_seen += 1
                existing.signal = ap.signal
                existing.channel = ap.channel or existing.channel
                existing.auth = ap.auth or existing.auth
                if ap.vendor:
                    existing.vendor = ap.vendor
            else:
                self.aps[ap.bssid] = ap
            hist = self.signal_history.setdefault(
                ap.bssid, deque(maxlen=self.history_per_ap))
            hist.append((scan.timestamp, ap.signal))
        self._prune(scan.timestamp)

    def _prune(self, now: float) -> None:
        """Drop APs not seen for a while so the inventory reflects the present
        and transient (rotating-MAC) rogues do not accumulate forever."""
        stale = [b for b, ap in self.aps.items()
                 if now - ap.last_seen > self.prune_after]
        for b in stale:
            self.aps.pop(b, None)
            self.signal_history.pop(b, None)

    def previous_signal(self, bssid: str) -> Optional[int]:
        hist = self.signal_history.get(bssid)
        if hist and len(hist) >= 2:
            return hist[-2][1]
        return None

    def record_detections(self, dets: list[Detection]) -> list[Detection]:
        """Add new detections to the alert log, de-duplicating by code+target."""
        fresh: list[Detection] = []
        now = time.time()
        for d in dets:
            akey = f"{d.code}|{d.ssid}|{d.bssid}"
            prev = self._alert_index.get(akey)
            if prev and (now - prev.timestamp) < self.alert_cooldown:
                prev.timestamp = now  # refresh, still the same active alert
                continue
            self._alert_index[akey] = d
            self.alerts.insert(0, d)
            fresh.append(d)
        if len(self.alerts) > self.alert_cap:
            self.alerts = self.alerts[: self.alert_cap]
        return fresh

    def counts_by_severity(self) -> dict[str, int]:
        out = {s.label: 0 for s in Severity}
        for d in self.current_detections:
            out[d.severity.label] += 1
        return out

    def snapshot(self) -> dict:
        # Inventory reflects what was visible in the most recent scan.
        current = [a for a in self.aps.values() if a.last_seen >= self.last_scan_ts]
        aps = sorted(current, key=lambda a: a.signal, reverse=True)
        return {
            "scan_count": self.scan_count,
            "uptime_s": int(time.time() - self.started),
            "last_scan_ts": self.last_scan_ts,
            "ap_count": len(current),
            "total_tracked": len(self.aps),
            "risk": self.current_risk,
            "severity_counts": self.counts_by_severity(),
            "access_points": [a.to_dict() for a in aps],
            "detections": [d.to_dict() for d in self.current_detections],
            "alerts": [d.to_dict() for d in self.alerts[:120]],
        }
