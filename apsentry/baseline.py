"""Trusted access-point baseline: the known-good environment to compare against.

An evil twin is, by definition, an AP that impersonates a network you trust.
The baseline records the legitimate (SSID, BSSID, auth, vendor, channel) tuples
so the engine can tell impersonation from a genuinely new neighbor.
"""
from __future__ import annotations

import json
import os
from typing import Optional

from .models import AccessPoint, ScanResult


class Baseline:
    def __init__(self, path: Optional[str] = None):
        self.path = path
        self.entries: dict[str, dict] = {}  # bssid -> attributes
        if path and os.path.exists(path):
            self.load()

    def load(self) -> None:
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.entries = {k.lower(): v for k, v in data.get("entries", {}).items()}
        except (OSError, json.JSONDecodeError, AttributeError):
            self.entries = {}

    def save(self) -> None:
        if not self.path:
            return
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump({"version": 1, "entries": self.entries}, f, indent=2)

    def add(self, ap: AccessPoint) -> None:
        self.entries[ap.bssid.lower()] = {
            "ssid": ap.ssid, "auth": ap.auth, "vendor": ap.vendor,
            "channel": ap.channel,
        }

    def remove(self, bssid: str) -> bool:
        return self.entries.pop(bssid.lower(), None) is not None

    def learn(self, scan: ScanResult) -> int:
        before = len(self.entries)
        for ap in scan.aps:
            if ap.bssid:
                self.add(ap)
        return len(self.entries) - before

    def is_trusted_bssid(self, bssid: str) -> bool:
        return bssid.lower() in self.entries

    def get(self, bssid: str) -> Optional[dict]:
        return self.entries.get(bssid.lower())

    @property
    def trusted_ssids(self) -> set[str]:
        return {e.get("ssid", "") for e in self.entries.values() if e.get("ssid")}

    def trusted_bssids_for(self, ssid: str) -> list[str]:
        return [b for b, e in self.entries.items() if e.get("ssid") == ssid]

    def __len__(self) -> int:
        return len(self.entries)
