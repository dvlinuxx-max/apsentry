"""Core data types: access points, detections, alerts, and severity."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @property
    def color(self) -> str:
        return {
            Severity.INFO: "#6b7280",
            Severity.LOW: "#3b82f6",
            Severity.MEDIUM: "#f59e0b",
            Severity.HIGH: "#f97316",
            Severity.CRITICAL: "#ef4444",
        }[self]

    @classmethod
    def from_score(cls, score: int) -> "Severity":
        if score >= 90:
            return cls.CRITICAL
        if score >= 65:
            return cls.HIGH
        if score >= 40:
            return cls.MEDIUM
        if score >= 15:
            return cls.LOW
        return cls.INFO


@dataclass
class AccessPoint:
    """One observed access point (a single BSSID)."""
    ssid: str
    bssid: str
    auth: str = ""
    encryption: str = ""
    channel: int = 0
    signal: int = 0           # percent 0-100 (Windows) or normalized
    rssi: Optional[int] = None  # dBm where available
    radio: str = ""
    band: str = ""
    vendor: str = ""
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    times_seen: int = 1
    trusted: bool = False

    @property
    def is_open(self) -> bool:
        a = (self.auth or "").lower()
        return a in ("", "open") or "open" in a

    @property
    def is_hidden(self) -> bool:
        return self.ssid == "" or self.ssid.lower() in ("<hidden>", "(hidden)")

    @property
    def key(self) -> str:
        return f"{self.ssid}\x00{self.bssid}".lower()

    def to_dict(self) -> dict:
        return {
            "ssid": self.ssid or "<hidden>",
            "bssid": self.bssid,
            "auth": self.auth,
            "encryption": self.encryption,
            "channel": self.channel,
            "signal": self.signal,
            "rssi": self.rssi,
            "radio": self.radio,
            "band": self.band,
            "vendor": self.vendor,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "times_seen": self.times_seen,
            "trusted": self.trusted,
            "open": self.is_open,
        }


@dataclass
class Detection:
    """A single suspicious finding produced by the detection engine."""
    code: str
    title: str
    severity: Severity
    score: int
    ssid: str
    bssid: str
    detail: str
    recommendation: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "title": self.title,
            "severity": self.severity.label,
            "severity_value": int(self.severity),
            "color": self.severity.color,
            "score": self.score,
            "ssid": self.ssid or "<hidden>",
            "bssid": self.bssid,
            "detail": self.detail,
            "recommendation": self.recommendation,
            "timestamp": self.timestamp,
        }


@dataclass
class ScanResult:
    aps: list[AccessPoint]
    source: str
    timestamp: float = field(default_factory=time.time)
