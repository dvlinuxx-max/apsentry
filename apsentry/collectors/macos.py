"""macOS collector: parse the legacy `airport -s` scan table."""
from __future__ import annotations

import re
import subprocess

from ..models import AccessPoint, ScanResult
from ..oui import normalize_mac, vendor
from . import Collector, channel_to_band

_AIRPORT = ("/System/Library/PrivateFrameworks/Apple80211.framework/"
            "Versions/Current/Resources/airport")
_ROW = re.compile(
    r"^\s*(.*\S)\s+([0-9a-fA-F:]{17})\s+(-?\d+)\s+([0-9,+\-]+)\s+\S+\s+\S+\s+(.*)$")


class MacCollector(Collector):
    name = "macos-airport"

    def available(self) -> bool:
        import os
        return os.path.exists(_AIRPORT)

    def _raw(self) -> str:
        return subprocess.run([_AIRPORT, "-s"], capture_output=True,
                              text=True, timeout=25).stdout

    def parse(self, text: str) -> list[AccessPoint]:
        aps: list[AccessPoint] = []
        lines = text.splitlines()
        for line in lines[1:]:  # first line is the header
            m = _ROW.match(line)
            if not m:
                continue
            ssid, bssid, rssi, chan, security = m.groups()
            mac = normalize_mac(bssid)
            if not mac:
                continue
            channel = int(re.split(r"[,+\-]", chan)[0]) if chan else 0
            rssi_v = int(rssi)
            # Map dBm to a rough 0-100 quality for a consistent UI scale.
            quality = max(0, min(100, 2 * (rssi_v + 100)))
            aps.append(AccessPoint(
                ssid=ssid.strip(),
                bssid=mac,
                auth=security.strip() or "Open",
                encryption=security.strip(),
                channel=channel,
                signal=quality,
                rssi=rssi_v,
                band=channel_to_band(channel),
                vendor=vendor(mac),
            ))
        return aps

    def scan(self) -> ScanResult:
        return ScanResult(aps=self.parse(self._raw()), source=self.name)
