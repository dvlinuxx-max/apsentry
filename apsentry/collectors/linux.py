"""Linux collector: parse `nmcli` Wi-Fi scan output."""
from __future__ import annotations

import re
import subprocess

from ..models import AccessPoint, ScanResult
from ..oui import normalize_mac, vendor
from . import Collector, channel_to_band

_FIELDS = "SSID,BSSID,CHAN,SIGNAL,SECURITY,FREQ"


def _split_terse(line: str) -> list[str]:
    """Split an nmcli -t line on unescaped colons, then unescape."""
    parts = re.split(r"(?<!\\):", line)
    return [p.replace("\\:", ":").replace("\\\\", "\\") for p in parts]


class LinuxCollector(Collector):
    name = "linux-nmcli"

    def available(self) -> bool:
        try:
            subprocess.run(["nmcli", "--version"], capture_output=True,
                           text=True, timeout=6)
            return True
        except (OSError, subprocess.SubprocessError):
            return False

    def _raw(self) -> str:
        return subprocess.run(
            ["nmcli", "-t", "-f", _FIELDS, "device", "wifi", "list", "--rescan", "yes"],
            capture_output=True, text=True, timeout=25).stdout

    def parse(self, text: str) -> list[AccessPoint]:
        aps: list[AccessPoint] = []
        for line in text.splitlines():
            if not line.strip():
                continue
            cols = _split_terse(line)
            if len(cols) < 5:
                continue
            ssid, bssid, chan, signal, security = cols[0], cols[1], cols[2], cols[3], cols[4]
            freq = cols[5] if len(cols) > 5 else ""
            mac = normalize_mac(bssid)
            if not mac:
                continue
            try:
                channel = int(chan)
            except ValueError:
                channel = 0
            try:
                sig = int(signal)
            except ValueError:
                sig = 0
            band = channel_to_band(channel)
            if not band and "5" in freq[:1]:
                band = "5 GHz"
            ap = AccessPoint(
                ssid=ssid.strip(),
                bssid=mac,
                auth=(security.strip() or "Open"),
                encryption=security.strip(),
                channel=channel,
                signal=sig,
                band=band,
                vendor=vendor(mac),
            )
            aps.append(ap)
        return aps

    def scan(self) -> ScanResult:
        return ScanResult(aps=self.parse(self._raw()), source=self.name)
