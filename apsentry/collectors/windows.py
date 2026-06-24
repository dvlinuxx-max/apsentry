"""Windows collector: parse `netsh wlan show networks mode=bssid`."""
from __future__ import annotations

import re
import subprocess

from ..models import AccessPoint, ScanResult
from ..oui import normalize_mac, vendor
from . import Collector, channel_to_band

_SSID = re.compile(r"^SSID\s+\d+\s*:\s?(.*)$")
_AUTH = re.compile(r"^\s*Authentication\s*:\s*(.+)$")
_ENC = re.compile(r"^\s*Encryption\s*:\s*(.+)$")
_BSSID = re.compile(r"^\s*BSSID\s+\d+\s*:\s*(.+)$")
_SIGNAL = re.compile(r"^\s*Signal\s*:\s*(\d+)%")
_RADIO = re.compile(r"^\s*Radio type\s*:\s*(.+)$")
_CHANNEL = re.compile(r"^\s*Channel\s*:\s*(\d+)")


class WindowsCollector(Collector):
    name = "windows-netsh"

    def available(self) -> bool:
        try:
            out = subprocess.run(["netsh", "wlan", "show", "interfaces"],
                                 capture_output=True, text=True, timeout=8).stdout
        except (OSError, subprocess.SubprocessError):
            return False
        return "no wireless interface" not in out.lower()

    def _raw(self) -> str:
        return subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"],
                              capture_output=True, text=True, timeout=20).stdout

    def parse(self, text: str) -> list[AccessPoint]:
        aps: list[AccessPoint] = []
        ssid = auth = enc = ""
        cur: AccessPoint | None = None
        for line in text.splitlines():
            m = _SSID.match(line)
            if m:
                ssid = m.group(1).strip()
                auth = enc = ""
                cur = None
                continue
            m = _AUTH.match(line)
            if m and cur is None:
                auth = m.group(1).strip()
                continue
            m = _ENC.match(line)
            if m and cur is None:
                enc = m.group(1).strip()
                continue
            m = _BSSID.match(line)
            if m:
                mac = normalize_mac(m.group(1).strip())
                if not mac:
                    cur = None
                    continue
                cur = AccessPoint(ssid=ssid, bssid=mac, auth=auth, encryption=enc,
                                  vendor=vendor(mac))
                aps.append(cur)
                continue
            if cur is None:
                continue
            m = _SIGNAL.match(line)
            if m:
                cur.signal = int(m.group(1))
                continue
            m = _RADIO.match(line)
            if m:
                cur.radio = m.group(1).strip()
                continue
            m = _CHANNEL.match(line)
            if m:
                cur.channel = int(m.group(1))
                cur.band = channel_to_band(cur.channel)
        return aps

    def scan(self) -> ScanResult:
        return ScanResult(aps=self.parse(self._raw()), source=self.name)
