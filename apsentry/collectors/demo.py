"""Demo collector: a synthetic wireless environment for testing without hardware.

Generates a stable set of legitimate access points and, scan to scan, injects
realistic threats (evil twins, open clones, randomized-MAC rogues, beacon
floods) so the detection engine and dashboard can be exercised end to end.
Also replays scans from a JSON file written by --export.
"""
from __future__ import annotations

import json
import random
from typing import Optional

from ..models import AccessPoint, ScanResult
from ..oui import normalize_mac, vendor
from . import Collector, channel_to_band

# (ssid, auth, encryption, oui_prefix, channel, base_signal)
_LEGIT = [
    ("HomeNet", "WPA2-Personal", "CCMP", "50:c7:bf", 6, 88),
    ("HomeNet_5G", "WPA3-Personal", "CCMP", "50:c7:bf", 36, 80),
    ("CoffeeShop-WiFi", "Open", "", "e0:55:3d", 1, 72),
    ("Office-Corp", "WPA2-Enterprise", "CCMP", "6c:f3:7f", 11, 76),
    ("Neighbor-2G", "WPA2-Personal", "CCMP", "2c:56:dc", 11, 45),
    ("Linksys-2331", "WPA2-Personal", "CCMP", "48:f8:b3", 6, 38),
    ("TP-Link_Guest", "WPA2-Personal", "CCMP", "a4:2b:b0", 44, 55),
]


def _mac_from_oui(prefix: str, rng: random.Random) -> str:
    tail = ":".join(f"{rng.randint(0, 255):02x}" for _ in range(3))
    return normalize_mac(prefix + ":" + tail)


def _random_local_mac(rng: random.Random) -> str:
    first = (rng.randint(0, 255) | 0x02) & 0xFE  # locally administered, unicast
    rest = ":".join(f"{rng.randint(0, 255):02x}" for _ in range(5))
    return normalize_mac(f"{first:02x}:{rest}")


class DemoCollector(Collector):
    name = "demo"

    def __init__(self, seed: Optional[int] = None, scenario: str = "mixed",
                 replay: Optional[str] = None, **_):
        self.rng = random.Random(seed)
        self.scenario = (scenario or "mixed").lower()
        self.replay_scans: list[list[dict]] = []
        self.replay_idx = 0
        self._tick = 0
        self.base: list[AccessPoint] = []
        for ssid, auth, enc, prefix, chan, sig in _LEGIT:
            self.base.append(AccessPoint(
                ssid=ssid, bssid=_mac_from_oui(prefix, self.rng), auth=auth,
                encryption=enc, channel=chan, signal=sig,
                band=channel_to_band(chan), vendor=vendor(_mac_from_oui(prefix, self.rng)),
            ))
        # vendor() recomputed from the actual bssid below
        for ap in self.base:
            ap.vendor = vendor(ap.bssid)
        if replay:
            with open(replay, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.replay_scans = data if isinstance(data, list) else [data]

    def available(self) -> bool:
        return True

    def _jitter(self, ap: AccessPoint) -> AccessPoint:
        sig = max(5, min(99, ap.signal + self.rng.randint(-4, 4)))
        return AccessPoint(
            ssid=ap.ssid, bssid=ap.bssid, auth=ap.auth, encryption=ap.encryption,
            channel=ap.channel, signal=sig, band=ap.band, vendor=ap.vendor,
            radio="802.11ac" if ap.channel > 14 else "802.11n",
        )

    def _evil_twin_of(self, target_ssid: str) -> AccessPoint:
        legit = next(a for a in self.base if a.ssid == target_ssid)
        return AccessPoint(
            ssid=target_ssid, bssid=_random_local_mac(self.rng),
            auth="Open", encryption="", channel=legit.channel,
            signal=min(99, legit.signal + self.rng.randint(8, 18)),
            band=legit.band, vendor=vendor(_random_local_mac(self.rng)),
            radio="802.11n",
        )

    def _flood(self, n: int) -> list[AccessPoint]:
        out = []
        for i in range(n):
            ch = self.rng.choice([1, 6, 11])
            out.append(AccessPoint(
                ssid=f"FreeWiFi-{self.rng.randint(1000, 9999)}",
                bssid=_random_local_mac(self.rng), auth="Open", encryption="",
                channel=ch, signal=self.rng.randint(20, 60),
                band=channel_to_band(ch), radio="802.11n"))
        return out

    def scan(self) -> ScanResult:
        if self.replay_scans:
            raw = self.replay_scans[self.replay_idx % len(self.replay_scans)]
            self.replay_idx += 1
            aps = [AccessPoint(
                ssid=d.get("ssid", "").replace("<hidden>", ""),
                bssid=d.get("bssid", ""), auth=d.get("auth", ""),
                encryption=d.get("encryption", ""), channel=d.get("channel", 0),
                signal=d.get("signal", 0), band=d.get("band", ""),
                vendor=d.get("vendor", "")) for d in raw]
            return ScanResult(aps=aps, source="replay")

        self._tick += 1
        aps = [self._jitter(a) for a in self.base]

        inject = self.scenario
        if inject == "mixed":
            choices = ["clean", "eviltwin", "openclone", "flood", "randomized"]
            inject = choices[self._tick % len(choices)]

        if inject == "eviltwin":
            aps.append(self._evil_twin_of("Office-Corp"))
        elif inject == "openclone":
            aps.append(self._evil_twin_of("HomeNet"))
        elif inject == "flood":
            aps.extend(self._flood(8))
        elif inject == "randomized":
            aps.append(AccessPoint(
                ssid="pineapple_net", bssid=_random_local_mac(self.rng),
                auth="Open", encryption="", channel=6, signal=66,
                band="2.4 GHz", radio="802.11n"))

        self.rng.shuffle(aps)
        return ScanResult(aps=aps, source=self.name)
