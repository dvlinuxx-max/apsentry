"""MAC-address helpers and a built-in OUI vendor lookup.

The OUI table is a curated subset weighted toward access-point and router
vendors, which is what matters for rogue-AP analysis. An external IEEE OUI file
can be loaded with load_oui_file() to extend it.
"""
from __future__ import annotations

import re
from typing import Optional

_MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")

# OUI prefix (lowercase, colon form) -> vendor. AP/router-heavy subset.
VENDORS: dict[str, str] = {
    "00:0c:29": "VMware", "00:50:56": "VMware", "08:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM", "00:15:5d": "Microsoft Hyper-V",
    "00:1a:1e": "Aruba", "00:0b:86": "Aruba", "6c:f3:7f": "Aruba",
    "24:de:c6": "Aruba", "94:b4:0f": "Aruba",
    "00:18:0a": "Cisco Meraki", "e0:55:3d": "Cisco Meraki", "88:15:44": "Cisco Meraki",
    "00:1b:0c": "Cisco", "00:1c:57": "Cisco", "00:24:14": "Cisco",
    "f4:cf:e2": "Cisco", "00:23:04": "Cisco",
    "fc:ec:da": "Ubiquiti", "24:a4:3c": "Ubiquiti", "78:8a:20": "Ubiquiti",
    "44:d9:e7": "Ubiquiti", "68:d7:9a": "Ubiquiti", "e0:63:da": "Ubiquiti",
    "04:18:d6": "Ubiquiti", "dc:9f:db": "Ubiquiti",
    "00:1d:0f": "TP-Link", "50:c7:bf": "TP-Link", "c0:25:e9": "TP-Link",
    "ec:08:6b": "TP-Link", "a4:2b:b0": "TP-Link", "60:32:b1": "TP-Link",
    "00:14:6c": "Netgear", "00:1f:33": "Netgear", "20:e5:2a": "Netgear",
    "a0:40:a0": "Netgear", "9c:3d:cf": "Netgear", "cc:40:d0": "Netgear",
    "00:1a:2b": "ASUS", "2c:56:dc": "ASUS", "ac:9e:17": "ASUS",
    "04:d4:c4": "ASUS", "38:d5:47": "ASUS", "d8:50:e6": "ASUS",
    "00:24:01": "D-Link", "00:26:5a": "D-Link", "1c:bd:b9": "D-Link",
    "c8:be:19": "D-Link", "00:1c:f0": "D-Link",
    "00:1e:58": "WatchGuard", "00:18:e7": "Cameo",
    "4c:5e:0c": "Huawei", "00:e0:fc": "Huawei", "ac:e2:15": "Huawei",
    "48:8e:ef": "Huawei", "78:d7:52": "Huawei",
    "b8:69:f4": "Ruckus", "c0:8a:de": "Ruckus", "2c:5d:93": "Ruckus",
    "00:0c:42": "MikroTik", "48:8f:5a": "MikroTik", "dc:2c:6e": "MikroTik",
    "6c:3b:6b": "MikroTik", "e4:8d:8c": "MikroTik",
    "b4:fb:e4": "Ubiquiti", "00:27:22": "Ubiquiti",
    "ac:bc:32": "Apple", "f0:18:98": "Apple", "a4:83:e7": "Apple",
    "d8:96:95": "Apple", "3c:15:c2": "Apple", "f4:f1:5a": "Apple",
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi",
    "00:25:9c": "Cisco-Linksys", "48:f8:b3": "Cisco-Linksys",
    "c4:41:1e": "Belkin", "94:10:3e": "Belkin",
    "00:90:4c": "Epigram", "00:13:10": "Cisco-Linksys",
    "40:9b:cd": "Sagemcom", "44:e9:dd": "Sagemcom",
    "84:1b:5e": "Netgear", "00:09:5b": "Netgear",
}


def normalize_mac(mac: str) -> str:
    """Lowercase, colon-separated, single-form MAC. Empty on failure."""
    if not mac:
        return ""
    cleaned = re.sub(r"[^0-9a-fA-F]", "", mac).lower()
    if len(cleaned) != 12:
        return ""
    return ":".join(cleaned[i:i + 2] for i in range(0, 12, 2))


def is_valid_mac(mac: str) -> bool:
    return bool(_MAC_RE.match(mac))


def oui(mac: str) -> str:
    mac = normalize_mac(mac)
    return mac[:8] if mac else ""


def vendor(mac: str) -> str:
    return VENDORS.get(oui(mac), "")


def first_octet(mac: str) -> int:
    mac = normalize_mac(mac)
    return int(mac[:2], 16) if mac else 0


def is_locally_administered(mac: str) -> bool:
    """True when the U/L bit is set: a randomized or spoofed MAC, not a burned-in OUI."""
    return bool(first_octet(mac) & 0x02)


def is_multicast(mac: str) -> bool:
    return bool(first_octet(mac) & 0x01)


def load_oui_file(path: str) -> int:
    """Load extra OUIs from an IEEE oui.txt-style file. Returns count added."""
    added = 0
    line_re = re.compile(r"([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)")
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                m = line_re.search(line)
                if not m:
                    continue
                prefix = m.group(1).lower().replace("-", ":")
                if prefix not in VENDORS:
                    VENDORS[prefix] = m.group(2).strip()
                    added += 1
    except OSError:
        return 0
    return added
