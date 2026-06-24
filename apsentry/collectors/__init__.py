"""Wireless scan collectors. One backend per platform, plus a demo source.

A collector turns a platform-specific Wi-Fi scan into a ScanResult of
AccessPoint objects. get_collector() picks a backend by name or autodetects.
"""
from __future__ import annotations

import platform
from typing import Optional

from ..models import ScanResult


def channel_to_band(channel: int) -> str:
    if 1 <= channel <= 14:
        return "2.4 GHz"
    if 32 <= channel <= 177:
        return "5 GHz"
    if channel >= 181:
        return "6 GHz"
    return ""


class Collector:
    name = "base"

    def available(self) -> bool:
        return False

    def scan(self) -> ScanResult:
        raise NotImplementedError


def get_collector(source: str = "auto", **kwargs) -> Collector:
    source = (source or "auto").lower()
    from .windows import WindowsCollector
    from .linux import LinuxCollector
    from .macos import MacCollector
    from .demo import DemoCollector

    if source in ("demo", "synthetic"):
        return DemoCollector(**kwargs)
    if source == "replay":
        return DemoCollector(replay=kwargs.get("replay_path"), **{
            k: v for k, v in kwargs.items() if k != "replay_path"})
    if source == "windows":
        return WindowsCollector()
    if source == "linux":
        return LinuxCollector()
    if source == "macos":
        return MacCollector()

    sysname = platform.system().lower()
    candidates = {
        "windows": WindowsCollector,
        "linux": LinuxCollector,
        "darwin": MacCollector,
    }
    cls = candidates.get(sysname)
    if cls:
        c = cls()
        if c.available():
            return c
    # Fall back to demo so the pipeline and UI still work without hardware.
    return DemoCollector(**kwargs)
