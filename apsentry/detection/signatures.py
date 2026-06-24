"""Detection signatures. Each function inspects a scan and returns detections.

The engine runs them all and aggregates the results. Signatures take the current
ScanResult, the trusted Baseline, and the rolling MonitorState (for history).
"""
from __future__ import annotations

from collections import defaultdict

from ..models import AccessPoint, Detection, ScanResult, Severity
from ..oui import is_locally_administered, oui
from ..baseline import Baseline
from ..state import MonitorState


def _det(code: str, title: str, score: int, ap: AccessPoint, detail: str,
         rec: str = "") -> Detection:
    score = max(0, min(100, score))
    return Detection(code=code, title=title, severity=Severity.from_score(score),
                     score=score, ssid=ap.ssid, bssid=ap.bssid, detail=detail,
                     recommendation=rec)


def _named(aps: list[AccessPoint]) -> list[AccessPoint]:
    return [a for a in aps if not a.is_hidden]


def duplicate_ssid(scan: ScanResult, baseline: Baseline,
                   state: MonitorState) -> list[Detection]:
    """Same SSID on multiple BSSIDs: the classic evil-twin shape."""
    out: list[Detection] = []
    groups: dict[str, list[AccessPoint]] = defaultdict(list)
    for ap in _named(scan.aps):
        groups[ap.ssid].append(ap)
    for ssid, members in groups.items():
        bssids = {a.bssid for a in members}
        if len(bssids) < 2:
            continue
        opens = [a for a in members if a.is_open]
        secured = [a for a in members if not a.is_open]
        ouis = {oui(a.bssid) for a in members}
        # Pick the legitimate anchor: a trusted BSSID, else a secured AP.
        trusted = [a for a in members if baseline.is_trusted_bssid(a.bssid)]
        anchor = trusted[0] if trusted else (secured[0] if secured else members[0])
        for ap in members:
            if ap.bssid == anchor.bssid:
                continue
            score = 22
            reasons = ["same SSID advertised by a second BSSID"]
            if opens and secured:
                score += 38
                reasons.append("encryption mismatch (one open, one secured)")
            if len(ouis) > 1:
                score += 18
                reasons.append("different hardware vendor than the legitimate AP")
            if is_locally_administered(ap.bssid):
                score += 26
                reasons.append("randomized/spoofed MAC")
            if anchor and ap.signal - anchor.signal >= 12:
                score += 12
                reasons.append("stronger signal than the legitimate AP")
            if trusted and not baseline.is_trusted_bssid(ap.bssid):
                score += 14
                reasons.append("BSSID not in the trusted baseline")
            title = ("Evil twin (encryption downgrade)" if opens and secured
                     else "Possible evil twin / duplicate SSID")
            out.append(_det(
                "evil_twin", title, score, ap,
                f"SSID '{ssid}' is also served by {anchor.bssid} "
                f"({anchor.auth or 'open'}); this BSSID: " + ", ".join(reasons) + ".",
                "Confirm the legitimate BSSID with the network owner; do not "
                "connect to the impersonating AP; consider locating it by signal."))
    return out


def trusted_ssid_impersonation(scan: ScanResult, baseline: Baseline,
                               state: MonitorState) -> list[Detection]:
    """An untrusted BSSID broadcasting an SSID you have marked as trusted."""
    out: list[Detection] = []
    if not len(baseline):
        return out
    trusted_ssids = baseline.trusted_ssids
    for ap in _named(scan.aps):
        if ap.ssid not in trusted_ssids:
            continue
        if baseline.is_trusted_bssid(ap.bssid):
            continue
        score = 46
        reasons = ["BSSID not in the trusted baseline for this network"]
        baseline_auth_open = any(
            (e.get("auth", "") or "open").lower() in ("open", "")
            for b, e in baseline.entries.items() if e.get("ssid") == ap.ssid)
        if ap.is_open and not baseline_auth_open:
            score += 26
            reasons.append("offered as open while the real network is secured")
        if is_locally_administered(ap.bssid):
            score += 20
            reasons.append("randomized/spoofed MAC")
        title = ("Evil twin of a trusted network" if ap.is_open
                 else "Rogue AP impersonating a trusted network")
        out.append(_det(
            "rogue_trusted_ssid", title, score, ap,
            f"'{ap.ssid}' is in your trusted baseline but {ap.bssid} is not a "
            "known BSSID for it: " + ", ".join(reasons) + ".",
            "Treat as hostile. Verify with the network owner and physically "
            "locate the device before connecting any client."))
    return out


def spoofed_trusted_bssid(scan: ScanResult, baseline: Baseline,
                          state: MonitorState) -> list[Detection]:
    """A trusted BSSID whose attributes changed: MAC spoofing of your AP."""
    out: list[Detection] = []
    for ap in scan.aps:
        entry = baseline.get(ap.bssid)
        if not entry:
            continue
        base_auth = (entry.get("auth", "") or "open").lower()
        now_open = ap.is_open
        base_open = base_auth in ("open", "")
        if now_open and not base_open:
            out.append(_det(
                "bssid_downgrade", "Trusted AP appears with weaker security", 64, ap,
                f"{ap.bssid} is trusted as '{entry.get('ssid')}' with "
                f"{entry.get('auth')}, but is now advertising open. Likely a "
                "spoofed BSSID running an evil twin.",
                "Do not connect. The real AP's MAC is being impersonated."))
        elif entry.get("channel") and ap.channel and \
                abs(entry["channel"] - ap.channel) > 0 and ap.ssid != entry.get("ssid"):
            out.append(_det(
                "bssid_mismatch", "Trusted BSSID broadcasting a different SSID", 40, ap,
                f"{ap.bssid} is trusted as '{entry.get('ssid')}' but now shows "
                f"SSID '{ap.ssid}'. Possible MAC reuse or spoofing.",
                "Verify the device identity."))
    return out


def randomized_mac(scan: ScanResult, baseline: Baseline,
                   state: MonitorState) -> list[Detection]:
    """A named AP using a locally-administered (randomized/spoofed) MAC."""
    out: list[Detection] = []
    for ap in _named(scan.aps):
        if not is_locally_administered(ap.bssid):
            continue
        if baseline.is_trusted_bssid(ap.bssid):
            continue
        score = 26 if ap.is_open else 18
        out.append(_det(
            "randomized_mac", "Access point with randomized/spoofed MAC", score, ap,
            f"{ap.bssid} has the locally-administered bit set. Production APs "
            "normally use a vendor-assigned MAC; rogue tools randomize it.",
            "Correlate with duplicate-SSID and signal findings for the same area."))
    return out


def weak_crypto(scan: ScanResult, baseline: Baseline,
                state: MonitorState) -> list[Detection]:
    """WEP and other deprecated ciphers are trivially broken."""
    out: list[Detection] = []
    for ap in _named(scan.aps):
        a = (ap.auth + " " + ap.encryption).lower()
        if "wep" in a:
            out.append(_det(
                "weak_crypto", "Deprecated WEP encryption", 28, ap,
                f"'{ap.ssid}' uses WEP, which can be cracked in minutes.",
                "Migrate to WPA2/WPA3; WEP offers no real protection."))
    return out


def beacon_flood(scan: ScanResult, baseline: Baseline,
                 state: MonitorState) -> list[Detection]:
    """Many spoofed/open SSIDs at once suggests beacon flooding or a karma AP."""
    out: list[Detection] = []
    rnd_open = [a for a in scan.aps if a.is_open and is_locally_administered(a.bssid)]
    if len(rnd_open) >= 5:
        score = min(80, 30 + 5 * len(rnd_open))
        anchor = rnd_open[0]
        out.append(_det(
            "beacon_flood", "Possible beacon flood / mass rogue SSIDs", score, anchor,
            f"{len(rnd_open)} open networks with randomized MACs appeared at once "
            "(e.g. " + ", ".join(sorted({a.ssid for a in rnd_open})[:4]) + ").",
            "Indicative of a beacon-flood or rogue-AP tool nearby. Sweep the area."))
    return out


def signal_anomaly(scan: ScanResult, baseline: Baseline,
                   state: MonitorState) -> list[Detection]:
    """A known AP whose signal jumps sharply may have been relocated or spoofed."""
    out: list[Detection] = []
    for ap in scan.aps:
        prev = state.previous_signal(ap.bssid)
        if prev is None:
            continue
        if abs(ap.signal - prev) >= 35:
            out.append(_det(
                "signal_anomaly", "Sharp signal change for a known AP", 20, ap,
                f"{ap.bssid} ('{ap.ssid or '<hidden>'}') moved from {prev}% to "
                f"{ap.signal}% between scans.",
                "A sudden jump can mean the device moved closer or is being "
                "impersonated from a nearer location."))
    return out


def new_neighbor(scan: ScanResult, baseline: Baseline,
                 state: MonitorState) -> list[Detection]:
    """Inventory note: a new AP not in the baseline (informational only)."""
    out: list[Detection] = []
    if not len(baseline):
        return out
    for ap in _named(scan.aps):
        if baseline.is_trusted_bssid(ap.bssid) or ap.ssid in baseline.trusted_ssids:
            continue
        if ap.bssid in state.aps and state.aps[ap.bssid].times_seen > 1:
            continue
        out.append(_det(
            "new_ap", "New access point observed", 5, ap,
            f"{ap.bssid} ('{ap.ssid}', {ap.auth or 'open'}, ch {ap.channel}) "
            "is not in the baseline.",
            "Add to the baseline if you recognize it as legitimate."))
    return out


ALL_SIGNATURES = [
    duplicate_ssid,
    trusted_ssid_impersonation,
    spoofed_trusted_bssid,
    randomized_mac,
    weak_crypto,
    beacon_flood,
    signal_anomaly,
    new_neighbor,
]
