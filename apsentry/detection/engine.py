"""Detection engine: run every signature over a scan and aggregate findings."""
from __future__ import annotations

from ..baseline import Baseline
from ..models import Detection, ScanResult
from ..state import MonitorState
from .signatures import ALL_SIGNATURES


class Engine:
    def __init__(self, baseline: Baseline, signatures=None):
        self.baseline = baseline
        self.signatures = signatures or ALL_SIGNATURES

    def analyze(self, scan: ScanResult, state: MonitorState) -> list[Detection]:
        detections: list[Detection] = []
        for sig in self.signatures:
            try:
                detections.extend(sig(scan, self.baseline, state))
            except Exception:
                continue
        detections.sort(key=lambda d: (d.score, d.severity), reverse=True)
        return detections
