"""Continuous monitor loop: scan, analyze, score, and record on an interval."""
from __future__ import annotations

import threading
import time
from typing import Callable, Optional

from .collectors import Collector
from .detection import Engine
from .models import Detection, ScanResult
from .scoring import environment_risk
from .state import MonitorState


class Monitor:
    def __init__(self, collector: Collector, engine: Engine, state: MonitorState,
                 interval: float = 10.0,
                 on_cycle: Optional[Callable[[ScanResult, list, list], None]] = None):
        self.collector = collector
        self.engine = engine
        self.state = state
        self.interval = interval
        self.on_cycle = on_cycle
        self._stop = threading.Event()

    def run_once(self) -> tuple[ScanResult, list[Detection]]:
        scan = self.collector.scan()
        self.state.ingest_scan(scan)
        detections = self.engine.analyze(scan, self.state)
        self.state.current_detections = detections
        self.state.current_risk = environment_risk(detections)
        fresh = self.state.record_detections(detections)
        if self.on_cycle:
            self.on_cycle(scan, detections, fresh)
        return scan, detections

    def run_forever(self) -> None:
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception:
                pass
            self._stop.wait(self.interval)

    def start_background(self) -> threading.Thread:
        t = threading.Thread(target=self.run_forever, daemon=True)
        t.start()
        return t

    def stop(self) -> None:
        self._stop.set()
