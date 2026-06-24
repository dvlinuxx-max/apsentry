"""Command-line entry point: serve the dashboard, or scan/monitor in the terminal."""
from __future__ import annotations

import argparse
import sys
import time

from .baseline import Baseline
from .collectors import get_collector
from .detection import Engine
from .models import Severity
from .monitor import Monitor
from .scoring import environment_risk, risk_label
from .state import MonitorState

__version__ = "1.0.0"


class C:
    GREY = "\033[90m"; BLUE = "\033[34m"; YEL = "\033[33m"
    ORANGE = "\033[38;5;208m"; RED = "\033[31m"; GREEN = "\033[32m"
    CYAN = "\033[36m"; BOLD = "\033[1m"; RESET = "\033[0m"

    @classmethod
    def off(cls):
        for n in ("GREY", "BLUE", "YEL", "ORANGE", "RED", "GREEN", "CYAN", "BOLD", "RESET"):
            setattr(cls, n, "")


_SEV_COLOR = {
    Severity.INFO: lambda: C.GREY, Severity.LOW: lambda: C.BLUE,
    Severity.MEDIUM: lambda: C.YEL, Severity.HIGH: lambda: C.ORANGE,
    Severity.CRITICAL: lambda: C.RED,
}


def _build(args):
    kwargs = {}
    if args.seed is not None:
        kwargs["seed"] = args.seed
    if getattr(args, "scenario", None):
        kwargs["scenario"] = args.scenario
    if getattr(args, "replay", None):
        kwargs["replay_path"] = args.replay
    collector = get_collector(args.source, **kwargs)
    baseline = Baseline(args.baseline)
    engine = Engine(baseline)
    state = MonitorState()
    return collector, baseline, engine, state


def _print_detections(detections, risk):
    label = risk_label(risk)
    bar_col = C.GREEN if risk < 30 else C.YEL if risk < 55 else C.RED
    print(f"\n{C.BOLD}Environment risk: {bar_col}{risk}/100 ({label}){C.RESET}")
    if not detections:
        print(f"  {C.GREEN}No threats detected.{C.RESET}")
        return
    for d in detections:
        col = _SEV_COLOR[d.severity]()
        print(f"\n  {col}[{d.severity.label.upper():8}]{C.RESET} {C.BOLD}{d.title}{C.RESET} "
              f"{C.GREY}(score {d.score}){C.RESET}")
        print(f"    {C.CYAN}{d.ssid or '<hidden>'}{C.RESET}  {C.GREY}{d.bssid}{C.RESET}")
        print(f"    {d.detail}")
        if d.recommendation:
            print(f"    {C.GREY}-> {d.recommendation}{C.RESET}")


def cmd_scan(args):
    collector, baseline, engine, state = _build(args)
    mon = Monitor(collector, engine, state)
    scan, detections = mon.run_once()
    if args.json:
        import json
        print(json.dumps({"risk": state.current_risk,
                          "source": scan.source,
                          "access_points": [a.to_dict() for a in scan.aps],
                          "detections": [d.to_dict() for d in detections]}, indent=2))
        return 0
    print(f"{C.GREY}apsentry {__version__} - source: {scan.source} - "
          f"{len(scan.aps)} AP(s){C.RESET}")
    for a in sorted(scan.aps, key=lambda x: x.signal, reverse=True):
        sec = f"{C.GREEN}{a.auth}{C.RESET}" if not a.is_open else f"{C.ORANGE}open{C.RESET}"
        print(f"  {C.BOLD}{(a.ssid or '<hidden>'):<22}{C.RESET} {C.GREY}{a.bssid}{C.RESET} "
              f"{(a.vendor or '-'):<14} ch{a.channel:<4} {a.signal:>3}%  {sec}")
    _print_detections(detections, state.current_risk)
    return 0


def cmd_monitor(args):
    collector, baseline, engine, state = _build(args)
    seen = set()

    def on_cycle(scan, detections, fresh):
        for d in fresh:
            col = _SEV_COLOR[d.severity]()
            ts = time.strftime("%H:%M:%S")
            print(f"{C.GREY}{ts}{C.RESET} {col}[{d.severity.label.upper()}]{C.RESET} "
                  f"{d.title} - {C.CYAN}{d.ssid or '<hidden>'}{C.RESET} {C.GREY}{d.bssid}{C.RESET}")

    mon = Monitor(collector, engine, state, interval=args.interval, on_cycle=on_cycle)
    print(f"{C.GREY}apsentry monitor - source {collector.name}, every {args.interval}s. "
          f"Ctrl+C to stop.{C.RESET}")
    try:
        mon.run_forever()
    except KeyboardInterrupt:
        print(f"\n{C.GREY}stopped after {state.scan_count} scans.{C.RESET}")
    return 0


def cmd_serve(args):
    from .server import run_server
    collector, baseline, engine, state = _build(args)
    mon = Monitor(collector, engine, state, interval=args.interval)
    print(f"{C.GREY}source: {collector.name} · baseline: "
          f"{len(baseline)} trusted AP(s){C.RESET}")
    run_server(mon, state, baseline, host=args.host, port=args.port)
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="apsentry",
        description="Evil Twin / Rogue AP detection and wireless threat monitor. "
                    "For authorized monitoring of networks you own or operate.")
    p.add_argument("--version", action="version", version=f"apsentry {__version__}")
    p.add_argument("-s", "--source", default="auto",
                   help="auto|windows|linux|macos|demo|replay (default auto)")
    p.add_argument("-b", "--baseline", default="apsentry-baseline.json",
                   help="trusted-AP baseline file")
    p.add_argument("--seed", type=int, help="demo RNG seed")
    p.add_argument("--scenario", help="demo scenario: clean|eviltwin|openclone|flood|randomized|mixed")
    p.add_argument("--replay", help="JSON file to replay as scans (with --source replay)")
    p.add_argument("--no-color", action="store_true")

    sub = p.add_subparsers(dest="cmd")
    sp = sub.add_parser("serve", help="run the web dashboard (default)")
    sp.add_argument("--host", default="127.0.0.1")
    sp.add_argument("--port", type=int, default=8787)
    sp.add_argument("-i", "--interval", type=float, default=10.0)
    sp.set_defaults(func=cmd_serve)

    sc = sub.add_parser("scan", help="single scan and analysis to the terminal")
    sc.add_argument("--json", action="store_true")
    sc.set_defaults(func=cmd_scan)

    mo = sub.add_parser("monitor", help="continuous terminal monitor")
    mo.add_argument("-i", "--interval", type=float, default=10.0)
    mo.set_defaults(func=cmd_monitor)

    args = p.parse_args(argv)
    if args.no_color or not sys.stdout.isatty():
        C.off()
    if not getattr(args, "cmd", None):
        # default to serve with its defaults
        args.host, args.port, args.interval = "127.0.0.1", 8787, 10.0
        return cmd_serve(args)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
