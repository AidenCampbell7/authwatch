"""
Command line interface.

    python -m authwatch ingest data/auth.log
    python -m authwatch alerts --severity high
    python -m authwatch stats
    python -m authwatch serve
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import timedelta

from .detections import Config, run_all
from .parser import parse_file
from .store import Store

SEV_ORDER = {"high": 0, "medium": 1, "low": 2}
COLOR = {"high": "\033[91m", "medium": "\033[93m", "low": "\033[94m"}
RESET = "\033[0m"


def _config_from_args(args) -> Config:
    cfg = Config()
    if args.brute_force_threshold is not None:
        cfg.brute_force_threshold = args.brute_force_threshold
    if args.window_minutes is not None:
        cfg.brute_force_window = timedelta(minutes=args.window_minutes)
    if args.baseline_hours is not None:
        cfg.baseline_period = timedelta(hours=args.baseline_hours)
    return cfg


def cmd_ingest(args) -> int:
    events = parse_file(args.logfile, year=args.year)
    if not events:
        print(f"No auth events parsed from {args.logfile}", file=sys.stderr)
        return 1

    alerts = run_all(events, _config_from_args(args))
    store = Store(args.db)
    n_events = store.insert_events(events)
    n_alerts = store.insert_alerts(alerts)

    print(f"Parsed  {len(events)} events from {args.logfile}")
    print(f"Stored  {n_events} new events, {n_alerts} new alerts")
    if alerts:
        print()
        _print_alerts([{"severity": a.severity, "rule": a.rule,
                        "timestamp": a.timestamp.isoformat(),
                        "summary": a.summary} for a in alerts], color=not args.no_color)
    return 0


def cmd_alerts(args) -> int:
    rows = Store(args.db).alerts(severity=args.severity, limit=args.limit)
    if args.json:
        print(json.dumps(rows, indent=2, default=str))
        return 0
    if not rows:
        print("No alerts stored. Run `ingest` first.")
        return 0
    _print_alerts(rows, color=not args.no_color)
    return 0


def cmd_stats(args) -> int:
    print(json.dumps(Store(args.db).stats(), indent=2))
    return 0


def cmd_serve(args) -> int:
    try:
        import uvicorn
    except ImportError:
        print("uvicorn not installed. pip install fastapi uvicorn", file=sys.stderr)
        return 1
    from .api import create_app
    uvicorn.run(create_app(args.db), host=args.host, port=args.port)
    return 0


def _print_alerts(rows, color: bool = True) -> None:
    rows = sorted(rows, key=lambda r: (SEV_ORDER.get(r["severity"], 9), r["timestamp"]))
    for r in rows:
        tag = f"[{r['severity'].upper():6}]"
        if color:
            tag = f"{COLOR.get(r['severity'], '')}{tag}{RESET}"
        print(f"{tag} {r['timestamp']}  {r['rule']:18}  {r['summary']}")


def build_parser() -> argparse.ArgumentParser:
    # Shared flags live on a parent parser so they are accepted both before and
    # after the subcommand. `authwatch --db x ingest f` and
    # `authwatch ingest f --db x` both work, which is what people actually type.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--db", default="data/authwatch.db", help="SQLite database path")
    common.add_argument("--no-color", action="store_true", help="disable ANSI colour output")

    p = argparse.ArgumentParser(prog="authwatch", parents=[common],
                                description="Parse SSH auth logs and detect suspicious activity.")
    sub = p.add_subparsers(dest="command", required=True)

    ing = sub.add_parser("ingest", parents=[common],
                         help="parse a log file, run detections, store results")
    ing.add_argument("logfile")
    ing.add_argument("--year", type=int, default=2026,
                     help="syslog lines carry no year; supply one (default 2026)")
    ing.add_argument("--brute-force-threshold", type=int, default=None)
    ing.add_argument("--window-minutes", type=int, default=None)
    ing.add_argument("--baseline-hours", type=int, default=None)
    ing.set_defaults(func=cmd_ingest)

    al = sub.add_parser("alerts", parents=[common], help="list stored alerts")
    al.add_argument("--severity", choices=["high", "medium", "low"], default=None)
    al.add_argument("--limit", type=int, default=100)
    al.add_argument("--json", action="store_true")
    al.set_defaults(func=cmd_alerts)

    st = sub.add_parser("stats", parents=[common], help="summary counts")
    st.set_defaults(func=cmd_stats)

    sv = sub.add_parser("serve", parents=[common], help="run the web dashboard")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8000)
    sv.set_defaults(func=cmd_serve)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    # subcommands that don't take these still need the attributes present
    for attr in ("brute_force_threshold", "window_minutes", "baseline_hours"):
        if not hasattr(args, attr):
            setattr(args, attr, None)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
