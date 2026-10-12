"""Parse SSH logs or emit deterministic authentication triage findings."""

import argparse
from collections.abc import Iterator, Sequence
import json
from pathlib import Path
import sys
from typing import TextIO

from .config import DetectionConfig
from .detector import (
    MAX_BATCH_EVENTS,
    FailureBurst,
    SuccessAfterFailure,
    correlate_success_after_failure_bursts,
    detect_failure_bursts,
)
from .parser import AuthEvent, parse_line

_MAX_LINE_CHARS = 8192


def _add_log_arguments(parser: argparse.ArgumentParser) -> None:
    """Add the bounded log parser's shared timestamp arguments."""
    parser.add_argument("log", type=Path)
    parser.add_argument("--year", type=int, required=True,
                        choices=range(1, 10000), metavar="YEAR")
    parser.add_argument("--utc-offset-minutes", type=int, default=0,
                        choices=range(-1439, 1440), metavar="MINUTES")


def _iter_records(
    stream: TextIO, *, year: int, utc_offset_minutes: int,
) -> Iterator[AuthEvent | None]:
    """Yield parsed records, using ``None`` for rejected logical lines."""
    while True:
        line = stream.readline(_MAX_LINE_CHARS + 1)
        if not line:
            return
        if len(line) > _MAX_LINE_CHARS:
            while not line.endswith("\n"):
                line = stream.readline(_MAX_LINE_CHARS + 1)
                if not line:
                    break
            yield None
            continue
        yield parse_line(
            line, year=year, utc_offset_minutes=utc_offset_minutes,
        )


def _run_parse(args: argparse.Namespace) -> int:
    """Stream normalized events while preserving the original CLI contract."""
    parsed = skipped = 0
    try:
        with args.log.open("r", encoding="utf-8", errors="strict") as stream:
            for event in _iter_records(
                stream, year=args.year,
                utc_offset_minutes=args.utc_offset_minutes,
            ):
                if event is None:
                    skipped += 1
                    continue
                print(json.dumps(event.to_dict(), ensure_ascii=True))
                parsed += 1
    except (OSError, UnicodeError) as exc:
        print(f"traceguard: {exc}", file=sys.stderr)
        return 2
    print(f"parsed={parsed} skipped={skipped}", file=sys.stderr)
    return 0


def _failure_dict(finding: FailureBurst) -> dict[str, object]:
    """Serialize a failure burst without including private raw log content."""
    return {
        "finding_type": "failure_burst",
        "finding_id": finding.finding_id,
        "host": finding.host,
        "source_ip": finding.source_ip,
        "username": finding.username,
        "started_at": finding.started_at,
        "ended_at": finding.ended_at,
        "failure_count": finding.failure_count,
        "evidence_ids": list(finding.evidence_ids),
    }


def _success_dict(finding: SuccessAfterFailure) -> dict[str, object]:
    """Serialize a correlation without including private raw log content."""
    return {
        "finding_type": "success_after_failure",
        "finding_id": finding.finding_id,
        "host": finding.host,
        "source_ip": finding.source_ip,
        "username": finding.username,
        "burst_finding_id": finding.burst_finding_id,
        "success_event_id": finding.success_event_id,
        "burst_started_at": finding.burst_started_at,
        "burst_ended_at": finding.burst_ended_at,
        "succeeded_at": finding.succeeded_at,
        "failure_count": finding.failure_count,
        "evidence_ids": list(finding.evidence_ids),
    }


def _run_triage(args: argparse.Namespace) -> int:
    """Detect bounded findings offline and emit stable JSON Lines."""
    try:
        policy = DetectionConfig(
            failure_threshold=args.failure_threshold,
            failure_window_seconds=args.failure_window_seconds,
            success_window_seconds=args.success_window_seconds,
        )
    except ValueError as exc:
        print(f"traceguard: {exc}", file=sys.stderr)
        return 2

    events: list[AuthEvent] = []
    skipped = 0
    try:
        with args.log.open("r", encoding="utf-8", errors="strict") as stream:
            for event in _iter_records(
                stream, year=args.year,
                utc_offset_minutes=args.utc_offset_minutes,
            ):
                if event is None:
                    skipped += 1
                    continue
                if len(events) >= MAX_BATCH_EVENTS:
                    raise ValueError("Triage input exceeds 10000 parsed events")
                events.append(event)
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"traceguard: {exc}", file=sys.stderr)
        return 2

    bursts = detect_failure_bursts(events, policy)
    correlations = correlate_success_after_failure_bursts(
        events, bursts, policy,
    )
    for finding in bursts:
        print(json.dumps(_failure_dict(finding), ensure_ascii=True,
                         separators=(",", ":")))
    for finding in correlations:
        print(json.dumps(_success_dict(finding), ensure_ascii=True,
                         separators=(",", ":")))
    print(
        f"parsed={len(events)} skipped={skipped} "
        f"failure_bursts={len(bursts)} "
        f"success_after_failure={len(correlations)}",
        file=sys.stderr,
    )
    return 0


def _parse_parser() -> argparse.ArgumentParser:
    """Build the backward-compatible parser command."""
    parser = argparse.ArgumentParser(
        description="Stream normalized SSH events as JSON Lines.",
    )
    _add_log_arguments(parser)
    return parser


def _triage_parser() -> argparse.ArgumentParser:
    """Build the deterministic offline triage subcommand."""
    parser = argparse.ArgumentParser(
        prog="python -m traceguard triage",
        description="Emit deterministic authentication findings as JSON Lines.",
    )
    _add_log_arguments(parser)
    defaults = DetectionConfig()
    parser.add_argument("--failure-threshold", type=int,
                        default=defaults.failure_threshold, metavar="COUNT")
    parser.add_argument("--failure-window-seconds", type=int,
                        default=defaults.failure_window_seconds, metavar="SECONDS")
    parser.add_argument("--success-window-seconds", type=int,
                        default=defaults.success_window_seconds, metavar="SECONDS")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Dispatch the triage subcommand or the original parser interface."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] == "triage":
        return _run_triage(_triage_parser().parse_args(arguments[1:]))
    return _run_parse(_parse_parser().parse_args(arguments))


if __name__ == "__main__":
    raise SystemExit(main())
