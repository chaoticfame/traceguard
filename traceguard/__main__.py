"""Parse SSH logs or emit deterministic authentication triage findings."""

import argparse
from collections.abc import Iterator, Sequence
import json
import os
from pathlib import Path
import sys
import tempfile
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
from .explanations import MAX_AI_FINDINGS, explain_finding
from .ingest import ingest_file
from .report import export_report
from .storage import EventOccurrence, EventStore, StorageError

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
    ai_requested = args.ai_model is not None or args.offline
    findings: list[FailureBurst | SuccessAfterFailure] = [*bursts, *correlations]
    for index, finding in enumerate(findings):
        record = (_failure_dict(finding) if isinstance(finding, FailureBurst)
                  else _success_dict(finding))
        if ai_requested:
            record["explanation"] = (
                {"status": "skipped_limit", "annotation": None}
                if index >= MAX_AI_FINDINGS and not args.offline
                else explain_finding(finding, model=args.ai_model, offline=args.offline)
            )
        print(json.dumps(record, ensure_ascii=True, separators=(",", ":")))
    if ai_requested and not findings:
        print("ai_status=no_findings", file=sys.stderr)
    print(
        f"parsed={len(events)} skipped={skipped} "
        f"failure_bursts={len(bursts)} "
        f"success_after_failure={len(correlations)}",
        file=sys.stderr,
    )
    return 0


def _matching_occurrence(
    finding: FailureBurst | SuccessAfterFailure,
    fingerprint: str,
    outcome: str,
    occurrences: list[EventOccurrence],
    excluded: set[str],
) -> EventOccurrence:
    """Select the first exact source occurrence not already allocated."""
    match = next((
        item for item in occurrences
        if item.occurrence_id not in excluded
        and item.event.event_id == fingerprint
        and item.event.host == finding.host
        and item.event.username == finding.username
        and item.event.source_ip == finding.source_ip
        and item.event.outcome == outcome
    ), None)
    if match is None:
        raise ValueError("Unable to link finding to parsed evidence")
    return match


def _link_findings(
    findings: list[FailureBurst | SuccessAfterFailure],
    occurrences: list[EventOccurrence],
) -> list[tuple[FailureBurst | SuccessAfterFailure, tuple[str, ...]]]:
    """Attach exact occurrences while preserving detector consumption rules."""
    linked: list[tuple[FailureBurst | SuccessAfterFailure, tuple[str, ...]]] = []
    burst_links: dict[str, tuple[str, ...]] = {}
    allocated_failures: set[str] = set()
    allocated_successes: set[str] = set()
    by_id = {item.occurrence_id: item for item in occurrences}
    for finding in findings:
        if isinstance(finding, FailureBurst):
            references: list[str] = []
            for fingerprint in finding.evidence_ids:
                match = _matching_occurrence(
                    finding, fingerprint, "failure", occurrences,
                    allocated_failures,
                )
                allocated_failures.add(match.occurrence_id)
                references.append(match.occurrence_id)
            result = tuple(references)
            burst_links[finding.finding_id] = result
        else:
            failures = burst_links.get(finding.burst_finding_id)
            if (failures is None
                    or tuple(by_id[item].event.event_id for item in failures)
                    != finding.evidence_ids[:-1]):
                raise ValueError("Correlation does not reference a stored burst")
            success = _matching_occurrence(
                finding, finding.success_event_id, "success", occurrences,
                allocated_successes,
            )
            allocated_successes.add(success.occurrence_id)
            result = (*failures, success.occurrence_id)
        linked.append((finding, result))
    return linked


def _write_private_report(path: Path, document: str) -> None:
    """Atomically replace one local report with restrictive file permissions."""
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="ascii", newline="\n", dir=path.parent,
            prefix=f".{path.name}.", suffix=".tmp", delete=False,
        ) as stream:
            temporary = Path(stream.name)
            os.chmod(temporary, 0o600)
            stream.write(document)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except (OSError, UnicodeError):
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
        raise


def _run_pipeline(args: argparse.Namespace) -> int:
    """Parse, detect, persist and export one evidence-linked local report."""
    try:
        paths = [args.log.resolve(), args.database.resolve(), args.report.resolve()]
        if len(set(paths)) != len(paths):
            raise ValueError("Log, database, and report paths must be distinct")
        policy = DetectionConfig(
            failure_threshold=args.failure_threshold,
            failure_window_seconds=args.failure_window_seconds,
            success_window_seconds=args.success_window_seconds,
        )
        batch = ingest_file(
            args.log, year=args.year,
            utc_offset_minutes=args.utc_offset_minutes,
        )
        records = list(batch.records)
        source_digest = batch.source_digest
        events = [event for _, event in records]
        bursts = detect_failure_bursts(events, policy)
        correlations = correlate_success_after_failure_bursts(events, bursts, policy)
        findings: list[FailureBurst | SuccessAfterFailure] = [*bursts, *correlations]
        statuses: list[str] = []
        for index, finding in enumerate(findings):
            result = ({"status": "skipped_limit", "annotation": None}
                      if args.ai_model is not None and not args.offline
                      and index >= MAX_AI_FINDINGS
                      else explain_finding(
                          finding, model=args.ai_model, offline=args.offline,
                      ))
            statuses.append(str(result["status"]))

        with EventStore(args.database) as store:
            occurrences = store.store_occurrences(source_digest, records)
            stored = store.store_findings(_link_findings(findings, occurrences))
            report = export_report(
                source_digest=source_digest,
                config=policy,
                occurrences=store.list_occurrences(source_digest),
                findings=stored,
                explanation_statuses={item.storage_id: status
                                      for item, status in zip(stored, statuses)},
            )
            occurrence_count = len(store.list_occurrences(source_digest))
        _write_private_report(args.report, report)
    except (OSError, UnicodeError, ValueError, RuntimeError, StorageError) as exc:
        print(f"traceguard: {exc}", file=sys.stderr)
        return 2

    print(json.dumps({
        "parsed": len(records), "skipped": batch.rejections.total,
        "occurrences": occurrence_count, "findings": len(findings),
        "schema_version": 1,
    }, separators=(",", ":")))
    print(
        f"rejected_records={batch.rejections.total} "
        f"unsupported={batch.rejections.unsupported} "
        f"event_limit={batch.rejections.event_limit}",
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
    parser.add_argument("--ai-model", metavar="MODEL",
                        help="opt in to local explanations for at most 10 findings")
    parser.add_argument("--offline", action="store_true",
                        help="disable AI requests even when --ai-model is supplied")
    return parser


def _pipeline_parser() -> argparse.ArgumentParser:
    """Build the end-to-end local evidence pipeline command."""
    parser = argparse.ArgumentParser(
        prog="python -m traceguard pipeline",
        description="Persist SSH evidence and atomically export a versioned report.",
    )
    _add_log_arguments(parser)
    parser.add_argument("--database", type=Path, required=True, metavar="PATH")
    parser.add_argument("--report", type=Path, required=True, metavar="PATH")
    defaults = DetectionConfig()
    parser.add_argument("--failure-threshold", type=int,
                        default=defaults.failure_threshold, metavar="COUNT")
    parser.add_argument("--failure-window-seconds", type=int,
                        default=defaults.failure_window_seconds, metavar="SECONDS")
    parser.add_argument("--success-window-seconds", type=int,
                        default=defaults.success_window_seconds, metavar="SECONDS")
    parser.add_argument("--ai-model", metavar="MODEL",
                        help="opt in to local explanations for at most 10 findings")
    parser.add_argument("--offline", action="store_true",
                        help="disable AI requests even when --ai-model is supplied")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Dispatch the triage subcommand or the original parser interface."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] == "pipeline":
        return _run_pipeline(_pipeline_parser().parse_args(arguments[1:]))
    if arguments and arguments[0] == "triage":
        return _run_triage(_triage_parser().parse_args(arguments[1:]))
    return _run_parse(_parse_parser().parse_args(arguments))


if __name__ == "__main__":
    raise SystemExit(main())
