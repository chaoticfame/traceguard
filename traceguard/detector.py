"""Deterministic, bounded detection of repeated SSH authentication failures."""

from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from itertools import islice
import json

from .config import DetectionConfig
from .parser import AuthEvent

MAX_BATCH_EVENTS = 10_000


@dataclass(frozen=True, slots=True)
class FailureBurst:
    """Threshold-sized evidence group; a review candidate, not proof of attack.

    Fingerprints retain multiplicity: identical lines are distinct occurrences
    until source-aware occurrence IDs are introduced by the storage layer.
    """

    finding_id: str
    host: str
    source_ip: str
    username: str
    started_at: str
    ended_at: str
    evidence_ids: tuple[str, ...]

    @property
    def failure_count(self) -> int:
        """Return the number of supporting failure occurrences."""
        return len(self.evidence_ids)


def _timestamp(event: AuthEvent) -> datetime:
    """Validate an event timestamp and normalize it to aware UTC."""
    if not isinstance(event, AuthEvent):
        raise ValueError("Detection requires AuthEvent records")
    try:
        stamp = datetime.fromisoformat(event.timestamp)
        if stamp.utcoffset() is None:
            raise ValueError("Missing timezone")
        return stamp.astimezone(timezone.utc)
    except (ValueError, TypeError, OverflowError) as exc:
        raise ValueError("Event timestamp must be valid and timezone-aware") from exc


def detect_failure_bursts(
    events: Iterable[AuthEvent], config: DetectionConfig | None = None,
) -> list[FailureBurst]:
    """Find non-overlapping threshold-sized failure groups in a finite batch.

    Read at most MAX_BATCH_EVENTS + 1 records and reject oversized batches.
    Sort by UTC time and stable event fields, keeping duplicate occurrences.
    Group by (host, source IP, username); count only failure outcomes. A window
    includes both endpoints. Expire failures older than the configured window.
    After emitting a group, consume its evidence so later groups do not repeat
    it. Successes do not reset failure history. Incomplete tails are not emitted.
    This bounds total emitted evidence to the batch size. Complexity is
    O(n log n) time and O(n) space. No input events or policies are modified.
    """
    policy = DetectionConfig() if config is None else config
    if not isinstance(policy, DetectionConfig):
        raise ValueError("Detection requires a validated DetectionConfig")
    batch = list(islice(events, MAX_BATCH_EVENTS + 1))
    if len(batch) > MAX_BATCH_EVENTS:
        raise ValueError("Detection batch exceeds 10000 events")
    ordered = [(_timestamp(event), event) for event in batch]
    if any(event.outcome not in ("failure", "success") for _, event in ordered):
        raise ValueError("Unsupported authentication outcome")
    ordered.sort(key=lambda pair: (
        pair[0], pair[1].host, pair[1].source_ip, pair[1].username,
        pair[1].event_id, pair[1].source_port, pair[1].outcome, pair[1].method,
    ))
    windows: dict[tuple[str, str, str], deque[tuple[datetime, AuthEvent]]] = {}
    group_counts: dict[tuple[str, str, str], int] = {}
    findings: list[FailureBurst] = []
    for stamp, event in ordered:
        if event.outcome != "failure":
            continue
        key = (event.host, event.source_ip, event.username)
        window = windows.setdefault(key, deque())
        while window and (stamp - window[0][0]).total_seconds() > policy.failure_window_seconds:
            window.popleft()
        window.append((stamp, event))
        if len(window) < policy.failure_threshold:
            continue
        evidence = tuple(record.event_id for _, record in window)
        start = window[0][0].isoformat()
        end = stamp.isoformat()
        ordinal = group_counts.get(key, 0)
        group_counts[key] = ordinal + 1
        fingerprint = json.dumps(["failure_burst", key, ordinal, start, end, evidence],
                                 ensure_ascii=True, separators=(",", ":"))
        findings.append(FailureBurst(sha256(fingerprint.encode()).hexdigest(),
                                    *key, start, end, evidence))
        window.clear()
    return findings
