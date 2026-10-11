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


@dataclass(frozen=True, slots=True)
class SuccessAfterFailure:
    """A successful login correlated to one preceding failure burst.

    This is an investigation lead, not proof that the login was unauthorized.
    Evidence contains every failure fingerprint followed by the success event
    fingerprint so downstream reports can retain the complete provenance.
    """

    finding_id: str
    host: str
    source_ip: str
    username: str
    burst_finding_id: str
    success_event_id: str
    burst_started_at: str
    burst_ended_at: str
    succeeded_at: str
    evidence_ids: tuple[str, ...]

    @property
    def failure_count(self) -> int:
        """Return the number of failure occurrences preceding the success."""
        return len(self.evidence_ids) - 1


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


def _timestamp_text(value: str, *, label: str) -> datetime:
    """Validate an external finding timestamp and normalize it to aware UTC."""
    try:
        stamp = datetime.fromisoformat(value)
        if stamp.utcoffset() is None:
            raise ValueError("Missing timezone")
        return stamp.astimezone(timezone.utc)
    except (ValueError, TypeError, OverflowError) as exc:
        raise ValueError(f"{label} must be valid and timezone-aware") from exc


def _validated_batch(events: Iterable[AuthEvent]) -> list[tuple[datetime, AuthEvent]]:
    """Read and validate one finite authentication-event batch."""
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
    return ordered


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
    ordered = _validated_batch(events)
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


def correlate_success_after_failure_bursts(
    events: Iterable[AuthEvent],
    bursts: Iterable[FailureBurst],
    config: DetectionConfig | None = None,
) -> list[SuccessAfterFailure]:
    """Correlate successful logins with preceding failure bursts.

    Both input collections are capped at MAX_BATCH_EVENTS. A success matches
    only a burst with the same (host, source IP, username), at or after the
    burst end, and no later than success_window_seconds afterward. Each success
    and burst is consumed at most once. When several bursts qualify, select the
    most recent; an earlier still-valid burst can match a later success. Results
    are ordered by normalized success time and stable evidence fields, making
    them independent of input order. Complexity is O((n + b) log(n + b)) time
    and O(n + b) space.
    """
    policy = DetectionConfig() if config is None else config
    if not isinstance(policy, DetectionConfig):
        raise ValueError("Detection requires a validated DetectionConfig")
    ordered_events = _validated_batch(events)
    burst_batch = list(islice(bursts, MAX_BATCH_EVENTS + 1))
    if len(burst_batch) > MAX_BATCH_EVENTS:
        raise ValueError("Failure-burst batch exceeds 10000 findings")

    pending: dict[tuple[str, str, str], list[tuple[datetime, FailureBurst]]] = {}
    for burst in burst_batch:
        if not isinstance(burst, FailureBurst):
            raise ValueError("Correlation requires FailureBurst findings")
        started = _timestamp_text(burst.started_at, label="Burst start")
        ended = _timestamp_text(burst.ended_at, label="Burst end")
        if started > ended or not burst.evidence_ids:
            raise ValueError("Failure burst has invalid evidence boundaries")
        key = (burst.host, burst.source_ip, burst.username)
        pending.setdefault(key, []).append((ended, burst))
    for queue in pending.values():
        queue.sort(key=lambda item: (item[0], item[1].finding_id, item[1].evidence_ids))

    successes: dict[tuple[str, str, str], list[tuple[datetime, AuthEvent]]] = {}
    for succeeded, success in ordered_events:
        if success.outcome == "success":
            key = (success.host, success.source_ip, success.username)
            successes.setdefault(key, []).append((succeeded, success))
    findings: list[tuple[datetime, SuccessAfterFailure]] = []
    for key, success_queue in successes.items():
        burst_queue = pending.get(key)
        if not burst_queue:
            continue
        eligible: deque[tuple[datetime, FailureBurst]] = deque()
        next_burst = 0
        ordinal = 0
        for succeeded, success in success_queue:
            while next_burst < len(burst_queue) and burst_queue[next_burst][0] <= succeeded:
                eligible.append(burst_queue[next_burst])
                next_burst += 1
            while (eligible and
                   (succeeded - eligible[0][0]).total_seconds()
                   > policy.success_window_seconds):
                eligible.popleft()
            if not eligible:
                continue
            _, burst = eligible.pop()
            evidence = (*burst.evidence_ids, success.event_id)
            fingerprint = json.dumps(
                ["success_after_failure", key, ordinal, burst.finding_id,
                 success.event_id, succeeded.isoformat(), evidence],
                ensure_ascii=True, separators=(",", ":"),
            )
            finding = SuccessAfterFailure(
                sha256(fingerprint.encode()).hexdigest(), *key,
                burst.finding_id, success.event_id, burst.started_at,
                burst.ended_at, succeeded.isoformat(), evidence,
            )
            findings.append((succeeded, finding))
            ordinal += 1
    findings.sort(key=lambda item: (
        item[0], item[1].host, item[1].source_ip, item[1].username,
        item[1].success_event_id, item[1].finding_id,
    ))
    return [finding for _, finding in findings]
