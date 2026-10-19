"""Versioned, deterministic local JSON reports with source-aware evidence links."""

from collections.abc import Iterable, Mapping
from dataclasses import fields
from datetime import datetime
from hashlib import sha256
from itertools import islice
import json
import re

from .config import DetectionConfig
from .detector import FailureBurst, SuccessAfterFailure
from .storage import EventOccurrence, StoredFinding

SCHEMA_VERSION = 1
MAX_REPORT_RECORDS = 10_000
MAX_REPORT_LINKS = 20_000
MAX_REPORT_CHARS = 8_000_000
_DIGEST = re.compile(r"[0-9a-f]{64}")
EXPLANATION_STATUSES = frozenset({
    "offline", "valid", "timeout", "unavailable", "http_error", "invalid_response",
    "response_too_large", "request_too_large", "invalid_request", "skipped_limit",
})


def _digest(value: object) -> str:
    """Validate an identifier without reflecting its contents in errors."""
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ValueError("Report requires lowercase SHA-256 identifiers")
    return value


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate keys in stored payloads rather than accepting ambiguity."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate report payload key")
        result[key] = value
    return result


def _stamp(value: object) -> datetime:
    """Require bounded timezone-aware timestamps for report boundaries."""
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError("Invalid report timestamp")
    try:
        result = datetime.fromisoformat(value)
        if result.utcoffset() is None:
            raise ValueError("Missing timezone")
        return result
    except (ValueError, OverflowError):
        raise ValueError("Invalid report timestamp") from None


def export_report(
    *,
    source_digest: str,
    config: DetectionConfig,
    occurrences: Iterable[EventOccurrence],
    findings: Iterable[StoredFinding],
    explanation_statuses: Mapping[str, str] | None = None,
) -> str:
    """Build a version-one JSON document without file or network I/O.

    Inputs are bounded snapshots from EventStore for exactly one source.
    Findings retain detector fingerprints plus ordered occurrence IDs, allowing
    identical log lines at different positions to remain distinct evidence.
    Explanation statuses are keyed by storage_id and default to offline. This
    version exports statuses only, never arbitrary model prose or raw logs.

    Output order is stable regardless of input order; no clock timestamps or
    random report IDs are added. The returned newline-terminated document is a
    private local artifact containing normalized identifiers, not an AI-safe
    payload. A source digest records provenance, not cryptographic authenticity.
    """
    _digest(source_digest)
    if not isinstance(config, DetectionConfig):
        raise ValueError("Report requires a validated detection configuration")
    evidence = list(islice(occurrences, MAX_REPORT_RECORDS + 1))
    batch = list(islice(findings, MAX_REPORT_RECORDS + 1))
    if len(evidence) > MAX_REPORT_RECORDS or len(batch) > MAX_REPORT_RECORDS:
        raise ValueError("Report exceeds 10000 records per collection")
    by_id: dict[str, EventOccurrence] = {}
    positions: set[int] = set()
    for item in evidence:
        if not isinstance(item, EventOccurrence) or item.source_digest != source_digest:
            raise ValueError("Report evidence belongs to another source")
        _digest(item.occurrence_id)
        _digest(item.event.event_id)
        if type(item.line_number) is not int or item.line_number < 1:
            raise ValueError("Invalid report line position")
        expected = sha256(
            f"{source_digest}:{item.line_number}:{item.event.event_id}".encode("ascii")
        ).hexdigest()
        if (item.occurrence_id != expected or item.occurrence_id in by_id
                or item.line_number in positions):
            raise ValueError("Conflicting or duplicate report evidence")
        by_id[item.occurrence_id] = item
        positions.add(item.line_number)
    statuses = {} if explanation_statuses is None else explanation_statuses
    if not isinstance(statuses, Mapping) or len(statuses) > MAX_REPORT_RECORDS:
        raise ValueError("Invalid report explanation statuses")
    output: list[dict[str, object]] = []
    seen: set[str] = set()
    link_count = 0
    payload_chars = 0
    for item in batch:
        if not isinstance(item, StoredFinding):
            raise ValueError("Report requires stored findings")
        _digest(item.storage_id)
        if item.storage_id in seen:
            raise ValueError("Duplicate report finding")
        seen.add(item.storage_id)
        if not isinstance(item.payload_json, str) or len(item.payload_json) > 1_000_000:
            raise ValueError("Invalid report finding payload")
        payload_chars += len(item.payload_json)
        if payload_chars > MAX_REPORT_CHARS:
            raise ValueError("Report finding payloads exceed character budget")
        try:
            payload = json.loads(item.payload_json, object_pairs_hook=_unique_object)
        except (ValueError, RecursionError):
            raise ValueError("Invalid report finding JSON") from None
        if not isinstance(payload, dict):
            raise ValueError("Report finding must be an object")
        kind = payload.get("finding_type")
        model = {"failure_burst": FailureBurst,
                 "success_after_failure": SuccessAfterFailure}.get(kind) if isinstance(kind, str) else None
        if model is None or set(payload) != {field.name for field in fields(model)} | {"finding_type"}:
            raise ValueError("Unsupported report finding schema")
        _digest(payload["finding_id"])
        fingerprints = payload["evidence_ids"]
        references = item.occurrence_ids
        if (not isinstance(fingerprints, list) or not isinstance(references, tuple)
                or not (3 if kind == "success_after_failure" else 2) <= len(references) <= MAX_REPORT_RECORDS
                or len(references) != len(fingerprints)):
            raise ValueError("Invalid report evidence references")
        link_count += len(references)
        if link_count > MAX_REPORT_LINKS:
            raise ValueError("Report exceeds 20000 evidence links")
        for reference in references:
            _digest(reference)
        if len(set(references)) != len(references):
            raise ValueError("Report finding reuses an occurrence")
        for index, (reference, fingerprint) in enumerate(zip(references, fingerprints)):
            _digest(fingerprint)
            occurrence = by_id.get(reference)
            outcome = "success" if kind == "success_after_failure" and index == len(references) - 1 else "failure"
            if (occurrence is None or occurrence.event.event_id != fingerprint
                    or occurrence.event.host != payload["host"]
                    or occurrence.event.username != payload["username"]
                    or occurrence.event.source_ip != payload["source_ip"]
                    or occurrence.event.outcome != outcome):
                raise ValueError("Report contains orphaned or mismatched evidence")
        if kind == "success_after_failure":
            _digest(payload["burst_finding_id"])
            if payload["success_event_id"] != fingerprints[-1]:
                raise ValueError("Report success evidence is inconsistent")
            start, end = payload["burst_started_at"], payload["burst_ended_at"]
            if _stamp(end) > _stamp(payload["succeeded_at"]):
                raise ValueError("Report success precedes its burst")
        else:
            start, end = payload["started_at"], payload["ended_at"]
        if _stamp(start) > _stamp(end):
            raise ValueError("Report burst has reversed timestamps")
        identity = json.dumps([item.payload_json, references], separators=(",", ":"))
        if sha256(identity.encode("ascii")).hexdigest() != item.storage_id:
            raise ValueError("Report finding storage identity is inconsistent")
        status = statuses.get(item.storage_id, "offline")
        if not isinstance(status, str) or status not in EXPLANATION_STATUSES:
            raise ValueError("Unknown report explanation status")
        output.append({"storage_id": item.storage_id, "finding": payload,
                       "occurrence_ids": list(references), "explanation_status": status})
    if any(key not in seen for key in statuses):
        raise ValueError("Explanation status references an unknown report finding")
    document = json.dumps({
        "schema_version": SCHEMA_VERSION,
        "source_digest": source_digest,
        "configuration": config.to_dict(),
        "evidence": [{"occurrence_id": item.occurrence_id, "line_number": item.line_number,
                      "event_id": item.event.event_id} for item in sorted(evidence, key=lambda item: item.line_number)],
        "findings": sorted(output, key=lambda item: item["storage_id"]),
    }, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")) + "\n"
    if len(document) > MAX_REPORT_CHARS:
        raise ValueError("Report exceeds 8000000 characters")
    return document
