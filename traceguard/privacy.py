"""Build bounded, allowlisted AI evidence payloads without raw identifiers."""

from collections.abc import Iterable
from datetime import datetime, timezone
from ipaddress import ip_address
from itertools import islice
import re
import secrets

from .detector import FailureBurst, SuccessAfterFailure

MAX_REPORT_FINDINGS = 1000
MAX_REPORT_EVIDENCE = 10_000
_DIGEST = re.compile(r"[0-9a-f]{64}")


def _digest(value: str) -> str:
    """Validate references without echoing supplied private content."""
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ValueError("Privacy references must be lowercase SHA-256 digests")
    return value


def _timestamp(value: str) -> str:
    """Return canonical UTC text, rejecting arbitrary free-form strings."""
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError("Privacy timestamp must be bounded ISO text")
    try:
        stamp = datetime.fromisoformat(value)
        if stamp.utcoffset() is None:
            raise ValueError("Missing timezone")
        return stamp.astimezone(timezone.utc).isoformat()
    except (ValueError, OverflowError) as exc:
        raise ValueError("Privacy timestamp must be valid and timezone-aware") from exc


def sanitize_findings(
    findings: Iterable[FailureBurst | SuccessAfterFailure],
) -> list[dict[str, object]]:
    """Return fresh, JSON-compatible evidence records for one report.

    Aliases are stable within this call and deliberately randomized between
    calls. Reference aliases preserve equality, order, and duplicate evidence
    without exposing raw event fingerprints. Private alias dictionaries remain
    local and are never returned. Unknown fields, raw logs, paths, and free-form
    descriptions are never copied. Only supported detector dataclasses are
    accepted; timestamps and references are validated before serialization.

    This is pseudonymization, not guaranteed anonymity: timing, counts, and
    relationships remain visible. No network access or model calls occur here.
    """
    batch = list(islice(findings, MAX_REPORT_FINDINGS + 1))
    if len(batch) > MAX_REPORT_FINDINGS:
        raise ValueError("Privacy report exceeds 1000 findings")
    namespace = secrets.token_hex(16)
    aliases: dict[str, dict[str, str]] = {}

    def alias(kind: str, value: str) -> str:
        """Assign an opaque role-separated identifier within this report."""
        mapping = aliases.setdefault(kind, {})
        if value not in mapping:
            mapping[value] = f"{kind}-{namespace}-{len(mapping) + 1}"
        return mapping[value]

    result: list[dict[str, object]] = []
    evidence_count = 0
    for finding in batch:
        if type(finding) not in (FailureBurst, SuccessAfterFailure):
            raise ValueError("Privacy requires supported detector findings")
        for value, limit in ((finding.host, 255), (finding.username, 256),
                             (finding.source_ip, 45)):
            if not isinstance(value, str) or not 1 <= len(value) <= limit:
                raise ValueError("Privacy identifier violates text limits")
        try:
            address = str(ip_address(finding.source_ip))
        except ValueError as exc:
            raise ValueError("Privacy source IP must be valid") from exc
        if (not isinstance(finding.evidence_ids, tuple)
                or not 2 <= len(finding.evidence_ids) <= MAX_REPORT_EVIDENCE):
            raise ValueError("Privacy evidence must be a bounded tuple")
        evidence_count += len(finding.evidence_ids)
        if evidence_count > MAX_REPORT_EVIDENCE:
            raise ValueError("Privacy report exceeds 10000 evidence references")
        evidence = [alias("evidence", _digest(value))
                    for value in finding.evidence_ids]
        record: dict[str, object] = {
            "finding_type": "failure_burst",
            "finding_id": alias("finding", _digest(finding.finding_id)),
            "host": alias("host", finding.host),
            "username": alias("user", finding.username),
            "source_ip": alias("ip", address),
            "failure_count": finding.failure_count,
            "evidence_ids": evidence,
        }
        if isinstance(finding, SuccessAfterFailure):
            if (len(evidence) < 3
                    or finding.success_event_id != finding.evidence_ids[-1]):
                raise ValueError("Privacy correlation has inconsistent success evidence")
            start = _timestamp(finding.burst_started_at)
            end = _timestamp(finding.burst_ended_at)
            success = _timestamp(finding.succeeded_at)
            if datetime.fromisoformat(end) > datetime.fromisoformat(success):
                raise ValueError("Privacy success precedes its failure burst")
            record.update({
                "finding_type": "success_after_failure",
                "burst_finding_id": alias("finding", _digest(finding.burst_finding_id)),
                "success_event_id": alias("evidence", _digest(finding.success_event_id)),
                "burst_started_at": start,
                "burst_ended_at": end,
                "succeeded_at": success,
            })
        else:
            start = _timestamp(finding.started_at)
            end = _timestamp(finding.ended_at)
            record.update({"started_at": start, "ended_at": end})
        if datetime.fromisoformat(start) > datetime.fromisoformat(end):
            raise ValueError("Privacy burst has reversed timestamps")
        result.append(record)
    return result
