"""Bounded ASCII-only terminal summaries; no terminal styling or I/O."""

from collections.abc import Iterable
from itertools import islice

from .detector import FailureBurst, SuccessAfterFailure

MAX_SUMMARY_FINDINGS = 100
MAX_FIELD_CHARS = 160
MAX_EVIDENCE_IDS = 10_000
DISPLAY_EVIDENCE_IDS = 3


def terminal_text(value: str, *, limit: int = MAX_FIELD_CHARS) -> str:
    """Escape text into at most limit ASCII characters, including truncation.

    Escape backslashes and quotes to distinguish literal text from escapes.
    Every non-printable or non-ASCII code point is shown as a Python-style
    escape, including bidi formatting, C1 controls, surrogates and newlines.
    Never split an escape token. Inspect at most limit + 1 input characters, even
    for very large strings. The limit counts output characters, not input.
    """
    if not isinstance(value, str):
        raise ValueError("Terminal fields must be strings")
    if type(limit) is not int or not 8 <= limit <= 1000:
        raise ValueError("Terminal field limit must be an integer from 8 to 1000")
    tokens: list[str] = []
    used = 0
    for char in value:
        code = ord(char)
        if char in ('\\', '"'):
            token = '\\' + char
        elif 32 <= code <= 126:
            token = char
        elif code <= 255:
            token = f"\\x{code:02x}"
        elif code <= 65535:
            token = f"\\u{code:04x}"
        else:
            token = f"\\U{code:08x}"
        if used + len(token) > limit:
            while tokens and used > limit - 3:
                used -= len(tokens.pop())
            return ''.join(tokens) + '...'
        tokens.append(token)
        used += len(token)
    return ''.join(tokens)


def render_finding(finding: FailureBurst | SuccessAfterFailure) -> str:
    """Render one deterministic finding as a private, display-only summary.

    Show at most three evidence fingerprints with an explicit omitted count.
    Fingerprint multiplicity is preserved, not deduplicated. This is not a
    serialized report or an AI-safe payload: identifiers may be private, and
    findings are review candidates rather than proof of compromise.
    """
    if not isinstance(finding, (FailureBurst, SuccessAfterFailure)):
        raise ValueError("Summary requires a supported deterministic finding")
    evidence = finding.evidence_ids
    minimum = 3 if isinstance(finding, SuccessAfterFailure) else 2
    if (not isinstance(evidence, tuple) or not minimum <= len(evidence) <= MAX_EVIDENCE_IDS
            or any(not isinstance(item, str) for item in evidence)):
        raise ValueError("Summary evidence count or fingerprint type is invalid")
    correlated = isinstance(finding, SuccessAfterFailure)
    title = 'success_after_failure' if correlated else 'failure_burst'
    start = finding.burst_started_at if correlated else finding.started_at
    end = finding.burst_ended_at if correlated else finding.ended_at
    rows = [
        f"{title} [{terminal_text(finding.finding_id)}] (review candidate)",
        f'  host="{terminal_text(finding.host)}"',
        f'  source_ip="{terminal_text(finding.source_ip)}"',
        f'  username="{terminal_text(finding.username)}"',
        f"  burst: {terminal_text(start)} -> {terminal_text(end)}",
        f"  failures: {finding.failure_count}",
    ]
    if correlated:
        rows.append(f"  success: {terminal_text(finding.succeeded_at)}")
    shown = ', '.join(terminal_text(item) for item in evidence[:DISPLAY_EVIDENCE_IDS])
    omitted = len(evidence) - DISPLAY_EVIDENCE_IDS
    suffix = f" (+{omitted} omitted)" if omitted > 0 else ''
    rows.append(f"  evidence ({len(evidence)}): {shown}{suffix}")
    return '\n'.join(rows) + '\n'


def render_findings(findings: Iterable[FailureBurst | SuccessAfterFailure]) -> str:
    """Render up to 100 findings in supplied order, rejecting larger batches.

    Consume at most 101 records so infinite iterators terminate predictably.
    No partial document is returned if any record fails validation. Neither
    input records nor their ordering are changed. Empty input is explicit.
    """
    try:
        batch = list(islice(findings, MAX_SUMMARY_FINDINGS + 1))
    except TypeError:
        raise ValueError("Summary requires a finding collection") from None
    if len(batch) > MAX_SUMMARY_FINDINGS:
        raise ValueError("Summary exceeds 100 findings")
    return '\n'.join(render_finding(item) for item in batch) if batch else 'No findings.\n'
