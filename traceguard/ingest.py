"""Bound local log ingestion before detection or persistence."""

from collections.abc import Iterator
from dataclasses import dataclass
from hashlib import sha256
import io
from pathlib import Path

from .parser import AuthEvent, parse_line

MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_INGEST_EVENTS = 10_000
MAX_LINE_CHARS = 8192
_READ_CHUNK_BYTES = 65_536


class IngestError(ValueError):
    """Describe a safe ingestion failure without exposing log content."""


@dataclass(frozen=True, slots=True)
class RejectionCounts:
    """Aggregate rejected records without retaining their private contents."""

    unsupported: int = 0
    event_limit: int = 0

    @property
    def total(self) -> int:
        """Return the number of records excluded from the batch."""
        return self.unsupported + self.event_limit


@dataclass(frozen=True, slots=True)
class IngestBatch:
    """A bounded parsed batch and its privacy-safe source metadata."""

    source_digest: str
    records: tuple[tuple[int, AuthEvent], ...]
    rejections: RejectionCounts


def _read_bounded(path: Path, max_file_bytes: int) -> bytes:
    """Read at most one configured file, rejecting overflow before parsing."""
    payload = bytearray()
    with path.open("rb") as stream:
        while True:
            remaining = max_file_bytes + 1 - len(payload)
            chunk = stream.read(min(_READ_CHUNK_BYTES, remaining))
            if not chunk:
                return bytes(payload)
            payload.extend(chunk)
            if len(payload) > max_file_bytes:
                raise IngestError(
                    f"Log exceeds the {max_file_bytes}-byte ingestion limit"
                )


def _logical_lines(text: str) -> Iterator[tuple[int, str | None]]:
    """Split bounded text while replacing oversized lines with ``None``."""
    stream = io.StringIO(text)
    line_number = 0
    while True:
        line = stream.readline(MAX_LINE_CHARS + 1)
        if not line:
            return
        line_number += 1
        if len(line) <= MAX_LINE_CHARS:
            yield line_number, line
            continue
        while line and not line.endswith("\n"):
            line = stream.readline(MAX_LINE_CHARS + 1)
        yield line_number, None


def ingest_file(
    path: Path,
    *,
    year: int,
    utc_offset_minutes: int = 0,
    max_file_bytes: int = MAX_FILE_BYTES,
    max_events: int = MAX_INGEST_EVENTS,
) -> IngestBatch:
    """Read and parse one bounded log without retaining rejected records.

    The source digest covers the exact accepted file bytes. Unsupported,
    malformed, and oversized lines are counted together because exposing their
    classification or contents is unnecessary for deterministic detection.
    Valid records beyond ``max_events`` are counted but omitted from the batch.
    """
    if isinstance(max_file_bytes, bool) or not isinstance(max_file_bytes, int):
        raise ValueError("max_file_bytes must be an integer")
    if isinstance(max_events, bool) or not isinstance(max_events, int):
        raise ValueError("max_events must be an integer")
    if not 1 <= max_file_bytes <= MAX_FILE_BYTES:
        raise ValueError(
            f"max_file_bytes must be between 1 and {MAX_FILE_BYTES}"
        )
    if not 1 <= max_events <= MAX_INGEST_EVENTS:
        raise ValueError(
            f"max_events must be between 1 and {MAX_INGEST_EVENTS}"
        )

    payload = _read_bounded(path, max_file_bytes)
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise IngestError("Log is not valid UTF-8") from exc

    records: list[tuple[int, AuthEvent]] = []
    unsupported = event_limit = 0
    for line_number, line in _logical_lines(text):
        event = None if line is None else parse_line(
            line, year=year, utc_offset_minutes=utc_offset_minutes,
        )
        if event is None:
            unsupported += 1
        elif len(records) >= max_events:
            event_limit += 1
        else:
            records.append((line_number, event))
    return IngestBatch(
        source_digest=sha256(payload).hexdigest(),
        records=tuple(records),
        rejections=RejectionCounts(
            unsupported=unsupported, event_limit=event_limit,
        ),
    )
