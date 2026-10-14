"""Transactional SQLite storage for source-aware event occurrences."""

from collections.abc import Iterable
from dataclasses import asdict, dataclass
from datetime import datetime
from hashlib import sha256
from ipaddress import ip_address
from itertools import islice
from pathlib import Path
import json
import re
import sqlite3

from .parser import AuthEvent
from .detector import FailureBurst, SuccessAfterFailure

MAX_STORED_OCCURRENCES = 10_000
_SHA256 = re.compile(r"[0-9a-f]{64}")
MAX_FINDING_EVIDENCE = 20_000


class StorageError(RuntimeError):
    """Report a storage failure without exposing event or path contents."""


@dataclass(frozen=True, slots=True)
class EventOccurrence:
    """One parsed event anchored to a source digest and one-based line number."""

    occurrence_id: str
    source_digest: str
    line_number: int
    event: AuthEvent


@dataclass(frozen=True, slots=True)
class StoredFinding:
    """Canonical finding JSON and its ordered source-aware evidence links."""

    storage_id: str
    payload_json: str
    occurrence_ids: tuple[str, ...]


def _validate_digest(value: str, *, label: str) -> None:
    """Require a canonical lowercase SHA-256 digest."""
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")


def _validate_event(event: AuthEvent) -> None:
    """Reject manually constructed events that violate storage boundaries."""
    if not isinstance(event, AuthEvent):
        raise ValueError("Occurrences require AuthEvent records")
    _validate_digest(event.event_id, label="event_id")
    try:
        stamp = datetime.fromisoformat(event.timestamp)
        if stamp.utcoffset() is None:
            raise ValueError("Missing timezone")
        ip_address(event.source_ip)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("Event timestamp and source IP must be valid") from exc
    text_limits = (
        (event.timestamp, 64),
        (event.host, 255),
        (event.username, 256),
        (event.source_ip, 45),
    )
    if any(not isinstance(value, str) or not value or len(value) > limit
           for value, limit in text_limits):
        raise ValueError("Event text fields violate storage limits")
    if type(event.source_port) is not int or not 1 <= event.source_port <= 65_535:
        raise ValueError("Event source port must be between 1 and 65535")
    if event.outcome not in ("failure", "success"):
        raise ValueError("Event outcome is unsupported")
    if event.method not in ("password", "publickey"):
        raise ValueError("Event authentication method is unsupported")


def _occurrence(source_digest: str, line_number: int,
                event: AuthEvent) -> EventOccurrence:
    """Validate and create a stable source-position occurrence."""
    if type(line_number) is not int or line_number < 1:
        raise ValueError("Line number must be a positive integer")
    _validate_event(event)
    identity = f"{source_digest}:{line_number}:{event.event_id}"
    return EventOccurrence(
        sha256(identity.encode("ascii")).hexdigest(),
        source_digest,
        line_number,
        event,
    )


class EventStore:
    """Own a SQLite connection containing normalized event occurrences.

    Raw log text and source paths are deliberately excluded. Callers identify a
    source by the SHA-256 digest of its bytes and provide one-based line numbers.
    """

    def __init__(self, database: str | Path) -> None:
        """Open or upgrade a version-one database without replacing evidence."""
        self._connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(database, isolation_level=None)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 5000")
            if connection.execute("PRAGMA user_version").fetchone()[0] not in (0, 1, 2):
                raise sqlite3.DatabaseError("Unsupported schema version")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS event_occurrences (
                    occurrence_id TEXT PRIMARY KEY CHECK(length(occurrence_id) = 64),
                    source_digest TEXT NOT NULL CHECK(length(source_digest) = 64),
                    line_number INTEGER NOT NULL CHECK(line_number > 0),
                    event_id TEXT NOT NULL CHECK(length(event_id) = 64),
                    timestamp TEXT NOT NULL,
                    host TEXT NOT NULL,
                    username TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    source_port INTEGER NOT NULL CHECK(source_port BETWEEN 1 AND 65535),
                    outcome TEXT NOT NULL CHECK(outcome IN ('failure', 'success')),
                    method TEXT NOT NULL CHECK(method IN ('password', 'publickey')),
                    UNIQUE(source_digest, line_number)
                );
                CREATE INDEX IF NOT EXISTS event_occurrences_event_id
                    ON event_occurrences(event_id);
                CREATE TABLE IF NOT EXISTS findings (
                    storage_id TEXT PRIMARY KEY CHECK(length(storage_id) = 64),
                    payload_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS finding_evidence (
                    storage_id TEXT NOT NULL REFERENCES findings(storage_id),
                    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
                    occurrence_id TEXT NOT NULL
                        REFERENCES event_occurrences(occurrence_id),
                    PRIMARY KEY(storage_id, ordinal),
                    UNIQUE(storage_id, occurrence_id)
                );
                PRAGMA user_version = 2;
                """
            )
            self._connection = connection
        except (OSError, TypeError, sqlite3.Error) as exc:
            connection = locals().get("connection")
            if isinstance(connection, sqlite3.Connection):
                connection.close()
            raise StorageError("Unable to open event store") from exc

    def __enter__(self) -> "EventStore":
        """Return this open store for context-manager use."""
        self._require_connection()
        return self

    def __exit__(self, *_: object) -> None:
        """Close the database connection."""
        self.close()

    def _require_connection(self) -> sqlite3.Connection:
        """Return the live connection or fail predictably after close."""
        if self._connection is None:
            raise StorageError("Event store is closed")
        return self._connection

    def close(self) -> None:
        """Close the store; repeated calls are harmless."""
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def store_occurrences(
        self,
        source_digest: str,
        records: Iterable[tuple[int, AuthEvent]],
    ) -> list[EventOccurrence]:
        """Atomically persist a bounded batch and return its stable identities.

        Repeating the same source-position records is idempotent. Reusing a
        source position for different event data is rejected and rolls back the
        entire batch rather than silently changing established evidence.
        """
        _validate_digest(source_digest, label="source_digest")
        batch = list(islice(records, MAX_STORED_OCCURRENCES + 1))
        if len(batch) > MAX_STORED_OCCURRENCES:
            raise ValueError("Storage batch exceeds 10000 occurrences")
        occurrences = [
            _occurrence(source_digest, line_number, event)
            for line_number, event in batch
        ]
        if len({item.line_number for item in occurrences}) != len(occurrences):
            raise ValueError("Storage batch contains duplicate line numbers")

        connection = self._require_connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            for item in occurrences:
                event = item.event
                connection.execute(
                    """
                    INSERT INTO event_occurrences (
                        occurrence_id, source_digest, line_number, event_id,
                        timestamp, host, username, source_ip, source_port,
                        outcome, method
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(source_digest, line_number) DO NOTHING
                    """,
                    (
                        item.occurrence_id, item.source_digest, item.line_number,
                        event.event_id, event.timestamp, event.host,
                        event.username, event.source_ip, event.source_port,
                        event.outcome, event.method,
                    ),
                )
                stored = connection.execute(
                    """
                    SELECT occurrence_id, event_id, timestamp, host, username,
                           source_ip, source_port, outcome, method
                    FROM event_occurrences
                    WHERE source_digest = ? AND line_number = ?
                    """,
                    (item.source_digest, item.line_number),
                ).fetchone()
                expected = (
                    item.occurrence_id, event.event_id, event.timestamp,
                    event.host, event.username, event.source_ip,
                    event.source_port, event.outcome, event.method,
                )
                if stored is None or tuple(stored) != expected:
                    raise StorageError("Source position conflicts with stored evidence")
            connection.commit()
        except StorageError:
            connection.rollback()
            raise
        except sqlite3.Error as exc:
            connection.rollback()
            raise StorageError("Unable to store event occurrences") from exc
        return occurrences

    def store_findings(
        self,
        records: Iterable[tuple[FailureBurst | SuccessAfterFailure, tuple[str, ...]]],
    ) -> list[StoredFinding]:
        """Persist findings and explicit occurrence links in one transaction.

        References must match detector evidence fingerprints in order, retain
        distinct occurrences, and match the finding's host/account/source.
        No fingerprint-to-occurrence inference is performed. Identical imports
        are idempotent; the storage identity includes the full payload and links.
        Batches are capped at 10,000 findings and 20,000 total evidence links.
        """
        batch = list(islice(records, MAX_STORED_OCCURRENCES + 1))
        if len(batch) > MAX_STORED_OCCURRENCES:
            raise ValueError("Storage batch exceeds 10000 findings")
        prepared: list[tuple[FailureBurst | SuccessAfterFailure, StoredFinding]] = []
        total = 0
        for finding, references in batch:
            if not isinstance(finding, (FailureBurst, SuccessAfterFailure)):
                raise ValueError("Storage requires supported detector findings")
            _validate_digest(finding.finding_id, label="finding_id")
            if (not isinstance(references, tuple)
                    or not isinstance(finding.evidence_ids, tuple)
                    or not 1 <= len(references) <= MAX_STORED_OCCURRENCES
                    or len(references) != len(finding.evidence_ids)):
                raise ValueError("Finding evidence references have invalid length or type")
            total += len(references)
            if total > MAX_FINDING_EVIDENCE:
                raise ValueError("Storage batch exceeds 20000 evidence links")
            for reference, fingerprint in zip(references, finding.evidence_ids):
                _validate_digest(reference, label="occurrence_id")
                _validate_digest(fingerprint, label="evidence_id")
            if len(set(references)) != len(references):
                raise ValueError("Finding cannot reuse an occurrence")
            payload = asdict(finding)
            payload["finding_type"] = (
                "failure_burst" if isinstance(finding, FailureBurst)
                else "success_after_failure"
            )
            try:
                document = json.dumps(payload, ensure_ascii=True, sort_keys=True,
                                      separators=(",", ":"), allow_nan=False)
            except (TypeError, ValueError) as exc:
                raise ValueError("Finding is not JSON serializable") from exc
            if len(document) > 1_000_000:
                raise ValueError("Finding payload exceeds 1000000 characters")
            identity = json.dumps([document, references], separators=(",", ":"))
            stored = StoredFinding(sha256(identity.encode("ascii")).hexdigest(),
                                   document, references)
            prepared.append((finding, stored))

        connection = self._require_connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            for finding, stored in prepared:
                for index, reference in enumerate(stored.occurrence_ids):
                    row = connection.execute(
                        "SELECT event_id, host, username, source_ip, outcome "
                        "FROM event_occurrences WHERE occurrence_id = ?",
                        (reference,),
                    ).fetchone()
                    outcome = (
                        "success" if isinstance(finding, SuccessAfterFailure)
                        and index == len(stored.occurrence_ids) - 1 else "failure"
                    )
                    expected = (finding.evidence_ids[index], finding.host,
                                finding.username, finding.source_ip, outcome)
                    if row is None or tuple(row) != expected:
                        raise StorageError("Finding evidence is orphaned or mismatched")
                connection.execute(
                    "INSERT INTO findings VALUES (?, ?) "
                    "ON CONFLICT(storage_id) DO NOTHING",
                    (stored.storage_id, stored.payload_json),
                )
                connection.executemany(
                    "INSERT INTO finding_evidence VALUES (?, ?, ?) "
                    "ON CONFLICT(storage_id, ordinal) DO NOTHING",
                    [(stored.storage_id, index, reference)
                     for index, reference in enumerate(stored.occurrence_ids)],
                )
            connection.commit()
        except StorageError:
            connection.rollback()
            raise
        except sqlite3.Error as exc:
            connection.rollback()
            raise StorageError("Unable to store findings") from exc
        return [stored for _, stored in prepared]

    def list_findings(self, *, limit: int = 1000) -> list[StoredFinding]:
        """Read up to 10,000 findings in stable identity and evidence order."""
        if type(limit) is not int or not 1 <= limit <= MAX_STORED_OCCURRENCES:
            raise ValueError("Finding read limit must be between 1 and 10000")
        connection = self._require_connection()
        try:
            rows = connection.execute(
                "SELECT storage_id, payload_json FROM findings "
                "ORDER BY storage_id LIMIT ?", (limit,),
            ).fetchall()
            return [
                StoredFinding(row["storage_id"], row["payload_json"], tuple(
                    evidence[0] for evidence in connection.execute(
                        "SELECT occurrence_id FROM finding_evidence "
                        "WHERE storage_id = ? ORDER BY ordinal",
                        (row["storage_id"],),
                    )
                )) for row in rows
            ]
        except sqlite3.Error as exc:
            raise StorageError("Unable to read findings") from exc

    def list_occurrences(
        self, source_digest: str | None = None,
    ) -> list[EventOccurrence]:
        """Return stored occurrences in stable source and position order."""
        parameters: tuple[str, ...] = ()
        where = ""
        if source_digest is not None:
            _validate_digest(source_digest, label="source_digest")
            where = "WHERE source_digest = ?"
            parameters = (source_digest,)
        try:
            rows = self._require_connection().execute(
                f"""
                SELECT occurrence_id, source_digest, line_number, event_id,
                       timestamp, host, username, source_ip, source_port,
                       outcome, method
                FROM event_occurrences
                {where}
                ORDER BY source_digest, line_number, occurrence_id
                """,
                parameters,
            ).fetchall()
        except sqlite3.Error as exc:
            raise StorageError("Unable to read event occurrences") from exc
        return [
            EventOccurrence(
                row["occurrence_id"], row["source_digest"], row["line_number"],
                AuthEvent(
                    row["event_id"], row["timestamp"], row["host"],
                    row["username"], row["source_ip"], row["source_port"],
                    row["outcome"], row["method"],
                ),
            )
            for row in rows
        ]
