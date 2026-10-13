"""Transactional SQLite storage for source-aware event occurrences."""

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from ipaddress import ip_address
from itertools import islice
from pathlib import Path
import re
import sqlite3

from .parser import AuthEvent

MAX_STORED_OCCURRENCES = 10_000
_SHA256 = re.compile(r"[0-9a-f]{64}")


class StorageError(RuntimeError):
    """Report a storage failure without exposing event or path contents."""


@dataclass(frozen=True, slots=True)
class EventOccurrence:
    """One parsed event anchored to a source digest and one-based line number."""

    occurrence_id: str
    source_digest: str
    line_number: int
    event: AuthEvent


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
        """Open a database and create the version-one schema if necessary."""
        self._connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(database, isolation_level=None)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 5000")
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
                PRAGMA user_version = 1;
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
