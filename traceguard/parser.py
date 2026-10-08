"""Parse a bounded subset of OpenSSH syslog authentication records."""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from hashlib import sha256
from ipaddress import ip_address
import re

_PREFIX = re.compile(
    r"^(?P<stamp>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}) "
    r"(?P<host>[\w.-]+) sshd\[\d+\]: (?P<body>.+)$"
)
_AUTH = re.compile(
    r"^(?P<outcome>Failed|Accepted) (?P<method>password|publickey) for "
    r"(?:invalid user )?(?P<user>[^\s\x00-\x1f]+) from (?P<ip>\S+) "
    r"port (?P<port>\d{1,5}) ssh2(?:$|: [^\x00-\x1f]+$)"
)
_MONTHS = {name: index for index, name in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1
)}


@dataclass(frozen=True, slots=True)
class AuthEvent:
    """Normalized event; timestamps use the timezone supplied at ingestion."""

    event_id: str
    timestamp: str
    host: str
    username: str
    source_ip: str
    source_port: int
    outcome: str
    method: str

    def to_dict(self) -> dict[str, str | int]:
        """Return a JSON-compatible representation."""
        return asdict(self)


def parse_line(line: str, *, year: int, utc_offset_minutes: int = 0) -> AuthEvent | None:
    """Return an event or None for unsupported/malformed input.

    Legacy syslog omits year and timezone; callers must supply those explicitly.
    This parser does not infer December-to-January rollover within a file.
    """
    if not 1 <= year <= 9999 or not -1439 <= utc_offset_minutes <= 1439:
        raise ValueError("Invalid year or UTC offset")
    if len(line) > 8192:
        return None
    prefix = _PREFIX.fullmatch(line.rstrip("\r\n"))
    if prefix is None:
        return None
    auth = _AUTH.fullmatch(prefix["body"])
    if auth is None:
        return None
    try:
        from datetime import timedelta

        month, day, clock = prefix["stamp"].split()
        hour, minute, second = map(int, clock.split(":"))
        stamp = datetime(year, _MONTHS[month], int(day), hour, minute, second,
                         tzinfo=timezone(timedelta(minutes=utc_offset_minutes)))
        address = str(ip_address(auth["ip"]))
        port = int(auth["port"])
        if not 1 <= port <= 65535:
            return None
    except (ValueError, KeyError):
        return None
    normalized = line.rstrip("\r\n")
    identifier = sha256(f"{year}:{utc_offset_minutes}:{normalized}".encode("utf-8")).hexdigest()
    return AuthEvent(identifier, stamp.astimezone(timezone.utc).isoformat(),
                     prefix["host"], auth["user"], address, port,
                     "failure" if auth["outcome"] == "Failed" else "success", auth["method"])
