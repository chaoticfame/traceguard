"""Stream normalized SSH events as JSON Lines."""

import argparse
import json
from pathlib import Path
import sys

from .parser import parse_line


def main() -> int:
    """Run the parser CLI with bounded input and explicit timestamp context."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    parser.add_argument("--year", type=int, required=True, choices=range(1, 10000), metavar="YEAR")
    parser.add_argument("--utc-offset-minutes", type=int, default=0,
                        choices=range(-1439, 1440), metavar="MINUTES")
    args = parser.parse_args()
    parsed = skipped = 0
    try:
        with args.log.open("r", encoding="utf-8", errors="strict") as stream:
            while True:
                line = stream.readline(8193)
                if not line:
                    break
                if len(line) > 8192:
                    while not line.endswith("\n"):
                        line = stream.readline(8193)
                        if not line:
                            break
                    skipped += 1
                    continue
                event = parse_line(line, year=args.year,
                                   utc_offset_minutes=args.utc_offset_minutes)
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


if __name__ == "__main__":
    raise SystemExit(main())
