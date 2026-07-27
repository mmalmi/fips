#!/usr/bin/env python3
"""Validate continuous, sequenced ICMP probes captured by rekey-test.sh."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

REPLY_RE = re.compile(r"icmp_seq=(\d+)")
SUMMARY_RE = re.compile(
    r"(\d+)\s+packets transmitted,\s+(\d+)\s+(?:packets\s+)?received"
)
TIMESTAMP_RE = re.compile(r"^\[(\d+(?:\.\d+)?)\]")


@dataclass(frozen=True)
class ProbeResult:
    stream: str
    transmitted: int
    received_reported: int
    unique_replies: int
    duplicates: int
    missing_sequences: list[int]
    first_reply_unix: float | None
    last_reply_unix: float | None
    error: str | None

    @property
    def passed(self) -> bool:
        return (
            self.error is None
            and self.transmitted > 0
            and self.received_reported == self.transmitted
            and self.unique_replies == self.transmitted
            and self.duplicates == 0
            and not self.missing_sequences
        )


def parse_probe(path: Path) -> ProbeResult:
    replies: list[int] = []
    timestamps: list[float] = []
    transmitted: int | None = None
    received_reported: int | None = None

    for line in path.read_text(errors="replace").splitlines():
        summary = SUMMARY_RE.search(line)
        if summary:
            transmitted = int(summary.group(1))
            received_reported = int(summary.group(2))

        reply = REPLY_RE.search(line) if "bytes from" in line else None
        if not reply:
            continue
        replies.append(int(reply.group(1)))
        timestamp = TIMESTAMP_RE.match(line)
        if timestamp:
            timestamps.append(float(timestamp.group(1)))

    error = None
    if transmitted is None or received_reported is None:
        error = "missing ping summary"
        transmitted = transmitted or 0
        received_reported = received_reported or 0

    unique = set(replies)
    missing = sorted(set(range(1, transmitted + 1)).difference(unique))
    return ProbeResult(
        stream=path.stem,
        transmitted=transmitted,
        received_reported=received_reported,
        unique_replies=len(unique),
        duplicates=len(replies) - len(unique),
        missing_sequences=missing,
        first_reply_unix=min(timestamps) if timestamps else None,
        last_reply_unix=max(timestamps) if timestamps else None,
        error=error,
    )


def analyze(probe_dir: Path, expected_streams: int, min_replies: int) -> tuple[list[ProbeResult], list[str]]:
    paths = sorted(probe_dir.glob("*.log"))
    errors: list[str] = []
    if len(paths) != expected_streams:
        errors.append(f"expected {expected_streams} streams, found {len(paths)}")

    results = [parse_probe(path) for path in paths]
    for result in results:
        if result.error:
            errors.append(f"{result.stream}: {result.error}")
        if result.unique_replies < min_replies:
            errors.append(
                f"{result.stream}: only {result.unique_replies} replies, expected at least {min_replies}"
            )
        if not result.passed:
            errors.append(
                f"{result.stream}: tx={result.transmitted} "
                f"rx={result.received_reported} unique={result.unique_replies} "
                f"duplicates={result.duplicates} missing={result.missing_sequences}"
            )
    return results, errors


def write_tsv(path: Path, results: list[ProbeResult]) -> None:
    lines = [
        "stream\ttransmitted\treceived_reported\tunique_replies\tduplicates\t"
        "missing_sequences\tfirst_reply_unix\tlast_reply_unix\tpassed"
    ]
    for result in results:
        lines.append(
            "\t".join(
                [
                    result.stream,
                    str(result.transmitted),
                    str(result.received_reported),
                    str(result.unique_replies),
                    str(result.duplicates),
                    ",".join(str(seq) for seq in result.missing_sequences),
                    "" if result.first_reply_unix is None else str(result.first_reply_unix),
                    "" if result.last_reply_unix is None else str(result.last_reply_unix),
                    str(result.passed).lower(),
                ]
            )
        )
    path.write_text("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("probe_dir", type=Path)
    parser.add_argument("--expected-streams", type=int, default=20)
    parser.add_argument("--min-replies", type=int, default=20)
    parser.add_argument("--json", dest="json_path", type=Path, required=True)
    parser.add_argument("--tsv", dest="tsv_path", type=Path, required=True)
    args = parser.parse_args()

    results, errors = analyze(args.probe_dir, args.expected_streams, args.min_replies)
    payload = {
        "passed": not errors,
        "expected_streams": args.expected_streams,
        "min_replies": args.min_replies,
        "totals": {
            "transmitted": sum(result.transmitted for result in results),
            "received_reported": sum(result.received_reported for result in results),
            "unique_replies": sum(result.unique_replies for result in results),
            "duplicates": sum(result.duplicates for result in results),
            "missing": sum(len(result.missing_sequences) for result in results),
        },
        "errors": errors,
        "streams": [asdict(result) | {"passed": result.passed} for result in results],
    }
    args.json_path.parent.mkdir(parents=True, exist_ok=True)
    args.json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    write_tsv(args.tsv_path, results)

    totals = payload["totals"]
    print(
        "continuous probes: "
        f"{len(results)}/{args.expected_streams} streams, "
        f"{totals['received_reported']}/{totals['transmitted']} replies, "
        f"{totals['missing']} missing, {totals['duplicates']} duplicates"
    )
    for error in errors:
        print(f"  {error}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
