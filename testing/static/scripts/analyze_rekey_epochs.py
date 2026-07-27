#!/usr/bin/env python3
"""Validate per-session FSP rekey cycles in complete timestamped node logs."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
TIMESTAMP_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?Z\s"
)
FIELD_RE = re.compile(r"\b(peer|src|received_k_bit)=([^\s]+)")
INITIATION_MESSAGE = "FSP rekey initiated, sent SessionSetup"
CUTOVER_MESSAGE = "FSP rekey cutover complete"


@dataclass(frozen=True)
class Cutover:
    timestamp: datetime
    k_bit: bool | None


@dataclass(frozen=True)
class NodeEvents:
    initiations: dict[str, list[datetime]]
    cutovers: dict[str, list[Cutover]]


@dataclass(frozen=True)
class SessionEvidence:
    target: str
    target_display: str
    initiations: int
    initiator_cutovers: int
    target_cutovers: int
    second_initiation_after_cutover_seconds: float | None
    initiator_k_bits: list[bool]
    target_k_bits: list[bool]
    errors: list[str]

    @property
    def passed(self) -> bool:
        return not self.errors


def short_npub(npub: str) -> str:
    if not npub.startswith("npub1") or len(npub) < 13:
        raise ValueError(f"invalid npub: {npub!r}")
    data = npub[5:]
    return f"npub1{data[:4]}...{data[-4:]}"


def parse_timestamp(line: str) -> datetime | None:
    match = TIMESTAMP_RE.match(line)
    if not match:
        return None
    fractional = (match.group(2) or "")[:6].ljust(6, "0")
    return datetime.fromisoformat(f"{match.group(1)}.{fractional}+00:00")


def parse_node_log(path: Path) -> NodeEvents:
    initiations: dict[str, list[datetime]] = {}
    cutovers: dict[str, list[Cutover]] = {}
    for raw_line in path.read_text(errors="replace").splitlines():
        line = ANSI_RE.sub("", raw_line)
        timestamp = parse_timestamp(line)
        if timestamp is None:
            continue
        fields = dict(FIELD_RE.findall(line))
        if INITIATION_MESSAGE in line and "peer" in fields:
            initiations.setdefault(fields["peer"], []).append(timestamp)
        if CUTOVER_MESSAGE in line and "src" in fields:
            k_bit_text = fields.get("received_k_bit")
            k_bit = (
                k_bit_text == "true"
                if k_bit_text in {"true", "false"}
                else None
            )
            cutovers.setdefault(fields["src"], []).append(Cutover(timestamp, k_bit))

    for timestamps in initiations.values():
        timestamps.sort()
    for peer_cutovers in cutovers.values():
        peer_cutovers.sort(key=lambda cutover: cutover.timestamp)
    return NodeEvents(initiations=initiations, cutovers=cutovers)


def alternating(bits: list[bool], count: int) -> bool:
    selected = bits[:count]
    return len(selected) == count and all(
        previous != current for previous, current in zip(selected, selected[1:])
    )


def analyze(
    log_dir: Path,
    *,
    initiator_node: str,
    initiator_npub: str,
    targets: dict[str, str],
    min_cycles: int,
    drain_seconds: float,
) -> tuple[list[SessionEvidence], list[str]]:
    if min_cycles < 2:
        raise ValueError("min_cycles must be at least 2")
    if drain_seconds <= 0:
        raise ValueError("drain_seconds must be positive")

    initiator_path = log_dir / f"node-{initiator_node}.log"
    initiator_events = (
        parse_node_log(initiator_path)
        if initiator_path.is_file()
        else NodeEvents(initiations={}, cutovers={})
    )
    initiator_display = short_npub(initiator_npub)

    results: list[SessionEvidence] = []
    all_errors: list[str] = []
    for target, target_npub in targets.items():
        target_display = short_npub(target_npub)
        target_path = log_dir / f"node-{target}.log"
        target_events = (
            parse_node_log(target_path)
            if target_path.is_file()
            else NodeEvents(initiations={}, cutovers={})
        )
        initiations = initiator_events.initiations.get(target_display, [])
        initiator_cutovers = initiator_events.cutovers.get(target_display, [])
        target_cutovers = target_events.cutovers.get(initiator_display, [])
        session_errors: list[str] = []

        if not initiator_path.is_file():
            session_errors.append(f"missing initiator log {initiator_path.name}")
        if not target_path.is_file():
            session_errors.append(f"missing target log {target_path.name}")
        if len(initiations) < min_cycles:
            session_errors.append(
                f"initiations={len(initiations)}, expected at least {min_cycles}"
            )
        if len(initiator_cutovers) < min_cycles:
            session_errors.append(
                f"initiator cutovers={len(initiator_cutovers)}, "
                f"expected at least {min_cycles}"
            )
        if len(target_cutovers) < min_cycles:
            session_errors.append(
                f"target cutovers={len(target_cutovers)}, expected at least {min_cycles}"
            )

        gap: float | None = None
        if len(initiations) >= 2 and initiator_cutovers:
            gap = (
                initiations[1] - initiator_cutovers[0].timestamp
            ).total_seconds()
            if gap < drain_seconds:
                session_errors.append(
                    f"second initiation gap={gap:.3f}s, "
                    f"expected at least {drain_seconds:.3f}s after first cutover"
                )
        if len(initiations) >= 2 and len(initiator_cutovers) >= 2:
            if not (
                initiations[0]
                <= initiator_cutovers[0].timestamp
                <= initiations[1]
                <= initiator_cutovers[1].timestamp
            ):
                session_errors.append(
                    "initiator events are not ordered "
                    "initiation/cutover/initiation/cutover"
                )

        initiator_k_bits = [
            cutover.k_bit
            for cutover in initiator_cutovers
            if cutover.k_bit is not None
        ]
        target_k_bits = [
            cutover.k_bit for cutover in target_cutovers if cutover.k_bit is not None
        ]
        if not alternating(initiator_k_bits, min_cycles):
            session_errors.append(
                f"initiator K bits do not alternate for {min_cycles} cycles: "
                f"{initiator_k_bits[:min_cycles]}"
            )
        if not alternating(target_k_bits, min_cycles):
            session_errors.append(
                f"target K bits do not alternate for {min_cycles} cycles: "
                f"{target_k_bits[:min_cycles]}"
            )

        all_errors.extend(f"{target}: {error}" for error in session_errors)
        results.append(
            SessionEvidence(
                target=target,
                target_display=target_display,
                initiations=len(initiations),
                initiator_cutovers=len(initiator_cutovers),
                target_cutovers=len(target_cutovers),
                second_initiation_after_cutover_seconds=gap,
                initiator_k_bits=initiator_k_bits,
                target_k_bits=target_k_bits,
                errors=session_errors,
            )
        )

    return results, all_errors


def write_tsv(path: Path, results: list[SessionEvidence]) -> None:
    lines = [
        "target\ttarget_display\tinitiations\tinitiator_cutovers\t"
        "target_cutovers\tsecond_initiation_after_cutover_seconds\t"
        "initiator_k_bits\ttarget_k_bits\tpassed\terrors"
    ]
    for result in results:
        lines.append(
            "\t".join(
                [
                    result.target,
                    result.target_display,
                    str(result.initiations),
                    str(result.initiator_cutovers),
                    str(result.target_cutovers),
                    (
                        ""
                        if result.second_initiation_after_cutover_seconds is None
                        else f"{result.second_initiation_after_cutover_seconds:.3f}"
                    ),
                    ",".join(str(bit).lower() for bit in result.initiator_k_bits),
                    ",".join(str(bit).lower() for bit in result.target_k_bits),
                    str(result.passed).lower(),
                    "; ".join(result.errors),
                ]
            )
        )
    path.write_text("\n".join(lines) + "\n")


def parse_target(value: str) -> tuple[str, str]:
    if "=" not in value:
        raise argparse.ArgumentTypeError("target must be NODE=NPUB")
    node, npub = value.split("=", 1)
    if not node:
        raise argparse.ArgumentTypeError("target node must not be empty")
    try:
        short_npub(npub)
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from error
    return node, npub


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("log_dir", type=Path)
    parser.add_argument("--initiator-node", required=True)
    parser.add_argument("--initiator-npub", required=True)
    parser.add_argument("--target", action="append", type=parse_target, required=True)
    parser.add_argument("--min-cycles", type=int, default=2)
    parser.add_argument("--drain-seconds", type=float, default=45.0)
    parser.add_argument("--json", dest="json_path", type=Path, required=True)
    parser.add_argument("--tsv", dest="tsv_path", type=Path, required=True)
    args = parser.parse_args()

    targets = dict(args.target)
    results, errors = analyze(
        args.log_dir,
        initiator_node=args.initiator_node,
        initiator_npub=args.initiator_npub,
        targets=targets,
        min_cycles=args.min_cycles,
        drain_seconds=args.drain_seconds,
    )
    payload = {
        "passed": not errors,
        "initiator_node": args.initiator_node,
        "min_cycles": args.min_cycles,
        "drain_seconds": args.drain_seconds,
        "errors": errors,
        "sessions": [asdict(result) | {"passed": result.passed} for result in results],
    }
    args.json_path.parent.mkdir(parents=True, exist_ok=True)
    args.json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    write_tsv(args.tsv_path, results)

    print(
        "FSP epoch evidence: "
        f"{sum(result.passed for result in results)}/{len(results)} sessions passed"
    )
    for result in results:
        gap = result.second_initiation_after_cutover_seconds
        gap_text = "unknown" if gap is None else f"{gap:.3f}s"
        print(
            f"  {args.initiator_node}↔{result.target}: "
            f"initiations={result.initiations}, "
            f"cutovers={result.initiator_cutovers}/{result.target_cutovers}, "
            f"second-gap={gap_text}, "
            f"K={result.initiator_k_bits}/{result.target_k_bits}"
        )
    for error in errors:
        print(f"  {error}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
