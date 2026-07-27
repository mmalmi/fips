#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "analyze_rekey_epochs.py"
SPEC = importlib.util.spec_from_file_location("analyze_rekey_epochs", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

NPUB_B = "npub1bbbb000000000000000000000000000000000000000000000000bbbb"
TARGETS = {
    "a": "npub1aaaa000000000000000000000000000000000000000000000000aaaa",
    "d": "npub1dddd000000000000000000000000000000000000000000000000dddd",
    "e": "npub1eeee000000000000000000000000000000000000000000000000eeee",
}


def log_line(second: int, message: str, **fields: object) -> str:
    rendered_fields = " ".join(
        f"{name}={str(value).lower() if isinstance(value, bool) else value}"
        for name, value in fields.items()
    )
    return (
        f"2026-07-27T08:17:{second:02d}.000000000Z "
        f"2026-07-27T08:17:{second:02d}.000000Z DEBUG test: "
        f"{message} {rendered_fields}\n"
    )


def short_npub(npub: str) -> str:
    return f"{npub[:9]}...{npub[-4:]}"


def write_valid_logs(log_dir: Path) -> None:
    initiator_lines: list[str] = []
    for offset, (target, npub) in enumerate(TARGETS.items()):
        peer = short_npub(npub)
        initiator_lines.extend(
            [
                log_line(
                    1 + offset,
                    "FSP rekey initiated, sent SessionSetup",
                    peer=peer,
                ),
                log_line(
                    3 + offset,
                    "FSP rekey cutover complete after dataplane authenticated pending epoch",
                    src=peer,
                    received_k_bit=True,
                ),
                log_line(
                    49 + offset,
                    "FSP rekey initiated, sent SessionSetup",
                    peer=peer,
                ),
                log_line(
                    51 + offset,
                    "FSP rekey cutover complete after dataplane authenticated pending epoch",
                    src=peer,
                    received_k_bit=False,
                ),
            ]
        )
        (log_dir / f"node-{target}.log").write_text(
            log_line(
                3 + offset,
                "FSP rekey cutover complete after dataplane authenticated pending epoch",
                src=short_npub(NPUB_B),
                received_k_bit=True,
            )
            + log_line(
                51 + offset,
                "FSP rekey cutover complete after dataplane authenticated pending epoch",
                src=short_npub(NPUB_B),
                received_k_bit=False,
            )
        )
    (log_dir / "node-b.log").write_text("".join(sorted(initiator_lines)))


class AnalyzeRekeyEpochsTests(unittest.TestCase):
    def analyze(self, log_dir: Path):
        return MODULE.analyze(
            log_dir,
            initiator_node="b",
            initiator_npub=NPUB_B,
            targets=TARGETS,
            min_cycles=2,
            drain_seconds=45.0,
        )

    def test_accepts_two_post_drain_alternating_cycles_per_session(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp)
            write_valid_logs(log_dir)

            results, errors = self.analyze(log_dir)

            self.assertEqual(errors, [])
            self.assertEqual({result.target for result in results}, set(TARGETS))
            self.assertTrue(all(result.passed for result in results))
            self.assertTrue(
                all(
                    result.second_initiation_after_cutover_seconds >= 45.0
                    for result in results
                )
            )

    def test_rejects_aggregate_cycles_that_miss_one_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp)
            write_valid_logs(log_dir)
            node_e = log_dir / "node-e.log"
            node_e.write_text(node_e.read_text().splitlines(keepends=True)[0])

            _, errors = self.analyze(log_dir)

            self.assertTrue(any("e: target cutovers=1" in error for error in errors))

    def test_rejects_second_initiation_before_drain_expiry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp)
            write_valid_logs(log_dir)
            node_b = log_dir / "node-b.log"
            node_b.write_text(
                node_b.read_text().replace(
                    "2026-07-27T08:17:49.000000000Z "
                    "2026-07-27T08:17:49.000000Z",
                    "2026-07-27T08:17:40.000000000Z "
                    "2026-07-27T08:17:40.000000Z",
                    1,
                )
            )

            _, errors = self.analyze(log_dir)

            self.assertTrue(
                any("a: second initiation gap=37.000s" in error for error in errors)
            )

    def test_rejects_non_alternating_k_bit_on_either_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp)
            write_valid_logs(log_dir)
            node_d = log_dir / "node-d.log"
            node_d.write_text(
                node_d.read_text().replace("received_k_bit=false", "received_k_bit=true")
            )

            _, errors = self.analyze(log_dir)

            self.assertTrue(
                any("d: target K bits do not alternate" in error for error in errors)
            )


if __name__ == "__main__":
    unittest.main()
