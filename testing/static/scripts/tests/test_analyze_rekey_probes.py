#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "analyze_rekey_probes.py"
SPEC = importlib.util.spec_from_file_location("analyze_rekey_probes", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def ping_log(*sequences: int, transmitted: int | None = None) -> str:
    transmitted = transmitted if transmitted is not None else len(sequences)
    lines = [
        f"[1770000000.{sequence:03d}] 64 bytes from fd00::1: icmp_seq={sequence} ttl=64 time=1.0 ms"
        for sequence in sequences
    ]
    lines.extend(
        [
            "",
            "--- target.fips ping statistics ---",
            f"{transmitted} packets transmitted, {len(sequences)} received, 0% packet loss",
        ]
    )
    return "\n".join(lines) + "\n"


class AnalyzeRekeyProbesTests(unittest.TestCase):
    def test_accepts_complete_sequenced_streams(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            probe_dir = Path(tmp)
            (probe_dir / "a-to-b.log").write_text(ping_log(1, 2, 3))
            (probe_dir / "b-to-a.log").write_text(ping_log(1, 2, 3))

            results, errors = MODULE.analyze(probe_dir, expected_streams=2, min_replies=3)

            self.assertEqual(errors, [])
            self.assertTrue(all(result.passed for result in results))

    def test_rejects_a_sequence_gap_even_when_summary_claims_no_loss(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            probe_dir = Path(tmp)
            log = ping_log(1, 3, transmitted=3).replace(
                "[1770000000.003]",
                "[1770000000.002] no answer yet for icmp_seq=2\n[1770000000.003]",
            )
            (probe_dir / "a-to-b.log").write_text(log)

            results, errors = MODULE.analyze(probe_dir, expected_streams=1, min_replies=1)

            self.assertEqual(results[0].missing_sequences, [2])
            self.assertTrue(errors)

    def test_rejects_truncated_log_without_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            probe_dir = Path(tmp)
            (probe_dir / "a-to-b.log").write_text(
                "[1770000000.001] 64 bytes from fd00::1: icmp_seq=1 ttl=64 time=1.0 ms\n"
            )

            results, errors = MODULE.analyze(probe_dir, expected_streams=1, min_replies=1)

            self.assertEqual(results[0].error, "missing ping summary")
            self.assertTrue(errors)


if __name__ == "__main__":
    unittest.main()
