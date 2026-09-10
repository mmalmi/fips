#!/usr/bin/env python3
"""Exercise the production config-injection command without starting nodes."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


STATIC = Path(__file__).resolve().parents[2]


class RekeyConfigTests(unittest.TestCase):
    def inject(self, scenario):
        with tempfile.TemporaryDirectory() as tmp:
            static = Path(tmp) / "static"
            scripts = static / "scripts"
            scripts.mkdir(parents=True)
            script = scripts / "rekey-test.sh"
            shutil.copyfile(STATIC / "scripts/rekey-test.sh", script)
            lib = static.parent / "lib"
            lib.mkdir()
            shutil.copyfile(STATIC.parent / "lib/wait-converge.sh", lib / "wait-converge.sh")
            configs = static / "generated-configs/rekey-outbound-only"
            configs.mkdir(parents=True)
            template = (STATIC / "configs/node.template.yaml").read_text()
            for node in "abcde":
                (configs / f"node-{node}.yaml").write_text(template.replace(
                    "{{PEERS}}", "  - addresses:\n      - addr: 172.20.0.12:2121"
                ))
            result = subprocess.run(
                ["bash", str(script), "inject-config"],
                env=dict(os.environ, REKEY_SCENARIO=scenario,
                         REKEY_TOPOLOGY="rekey-outbound-only",
                         REKEY_ACCEPT_OFF_NODES="", REKEY_OUTBOUND_ONLY_NODES="b"),
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return {node: (configs / f"node-{node}.yaml").read_text() for node in "abcde"}

    def test_overlap_isolates_periodic_tree_changes_and_preserves_rekey(self):
        configs = self.inject("staggered-overlap")
        for node, config in configs.items():
            with self.subTest(node=node):
                self.assertIn("node:\n  tree:\n    reeval_interval_secs: 0\n  rekey:\n", config)
                self.assertEqual(config.count("  tree:\n"), 1)
                self.assertIn("    enabled: true\n    after_secs: 300\n", config)
                self.assertIn(f"    after_messages: {512 if node == 'b' else 65536}\n", config)
        self.assertIn("    outbound_only: true\n", configs["b"])
        self.assertIn("addr: node-c:2121", configs["b"])
        self.assertIn("addr: 172.20.0.12:2121", configs["a"])

    def test_standard_rekey_keeps_default_tree_maintenance(self):
        configs = self.inject("standard")
        for config in configs.values():
            self.assertNotIn("  tree:\n", config)
            self.assertIn("    after_secs: 75\n    after_messages: 65536\n", config)


if __name__ == "__main__":
    unittest.main()
