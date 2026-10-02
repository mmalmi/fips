"""Exercise the startup wrapper with isolated OpenWrt command and clock doubles."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
WRAPPER = Path(os.environ.get(
    "FIPS_RELAY_TEST_STARTUP_WRAPPER",
    ROOT / "crates/fips-relay/openwrt/fips-relay-openwrt",
))

# Redirect only the boot-clock marker; all other file checks remain real.
HARNESS = """
function [ {
    if [[ $# == 3 && $1 == -f && $2 == /var/run/fips-relay.time-valid ]]; then
        builtin test "$TEST_CLOCK_READY" = 1
    else
        builtin [ "$@"
    fi
}
source "$1" "$2" "$3"
"""


class StartupTests(unittest.TestCase):
    def run_wrapper(self, clock_ready):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "state"
            state.mkdir()
            for name in ("service.json", "identity.key"):
                (state / name).write_text("fixture")
            config = root / "config.json"
            config.write_text("{}")
            commands = {
                "jsonfilter": """case "$4" in
                    '@.state_directory') printf '%s\\n' "$TEST_STATE" ;;
                    '@.terms.controller.mint_url') echo 'http://127.0.0.1:1' ;;
                esac""",
                "df": "printf 'Filesystem Type\\nfixture ext4\\n'",
                "uclient-fetch": 'echo called > "$TEST_PROBE"; exit 1',
                "sleep": "exit 12",
                "relay": 'printf "%s\\n" "$@" > "$TEST_EXEC"',
            }
            for name, body in commands.items():
                path = root / name
                path.write_text("#!/bin/sh\n" + body + "\n")
                path.chmod(0o755)
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"],
                       TEST_STATE=str(state), TEST_CLOCK_READY=str(int(clock_ready)),
                       TEST_PROBE=str(root / "probe"), TEST_EXEC=str(root / "executed"))
            result = subprocess.run(
                ["bash", "-c", HARNESS, "startup-test", str(WRAPPER),
                 str(root / "relay"), str(config)],
                env=env, capture_output=True, text=True, timeout=5,
            )
            executed = root / "executed"
            arguments = executed.read_text().splitlines() if executed.exists() else []
            return result, arguments, (root / "probe").exists(), str(config)

    def test_saved_account_starts_without_a_reachable_mint(self):
        result, arguments, probed, config = self.run_wrapper(clock_ready=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(arguments, ["run", config])
        self.assertFalse(probed, "mint-dependent operations belong to the relay")

    def test_unsynchronized_clock_still_blocks_startup(self):
        result, arguments, probed, _ = self.run_wrapper(clock_ready=False)
        self.assertEqual(result.returncode, 12)
        self.assertIn("waiting for clock synchronization", result.stderr)
        self.assertEqual(arguments, [])
        self.assertFalse(probed)


if __name__ == "__main__":
    unittest.main()
