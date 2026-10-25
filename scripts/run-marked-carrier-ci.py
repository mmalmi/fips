"""Temporary, bounded CI qualification for the marked-carrier diagnostic."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time


def output(*args):
    return subprocess.check_output(args, text=True).strip()


def digest(data):
    return hashlib.sha256(data).hexdigest()


source = output("git", "rev-parse", "HEAD")
assert source == os.environ["DIAGNOSTIC_SOURCE_SHA"]
assert not output("git", "status", "--porcelain")
workflow = os.environ["GITHUB_SHA"]
result = {
    "source_sha": source,
    "source_tree": output("git", "rev-parse", "HEAD^{tree}"),
    "workflow_sha": workflow,
    "workflow_file_sha256": digest(subprocess.check_output([
        "git", "show", workflow + ":.github/workflows/marked-carrier-diagnostic.yml"
    ])),
    "harness_sha256": digest(Path(__file__).read_bytes()),
    "cargo_lock_sha256": digest(Path("Cargo.lock").read_bytes()),
    "rustc": output("rustc", "--version", "--verbose"),
    "cargo": output("cargo", "--version"),
    "run_id": os.environ["GITHUB_RUN_ID"],
    "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
    "policy": {name: os.environ[name] for name in [
        "RUSTUP_TOOLCHAIN", "CARGO_BUILD_JOBS", "CARGO_INCREMENTAL",
        "CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG"
    ]},
    "commands": [],
    "success": False,
}
disk = os.statvfs(".")
memory = dict(line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())
result["hosted_resources_before"] = {
    "available_disk_bytes": disk.f_bavail * disk.f_frsize,
    "memory_total": memory["MemTotal"].strip(),
    "memory_available": memory["MemAvailable"].strip(),
}
print(json.dumps(result["hosted_resources_before"]), flush=True)
assert result["rustc"].startswith("rustc 1.95.0 ")
logs = Path("diagnostic-results")
logs.mkdir()
started = time.monotonic()
base = ["cargo", "test", "--locked", "-p", "nvpn-fips-core", "--lib", "--features", "sim-transport"]
groups = [
    ("recorder", "marked_carrier_diagnostic::tests::", [], 7, 1),
    ("isolated-websocket", "marked_carrier_diagnostic::tests::marked_upgrade_covers_reconnect_queue_cancellation_and_delayed_handler",
     ["--ignored", "--exact"], 1, 0),
    ("write-lifetime", "transport::websocket::tests::write_lifetime::", [], 5, 0),
    ("url-only-seed", "node::tests::websocket::url_only_seed_hint_completes_noise_ik_and_datagram_exchange",
     ["--exact"], 1, 0),
]


def run(name, command, expected=None, ignored=None):
    path = logs / (name + ".log")
    start = time.monotonic()
    with path.open("w") as log:
        completed = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
    raw = path.read_bytes()
    text = raw.decode(errors="replace")
    matches = re.findall(r"test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;", text)
    counts = dict(zip(("passed", "failed", "ignored"), map(int, matches[-1]))) if matches else None
    success = completed.returncode == 0
    if expected is not None:
        success = success and counts == {"passed": expected, "failed": 0, "ignored": ignored}
    row = {"name": name, "command": command, "exit_code": completed.returncode,
           "seconds": time.monotonic() - start, "counts": counts,
           "expected_passed": expected, "expected_ignored": ignored,
           "success": success, "log": path.name, "log_bytes": len(raw), "log_sha256": digest(raw)}
    result["commands"].append(row)
    print(json.dumps(row), flush=True)
    lines = text.splitlines()
    print(f"Last {min(30, len(lines))} of {len(lines)} log lines; full log in artifact.", flush=True)
    print("\n".join(lines[-30:]), flush=True)
    return success


try:
    compiled = run("compile", base + ["--no-run"])
    if compiled:
        for name, test_filter, flags, expected, ignored in groups:
            run(name, base + [test_filter, "--", "--test-threads=1"] + flags, expected, ignored)
    result["success"] = len(result["commands"]) == 5 and all(row["success"] for row in result["commands"])
finally:
    result["seconds"] = time.monotonic() - started
    result["tracked_diff_after"] = output("git", "diff", "--name-only", "HEAD")
    if result["tracked_diff_after"]:
        result["success"] = False
    (logs / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"success": result["success"], "seconds": result["seconds"]}), flush=True)

sys.exit(0 if result["success"] else 1)
