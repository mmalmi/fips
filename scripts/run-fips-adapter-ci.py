"""Qualify dependency-only adapter releases against their published source."""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import time
import tomllib
import urllib.request

control = Path.cwd()
repo = control / "adapter"
os.chdir(repo / os.environ["ADAPTER_WORKSPACE"])
name = os.environ["ADAPTER_PACKAGE"]
version = os.environ["ADAPTER_VERSION"]
folder = os.environ["ADAPTER_PACKAGE_PATH"]
logs = control / "adapter-results"
logs.mkdir()

def sha(data):
    return hashlib.sha256(data).hexdigest()

def git(*args):
    return subprocess.check_output(["git", *args], cwd=repo, text=True).strip()

source = git("rev-parse", "HEAD")
assert source == os.environ["ADAPTER_SOURCE_SHA"]
assert not git("status", "--porcelain")
changed = git("diff", "--name-only", os.environ["ADAPTER_BASE_SHA"], source).splitlines()
allowed = (["rust/Cargo.lock", "rust/fips-tcp-endpoint/Cargo.toml"]
           if name == "nvpn-fips-tcp-endpoint" else
           ["Cargo.toml", "crates/nostr-pubsub-fips/Cargo.toml"])
assert sorted(changed) == sorted(allowed)
lock_before = Path("Cargo.lock").read_bytes()
if os.environ.get("ADAPTER_EXPECTED_LOCK_SHA256"):
    assert sha(lock_before) == os.environ["ADAPTER_EXPECTED_LOCK_SHA256"]
result = {"source_sha": source, "source_tree": git("rev-parse", "HEAD^{tree}"),
          "base_sha": os.environ["ADAPTER_BASE_SHA"], "source_changed_files": changed,
          "workflow_sha": os.environ["GITHUB_SHA"], "run_id": os.environ["GITHUB_RUN_ID"],
          "harness_sha256": sha(Path(__file__).read_bytes()),
          "workflow_file_sha256": sha((control / ".github/workflows/marked-carrier-diagnostic.yml").read_bytes()),
          "cargo_lock_sha256": sha(lock_before),
          "rustc": subprocess.check_output(["rustc", "--version"], text=True).strip(),
          "cargo": subprocess.check_output(["cargo", "--version"], text=True).strip(),
          "commands": [], "packages": [], "success": False}
assert result["rustc"].startswith("rustc 1.95.0 ")
started = time.monotonic()

def run(label, command, expected=None):
    path = logs / (label + ".log")
    begin = time.monotonic()
    with path.open("w") as sink:
        completed = subprocess.run(command, stdout=sink, stderr=subprocess.STDOUT)
    raw = path.read_bytes()
    counts = [tuple(map(int, m)) for m in re.findall(
        r"test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;", raw.decode())]
    row = {"name": label, "command": command, "exit_code": completed.returncode,
           "seconds": time.monotonic() - begin, "counts": counts,
           "log": path.name, "log_bytes": len(raw), "log_sha256": sha(raw)}
    result["commands"].append(row)
    print(json.dumps(row), flush=True)
    lines = raw.decode(errors="replace").splitlines()
    print("Last %d of %d lines; full log retained." % (min(30, len(lines)), len(lines)))
    print("\n".join(lines[-30:]), flush=True)
    assert completed.returncode == 0
    if expected is not None:
        assert sum(c[0] for c in counts) == expected
        assert all(c[1:] == (0, 0) for c in counts)
    return raw

def entries(raw):
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
        return {m.name.split("/", 1)[1]: tar.extractfile(m).read()
                for m in tar.getmembers() if m.isfile()}

try:
    tests = ["cargo", "test", "--locked", "-p", name]
    if name == "nostr-pubsub-fips":
        tests.append("--lib")
    tests += ["--", "--test-threads=1"]
    run("adapter-tests", tests, int(os.environ["ADAPTER_EXPECTED_TESTS"]))
    raw_log = run("package-default-verification", ["cargo", "package", "--locked",
                  "--registry", "crates-io", "-p", name])
    assert ("Verifying " + name + " v" + version).encode() in raw_log
    archive = Path(os.environ["CARGO_TARGET_DIR"]) / "package" / (name + "-" + version + ".crate")
    raw = archive.read_bytes()
    files = entries(raw)
    baseline_url = "https://static.crates.io/crates/" + name + "/" + name + "-" + os.environ["ADAPTER_BASE_VERSION"] + ".crate"
    baseline = urllib.request.urlopen(baseline_url, timeout=30).read()
    assert sha(baseline) == os.environ["ADAPTER_BASE_CHECKSUM"]
    old = entries(baseline)
    assert set(files) == set(old)
    generated = {"Cargo.toml", "Cargo.toml.orig", "Cargo.lock", ".cargo_vcs_info.json"}
    assert all(files[p] == old[p] for p in files if p not in generated)
    vcs = json.loads(files[".cargo_vcs_info.json"])
    assert vcs["git"]["sha1"] == source and not vcs["git"].get("dirty", False)
    assert vcs["path_in_vcs"] == folder
    manifest = tomllib.loads(files["Cargo.toml"].decode())
    assert manifest["package"]["version"] == version
    assert manifest["dependencies"]["nvpn-fips-core"]["version"] == "=0.4.109"
    if name == "nostr-pubsub-fips":
        assert manifest["dependencies"]["nvpn-fips-tcp-endpoint"]["version"] == "=0.2.44"
        assert manifest["dev-dependencies"]["nvpn-fips-core"]["version"] == "=0.4.109"
    tracked = []
    for relative, content in files.items():
        if relative in generated - {"Cargo.toml.orig"}:
            continue
        original = "Cargo.toml" if relative == "Cargo.toml.orig" else relative
        expected = subprocess.check_output(["git", "show", source + ":" + folder + "/" + original], cwd=repo)
        assert content == expected, original
        tracked.append({"path": original, "sha256": sha(content), "bytes": len(content)})
    shutil.copyfile(archive, logs / archive.name)
    result["packages"].append({
        "name": name, "version": version, "archive": archive.name,
        "archive_bytes": len(raw), "archive_sha256": sha(raw), "vcs": vcs,
        "original_manifest_sha256": sha(files["Cargo.toml.orig"]),
        "normalized_manifest_sha256": sha(files["Cargo.toml"]),
        "package_lock_sha256": sha(files["Cargo.lock"]) if "Cargo.lock" in files else None,
        "packaged_file_count": len(files), "tracked_files": tracked,
        "baseline_archive_sha256": sha(baseline), "runtime_files_identical_to_published": True,
    })
    result["success"] = True
finally:
    result["seconds"] = time.monotonic() - started
    result["tracked_diff_after"] = git("diff", "--name-only", "HEAD")
    result["lock_unchanged"] = Path("Cargo.lock").read_bytes() == lock_before
    result["success"] = result["success"] and not result["tracked_diff_after"] and result["lock_unchanged"]
    (logs / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"success": result["success"], "seconds": result["seconds"]}), flush=True)
assert result["success"]
