"""Verify the immutable production packages before registry publication."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import time
import tomllib


def output(*args):
    return subprocess.check_output(args, text=True).strip()


def sha(data):
    return hashlib.sha256(data).hexdigest()


source = output("git", "rev-parse", "HEAD")
assert source == os.environ["PRODUCTION_SOURCE_SHA"]
assert not output("git", "status", "--porcelain")
logs = Path("package-results")
logs.mkdir()
workflow = os.environ["GITHUB_SHA"]
lock_before = Path("Cargo.lock").read_bytes()
result = {
    "source_sha": source,
    "source_tree": output("git", "rev-parse", "HEAD^{tree}"),
    "workflow_sha": workflow,
    "workflow_file_sha256": sha(subprocess.check_output([
        "git", "show", workflow + ":.github/workflows/marked-carrier-diagnostic.yml"
    ])),
    "harness_sha256": sha(Path(__file__).read_bytes()),
    "cargo_lock_sha256": sha(lock_before),
    "rustc": output("rustc", "--version", "--verbose"),
    "cargo": output("cargo", "--version"),
    "run_id": os.environ["GITHUB_RUN_ID"],
    "policy": {key: os.environ[key] for key in [
        "RUSTUP_TOOLCHAIN", "CARGO_BUILD_JOBS", "CARGO_INCREMENTAL",
        "CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG"
    ]},
    "commands": [], "packages": [], "success": False,
}
assert result["rustc"].startswith("rustc 1.95.0 ")
started = time.monotonic()


def inspect_archive(name, folder):
    archive = Path(os.environ["CARGO_TARGET_DIR"]) / "package" / (name + "-0.4.109.crate")
    raw = archive.read_bytes()
    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers()
        prefix = name + "-0.4.109/"
        assert all(m.isfile() and m.name.startswith(prefix) for m in members)
        entries = {m.name[len(prefix):]: tar.extractfile(m).read() for m in members}
    assert len(entries) == len(members)
    vcs = json.loads(entries[".cargo_vcs_info.json"])
    assert vcs["git"]["sha1"] == source and not vcs["git"].get("dirty", False)
    assert vcs["path_in_vcs"] == folder
    assert entries["Cargo.toml.orig"] == Path(folder, "Cargo.toml").read_bytes()
    manifest = tomllib.loads(entries["Cargo.toml"].decode())
    assert manifest["package"]["name"] == name
    assert manifest["package"]["version"] == "0.4.109"
    if name == "nvpn-fips-core":
        assert manifest["features"]["default"] == []
    else:
        assert manifest["dependencies"]["nvpn-fips-core"]["version"] == "=0.4.109"
    tracked = set(output("git", "ls-tree", "-r", "--name-only", source, "--", folder).splitlines())
    files = []
    generated = {"Cargo.toml", "Cargo.lock", ".cargo_vcs_info.json"}
    for relative, contents in entries.items():
        if relative in generated:
            continue
        original = "Cargo.toml" if relative == "Cargo.toml.orig" else relative
        path = folder + "/" + original
        assert path in tracked, path
        assert contents == subprocess.check_output(["git", "show", source + ":" + path]), path
        files.append({"path": original, "sha256": sha(contents), "bytes": len(contents)})
    missing_rust = [p for p in tracked if p.endswith(".rs") and p[len(folder) + 1:] not in entries]
    assert not missing_rust, missing_rust
    package_lock = tomllib.loads(entries["Cargo.lock"].decode())
    shutil.copyfile(archive, logs / archive.name)
    row = {
        "name": name, "version": "0.4.109", "archive": archive.name,
        "archive_bytes": len(raw), "archive_sha256": sha(raw), "vcs": vcs,
        "original_manifest_sha256": sha(entries["Cargo.toml.orig"]),
        "normalized_manifest_sha256": sha(entries["Cargo.toml"]),
        "package_lock_sha256": sha(entries["Cargo.lock"]),
        "tracked_files": sorted(files, key=lambda f: f["path"]),
        "packaged_file_count": len(entries), "package_lock_entries": len(package_lock["package"]),
    }
    result["packages"].append(row)
    print(json.dumps({k: v for k, v in row.items() if k != "tracked_files"}), flush=True)


try:
    command = ["cargo", "package", "--locked", "--registry", "crates-io",
               "-p", "nvpn-fips-core", "-p", "nvpn-fips-endpoint"]
    log = logs / "package-default-verification.log"
    step_start = time.monotonic()
    with log.open("w") as sink:
        completed = subprocess.run(command, stdout=sink, stderr=subprocess.STDOUT)
    raw = log.read_bytes()
    result["commands"].append({
        "name": "package-default-verification", "command": command,
        "exit_code": completed.returncode, "seconds": time.monotonic() - step_start,
        "log": log.name, "log_bytes": len(raw), "log_sha256": sha(raw),
    })
    lines = raw.decode(errors="replace").splitlines()
    print("Last %d of %d lines; complete log retained." % (min(35, len(lines)), len(lines)))
    print("\n".join(lines[-35:]), flush=True)
    assert completed.returncode == 0
    for name, folder in [("nvpn-fips-core", "crates/fips-core"),
                         ("nvpn-fips-endpoint", "crates/fips-endpoint")]:
        assert "Verifying " + name + " v0.4.109" in raw.decode()
        inspect_archive(name, folder)
    result["success"] = True
finally:
    result["seconds"] = time.monotonic() - started
    result["tracked_diff_after"] = output("git", "diff", "--name-only", "HEAD")
    result["lock_unchanged"] = Path("Cargo.lock").read_bytes() == lock_before
    result["success"] = result["success"] and not result["tracked_diff_after"] and result["lock_unchanged"]
    (logs / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"success": result["success"], "seconds": result["seconds"]}), flush=True)

assert result["success"]
