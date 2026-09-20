#!/usr/bin/env python3
"""Export a locked Rust workspace and its local patches for offline relocation."""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tempfile


MANIFEST = "source-manifest.json"
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*\Z")
REVISION = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")


def clean_git_environment():
    return {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}


def cargo_environment(cargo_home=None):
    env = clean_git_environment()
    if cargo_home is not None:
        # Prove source closure without the caller's registry cache, Cargo patches,
        # compiler wrappers or incremental artifacts. Rust/toolchain tools remain external.
        env = {key: value for key, value in env.items()
               if not key.startswith("CARGO_") and key not in {
                   "RUSTFLAGS", "RUSTDOCFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
               }}
        env["CARGO_HOME"] = str(cargo_home)
        env["CARGO_TARGET_DIR"] = str(cargo_home / "target")
        # Cargo also loads configuration from checkout ancestors, independently
        # of CARGO_HOME. Empty overrides disable wrappers from those files too.
        env["RUSTC_WRAPPER"] = ""
        env["RUSTC_WORKSPACE_WRAPPER"] = ""
    return env


def command(args, cwd, env=None):
    result = subprocess.run(args, cwd=cwd, env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, check=False)
    if result.returncode:
        raise ValueError(f"{args[0]} failed: {result.stderr.decode(errors='replace').strip()}")
    return result.stdout


def git(root, *args):
    return command(["git", *args], root, clean_git_environment())


def safe_path(value, allow_dot=False):
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ValueError("invalid relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or (not path.parts and not allow_dot):
        raise ValueError(f"invalid relative path: {value}")
    return path


def contained(path, root):
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (ValueError, RuntimeError):
        return False


def check_source(source):
    root = Path(source["path"]).resolve()
    revision = source["revision"]
    if not isinstance(revision, str) or not REVISION.fullmatch(revision):
        raise ValueError("source revision must be a full lowercase Git object ID")
    top = Path(git(root, "rev-parse", "--show-toplevel").decode().strip()).resolve()
    if top != root:
        raise ValueError("source path must be the Git workspace root")
    if git(root, "rev-parse", "HEAD").decode().strip() != revision:
        raise ValueError("source revision does not match HEAD")
    if git(root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise ValueError("source must be clean, including nonignored untracked files")
    return root


def validate_spec(spec):
    if spec.get("schema") != 1:
        raise ValueError("unsupported source specification schema")
    names, packages = set(), set()
    for dep in spec["dependencies"]:
        name = dep["name"]
        if not isinstance(name, str) or not NAME.fullmatch(name) or name in names:
            raise ValueError("invalid or duplicate dependency name")
        names.add(name)
        if not dep["packages"]:
            raise ValueError("each dependency must supply at least one package")
        for package, path in dep["packages"].items():
            if not NAME.fullmatch(package) or package in packages:
                raise ValueError("invalid or duplicate package name")
            packages.add(package)
            safe_path(path, allow_dot=True)
    sources = [spec["workspace"], *spec["dependencies"]]
    roots = [check_source(source) for source in sources]
    lock = Path(spec["lockfile"]).read_bytes()
    if hashlib.sha256(lock).hexdigest() != spec["lockfile_sha256"]:
        raise ValueError("tested lockfile digest does not match")
    return sources, roots, lock


def export_source(root, revision, output):
    """Read the committed tree, including export-ignore files, without Git history."""
    output.mkdir(parents=True)
    entries = git(root, "ls-tree", "-rz", "--full-tree", revision).split(b"\0")
    links = []
    with subprocess.Popen(["git", "cat-file", "--batch"], cwd=root,
                          env=clean_git_environment(), stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE) as blobs:
        for entry in filter(None, entries):
            header, name = entry.split(b"\t", 1)
            mode, kind, oid = header.split()
            if kind != b"blob" or mode not in (b"100644", b"100755", b"120000"):
                raise ValueError("submodules and special Git file modes are unsupported")
            path = output / safe_path(name.decode())
            blobs.stdin.write(oid + b"\n")
            blobs.stdin.flush()
            actual_oid, actual_kind, length = blobs.stdout.readline().split()
            if actual_oid != oid or actual_kind != b"blob":
                raise ValueError("invalid Git blob response")
            size = int(length)
            data = blobs.stdout.read(size)
            if len(data) != size or blobs.stdout.read(1) != b"\n":
                raise ValueError("incomplete Git blob")
            path.parent.mkdir(parents=True, exist_ok=True)
            if mode == b"120000":
                links.append((path, data.decode()))
            else:
                path.write_bytes(data)
                path.chmod(0o755 if mode == b"100755" else 0o644)
        blobs.stdin.close()
        if blobs.wait():
            raise ValueError("Git blob export failed")
    for path, target in links:
        if os.path.isabs(target):
            raise ValueError("absolute source symlink is not portable")
        path.symlink_to(target)
    for path, _ in links:
        if not contained(path, output):
            raise ValueError("source symlink leaves its source root")


def inventory(root):
    files = {}
    for directory, dirs, names in os.walk(root, followlinks=False):
        directory = Path(directory)
        for name in sorted(dirs + names):
            path = directory / name
            relative = path.relative_to(root).as_posix()
            if relative == "checkout/target" and name in dirs and not path.is_symlink():
                dirs.remove(name)
                continue
            if relative == MANIFEST:
                continue
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode):
                if name in dirs:
                    dirs.remove(name)
                if os.path.isabs(os.readlink(path)) or not contained(path, root):
                    raise ValueError("bundle symlink is not contained")
                files[relative] = {"symlink": os.readlink(path)}
            elif stat.S_ISREG(mode):
                digest = hashlib.sha256()
                with path.open("rb") as source:
                    for chunk in iter(lambda: source.read(1024 * 1024), b""):
                        digest.update(chunk)
                files[relative] = {"sha256": digest.hexdigest(), "executable": bool(mode & 0o111)}
            elif not stat.S_ISDIR(mode):
                raise ValueError("special files are unsupported in a source bundle")
    return dict(sorted(files.items()))


def resolve_bundle(root, toolchain):
    with tempfile.TemporaryDirectory(prefix="fips-bundle-cargo-") as home:
        output = command(["cargo", f"+{toolchain}", "metadata", "--offline", "--locked",
                          "--all-features", "--format-version", "1"], root / "checkout",
                         cargo_environment(Path(home)))
    metadata = json.loads(output)
    if Path(metadata["workspace_root"]).resolve() != (root / "checkout").resolve():
        raise ValueError("resolved workspace is outside the bundle checkout")
    for package in metadata["packages"]:
        if not Path(package["manifest_path"]).is_file():
            raise ValueError(f"resolved package manifest is missing: {package['name']}")
        paths = [package["manifest_path"], *(target["src_path"] for target in package["targets"])]
        for value in paths:
            path = Path(value)
            if not contained(path, root) or contained(path, root / "checkout/target"):
                raise ValueError(f"resolved package source outside bundle inventory: {package['name']}")
        source = package["source"]
        if source is not None and source != "registry+https://github.com/rust-lang/crates.io-index":
            raise ValueError("only vendored crates.io and local packages are supported")
    return {
        "resolved_packages": len(metadata["packages"]),
        "registry_packages": sum(package["source"] is not None for package in metadata["packages"]),
    }


def verify(root, resolve=False):
    root = root.resolve()
    manifest = json.loads((root / MANIFEST).read_text())
    if manifest.get("schema") != 1:
        raise ValueError("unsupported bundle manifest schema")
    actual = inventory(root)
    expected = manifest["files"]
    changed = sorted(path for path in actual.keys() | expected.keys()
                     if actual.get(path) != expected.get(path))
    if changed:
        raise ValueError("source integrity mismatch: " + ", ".join(changed[:10]))
    if resolve:
        resolved = resolve_bundle(root, manifest["toolchain"])
        if any(manifest[key] != value for key, value in resolved.items()):
            raise ValueError("resolved package counts differ from manifest")
    return manifest


def cargo_config(spec):
    lines = ["# Paths resolve from checkout/, the parent of .cargo/.",
             "# Do not inherit revision metadata from an enclosing Git repository.",
             "[env]", 'GIT_CEILING_DIRECTORIES = { value = "..", relative = true, force = true }',
             "", "[patch.crates-io]"]
    for dep in spec["dependencies"]:
        for package, path in sorted(dep["packages"].items()):
            relative = str(PurePosixPath("../deps") / dep["name"] / path)
            lines.append(f"{json.dumps(package)} = {{ path = {json.dumps(relative)} }}")
    return "\n".join(lines) + "\n"


def create(spec, destination, toolchain, offline=False):
    destination = destination.absolute()
    if destination.exists() or destination.is_symlink():
        raise ValueError("output already exists; choose a new destination")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", toolchain):
        raise ValueError("use an exact stable Rust toolchain version")
    sources, roots, lock = validate_spec(spec)
    if any(contained(destination, source_root) for source_root in roots):
        raise ValueError("output path must be outside the source repositories")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".fips-bundle-", dir=destination.parent) as temp:
        root = Path(temp).resolve() / "bundle"
        checkout = root / "checkout"
        export_source(roots[0], sources[0]["revision"], checkout)
        for source, source_root in zip(sources[1:], roots[1:]):
            export_source(source_root, source["revision"], root / "deps" / source["name"])
            for crate in source["packages"].values():
                if not (root / "deps" / source["name"] / crate / "Cargo.toml").is_file():
                    raise ValueError("patch path must contain a crate manifest")
        cargo_dir = checkout / ".cargo"
        if cargo_dir.exists():
            raise ValueError("workspace .cargo configuration needs an explicit merge before export")
        cargo_dir.mkdir()
        config = cargo_dir / "config.toml"
        config.write_text(cargo_config(spec))
        (checkout / "Cargo.lock").write_bytes(lock)
        vendor = ["cargo", f"+{toolchain}", "vendor", "--locked", "--versioned-dirs"]
        if offline:
            vendor.append("--offline")
        output = command([*vendor, "../vendor"], checkout, cargo_environment()).decode()
        with config.open("a") as out:
            out.write("\n" + output)
        resolved = resolve_bundle(root, toolchain)
        if (checkout / "Cargo.lock").read_bytes() != lock:
            raise ValueError("Cargo changed the tested lockfile")
        for source in sources:
            check_source(source)
        manifest = {
            "schema": 1,
            "toolchain": toolchain,
            "workspace": {"path": "checkout", "revision": sources[0]["revision"]},
            "dependencies": [{"name": dep["name"], "path": "deps/" + dep["name"],
                              "revision": dep["revision"], "packages": dep["packages"]}
                             for dep in sources[1:]],
            "lockfile_sha256": spec["lockfile_sha256"],
            **resolved,
            "files": inventory(root),
        }
        (root / MANIFEST).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        if destination.exists() or destination.is_symlink():
            raise ValueError("output already exists; choose a new destination")
        root.rename(destination)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    export = commands.add_parser("create", help="export clean committed sources and vendor the lock")
    export.add_argument("spec", type=Path, help="private JSON source specification")
    export.add_argument("destination", type=Path)
    export.add_argument("--toolchain", required=True)
    export.add_argument("--offline", action="store_true", help="use only cached registry sources")
    check = commands.add_parser("verify", help="check source contents and optional offline closure")
    check.add_argument("bundle", type=Path)
    check.add_argument("--resolve", action="store_true", help="resolve offline with an empty Cargo home")
    args = parser.parse_args()
    try:
        if args.command == "create":
            manifest = create(json.loads(args.spec.read_text()), args.destination, args.toolchain, args.offline)
        else:
            manifest = verify(args.bundle, args.resolve)
    except (ValueError, KeyError, OSError) as error:
        parser.exit(1, f"source bundle: {error}\n")
    print(f"Verified {len(manifest['files'])} files, {manifest['resolved_packages']} packages "
          f"({manifest['registry_packages']} registry), Rust {manifest['toolchain']}")


if __name__ == "__main__":
    main()
