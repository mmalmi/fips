"""Exercise source export and relocation with real Git and Cargo, without a network."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[2] / "scripts/source_bundle.py"
SPEC = importlib.util.spec_from_file_location("source_bundle", SCRIPT)
bundle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bundle)


def run(args, cwd, env=None):
    return subprocess.check_output(args, cwd=cwd, env=env, stderr=subprocess.STDOUT).decode()


def commit(root):
    run(["git", "add", "."], root)
    run(["git", "commit", "-qm", "fixture"], root)
    return run(["git", "rev-parse", "HEAD"], root).strip()


def repo(root, files):
    root.mkdir()
    run(["git", "init", "-q"], root)
    run(["git", "config", "user.name", "Source bundle test"], root)
    run(["git", "config", "user.email", "test@example.invalid"], root)
    for name, value in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value)


class SourceBundleTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="fips-source-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.checkout = self.root / "original"
        self.dep = self.root / "dependency"
        repo(self.dep, {
            "Cargo.toml": '[package]\nname="bundle-fixture-dep"\nversion="0.1.0"\nedition="2021"\n',
            "src/lib.rs": "pub fn answer() -> u32 { 42 }\n",
        })
        dep_revision = commit(self.dep)
        repo(self.checkout, {
            "Cargo.toml": '[package]\nname="bundle-fixture"\nversion="0.1.0"\nedition="2021"\n'
                          '[dependencies]\nbundle-fixture-dep="=0.1.0"\n',
            "src/main.rs": 'fn main() { println!("{} {}", bundle_fixture_dep::answer(), env!("REV")); }\n',
            "build.rs": 'fn main() {\n'
                        'let output = std::process::Command::new("git")\n'
                        '.current_dir(env!("CARGO_MANIFEST_DIR"))\n'
                        '.args(["rev-parse", "--short", "HEAD"]).output().unwrap();\n'
                        'let rev = if output.status.success() { String::from_utf8(output.stdout).unwrap() }'
                        ' else { "no-git".into() };\n'
                        'println!("cargo:rustc-env=REV={}", rev.trim()); }\n',
            ".gitignore": "target/\nignored.txt\n",
            ".gitattributes": "needed.txt export-ignore\n",
            "needed.txt": "tracked even when git archive would omit it\n",
            "tool.sh": "#!/bin/sh\nexit 0\n",
        })
        (self.checkout / "tool.sh").chmod(0o755)
        (self.checkout / "needed-link").symlink_to("needed.txt")
        patch = self.root / "patch.toml"
        patch.write_text('[patch.crates-io]\nbundle-fixture-dep={path=' + json.dumps(str(self.dep)) + '}\n')
        run(["cargo", "+1.96.0", "generate-lockfile", "--offline", "--config", str(patch)], self.checkout)
        revision = commit(self.checkout)
        (self.checkout / "ignored.txt").write_text("must not export\n")
        lock = self.checkout / "Cargo.lock"
        self.spec = {
            "schema": 1,
            "workspace": {"path": str(self.checkout), "revision": revision},
            "dependencies": [{"name": "fixture", "path": str(self.dep), "revision": dep_revision,
                              "packages": {"bundle-fixture-dep": "."}}],
            "lockfile": str(lock),
            "lockfile_sha256": hashlib.sha256(lock.read_bytes()).hexdigest(),
        }
        self.output = self.root / "bundle"

    def create(self):
        bundle.create(self.spec, self.output, "1.96.0", offline=True)

    def test_relocated_bundle_builds_without_originals_or_parent_git_metadata(self):
        self.create()
        manifest = bundle.verify(self.output, resolve=True)
        self.assertEqual(manifest["resolved_packages"], 2)
        self.assertEqual(manifest["registry_packages"], 0)
        self.assertTrue((self.output / "checkout/needed.txt").is_file())
        self.assertTrue((self.output / "checkout/needed-link").is_symlink())
        self.assertTrue(os.access(self.output / "checkout/tool.sh", os.X_OK))
        self.assertFalse((self.output / "checkout/ignored.txt").exists())
        self.assertFalse((self.output / "checkout/.git").exists())
        self.assertNotIn(str(self.root), (self.output / "source-manifest.json").read_text())
        self.assertNotIn(str(self.root), (self.output / "checkout/.cargo/config.toml").read_text())
        parent = self.root / "unrelated"
        repo(parent, {
            "README": "unrelated parent repository\n",
            ".cargo/config.toml": '[build]\nrustc-wrapper="/must-not-use-parent-wrapper"\n'
                                  'rustc-workspace-wrapper="/must-not-use-parent-workspace-wrapper"\n',
        })
        commit(parent)
        moved = parent / "moved bundle"
        self.output.rename(moved)
        shutil.rmtree(self.checkout)
        shutil.rmtree(self.dep)
        bundle.verify(moved, resolve=True)
        with tempfile.TemporaryDirectory(dir=self.root) as cargo_home:
            env = bundle.cargo_environment(Path(cargo_home))
            result = run(["cargo", "+1.96.0", "run", "--offline", "--locked", "--quiet"],
                         moved / "checkout", env)
        self.assertEqual(result.strip(), "42 no-git")
        bundle.verify(moved)

    def test_refuses_dirty_or_wrong_revision_sources(self):
        (self.dep / "src/lib.rs").write_text("changed\n")
        with self.assertRaisesRegex(ValueError, "clean"):
            self.create()
        self.assertFalse(self.output.exists())
        run(["git", "restore", "src/lib.rs"], self.dep)
        self.spec["dependencies"][0]["revision"] = "0" * 40
        with self.assertRaisesRegex(ValueError, "revision"):
            self.create()

    def test_refuses_wrong_lock_digest(self):
        self.spec["lockfile_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "lock"):
            self.create()

    def test_existing_output_is_never_overwritten(self):
        self.output.mkdir()
        marker = self.output / "keep"
        marker.write_text("keep")
        with self.assertRaisesRegex(ValueError, "exists"):
            self.create()
        self.assertEqual(marker.read_text(), "keep")

    def test_refuses_output_inside_a_source_repository(self):
        self.output = self.checkout / "export"
        with self.assertRaisesRegex(ValueError, "outside"):
            self.create()
        self.assertFalse(self.output.exists())

    def test_rejects_traversing_package_paths_and_duplicate_packages(self):
        dep = self.spec["dependencies"][0]
        dep["packages"]["bundle-fixture-dep"] = "../../escape"
        with self.assertRaisesRegex(ValueError, "path"):
            self.create()
        dep["packages"]["bundle-fixture-dep"] = "."
        self.spec["dependencies"].append(dict(dep, name="second"))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.create()

    def test_rejects_symlinks_leaving_source_root(self):
        (self.checkout / "outside").symlink_to("../dependency/src/lib.rs")
        self.spec["workspace"]["revision"] = commit(self.checkout)
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.create()
        self.assertFalse(self.output.exists())

    def test_detects_content_modes_links_and_unexpected_files(self):
        self.create()
        source = self.output / "checkout/needed.txt"
        original = source.read_bytes()
        source.write_text("changed")
        with self.assertRaisesRegex(ValueError, "integrity"):
            bundle.verify(self.output)
        source.write_bytes(original)
        script = self.output / "checkout/tool.sh"
        script.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "integrity"):
            bundle.verify(self.output)
        script.chmod(0o755)
        link = self.output / "checkout/needed-link"
        link.unlink()
        link.symlink_to("tool.sh")
        with self.assertRaisesRegex(ValueError, "integrity"):
            bundle.verify(self.output)
        link.unlink()
        link.symlink_to("needed.txt")
        extra = self.output / "checkout/unrecorded.rs"
        extra.write_text("extra")
        with self.assertRaisesRegex(ValueError, "integrity"):
            bundle.verify(self.output)
        extra.unlink()
        bundle.verify(self.output)

    def test_resolver_rejects_dependencies_outside_bundle_even_if_manifest_rehashed(self):
        self.create()
        config = self.output / "checkout/.cargo/config.toml"
        config.write_text(config.read_text().replace("../deps/fixture", str(self.dep)))
        manifest_path = self.output / "source-manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["files"] = bundle.inventory(self.output)
        manifest_path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "outside"):
            bundle.verify(self.output, resolve=True)

    def test_resolver_rejects_target_source_outside_bundle(self):
        manifest = self.dep / "Cargo.toml"
        manifest.write_text(manifest.read_text() + '\n[lib]\npath=' +
                            json.dumps(str(self.dep / "src/lib.rs")) + '\n')
        self.spec["dependencies"][0]["revision"] = commit(self.dep)
        with self.assertRaisesRegex(ValueError, "outside"):
            self.create()
        self.assertFalse(self.output.exists())

    def test_dependency_metadata_may_list_unpublished_example_sources(self):
        manifest = self.dep / "Cargo.toml"
        manifest.write_text(manifest.read_text() +
                            '\n[[example]]\nname="omitted"\npath="examples/omitted.rs"\n')
        self.spec["dependencies"][0]["revision"] = commit(self.dep)
        self.create()
        bundle.verify(self.output, resolve=True)


if __name__ == "__main__":
    unittest.main()
