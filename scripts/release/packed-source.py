#!/usr/bin/env python3
"""Prepare public Git objects remotely, then cold-verify their signed route.

The private plan supplies existing destinations and paths. Neither phase needs
the publisher identity. Signing is a separate, bounded publisher operation.
"""
import hashlib
import base64
import io
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import time
import urllib.request

if not __debug__ or sys.version_info < (3, 11):
    raise RuntimeError('Python >=3.11 without optimization is required')

PLAN = json.loads(Path(sys.argv[1]).read_text())
MODE = sys.argv[2]
assert MODE in ("prepare", "verify-signed")
OUT = Path(PLAN["output"])
WORK = Path(PLAN["work"]) / MODE
HELPERS = Path(PLAN["helpers"])
ALL_INPUTS = json.loads(Path(PLAN["inputs"]).read_text())
INPUTS = ALL_INPUTS["linux_git_remote_htree"]
SCRIPTS = Path(__file__).resolve().parent
SOURCE, HEAD = PLAN["source_url"], PLAN["head"]
TAG = "refs/tags/haps-source/" + HEAD
assert re.fullmatch(r'htree://npub1[a-z0-9]+/[a-z0-9_-]+', SOURCE)
REPOSITORY = SOURCE.rsplit('/', 1)[1]
assert re.fullmatch("[0-9a-f]{40}", HEAD)
OUT.mkdir(parents=True, exist_ok=True)
assert not WORK.exists() and not (OUT / (MODE + "-receipt.json")).exists()
INITIAL = shutil.disk_usage(OUT).free
assert INITIAL >= PLAN["entry_bytes"]
START = time.monotonic()
STEPS = []
CHILDREN = []
INTERRUPTED = False


def digest(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def interrupt(_signal, _frame):
    global INTERRUPTED
    INTERRUPTED = True


for sig in (signal.SIGHUP, signal.SIGTERM, signal.SIGINT):
    signal.signal(sig, interrupt)


def guard():
    available = shutil.disk_usage(OUT).free
    assert available >= PLAN["floor_bytes"], "protected native reserve"
    assert INITIAL - available <= PLAN["growth_bytes"], "global growth bound"
    assert time.monotonic() - START < PLAN["seconds"] and not INTERRUPTED


def run(label, args, env, timeout=600, input_text=None, binary_output=None):
    guard()
    output = Path(binary_output) if binary_output else OUT / (MODE + "-" + label + ".out")
    errors = OUT / (MODE + "-" + label + ".log")
    began = time.monotonic()
    with output.open("xb") as stdout, errors.open("xb") as stderr:
        child = subprocess.Popen(args, env=env, stdout=stdout, stderr=stderr,
                                 stdin=subprocess.PIPE if input_text is not None else None,
                                 start_new_session=True)
        CHILDREN.append(child)
        if input_text is not None:
            child.stdin.write(input_text.encode())
            child.stdin.close()
        while child.poll() is None:
            guard()
            assert time.monotonic() - began < timeout, label + " deadline"
            assert errors.stat().st_size < 16 * 1024**2
            assert output.stat().st_size < (256 if binary_output else 16) * 1024**2
            time.sleep(.2)
        code = child.wait()
    STEPS.append({"phase": label, "exit": code, "seconds": time.monotonic() - began})
    assert code == 0, label + " failed; inspect retained logs"
    return '' if binary_output else output.read_text()


def environment(name, writable=False, relay=None):
    config, data = WORK / (name + "-config"), WORK / (name + "-data")
    config.mkdir()
    config.joinpath("config.toml").write_text(
        '[blossom]\nservers = []\nread_servers = ["https://cdn.iris.to", "https://upload.iris.to"]\n'
        + 'write_servers = ' + ('["https://upload.iris.to"]' if writable else '[]') + '\n'
        + ('[nostr]\nrelays = ' + json.dumps([relay]) + '\n' if relay else ''))
    env = dict(os.environ, PATH=str(HELPERS) + os.pathsep + os.environ["PATH"],
               HTREE_CONFIG_DIR=str(config), HTREE_DATA_DIR=str(data),
               HTREE_PREFER_LOCAL_DAEMON="false", HTREE_LOCAL_DAEMON_ONLY="false",
               GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
               GIT_NO_REPLACE_OBJECTS="1", GIT_NO_LAZY_FETCH="1", GIT_TERMINAL_PROMPT="0",
               TOKIO_WORKER_THREADS="1", RAYON_NUM_THREADS="1", TMPDIR=str(WORK))
    for key in ("GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS", "GIT_DIR", "GIT_WORK_TREE",
                "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
                "GIT_SHALLOW_FILE", "GIT_GRAFT_FILE", "NOSTR_RELAYS", "HTREE_GIT_REBUILD_FROM_LOCAL"):
        env.pop(key, None)
    return env


def git(repo, *args):
    return ["git", "-c", "protocol.ext.allow=never", "-C", str(repo), *args]


def read_refs(repo, env):
    result = subprocess.check_output(git(repo, "for-each-ref", "--format=%(refname) %(objectname)"),
                                     env=env, text=True, timeout=60)
    refs = dict(line.split() for line in result.splitlines())
    head = subprocess.check_output(git(repo, "symbolic-ref", "HEAD"), env=env,
                                   text=True, timeout=60).strip()
    return {"head": head, "refs": refs}


def closure(repo, expected, label, env):
    assert read_refs(repo, env) == expected, "public ref set or HEAD differs"
    assert subprocess.check_output(git(repo, "rev-parse", "--is-shallow-repository"),
                                   env=env, text=True).strip() == "false"
    assert not (repo / "objects/info/alternates").exists()
    assert not (repo / "objects/info/http-alternates").exists()
    assert subprocess.check_output(git(repo, "rev-parse", HEAD + "^{tree}"),
                                   env=env, text=True).strip() == PLAN["tree"]
    objects = run(label, git(repo, "rev-list", "--objects", "--missing=error",
                            *sorted(set(expected["refs"].values())), "--"), env, 120)
    return {"count": len(objects.splitlines()), "sha256": hashlib.sha256(objects.encode()).hexdigest()}


def install_pinned_sdk():
    total = 0
    for package in ALL_INPUTS['source_sdk']:
        with urllib.request.urlopen(package['url'], timeout=30) as response:
            archive = response.read(2 * 1024**2 + 1)
        assert len(archive) <= 2 * 1024**2
        assert hashlib.sha256(archive).hexdigest() == package['archiveSha256']
        assert 'sha512-' + base64.b64encode(hashlib.sha512(archive).digest()).decode() == package['integrity']
        destination = WORK / 'sdk/node_modules' / package['name']
        destination.mkdir(parents=True)
        with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as tar:
            for member in tar:
                parts = Path(member.name).parts
                assert parts[0] == 'package' and '..' not in parts
                assert member.isdir() or member.isfile()
                if len(parts) == 1:
                    continue
                target = destination.joinpath(*parts[1:])
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    total += member.size
                    assert total < 4 * 1024**2
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(tar.extractfile(member).read())
        manifest = json.loads((destination / 'package.json').read_text())
        assert manifest['name'] == package['name'] and manifest['version'] == package['version']


def resolve_public_root(label, env):
    # Unlike `info`'s hardcoded 500 ms resolver, pinned `get` uses configured
    # public relays with a 10-second verified observation window. Fetch only
    # the tiny HEAD path, and bind the full authenticated root hash it reports.
    run(label, [str(HELPERS / 'htree'), 'get', SOURCE + '/.git/HEAD',
                '--output', str(WORK / (label + '-HEAD'))], env, 60)
    log = (OUT / (MODE + '-' + label + '.log')).read_text()
    return re.search(r'Resolved to: ([0-9a-f]{64})', log).group(1)


def verify_ordinary_reader(root, key, expected, original, env):
    relay_log = (OUT / 'prepare-loopback-relay.log').open('xb')
    relay = subprocess.Popen(['node', str(SCRIPTS / 'source-loopback-relay.mjs'), str(WORK)],
                             env=env, stdout=relay_log, stderr=relay_log, start_new_session=True)
    CHILDREN.append(relay)
    deadline = time.monotonic() + 10
    while not (WORK / 'fixture-address.json').exists():
        assert relay.poll() is None and time.monotonic() < deadline
        time.sleep(.1)
    address = json.loads((WORK / 'fixture-address.json').read_text())
    assert address['host'] == '127.0.0.1'
    fixture_env = environment('fixture-sign', relay=address['url'])
    published = run('fixture-sign', [str(HELPERS / 'htree'), 'publish', REPOSITORY,
                                    root, '--key', key], fixture_env, 90)
    route = re.search(r'Published: (npub1[a-z0-9]+/' + re.escape(REPOSITORY) + ')', published).group(1)
    reader = environment('fixture-reader', relay=address['url'])
    repo = WORK / 'fixture.git'
    run('ordinary-reader-clone', ['git', 'clone', '--mirror', '--no-local', '--',
                                  'htree://' + route, str(repo)], reader)
    assert closure(repo, expected, 'ordinary-reader-closure', reader) == original
    relay.terminate()
    relay.wait(timeout=5)
    relay_log.close()


receipt = {"passed": False, "head": HEAD, "source_url": SOURCE, "steps": STEPS}
try:
    cgroup = Path("/sys/fs/cgroup") / Path("/proc/self/cgroup").read_text().strip()[3:].lstrip("/")
    controls = {key: (cgroup / key).read_text().strip() for key in ("memory.max", "memory.swap.max", "cpu.max")}
    assert controls == {"memory.max": "1073741824", "memory.swap.max": "0", "cpu.max": "100000 100000"}
    receipt["cgroup_controls"] = controls
    assert digest(HELPERS / "git-remote-htree") == INPUTS["sha256"]
    assert digest(HELPERS / "htree") == INPUTS["htree_sha256"]
    WORK.mkdir(parents=True)
    env = environment("public")
    if MODE == "prepare":
        install_pinned_sdk()
        old_root = resolve_public_root('original-root', env)
        repo = WORK / "public.git"
        run("clone-public", ["git", "clone", "--mirror", "--no-local", "--", SOURCE, str(repo)], env)
        before = read_refs(repo, env)
        assert TAG not in before["refs"] or before["refs"][TAG] == HEAD
        (OUT / "refs-before.json").write_text(json.dumps(before, indent=2) + "\n")
        assert digest(PLAN["bundle"]) == PLAN["bundle_sha256"]
        run("candidate-fetch", git(repo, "fetch", "--no-tags", "--", PLAN["bundle"],
                                   PLAN["candidate_ref"] + ":" + TAG), env, 120)
        expected = {"head": before["head"], "refs": dict(before["refs"], **{TAG: HEAD})}
        original = closure(repo, expected, "original-closure", env)
        tree = WORK / "source-tree"
        bare = tree / ".git"
        bare.mkdir(parents=True)
        # Normalize the public closure into one pack. Copying a clone's loose
        # fanout can create a directory B-tree in the uploaded metadata, while
        # the qualified size repair deliberately handles direct directories.
        # Only these explicit public tips are input; no local private refs or
        # repository configuration are copied into the source tree.
        (bare / 'objects/pack').mkdir(parents=True)
        packed = WORK / 'public-closure.pack'
        tips = '\n'.join(sorted(set(expected['refs'].values()))) + '\n'
        run('pack-public-closure', git(repo, '-c', 'pack.threads=1', '-c',
            'pack.windowMemory=32m', '-c', 'pack.deltaCacheSize=16m', 'pack-objects',
            '--revs', '--stdout'), env, 600, input_text=tips, binary_output=packed)
        pack_id = run('index-public-closure', git(repo, 'index-pack', '--threads=1',
                      str(packed)), env, 120).strip()
        assert re.fullmatch('[0-9a-f]{40}', pack_id)
        for extension in ('pack', 'idx'):
            packed.with_suffix('.' + extension).rename(bare / 'objects/pack' / ('pack-' + pack_id + '.' + extension))
        (bare / "HEAD").write_text("ref: " + expected["head"] + "\n")
        for ref, oid in expected["refs"].items():
            path = bare / ref
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(oid + "\n")
        run("server-info", ["git", "--git-dir", str(bare), "update-server-info"], env, 60)
        assert closure(bare, expected, "packed-closure", env) == original
        receipt["packed_tree_bytes"] = sum(p.stat().st_size for p in tree.rglob("*") if p.is_file())
        upload_env = environment("upload", True)
        added = run("upload", [str(HELPERS / "htree"), "add", "--no-ignore", str(tree)], upload_env)
        assert "0 failed)" in added, "some immutable blocks failed to upload"
        uri = re.search(r"^\s*url:\s+(?:htree://)?(nhash1[a-z0-9]+)\s*$", added, re.M).group(1)
        root = re.search(r"^\s*hash:\s+([0-9a-f]{64})\s*$", added, re.M).group(1)
        key = re.search(r"^\s*key:\s+([0-9a-f]{64})\s*$", added, re.M).group(1)
        receipt.update(immutable_source="htree://" + uri, root_hash=root, public_chk_key=key,
                       refs=expected, closure=original, mutable_ref_published=False)
        # A new environment has no access to either producer's object cache.
        cold_env = environment("cold")
        downloaded = WORK / "cold-tree"
        run("fetch-immutable", [str(HELPERS / "htree"), "get", receipt["immutable_source"],
                                "--output", str(downloaded)], cold_env)
        cold = WORK / "cold.git"
        run("clone-immutable", ["git", "clone", "--mirror", "--no-local", "--no-hardlinks",
                                "--", str(downloaded), str(cold)], cold_env)
        assert closure(cold, expected, "cold-closure", cold_env) == original
        # `add` stores packed object bytes correctly but loses their entry
        # lengths. Repair only measured lengths and their directory ancestors,
        # using the pinned canonical codec; never sign the intermediate root.
        run('repair-pack-metadata', ['node', str(SCRIPTS / 'repair-pack-metadata.mjs'),
                                    str(WORK), root, key], upload_env, 180)
        metadata = json.loads((WORK / 'metadata-plan.json').read_text())
        assert metadata['allObjectCiphertextCidsPreserved'] and metadata['allRefsAndHeadBytesPreserved']
        (OUT / 'metadata-plan.json').write_text(json.dumps(metadata, indent=2) + '\n')
        for index, node in enumerate(metadata['nodes']):
            added = run('upload-metadata-' + str(index), [str(HELPERS / 'htree'), 'add',
                         '--unencrypted', node['file']], upload_env, 120)
            assert re.search(r'^\s*hash:\s+' + node['newHash'] + r'\s*$', added, re.M)
            checked = WORK / ('checked-node-' + str(index))
            check_env = environment('metadata-reader-' + str(index))
            run('read-metadata-' + str(index), [str(HELPERS / 'htree'), 'get', node['newHash'],
                                               '--output', str(checked)], check_env, 120)
            assert digest(checked) == node['newHash']
            assert checked.read_bytes() == Path(node['file']).read_bytes()
        root, key = metadata['newRootHash'], metadata['newRootKey']
        verify_ordinary_reader(root, key, expected, original, env)
        resolved = run('corrected-root', [str(HELPERS / 'htree'), 'info', root + ':' + key], env, 60)
        uri = re.search(r'\b(nhash1[a-z0-9]+)', resolved).group(1)
        receipt.update(immutable_source='htree://' + uri, root_hash=root, public_chk_key=key,
                       original_public_root_hash=old_root,
                       actual_ordinary_reader_verified=True, private_fixture_only=True,
                       source_sdk=ALL_INPUTS['source_sdk'])
    else:
        previous = json.loads((OUT / "prepare-receipt.json").read_text())
        assert previous["passed"] and previous["head"] == HEAD
        assert resolve_public_root('resolve-signed-root', env) == previous['root_hash']
        repo = WORK / "signed.git"
        run("clone-signed", ["git", "clone", "--mirror", "--no-local", "--", SOURCE, str(repo)], env)
        assert closure(repo, previous["refs"], "signed-closure", env) == previous["closure"]
        receipt.update(verified_objects=previous["closure"]["count"], nonshallow=True,
                       publisher_cache_or_daemon_used_for_readback=False,
                       all_existing_refs_preserved=True, signed_root_matches_immutable=True)
    receipt["passed"] = True
except BaseException as error:
    receipt["error"] = str(error)
finally:
    for child in CHILDREN:
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGTERM)
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
    # Keep failed work for inspection. Successful work is entirely task-owned.
    if receipt["passed"]:
        shutil.rmtree(WORK)
    receipt.update(seconds=time.monotonic() - START, final_free_bytes=shutil.disk_usage(OUT).free)
    if "cgroup" in globals():
        receipt["peak_memory_bytes"] = int((cgroup / "memory.peak").read_text())
    (OUT / (MODE + "-receipt.json")).write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({key: receipt.get(key) for key in ("passed", "error", "seconds", "peak_memory_bytes")}))
sys.exit(0 if receipt["passed"] else 1)
