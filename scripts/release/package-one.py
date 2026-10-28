#!/usr/bin/env python3
"""Bounded, serialized no-build package publication with source/registry receipts."""
import hashlib, io, json, os, signal, subprocess, sys, tarfile, time, tomllib
import urllib.error, urllib.request
from pathlib import Path

OUT = Path(sys.argv[1]).resolve()
PLAN = json.loads((OUT / 'preparation.json').read_text())
ROOT, TARGET = Path(PLAN['root']), Path(PLAN['target'])
NAME = sys.argv[2]
RELATIVE = {'nvpn-fips-core': 'crates/fips-core', 'nvpn-fips-endpoint': 'crates/fips-endpoint'}[NAME]
VERSION = PLAN['version']
START = time.monotonic()
PHASES, SAMPLES = [], []
INTERRUPTED = False
ENV = os.environ.copy()
INPUTS = json.loads((ROOT / 'scripts/release/inputs.json').read_text())
ENV.update(RUSTUP_TOOLCHAIN=INPUTS['rust_toolchain'], CARGO_TARGET_DIR=str(TARGET), CARGO_BUILD_JOBS='2',
           CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0')

def free():
    fs = os.statvfs(TARGET)
    return fs.f_bavail * fs.f_frsize

INITIAL = MINIMUM = free()

def sha(data): return hashlib.sha256(data).hexdigest()

def save(suffix, value):
    (OUT / (NAME + '-' + suffix + '.json')).write_text(json.dumps(value, indent=2) + '\n')

def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT, text=True).strip()

def source_valid():
    assert git('rev-parse', 'HEAD') == PLAN['head']
    assert not git('status', '--porcelain'), 'source dirty'

def guard():
    global MINIMUM
    now, available = time.monotonic() - START, free()
    MINIMUM = min(MINIMUM, available)
    if not SAMPLES or now - SAMPLES[-1]['elapsed'] >= 1:
        SAMPLES.append({'elapsed': now, 'free_bytes': available})
    if INTERRUPTED: raise RuntimeError('interrupted')
    if now >= PLAN['package_seconds']: raise RuntimeError('package time limit')
    if available < PLAN['floor_bytes']: raise RuntimeError('protected free-space floor')
    if INITIAL - available > PLAN['max_global_loss_bytes']: raise RuntimeError('maximum global space loss')

def exists(group):
    try: os.killpg(group, 0); return True
    except ProcessLookupError: return False

def close(process):
    for sig, grace in [(signal.SIGTERM, 5), (signal.SIGKILL, 2)]:
        process.poll()
        if not exists(process.pid): break
        os.killpg(process.pid, sig)
        end = time.monotonic() + grace
        while exists(process.pid) and time.monotonic() < end:
            process.poll(); time.sleep(.05)
    process.wait(timeout=2)
    assert not exists(process.pid), 'owned process group not reaped'

def interrupted(_sig, _frame):
    global INTERRUPTED
    INTERRUPTED = True

for sig in [signal.SIGHUP, signal.SIGINT, signal.SIGTERM]: signal.signal(sig, interrupted)

def phase(label, command):
    source_valid(); guard()
    row = {'phase': label, 'command': command, 'start_elapsed': time.monotonic() - START}
    process = None
    logpath = OUT / (NAME + '-' + label + '.log')
    try:
        with logpath.open('xb') as log:
            process = subprocess.Popen(command, cwd=ROOT, env=ENV, stdout=log,
                                       stderr=subprocess.STDOUT, start_new_session=True)
            row['process_group'] = process.pid
            save('current', row)
            while process.poll() is None:
                guard(); time.sleep(.2)
    finally:
        if process is not None:
            close(process)
            row.update(exit_code=process.returncode, process_group_reaped=True)
        row['end_elapsed'] = time.monotonic() - START
        PHASES.append(row); save('phases', PHASES); save('resources', SAMPLES)
    assert row.get('exit_code') == 0, label + ' failed; inspect retained log, do not blindly retry publication'
    assert 'Compiling ' not in logpath.read_text(), 'unexpected compilation'

def request(url, allow_missing=False):
    guard()
    req = urllib.request.Request(url, headers={'User-Agent': 'FIPS release provenance verification'})
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            data = response.read(25 * 1024 * 1024 + 1)
            assert len(data) <= 25 * 1024 * 1024
            guard(); return data
    except urllib.error.HTTPError as error:
        if allow_missing and error.code == 404: return None
        raise

def inspect_archive(archive):
    source_valid()
    prefix, count = NAME + '-' + VERSION + '/', 0
    with tarfile.open(fileobj=io.BytesIO(archive)) as packed:
        vcs = json.load(packed.extractfile(prefix + '.cargo_vcs_info.json'))
        assert vcs['git']['sha1'] == PLAN['head'] and not vcs['git'].get('dirty', False), vcs
        assert vcs['path_in_vcs'] == RELATIVE
        for member in packed.getmembers():
            assert member.name.startswith(prefix)
            rel = member.name[len(prefix):]
            assert not any(x in Path(rel).parts for x in ['..', 'work', '.env', '.git'])
            assert not member.issym() and not member.islnk()
            if not member.isfile() or rel in ['.cargo_vcs_info.json', 'Cargo.toml', 'Cargo.lock']: continue
            source = ROOT / RELATIVE / ('Cargo.toml' if rel == 'Cargo.toml.orig' else rel)
            assert source.is_file() and source.read_bytes() == packed.extractfile(member).read(), rel
            count += 1
        manifest_bytes = packed.extractfile(prefix + 'Cargo.toml').read()
        assert str(ROOT).encode() not in manifest_bytes and b'[patch.' not in manifest_bytes
        manifest = tomllib.loads(manifest_bytes.decode())
        assert manifest['package']['name'] == NAME and manifest['package']['version'] == VERSION
        if NAME == 'nvpn-fips-endpoint':
            assert manifest['dependencies']['nvpn-fips-core']['version'] == '=' + VERSION
        (OUT / (NAME + '-packaged.lock')).write_bytes(packed.extractfile(prefix + 'Cargo.lock').read())
    assert count > 0
    return {'sha256': sha(archive), 'bytes': len(archive), 'source_files_verified': count,
            'vcs_commit': PLAN['head'], 'vcs_clean': True, 'no_compile': True,
            'reused_tested_source': PLAN['tested_head']}

passed, failure, package, registry = False, None, None, None
try:
    assert not (OUT / (NAME + '-closure.json')).exists(), 'existing attempt receipt; inspect instead of restarting'
    source_valid()
    source_proof = json.loads((OUT / 'source-closure.json').read_text())
    assert source_proof['passed'] and source_proof['head'] == PLAN['head']
    assert source_proof['nonshallow'] and source_proof['verified_objects'] > 0
    assert source_proof['publisher_cache_or_daemon_used_for_readback'] is False
    assert INITIAL >= PLAN['initial_min_bytes'], 'fresh free space below entry gate'
    api = 'https://crates.io/api/v1/crates/' + NAME + '/' + VERSION
    assert request(api, allow_missing=True) is None, 'version already exists; reconcile before publication'
    phase('package', ['cargo', 'package', '-p', NAME, '--locked', '--no-verify'])
    archive_path = TARGET / 'package' / (NAME + '-' + VERSION + '.crate')
    archive = archive_path.read_bytes()
    package = inspect_archive(archive)
    (OUT / (NAME + '-' + VERSION + '.crate')).write_bytes(archive)
    save('package', package)
    phase('publish', ['cargo', 'publish', '-p', NAME, '--locked', '--no-verify'])
    assert sha(archive_path.read_bytes()) == package['sha256'], 'published local archive changed'
    metadata = None
    for delay in [0, 2, 4, 8, 16]:
        if delay: time.sleep(delay)
        data = request(api, allow_missing=True)
        if data is not None: metadata = json.loads(data)['version']; break
    assert metadata is not None, 'registry visibility pending; do not republish'
    assert metadata['num'] == VERSION and not metadata['yanked']
    assert metadata['checksum'] == package['sha256']
    remote = request('https://static.crates.io/crates/' + NAME + '/' + NAME + '-' + VERSION + '.crate')
    assert remote == archive, 'registry bytes differ from verified archive'
    registry = {'name': NAME, 'version': VERSION, 'checksum': metadata['checksum'],
                'byte_equal': True, 'yanked': False, 'source_commit': PLAN['head']}
    save('registry', registry)
    source_valid(); guard(); passed = True
except Exception as error:
    failure = str(error)
finally:
    receipt = {'passed': passed, 'failure': failure, 'name': NAME, 'version': VERSION,
               'head': PLAN['head'], 'elapsed_seconds': time.monotonic()-START,
               'initial_free_bytes': INITIAL, 'minimum_free_bytes': MINIMUM, 'final_free_bytes': free(),
               'phases': PHASES, 'package': package, 'registry': registry}
    save('closure', receipt); save('resources', SAMPLES)
    print(json.dumps(receipt), flush=True)
sys.exit(0 if passed else 1)
