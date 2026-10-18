import hashlib, json, os, pathlib, subprocess, tarfile, tempfile, time

here = pathlib.Path(__file__).resolve().parent
plan = json.loads((here / 'plan.json').read_text())
archive = here / plan['archive']
assert hashlib.sha256(archive.read_bytes()).hexdigest() == plan['sha256']
destination = pathlib.Path(tempfile.mkdtemp(prefix='fips-package-'))
with tarfile.open(archive) as packed:
    packed.extractall(destination, filter='data')
package = destination / (plan['name'] + '-' + plan['version'])
vcs = json.loads((package / '.cargo_vcs_info.json').read_text())
assert vcs['git']['sha1'] == plan['sourceCommit']
assert not vcs['git'].get('dirty', False)
receipts = []
result = dict(plan)
start = time.monotonic()
archive_verified = not plan.get('sourceRepository')
try:
    if plan.get('sourceRepository'):
        source = destination / 'source'
        source.mkdir()
        with (here / 'command-source.log').open('w') as log:
            for command in [
                ['git', 'init'],
                ['git', 'fetch', '--depth=1', plan['sourceRepository'], plan['sourceCommit']],
                ['git', 'checkout', '--detach', 'FETCH_HEAD'],
            ]:
                subprocess.run(command, cwd=source, stdout=log, stderr=subprocess.STDOUT, check=True)
        assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip() == plan['sourceCommit']
        assert not subprocess.check_output(['git', 'status', '--porcelain'], cwd=source, text=True)
        source_package = source / vcs['path_in_vcs']
        for item in package.rglob('*'):
            if not item.is_file():
                continue
            relative = item.relative_to(package)
            if str(relative) in ['Cargo.toml', 'Cargo.lock', '.cargo_vcs_info.json']:
                continue
            original = source_package / ('Cargo.toml' if str(relative) == 'Cargo.toml.orig' else relative)
            assert original.read_bytes() == item.read_bytes(), str(relative)
        package = source / plan['workingDirectory']
    for index, command in enumerate(plan['commands']):
        with (here / f'command-{index}.log').open('w') as log:
            done = subprocess.run(command, cwd=package, stdout=log, stderr=subprocess.STDOUT)
        receipts.append({'command': command, 'exitCode': done.returncode})
        print('\n'.join((here / f'command-{index}.log').read_text().splitlines()[-30:]), flush=True)
        done.check_returncode()
    if plan.get('sourceRepository'):
        generated = pathlib.Path(os.environ['CARGO_TARGET_DIR']) / 'package' / plan['archive']
        result['generatedArchiveSha256'] = hashlib.sha256(generated.read_bytes()).hexdigest()
        assert result['generatedArchiveSha256'] == plan['sha256']
        archive_verified = True
finally:
    result.update(commands=receipts, seconds=time.monotonic()-start,
                  success=archive_verified and len(receipts)==len(plan['commands']) and all(r['exitCode']==0 for r in receipts),
                  workflowCommit=os.environ['GITHUB_SHA'], runId=os.environ['GITHUB_RUN_ID'])
    (here / 'result.json').write_text(json.dumps(result, indent=2)+'\n')
