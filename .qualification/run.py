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
try:
    for index, command in enumerate(plan['commands']):
        with (here / f'command-{index}.log').open('w') as log:
            done = subprocess.run(command, cwd=package, stdout=log, stderr=subprocess.STDOUT)
        receipts.append({'command': command, 'exitCode': done.returncode})
        print('\n'.join((here / f'command-{index}.log').read_text().splitlines()[-30:]), flush=True)
        done.check_returncode()
finally:
    result.update(commands=receipts, seconds=time.monotonic()-start,
                  success=len(receipts)==len(plan['commands']) and all(r['exitCode']==0 for r in receipts),
                  workflowCommit=os.environ['GITHUB_SHA'], runId=os.environ['GITHUB_RUN_ID'])
    (here / 'result.json').write_text(json.dumps(result, indent=2)+'\n')
