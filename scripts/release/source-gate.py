#!/usr/bin/env python3
"""Publish one immutable source ref and verify it without publisher caches."""
import hashlib, json, os, shutil, signal, subprocess, sys, tempfile, time
from pathlib import Path

OUT = Path(sys.argv[1]).resolve()
PLAN = json.loads((OUT / 'preparation.json').read_text())
ROOT = Path(PLAN['root'])
INPUTS = json.loads((ROOT / 'scripts/release/inputs.json').read_text())
HELPERS = Path(sys.argv[2]).resolve()
EXPECTED_HELPER_SHA = INPUTS['git_remote_htree']['sha256']
URL = PLAN['source_url']
assert URL.startswith('htree://npub') and URL.endswith('/fips')
REF = 'refs/tags/haps-source/' + PLAN['head']
HELPER = HELPERS / 'git-remote-htree'
assert hashlib.sha256(HELPER.read_bytes()).hexdigest() == EXPECTED_HELPER_SHA
assert not (OUT / 'source-closure.json').exists(), 'Inspect prior evidence before retry'
START = time.monotonic()
PHASES, SAMPLES = [], []
INTERRUPTED = False

def free():
    f = os.statvfs(ROOT)
    return f.f_bavail * f.f_frsize

INITIAL = MINIMUM = free()
assert INITIAL >= PLAN['initial_min_bytes'], 'source free-space entry gate failed'
TEMP = Path(tempfile.mkdtemp(prefix='fips-public-source-'))
env = dict(os.environ, PATH=str(HELPERS) + os.pathsep + os.environ['PATH'],
           HTREE_PREFER_LOCAL_DAEMON='0', HTREE_LOCAL_DAEMON_ONLY='0', NOSTR_PREFER_LOCAL='0')
assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip() == PLAN['head']
assert not subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True).strip()

def interrupted(_sig, _frame):
    global INTERRUPTED
    INTERRUPTED = True

for sig in [signal.SIGHUP, signal.SIGINT, signal.SIGTERM]: signal.signal(sig, interrupted)

def exists(group):
    try: os.killpg(group, 0); return True
    except ProcessLookupError: return False

def run(label, args, cwd=ROOT, environment=env):
    global MINIMUM
    row = {'phase': label, 'start_elapsed': time.monotonic()-START}
    p = None
    logpath = OUT / ('source-' + label + '.log')
    try:
        with logpath.open('xb') as log:
            p = subprocess.Popen(args, cwd=cwd, env=environment, stdout=log,
                                 stderr=subprocess.STDOUT, start_new_session=True)
            row['process_group'] = p.pid
            while p.poll() is None:
                available, elapsed = free(), time.monotonic()-START
                MINIMUM = min(MINIMUM, available)
                if not SAMPLES or elapsed-SAMPLES[-1]['elapsed'] >= 1:
                    SAMPLES.append({'elapsed': elapsed, 'free_bytes': available})
                if INTERRUPTED: raise RuntimeError('interrupted')
                if elapsed >= PLAN['source_seconds']: raise RuntimeError('source time limit')
                if elapsed-row['start_elapsed'] >= PLAN['source_phase_seconds']: raise RuntimeError('source phase time limit')
                if available < PLAN['floor_bytes']: raise RuntimeError('source protected free-space floor')
                if INITIAL-available > PLAN['max_global_loss_bytes']: raise RuntimeError('source maximum global space loss')
                time.sleep(.2)
    finally:
        if p is not None:
            for sig, grace in [(signal.SIGTERM,5), (signal.SIGKILL,2)]:
                p.poll()
                if not exists(p.pid): break
                os.killpg(p.pid,sig); end=time.monotonic()+grace
                while exists(p.pid) and time.monotonic()<end: p.poll();time.sleep(.05)
            p.wait(timeout=2)
            row.update(exit_code=p.returncode, process_group_reaped=not exists(p.pid))
        row['end_elapsed']=time.monotonic()-START
        PHASES.append(row)
        (OUT/'source-phases.json').write_text(json.dumps(PHASES,indent=2)+'\n')
    assert row['exit_code']==0 and row['process_group_reaped'], label+' failed'
    return logpath.read_text()

def parse_refs(output):
    return {line.split()[1]:line.split()[0] for line in output.splitlines()
            if len(line.split())==2 and (line.split()[1]=='HEAD' or line.split()[1].startswith('refs/'))}

passed, failure, verified_objects = False, None, None
try:
    # Both selectors must name the same existing owner/repository before mutation.
    explicit = parse_refs(run('explicit-before', ['git','ls-remote','--',URL]))
    alias = parse_refs(run('alias-before',['git','ls-remote','--','htree://self/fips']))
    assert explicit and alias==explicit, 'self alias does not match pinned existing public owner'
    assert REF not in explicit or explicit[REF]==PLAN['head'], 'immutable source ref already differs'
    run('push',['git','-c','push.followTags=false','push','--',URL,PLAN['head']+':'+REF])
    after=parse_refs(run('after',['git','ls-remote','--',URL]))
    assert after.get(REF)==PLAN['head'], 'remote immutable ref mismatch'
    assert all(after.get(k)==v for k,v in explicit.items()), 'retained remote refs changed'
    cold=dict(env,HTREE_CONFIG_DIR=str(TEMP/'config'),HTREE_DATA_DIR=str(TEMP/'data'),
              GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL=os.devnull,GIT_NO_REPLACE_OBJECTS='1',
              GIT_TERMINAL_PROMPT='0',HTREE_PREFER_LOCAL_DAEMON='false',HTREE_LOCAL_DAEMON_ONLY='false')
    for key in ['GIT_CONFIG_COUNT','GIT_CONFIG_PARAMETERS','GIT_DIR','GIT_WORK_TREE',
                'GIT_INDEX_FILE','GIT_OBJECT_DIRECTORY','GIT_ALTERNATE_OBJECT_DIRECTORIES',
                'GIT_SHALLOW_FILE','NOSTR_RELAYS']:
        cold.pop(key,None)
    repo=TEMP/'repo.git'
    run('init',['git','init','--bare',str(repo)],cwd=TEMP,environment=cold)
    command=['git','-c','protocol.ext.allow=never','-C',str(repo)]
    run('cold-fetch',[*command,'fetch','--no-tags','--',URL,REF],cwd=TEMP,environment=cold)
    actual=run('cold-revision',[*command,'rev-parse','--verify','FETCH_HEAD^{commit}'],cwd=TEMP,environment=cold).strip()
    assert actual==PLAN['head']
    assert run('cold-shallow',[*command,'rev-parse','--is-shallow-repository'],cwd=TEMP,environment=cold).strip()=='false'
    assert not (repo/'objects/info/alternates').exists()
    objects=run('cold-objects',[*command,'rev-list','--objects','--missing=error',actual,'--'],cwd=TEMP,environment=cold)
    verified_objects=len(objects.splitlines())
    assert verified_objects>0
    passed=True
except Exception as error:
    failure=str(error)
finally:
    if passed: shutil.rmtree(TEMP)
    result={'passed':passed,'failure':failure,'source_url':URL,'immutable_ref':REF,'head':PLAN['head'],
            'helper_sha256':EXPECTED_HELPER_SHA,'verified_objects':verified_objects,
            'nonshallow':passed,'publisher_cache_or_daemon_used_for_readback':False,
            'temporary_readback_removed':passed,'retained_failure_directory':None if passed else str(TEMP),
            'initial_free_bytes':INITIAL,'minimum_free_bytes':MINIMUM,'final_free_bytes':free(),
            'elapsed_seconds':time.monotonic()-START,'phases':PHASES}
    (OUT/'source-closure.json').write_text(json.dumps(result,indent=2)+'\n')
    (OUT/'source-resources.json').write_text(json.dumps(SAMPLES,indent=2)+'\n')
    print(json.dumps(result),flush=True)
sys.exit(0 if passed else 1)
