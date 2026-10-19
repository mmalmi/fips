"""Owned offline wallet commands with durable results and bounded child lifetimes."""

import json
import math
from pathlib import Path
import shlex
import time


def save(path, value):
    with Path(path).open('x') as output:
        json.dump(value, output, indent=2)
        output.write('\n')


class WalletCLI:
    """One command per fresh directory; a lost reply never authorizes a retry."""
    def __init__(self, node, tool, output, *, time_tool=None):
        self.node, self.tool, self.output = node, tool, output
        self.time_tool = time_tool
        self.owners = ('child', 'timeout', 'observer') + (('measurement',) if time_tool else ())
        self.pending = {}
        self.window_end = None

    def idle(self):
        for remote, local in list(self.pending.items()):
            raw = self.node.remote('set -eu\ndir=' + shlex.quote(remote) + '''
for owner in ''' + ' '.join(self.owners) + '''; do
read pid epoch <"$dir/$owner"
test -n "$pid" && test -n "$epoch"
current=absent
if stat=$(cat /proc/$pid/stat 2>/dev/null); then
 current=$(printf '%s' "$stat" | sed 's/.*) //' | awk '{print $20}')
 test -n "$current"
else
 test ! -e /proc/$pid/stat
fi
printf '%s %s %s %s\\n' "$owner" "$pid" "$epoch" "$current"
done''')
            owners = [line.split() for line in raw.decode().splitlines()]
            assert len(owners) == len(self.owners) and {row[0] for row in owners} == set(self.owners)
            assert all(epoch.isdigit() and pid.isdigit() and actual != epoch
                       and (actual == 'absent' or actual.isdigit())
                       for _, pid, epoch, actual in owners), 'recorded command owner remains live'
            save(local/'owner-release.json', dict(owners=owners, recorded_owners_absent=True))
            del self.pending[remote]

    def command(self, label, body=None, action='wallet', error=None, seconds=330):
        assert 1 <= seconds <= 330
        if self.window_end is not None:
            seconds = min(seconds, int(self.window_end()-time.monotonic())-10)
            assert seconds >= 1, 'insufficient phase time to launch another wallet command'
        local = self.output / label
        local.mkdir(mode=0o700)
        remote = self.node.temporary + '/' + label
        argv = [self.node.binary, action, self.node.config]
        save(local / 'intent.json', dict(argv=argv, request=body, deadline_seconds=seconds,
                                       kill_after_seconds=1, retry_authorized=False))
        self.node.remote(['mkdir', '-m', '700', remote])
        self.node.write(remote + '/stdin', json.dumps(body).encode() if body is not None else b'')
        epoch = "epoch() { sed 's/.*) //' /proc/$1/stat | awk '{print $20}'; }"
        child = (epoch + '\nprintf "%s %s\\n" $$ "$(epoch $$)" >'
                 + shlex.quote(remote + '/child') + '\nexec ' + shlex.join(argv))
        command = [self.tool, '--kill-after=1s', f'{seconds}s', '/bin/sh', '-c', child]
        outer_owner = 'timeout'
        if self.time_tool:
            # Measure outside the deadline supervisor so its direct wallet child
            # and process-group termination semantics remain unchanged.
            timed = (epoch + '\nprintf "%s %s\\n" $$ "$(epoch $$)" >'
                     + shlex.quote(remote + '/timeout') + '\nexec ' + shlex.join(command))
            command = [self.time_tool, '-f', '%U %S %M', '-o', remote + '/usage',
                       '/bin/sh', '-c', timed]
            outer_owner = 'measurement'
        script = f'''trap '' HUP
umask 077
{epoch}
printf "%s %s\\n" $$ "$(epoch $$)" >{remote}/observer
before=$(cut -d ' ' -f1 /proc/uptime)
{shlex.join(command)} <{remote}/stdin >{remote}/stdout 2>{remote}/stderr &
pid=$!
printf "%s %s\\n" "$pid" "$(epoch "$pid")" >{remote}/{outer_owner}
wait "$pid"
code=$?
after=$(cut -d ' ' -f1 /proc/uptime)
printf "%s %s %s\\n" "$code" "$before" "$after" >{remote}/result
'''
        save(local / 'dispatch.json', dict(script=script))
        self.pending[remote] = local
        started = time.monotonic()
        try:
            self.node.remote(script, timeout=seconds + 10)
        except BaseException as failure:
            save(local / 'uncertain.json', dict(error=type(failure).__name__,
                                               retry_authorized=False))
            # Observation only. No signals, wallet replay, or financial recovery.
            remaining = max(0, seconds + 3 - (time.monotonic() - started))
            if remaining:
                self.node.remote('sleep ' + str(int(remaining) + 1), timeout=remaining + 10)
            try:
                self.idle()
            except Exception as observation:
                save(local / 'owner-uncertain.json', dict(error=type(observation).__name__))
            raise
        self.idle()
        code, before, after = self.node.remote(['cat', remote + '/result']).decode().split()
        stdout = self.node.remote(['cat', remote + '/stdout'])
        stderr = self.node.remote(['cat', remote + '/stderr'])
        (local / 'stdout').write_bytes(stdout)
        (local / 'stderr').write_bytes(stderr)
        owners = {kind: self.node.remote(['cat', remote + '/' + kind]).decode().strip()
                  for kind in self.owners}
        resources = dict(cpu_seconds=None, maximum_rss_kib=None)
        if self.time_tool:
            raw = self.node.remote(['cat', remote + '/usage'])
            (local / 'usage').write_bytes(raw)
            # GNU and BusyBox time may prefix a failed command's usage with a diagnostic.
            user, system, peak = raw.decode().splitlines()[-1].split()
            user, system = float(user), float(system)
            assert all(math.isfinite(value) and value >= 0 for value in (user, system))
            assert peak.isascii() and peak.isdecimal() and int(peak) > 0
            resources.update(cpu_seconds=user + system, user_cpu_seconds=user,
                             system_cpu_seconds=system, maximum_rss_kib=int(peak),
                             cpu_clock_resolution_seconds=0.01,
                             resource_scope='complete offline command including timeout supervision')
        save(local / 'result.json', dict(exit_code=int(code), device_seconds=float(after)-float(before),
             controller_seconds=time.monotonic()-started, device_clock_resolution_seconds=0.01,
             owners=owners, recorded_owners_absent=True, **resources))
        if error is not None:
            assert int(code) == 1 and error.encode() in stderr, 'unexpected refusal'
            return None
        assert int(code) == 0, 'wallet command failed; original state retained'
        return json.loads(stdout) if action == 'wallet' else stdout.decode().strip()

