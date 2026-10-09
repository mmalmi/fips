"""Recover original paid accounts after full storage rejects a relay restart."""

import argparse
import json
import os
from pathlib import Path
import signal

from .paid_relay import eventually
from .paid_settlement import original_channels, require
from .restart_finances import recovered_exposure, retained_finances
from .wifi_measurements import snapshot
from .wifi_remote import Router, digest
from .wifi_restart import crash_profile
from .wifi_restart_load import RestartLoadRun
from .wifi_signer_storage import SignerStorageRun
from .wifi_storage_faults import VolumeRouter


def validate_journals(before, after):
    require(set(before) == {'controller', 'buyer', 'seller'} and before == after,
            'full storage or rejected restart changed a saved journal')


class FullStateRun(SignerStorageRun):
    fault_node = 'n02'
    warmup = RestartLoadRun.warmup

    def __init__(self, args):
        super().__init__(args)
        self.crash_attempted = False
        self.evidence['warmup'] = []
        for name in ('wifi_full_state.py', 'wifi_restart.py', 'restart_finances.py'):
            self.evidence['harness_sha256'][name] = digest(Path(__file__).with_name(name).read_bytes())

    def make_router(self, spec, index):
        if index == 1:
            return VolumeRouter(spec, self.run, self.root, self.open_mesh,
                                image=self.args.volume_image, whole_state=True)
        return Router(spec, self.run, self.root, self.open_mesh)

    def journal_hashes(self):
        node = self.nodes[self.fault_node]
        return {name: node.remote(['sha256sum', node.state + '/' + name + '/' + file]).decode().split()[0]
                for name, file in (('controller', 'controller.json'), ('buyer', 'buyer.json'),
                                   ('seller', 'ledger.json'))}

    def refuse_transition(self):
        node = self.nodes[self.fault_node]
        output = node.guarded(f'''if {node.binary} ctl {node.config} >{node.temporary}/full-settle.out 2>{node.temporary}/full-settle.err; then
  echo 'settlement unexpectedly succeeded while full' >&2; exit 1
fi
grep -q 'os error 28' {node.temporary}/full-settle.err
cat {node.temporary}/full-settle.err
''', json.dumps({'type': 'settle'}).encode(), timeout=45)
        return output.decode().strip()

    def refuse_restart(self):
        node = self.nodes[self.fault_node]
        output = node.guarded(f'''sh {node.temporary}/guard.sh can-start {node.config}
test "$(df -k {node.volume} | awk 'NR==2 {{print $4}}')" = 0
{node.binary} run {node.config} >{node.temporary}/full-restart.log 2>&1 &
child=$!
echo "$child" >{node.temporary}/process.pid
deadline=$(( $(cut -d . -f 1 /proc/uptime) + 15 ))
while kill -0 "$child" 2>/dev/null; do
  test -r /proc/$child/stat || break
  record=$(cat /proc/$child/stat) || break
  tail=${{record##*) }}
  case "$tail" in 'Z '*) break;; esac
  if test "$(cut -d . -f 1 /proc/uptime)" -ge "$deadline"; then
    echo 'full-storage startup did not exit within its bound' >&2; exit 1
  fi
  sleep 1
done
if wait "$child"; then
  echo 'full-storage startup unexpectedly succeeded' >&2; exit 1
else
  status=$?
fi
test "$status" = 1
test "$(df -k {node.volume} | awk 'NR==2 {{print $4}}')" = 0
grep -Eq 'os error 28|^fips-relay: failed to open Cashu wallet database$' {node.temporary}/full-restart.log
printf '{{"exit_code":%s}}\\n' "$status"
''', timeout=20)
        return json.loads(output)

    def recover_process(self):
        node = self.nodes[self.fault_node]
        try:
            return snapshot(node, self.fault_node)
        except RuntimeError:
            node.start()
            return eventually('original middle account reopened after freeing storage',
                              lambda: snapshot(node, self.fault_node), 60)

    def exercise(self):
        node = self.nodes[self.fault_node]
        row = self.evidence['storage_fault']
        try:
            self.form_line()
            for source, destination in (('n01', 'n03'), ('n03', 'n01')):
                self.ctl(source, 'buy', destination=self.nodes[destination].npub)
                self.cohort(source, destination, 'healthy')
            row['before'] = eventually('original paid accounts', self.credited, 30)
            original_channels(self.nodes, row['before'])
            row['process_before'] = snapshot(node, self.fault_node)
            row['mount'] = node.storage_fault('arm')
            row['journals_before'] = self.journal_hashes()
            self.save()
            row['transition_error'] = self.refuse_transition()
            row['journals_after_failure'] = self.journal_hashes()
            validate_journals(row['journals_before'], row['journals_after_failure'])
            self.crash_attempted = True
            self.save()
            row['crash'] = crash_profile(node, row['process_before'])
            row['stopped_journal'] = self.state_json(self.fault_node, 'seller/ledger.json')
            row['expected_lost_msat'] = recovered_exposure(row['stopped_journal'])
            self.save()
            row['refused_restart'] = self.refuse_restart()
            row['journals_after_restart'] = self.journal_hashes()
            validate_journals(row['journals_before'], row['journals_after_restart'])
            self.phase('full account storage rejected a journal write and relay restart without replacing evidence')
            row['restoration'] = node.storage_fault('restore')
            row['process_after'] = self.recover_process()
            old, new = row['process_before']['host_process'], row['process_after']['host_process']
            require(row['process_before']['npub'] == row['process_after']['npub'] == node.npub
                    and new['start_ticks'] > old['start_ticks'], 'recovery changed identity or failed to restart')
            eventually('original authenticated line after freeing storage', lambda: self.ready(line=True), 150)
            self.warmup()
            row['recovered'] = eventually('original accounts retain exact restart exposure', lambda: retained_finances(
                row['before'], self.finances(), row['expected_lost_msat']), 60)
            for source, destination in (('n01', 'n03'), ('n03', 'n01')):
                self.cohort(source, destination, 'recovered')
            row['final'] = eventually('automatic payments advance on the original recovered channels', lambda: retained_finances(
                row['before'], self.finances(), row['expected_lost_msat']), 30)
            require(all(row['final'][name]['authorized'] > row['before'][name]['authorized']
                        for name in ('n01', 'n03')), 'recovered traffic did not advance both payments')
            row['passed'] = True
            self.phase('freeing storage recovered the original paid channels and bounded crash exposure')
        finally:
            signal.alarm(0)
            node.storage_fault('restore')
            if self.crash_attempted:
                self.recover_process()
                eventually('restored line for original financial closure', lambda: self.ready(line=True), 150)
            self.collect()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('inventory', 'binary', 'mint-binary', 'mint-host', 'volume-image', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--mint-address', required=True)
    args = parser.parse_args()
    args.mint_ssh_forward = False
    os.umask(0o077)

    def deadline(_signal, _frame):
        raise TimeoutError('router full-state acceptance exceeded its bounded window')

    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(600)
    FullStateRun(args).execute()


if __name__ == '__main__':
    main()
