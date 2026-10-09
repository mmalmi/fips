"""Recover automatic payments after blocked wallet snapshot replacement on OpenWrt.

Bind one test snapshot onto itself: reads and locks work, but atomic replacement
fails with EBUSY on the router's flash. The existing lease guard restores the
mount if the controller disappears.
"""

import argparse
import json
import os
from pathlib import Path
import signal

from .cadence_workloads import stream
from .paid_finances import payments_credited
from .paid_relay import eventually
from .paid_settlement import original_channels, require
from .paid_wifi import PaidWifiRun
from .restart_finances import QUOTE_UNITS, retained_finances
from .wifi_measurements import snapshot
from .wifi_priority_checks import received, submitted
from .wifi_remote import Router, digest


class StorageRouter(Router):
    def guard_restore_command(self):
        return (f'if [ -f {self.temporary}/storage-armed ]; then '
                f'sh {self.temporary}/storage-fault.sh restore; fi')

    def stage_runtime(self, binary):
        super().stage_runtime(binary)
        self.write(self.temporary + '/storage-fault.sh', self.storage_script().encode())

    def prepare(self, binary, config):
        super().prepare(binary, config)
        # Exercise the mount before funding, then remove the empty placeholder.
        self.guarded(f'mkdir -p {self.state}/wallet; '
                     f'set -C; : >{self.state}/wallet/spilman-client.json')
        try:
            self.storage_probe = {'mount': self.storage_fault('arm')}
            self.guarded(f'printf probe >{self.state}/wallet/.replace-probe; '
                         f'if mv {self.state}/wallet/.replace-probe '
                         f'{self.state}/wallet/spilman-client.json '
                         f'2>{self.temporary}/storage-error; then exit 1; fi; '
                         f'grep -qi "resource busy" {self.temporary}/storage-error')
            self.storage_probe['replacement_refused'] = True
        finally:
            restored = self.storage_fault('restore')
        self.storage_probe['restoration'] = restored
        self.guarded(f'mv {self.state}/wallet/.replace-probe '
                     f'{self.state}/wallet/spilman-client.json; '
                     f'rm {self.state}/wallet/spilman-client.json')

    def storage_script(self):
        return f'''#!/bin/sh
set -eu
snapshot={self.state}/wallet/spilman-client.json
temporary={self.temporary}
mounted() {{ awk -v p="$snapshot" '$5==p {{print $1}}' /proc/self/mountinfo; }}
identity() {{
  test -f "$snapshot" && test ! -L "$snapshot" || return 1
  device=$(awk -v p="$snapshot" '$5=="/" || p==$5 || index(p,$5"/")==1 {{
    if (length($5)>n) {{n=length($5); device=$3}}
  }} END {{if (!n) exit 1; print device}}' /proc/self/mountinfo)
  inode=$(ls -di "$snapshot" | awk '{{print $1}}')
  test -n "$inode"
  printf '%s:%s\\n' "$device" "$inode"
}}
case "$1" in
  arm)
    test ! -e "$temporary/storage-armed"
    test -z "$(mounted)"
    identity >"$temporary/storage-identity"
    rm -f "$temporary/storage-mount-id"
    touch "$temporary/storage-armed"
    mount -o bind "$snapshot" "$snapshot"
    mounted >"$temporary/storage-mount-id"
    test -s "$temporary/storage-mount-id"
    test "$(identity)" = "$(cat "$temporary/storage-identity")"
    awk -v p="$snapshot" '$5==p && $6 ~ /(^|,)rw(,|$)/ {{found++}}
      END {{exit found != 1}}' /proc/self/mountinfo
    # Native reads tighten file permissions; leave those and the lock writable.
    chmod 600 "$snapshot"
    cat "$snapshot" >/dev/null
    printf writable >{self.state}/.storage-parent-probe
    rm {self.state}/.storage-parent-probe
    echo '{{"snapshot_mounted":true,"parent_writable":true}}'
    ;;
  restore)
    test -f "$temporary/storage-armed" || exit 0
    current=$(mounted)
    if [ -n "$current" ]; then
      test "$(identity)" = "$(cat "$temporary/storage-identity")"
      # A lost mount reply can precede the saved mount ID. The fresh owned path
      # and original inode still identify that one bind; refuse stacked mounts.
      test "$(printf '%s\\n' "$current" | wc -l)" = 1
      if [ -s "$temporary/storage-mount-id" ]; then
        test "$current" = "$(cat "$temporary/storage-mount-id")"
      fi
      umount "$snapshot"
    fi
    test -z "$(mounted)"
    # Automatic payment may already replace the snapshot after unmount.
    rm "$temporary/storage-armed"
    echo '{{"snapshot_mounted":false,"restored":true}}'
    ;;
  *) exit 2;;
esac
'''

    def storage_fault(self, action):
        require(action in ('arm', 'restore'), 'unknown storage operation')
        output = self.guarded(f'sh {self.temporary}/storage-fault.sh {action}')
        return json.loads(output) if output.strip() else {'snapshot_mounted': False, 'restored': True}


def retained(before, current):
    retained_finances(before, current, dict.fromkeys(before['n02']['credited'], 0))
    require(all(0 <= state['remaining'] <= before[name]['remaining']
                and state['remaining'] + state['authorized'] == 64
                for name, state in current.items()), 'storage fault reset a lifetime budget')


def validate_blocked(before, blocked, opposite, channel, before_hash, blocked_hash):
    retained(before, blocked)
    retained(blocked, opposite)
    require(before_hash == blocked_hash, 'failed signer replaced its saved snapshot')
    credit = before['n02']['credited'][channel]
    require(blocked['n01']['signed'][channel] * 1000 > credit
            and blocked['n02']['credited'][channel] == credit
            and opposite['n02']['credited'][channel] == credit,
            'blocked signer did not retain an uncredited durable authorization')
    other, = before['n03']['signed']
    require(opposite['n03']['signed'][other] > before['n03']['signed'][other]
            and opposite['n02']['credited'][other] >= opposite['n03']['signed'][other] * 1000,
            'unaffected buyer did not continue paying')


class SignerStorageRun(PaidWifiRun):
    stream = stream

    def __init__(self, args):
        super().__init__(args)
        self.evidence.update(storage_fault={}, physical_power_loss=False)
        self.evidence['harness_sha256']['wifi_signer_storage.py'] = digest(
            Path(__file__).read_bytes())

    def make_router(self, spec, index):
        kind = StorageRouter if index == 0 else Router
        return kind(spec, self.run, self.root, self.open_mesh)

    def profile_config(self, node):
        config = super().profile_config(node)
        config['terms'].update(fee_msat_per_kib=1, max_rate_msat_per_kib=1,
                               quote_max_units=QUOTE_UNITS)
        config['return_allowance'] = False
        return config

    def before_launch(self):
        self.evidence['storage_fault']['unfunded_probe'] = self.nodes['n01'].storage_probe
        self.save()
        super().before_launch()

    def client_hash(self):
        node = self.nodes['n01']
        return node.remote(['sha256sum', node.state + '/wallet/spilman-client.json']).decode().split()[0]

    def cohort(self, source, destination, label):
        result = self.stream(1024, 200, source=source, destination=destination)
        shape = {'stream_id': result['sender']['stream_id'], 'packet_count': 1024, 'payload_bytes': 1000}
        self.evidence.setdefault('streams', []).append({'source': source, 'destination': destination,
                                                       'label': label, **result})
        self.save()
        submitted(result['sender'], shape)
        received(result['receiver'], shape, self.nodes[source].npub, complete=True)

    def credited(self):
        current = self.finances()
        return current if payments_credited(current) else None

    def processes(self):
        return {name: {key: value for key, value in snapshot(node, name)['host_process'].items()
                       if key in ('host', 'pid', 'start_ticks')}
                for name, node in self.nodes.items()}

    def exercise(self):
        self.form_line()
        node = self.nodes['n01']
        try:
            for source, destination in (('n01', 'n03'), ('n03', 'n01')):
                self.ctl(source, 'buy', destination=self.nodes[destination].npub)
                self.cohort(source, destination, 'healthy')
            before = eventually('initial paid channels', self.credited, 30)
            original_channels(self.nodes, before)
            channel, = before['n01']['signed']
            row = self.evidence['storage_fault']
            row.update(before=before, client_before=self.client_hash(),
                       processes_before=self.processes())
            self.save()
            row['mount'] = node.storage_fault('arm')
            self.save()
            self.cohort('n01', 'n03', 'signer-blocked')

            def signer_failed():
                state = self.ctl('n01', 'status')
                error = state.get('last_error') or ''
                row['observed_error'] = error
                self.save()
                return error if error.startswith('payment signer failed: failed to write Spilman client store:') and 'os error 16' in error else None

            row['signer_error'] = eventually('native snapshot replacement failure', signer_failed, 30)
            row['blocked'] = self.finances()
            self.cohort('n03', 'n01', 'opposite-buyer')

            def other_paid():
                current = self.finances()
                other, = current['n03']['signed']
                return current if (current['n03']['signed'][other] > before['n03']['signed'][other]
                                   and current['n02']['credited'][other] >= current['n03']['signed'][other] * 1000) else None

            row['opposite'] = eventually('unaffected buyer payment', other_paid, 30)
            row['client_blocked'] = self.client_hash()
            validate_blocked(before, row['blocked'], row['opposite'], channel,
                             row['client_before'], row['client_blocked'])
            self.phase('blocked snapshot retained evidence while the opposite buyer kept paying')
            row['restoration'] = node.storage_fault('restore')
            self.save()

            def recovered():
                current = self.credited()
                return current if current and current['n02']['credited'][channel] >= row['blocked']['n01']['signed'][channel] * 1000 else None

            row['recovered'] = eventually('automatic original payment retry after snapshot unmount', recovered, 45)
            retained(before, row['recovered'])
            for source, destination in (('n01', 'n03'), ('n03', 'n01')):
                self.cohort(source, destination, 'recovered')
            row['final'] = eventually('final automatic payments', self.credited, 30)
            retained(before, row['final'])
            row['processes_after'] = self.processes()
            require(row['processes_after'] == row['processes_before'], 'storage recovery restarted a relay')
            row['passed'] = True
            self.phase('original channels recovered automatically without restart or another purchase')
        finally:
            signal.alarm(0)
            node.storage_fault('restore')
            self.collect()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('inventory', 'binary', 'mint-binary', 'mint-host', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--mint-address', required=True)
    args = parser.parse_args()
    args.mint_ssh_forward = False
    os.umask(0o077)

    def deadline(_signal, _frame):
        raise TimeoutError('router signer-storage acceptance exceeded its bounded window')

    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(600)
    SignerStorageRun(args).execute()


if __name__ == '__main__':
    main()
