"""Recover automatic payments after a native wallet commit fails on OpenWrt."""

import argparse
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
from .wifi_storage_faults import SnapshotRouter, VolumeRouter


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
        self.evidence.update(storage_fault={'kind': self.nodes['n01'].fault_kind}, physical_power_loss=False)
        self.evidence['harness_sha256']['wifi_signer_storage.py'] = digest(
            Path(__file__).read_bytes())
        self.evidence['harness_sha256']['wifi_storage_faults.py'] = digest(
            Path(__file__).with_name('wifi_storage_faults.py').read_bytes())

    def make_router(self, spec, index):
        if index == 0 and getattr(self.args, 'volume_image', None):
            return VolumeRouter(spec, self.run, self.root, self.open_mesh,
                                image=self.args.volume_image)
        kind = SnapshotRouter if index == 0 else Router
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
                return error if error.startswith('payment signer failed: failed to write Spilman client store:') and f'os error {node.storage_errno}' in error else None

            row['signer_error'] = eventually('native wallet commit failure', signer_failed, 30)
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

            row['recovered'] = eventually('automatic original payment retry after storage recovery', recovered, 45)
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
    parser.add_argument('--volume-image', type=Path,
                        help='fresh 8 MiB ext4 image for a full-wallet-filesystem fault')
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
