"""Operator power cut while a committed funding or settlement reply is held.

Reuses the real mint barrier and original funding/recovery assertions. The test
process is frozen without sync while the operator reaches the adapter. Kernel
writeback can continue: this tests recovery at a held application boundary, not
power removal during an individual flash write. No software reboot is issued.
"""

import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import time

from .paid_relay import eventually, write_json
from .paid_settlement import require
from .wifi_funding import FundingRun
from .wifi_kernel_restart import KernelRestartRun, boot_id
from .wifi_remote import baseline_restored, digest
from .wifi_restart import pause_profile, sampled_process
from .wifi_settlement import SettlementRun


def confirmed_cycle(state, receipt):
    expected = {key: state[key] for key in ('run', 'node', 'old_boot_id')}
    expected['power_disconnected'] = True
    require(receipt == expected and receipt.get('power_disconnected') is True,
            'operator confirmation does not match this power-cut request')
    return (state.get('unreachable_at') is not None
            and state.get('new_boot_id') not in (None, state['old_boot_id']))


class PowerCutRecovery:
    """Share operator evidence and account-preserving recovery across boundaries."""

    monitor_nodes = KernelRestartRun.monitor_nodes
    operator_wait_seconds = 240
    restage_wait_seconds = 90

    def __init__(self, args):
        super().__init__(args)
        self.evidence.update(physical_power_loss=False, manual_power_cut_requested=True)
        self.evidence['harness_sha256']['wifi_power_cut.py'] = digest(Path(__file__).read_bytes())

    def ctl(self, node, kind, **fields):
        if kind == self.power_cut_command:
            fields['operation_timeout'] = 330
        return super().ctl(node, kind, **fields)

    def interrupt_participants(self):
        require('manual_power_cut' not in self.evidence, 'power-cut request already attempted')
        name = self.power_cut_node
        node = self.nodes[name]
        state = {
            'run': self.run, 'node': name, 'host': node.host,
            'old_boot_id': boot_id(node), 'requested_at': time.time(),
            'account_identity': node.remote(['sha256sum', node.config, node.state + '/identity.key']).decode(),
            'boundary': self.power_cut_boundary,
            'application_frozen': False, 'explicit_sync_at_boundary': False,
        }
        self.evidence['manual_power_cut'] = state
        self.save()
        # A lost pause reply is retained as an uncertain attempt; do not signal twice.
        pause_profile(node, self.samples[name])
        state['application_frozen'] = True
        self.save()
        try:
            super().interrupt_participants(exclude={name})
            for filename in ('process.log', 'guard.log'):
                (node.output / ('before-power-cut-' + filename)).write_bytes(
                    node.remote(['cat', node.temporary + '/' + filename]))
            self.monitor_nodes({key: peer for key, peer in self.nodes.items() if key != name})
            request = {key: state[key] for key in ('run', 'node', 'host', 'old_boot_id', 'boundary')}
            request['confirmation_file'] = 'power-cut-confirmation.json'
            request['wait_seconds'] = self.operator_wait_seconds
            write_json(self.root / 'power-cut-request.json', request)
            self.phase(state['boundary'] + ': awaiting operator disconnect/reconnect of the named adapter')
            self.wait_for_power_cycle(state)
            self.restage_after_power_cut(state)
            self.crash_attempts.append(name)
            self.evidence['physical_power_loss'] = True
            self.phase('operator-confirmed power cut observed; original account retained for recovery')
        except Exception:
            # If no new boot was observed, release a still-live paused candidate.
            # If unreachable or its epoch changed, preserve it for deliberate recovery.
            if 'new_boot_id' not in state:
                try:
                    if boot_id(node) == state['old_boot_id']:
                        pause_profile(node, self.samples[name], resume=True)
                        state['resumed_without_power_cut'] = True
                except (RuntimeError, subprocess.TimeoutExpired):
                    state['resume_unconfirmed'] = True
            self.save()
            raise

    def wait_for_power_cycle(self, state):
        node = self.nodes[self.power_cut_node]
        deadline = time.monotonic() + self.operator_wait_seconds
        while time.monotonic() < deadline:
            self.monitor.check()
            try:
                current = boot_id(node)
            except (RuntimeError, subprocess.TimeoutExpired):
                if 'unreachable_at' not in state:
                    state['unreachable_at'] = time.time()
                    self.save()
            else:
                if current == state['old_boot_id']:
                    require('new_boot_id' not in state, 'router returned to an earlier boot identity')
                    try:
                        node.management_check()
                        _, _, command = sampled_process(node, self.samples[self.power_cut_node])
                        node.guarded(command + 'test "$process_state" = T\n')
                    except (RuntimeError, subprocess.TimeoutExpired):
                        # Power may disappear between the boot read and heartbeat.
                        # A reachable unchanged boot is an actual guard failure.
                        try:
                            observed = boot_id(node)
                        except (RuntimeError, subprocess.TimeoutExpired):
                            observed = None
                        require(observed != current, 'live candidate guard failed before power cut')
                        state.setdefault('unreachable_at', time.time())
                        self.save()
                        continue
                else:
                    require(current == state.get('new_boot_id', current), 'router rebooted more than once')
                    if 'new_boot_id' not in state:
                        state['new_boot_id'] = current
                        node.created = node.guard_ready = False
                        self.save()
                path = self.root / 'power-cut-confirmation.json'
                if path.exists():
                    require(not path.is_symlink(), 'operator confirmation must be a regular local file')
                    with path.open('rb') as stream:
                        raw = stream.read(4097)
                    require(len(raw) <= 4096, 'operator confirmation is too large')
                    receipt = json.loads(raw)
                    if confirmed_cycle(state, receipt):
                        state['operator_confirmation'] = receipt
                        self.save()
                        return
            time.sleep(0.5)
        raise RuntimeError('manual power-cut confirmation/outage/new-boot deadline expired')

    def restage_after_power_cut(self, state):
        node = self.nodes[self.power_cut_node]
        require(confirmed_cycle(state, state['operator_confirmation']), 'power cut is not confirmed')
        require(not state.get('restage_attempted'), 'power-cut restaging already attempted')

        def original_ready():
            self.monitor.check()
            require(boot_id(node) == state['new_boot_id'], 'router rebooted again during recovery')
            baseline = node.baseline()
            require(baseline_restored(baseline, self.original[self.power_cut_node], self.original),
                    'power cut changed the original router configuration or account')
            return baseline

        state['restored_baseline'] = eventually('original router service after physical power cut',
                                                original_ready, self.restage_wait_seconds)
        require(node.remote(['sha256sum', node.config, node.state + '/identity.key']).decode()
                == state['account_identity'], 'power cut changed candidate identity or configuration')
        state['restage_attempted'] = True
        self.save()
        node.stage_runtime(self.args.binary.read_bytes())
        excluded = self.power_cut_excluded_peer
        node.install_filter(self.nodes[excluded].mac if excluded is not None else None)
        self.monitor_nodes(self.nodes)
        state['restaged'] = True
        self.save()

    def restarted_epoch(self, name, old, new):
        if name != self.power_cut_node:
            return super().restarted_epoch(name, old, new)
        state = self.evidence['manual_power_cut']
        return (state.get('restaged') and state['old_boot_id'] != state['new_boot_id']
                and boot_id(self.nodes[name]) == state['new_boot_id'])


class PowerCutFundingRun(PowerCutRecovery, FundingRun):
    """Recover original first funding after an operator-confirmed router power cut."""

    power_cut_node = 'n01'
    power_cut_excluded_peer = 'n03'
    power_cut_command = 'buy'
    power_cut_boundary = 'original funding committed at mint, reply withheld'

    def __init__(self, args):
        require(args.initial, 'manual power cut requires the initial funding scenario')
        super().__init__(args)


class PowerCutSettlementRun(PowerCutRecovery, SettlementRun):
    """Recover the original committed close after a physical cut of its provider."""

    power_cut_node = 'n02'
    power_cut_excluded_peer = None
    power_cut_command = 'settle'
    power_cut_boundary = 'original settlement committed at mint, reply withheld'
    # Controller service expiry is halfway to the sender's refund deadline.
    channel_lifetime_seconds = 1440
    expiry_wait_seconds = 750
    provider_recovery_seconds = 180

    def check_reverse_expiry(self, stage, journal, minimum_seconds):
        funding = list(journal['funding'].values())
        require(len(funding) == 1, 'expected one original reverse channel')
        expires = funding[0]['funded']['terms']['expires_unix']
        # The provider's clock triggers automatic expiry, including after boot.
        now = int(self.nodes[self.power_cut_node].remote(['date', '+%s']).strip())
        remaining = expires - now
        self.evidence.setdefault('reverse_expiry_margins', {})[stage] = {
            'provider_unix': now, 'expires_unix': expires,
            'remaining_seconds': remaining, 'minimum_seconds': minimum_seconds,
        }
        self.save()
        require(remaining >= minimum_seconds, 'reverse channel expires too soon for isolated close recovery')

    def interrupt_settlement(self, anchor):
        # Keep independent reverse expiry out of the strict no-resubmission check.
        minimum = (self.operator_wait_seconds + self.restage_wait_seconds
                   + self.provider_recovery_seconds + 90)
        self.check_reverse_expiry('before_arm', self.state_json('n03', 'controller/controller.json'), minimum)
        return super().interrupt_settlement(anchor)

    def launch(self, name):
        if name == self.power_cut_node and hasattr(self, 'reverse_pending'):
            try:
                self.check_reverse_expiry('before_provider_restart', self.reverse_pending,
                                          self.provider_recovery_seconds)
            except Exception:
                self.evidence['automatic_recovery_deferred'] = 'reverse channel expiry margin unverified after boot'
                self.save()
                raise
        super().launch(name)

    def restore_controls(self):
        require(not self.evidence.get('automatic_recovery_deferred'),
                'preserving original accounts and mint for deliberate recovery after expiry-margin rejection')
        super().restore_controls()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('inventory', 'binary', 'mint-binary', 'mint-host', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--mint-address', required=True)
    boundary = parser.add_mutually_exclusive_group(required=True)
    boundary.add_argument('--initial', action='store_true', help='cut the first-funding buyer n01')
    boundary.add_argument('--settlement', action='store_true', help='cut the committed-close provider n02')
    args = parser.parse_args()
    args.mint_ssh_forward = args.open_mesh = False
    os.umask(0o077)

    def deadline(_signal, _frame):
        raise TimeoutError('physical power-cut acceptance exceeded its bounded window')

    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(900 if args.initial else 1200)
    try:
        (PowerCutFundingRun if args.initial else PowerCutSettlementRun)(args).execute()
    finally:
        signal.alarm(0)


if __name__ == '__main__':
    main()
