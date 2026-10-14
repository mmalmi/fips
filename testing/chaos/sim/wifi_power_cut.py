"""Operator power cut during the first committed funding operation.

Reuses the real mint barrier and original funding/recovery assertions. The test
process is frozen without sync while the operator reaches the adapter. Kernel
writeback can continue: this tests recovery at a held application boundary, not
power removal during an individual flash write. No software reboot is issued.
"""

import json
from pathlib import Path
import subprocess
import time

from .paid_relay import eventually, write_json
from .paid_settlement import require
from .wifi_funding import FundingRun, main
from .wifi_kernel_restart import KernelRestartRun, boot_id
from .wifi_remote import baseline_restored, digest
from .wifi_restart import pause_profile, sampled_process


def confirmed_cycle(state, receipt):
    expected = {key: state[key] for key in ('run', 'node', 'old_boot_id')}
    expected['power_disconnected'] = True
    require(receipt == expected and receipt.get('power_disconnected') is True,
            'operator confirmation does not match this power-cut request')
    return (state.get('unreachable_at') is not None
            and state.get('new_boot_id') not in (None, state['old_boot_id']))


class PowerCutFundingRun(FundingRun):
    """Recover original first funding after an operator-confirmed router power cut."""

    monitor_nodes = KernelRestartRun.monitor_nodes

    def __init__(self, args):
        require(args.initial, 'manual power cut requires the initial funding scenario')
        super().__init__(args)
        self.evidence.update(physical_power_loss=False, manual_power_cut_requested=True)
        self.evidence['harness_sha256']['wifi_power_cut.py'] = digest(Path(__file__).read_bytes())

    def ctl(self, node, kind, **fields):
        if kind == 'buy':
            fields['operation_timeout'] = 330
        return super().ctl(node, kind, **fields)

    def interrupt_participants(self):
        require('manual_power_cut' not in self.evidence, 'power-cut request already attempted')
        node = self.nodes['n01']
        state = {
            'run': self.run, 'node': 'n01', 'host': node.host,
            'old_boot_id': boot_id(node), 'requested_at': time.time(),
            'account_identity': node.remote(['sha256sum', node.config, node.state + '/identity.key']).decode(),
            'boundary': 'original funding committed at mint, reply withheld',
            'application_frozen': False, 'explicit_sync_at_boundary': False,
        }
        self.evidence['manual_power_cut'] = state
        self.save()
        # A lost pause reply is retained as an uncertain attempt; do not signal twice.
        pause_profile(node, self.samples['n01'])
        state['application_frozen'] = True
        self.save()
        try:
            super().interrupt_participants(exclude={'n01'})
            for name in ('process.log', 'guard.log'):
                (node.output / ('before-power-cut-' + name)).write_bytes(
                    node.remote(['cat', node.temporary + '/' + name]))
            self.monitor_nodes({name: peer for name, peer in self.nodes.items() if name != 'n01'})
            request = {key: state[key] for key in ('run', 'node', 'host', 'old_boot_id', 'boundary')}
            request['confirmation_file'] = 'power-cut-confirmation.json'
            request['wait_seconds'] = 240
            write_json(self.root / 'power-cut-request.json', request)
            self.phase('first funding held: awaiting operator disconnect/reconnect of the named adapter')
            self.wait_for_power_cycle(state)
            self.restage_after_power_cut(state)
            self.crash_attempts.append('n01')
            self.evidence['physical_power_loss'] = True
            self.phase('operator-confirmed power cut observed; original account retained for recovery')
        except Exception:
            # If no new boot was observed, release a still-live paused candidate.
            # If unreachable or its epoch changed, preserve it for deliberate recovery.
            if 'new_boot_id' not in state:
                try:
                    if boot_id(node) == state['old_boot_id']:
                        pause_profile(node, self.samples['n01'], resume=True)
                        state['resumed_without_power_cut'] = True
                except (RuntimeError, subprocess.TimeoutExpired):
                    state['resume_unconfirmed'] = True
            self.save()
            raise

    def wait_for_power_cycle(self, state):
        node = self.nodes['n01']
        deadline = time.monotonic() + 240
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
                        _, _, command = sampled_process(node, self.samples['n01'])
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
        node = self.nodes['n01']
        require(confirmed_cycle(state, state['operator_confirmation']), 'power cut is not confirmed')
        require(not state.get('restage_attempted'), 'power-cut restaging already attempted')

        def original_ready():
            self.monitor.check()
            require(boot_id(node) == state['new_boot_id'], 'router rebooted again during recovery')
            baseline = node.baseline()
            require(baseline_restored(baseline, self.original['n01'], self.original),
                    'power cut changed the original router configuration or account')
            return baseline

        state['restored_baseline'] = eventually('original router service after physical power cut',
                                                original_ready, 90)
        require(node.remote(['sha256sum', node.config, node.state + '/identity.key']).decode()
                == state['account_identity'], 'power cut changed candidate identity or configuration')
        state['restage_attempted'] = True
        self.save()
        node.stage_runtime(self.args.binary.read_bytes())
        node.install_filter(self.nodes['n03'].mac)
        self.monitor_nodes(self.nodes)
        state['restaged'] = True
        self.save()

    def restarted_epoch(self, name, old, new):
        if name != 'n01':
            return super().restarted_epoch(name, old, new)
        state = self.evidence['manual_power_cut']
        return (state.get('restaged') and state['old_boot_id'] != state['new_boot_id']
                and boot_id(self.nodes[name]) == state['new_boot_id'])


if __name__ == '__main__':
    main(PowerCutFundingRun)
