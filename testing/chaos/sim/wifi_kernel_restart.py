"""Paid router recovery after an unsynced kernel reset, not a physical power cut."""

from pathlib import Path
import subprocess
import time

from .paid_relay import eventually
from .paid_settlement import require
from .restart_finances import recovered_exposure
from .wifi_discovery import ManagementMonitor
from .wifi_remote import BOOT_ID, BOOT_ID_PATTERN, baseline_restored, boot_id, digest
from .wifi_restart import sampled_process
from .wifi_restart_load import RestartLoadRun, main


def reboot_profile(node, before, old_boot):
    """Dispatch once; only a later changed boot ID proves that a reset occurred."""
    if not BOOT_ID_PATTERN.fullmatch(old_boot):
        raise ValueError('kernel reset requires a sampled boot identity')
    _, _, command = sampled_process(node, before)
    command += (f'test "$(cat {BOOT_ID})" = "{old_boot}"\n'
                'test -w /proc/sysrq-trigger\nowned\n'
                'printf b > /proc/sysrq-trigger\n')
    try:
        node.guarded(command, timeout=15)
    except (RuntimeError, subprocess.TimeoutExpired) as error:
        return {'reply': type(error).__name__, 'boot_change_required': True}
    return {'reply': 'returned', 'boot_change_required': True}


class KernelRestartRun(RestartLoadRun):
    def __init__(self, args):
        require(not any(getattr(args, flag, False) for flag in
                        ('frame_loss', 'active_restart', 'open_mesh')),
                'kernel reset is a separate saved-radio, between-stream experiment')
        super().__init__(args)
        self.evidence.update(kernel_cache_loss=True, automatic_service_boot=False)
        self.evidence['harness_sha256']['wifi_kernel_restart.py'] = digest(Path(__file__).read_bytes())

    def before_launch(self):
        super().before_launch()
        # Persist the initial accounts and saved system configuration before any
        # measured traffic. No explicit sync is performed at the crash boundary.
        for node in self.nodes.values():
            node.remote(['sync'])
        node = self.nodes['n02']
        node.remote('test -w /proc/sysrq-trigger && /etc/init.d/fips-relay enabled')
        self.evidence['initial_boot_id'] = boot_id(node)

    def monitor_nodes(self, nodes):
        previous = self.monitor
        previous.close()
        previous.check()
        self.monitor = ManagementMonitor(nodes)
        self.monitor.samples = previous.samples
        self.monitor.errors = previous.errors
        self.monitor.start()

    def recovered_boot(self):
        self.monitor.check()
        node, state = self.nodes['n02'], self.evidence['restart']
        try:
            current = boot_id(node)
            if current == state['old_boot_id']:
                return None
            if 'new_boot_id' not in state:
                state['new_boot_id'] = current
                node.created = node.guard_ready = False  # The old RAM guard died with the kernel.
            require(current == state['new_boot_id'], 'router reset more than once')
            baseline = node.baseline()
        except (RuntimeError, subprocess.TimeoutExpired):
            return None
        require(baseline_restored(baseline, self.original['n02'], self.original),
                'reboot changed the original router configuration or account')
        return baseline

    def resume_middle(self):
        node, state = self.nodes['n02'], self.evidence['restart']
        if not state.get('restaged'):
            require(not state.get('restage_attempted'), 'RAM staging was already attempted')
            state['restored_baseline'] = eventually('same router booted with original LAN and Wi-Fi',
                                                    self.recovered_boot, 180)
            require(node.remote(['sha256sum', node.config, node.state + '/identity.key']).decode()
                    == state['account_identity'], 'kernel reset changed candidate identity or configuration')
            state['stopped_journal'] = self.state_json('n02', 'seller/ledger.json')
            self.expected_lost = recovered_exposure(state['stopped_journal'])
            state['expected_lost_msat'] = self.expected_lost
            # A partial stage is retained for inspection, never adopted or overwritten.
            state['restage_attempted'] = True
            self.save()
            node.stage_runtime(self.args.binary.read_bytes())
            state['restaged'] = True
            self.monitor_nodes(self.nodes)
            state['management_resumed_at'] = time.monotonic()
            self.save()
        if not state.get('start_attempted'):
            state['start_attempted'] = True
            self.save()
            node.start()
        after = eventually('same paid account running after kernel reset', self.middle_sample, 60)
        require(after['npub'] == state['before']['npub'] == node.npub
                and after['host_process']['host'] == 'n02', 'kernel reset changed candidate identity')
        state['after'] = after
        self.save()

    def restart_middle(self, *, wait_for_recovery=True):
        require(wait_for_recovery, 'kernel reset cannot overlap an active test stream')
        node = self.nodes['n02']
        state = {
            'before': self.middle_sample(), 'old_boot_id': boot_id(node),
            'account_identity': node.remote(['sha256sum', node.config, node.state + '/identity.key']).decode(),
        }
        resets = self.evidence.setdefault('restarts', [])
        require(len(resets) < len(self.restart_rounds) and
                (not resets or resets[-1].get('completed_at')), 'previous reset is unresolved or reset limit reached')
        expected_boot = resets[-1]['new_boot_id'] if resets else self.evidence['initial_boot_id']
        require(state['old_boot_id'] == expected_boot, 'router already rebooted outside the test boundary')
        for name in ('process.log', 'guard.log'):
            prefix = 'before-reset-' if not resets else f'before-reset-{len(resets) + 1}-'
            (node.output / (prefix + name)).write_bytes(node.remote(['cat', node.temporary + '/' + name]))
        self.monitor_nodes({name: peer for name, peer in self.nodes.items() if name != 'n02'})
        state['management_paused_at'] = time.monotonic()
        self.restart_attempted = True
        state['attempted_at'] = time.monotonic()
        resets.append(state)
        self.evidence['restart'] = state
        self.save()  # Record intent before the single irreversible dispatch.
        state['dispatch'] = reboot_profile(node, state['before'], state['old_boot_id'])
        self.save()
        self.resume_middle()
        self.finish_restart()

    def restore_middle(self):
        if self.restart_attempted:
            self.resume_middle()  # Observe/recover only; never send a second reset.


if __name__ == '__main__':
    main(KernelRestartRun)
