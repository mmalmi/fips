"""An abrupt reboot resumes paid routing through the installed init/UCI service."""

import json
from pathlib import Path
import subprocess
import time

from .paid_relay import eventually
from .paid_settlement import require
from .restart_finances import recovered_exposure
from .wifi_boot_service import BootRouter, UCI
from .wifi_kernel_restart import KernelRestartRun, boot_id
from .wifi_mesh import profile
from .wifi_remote import digest
from .wifi_restart_load import main


class BootRestartRun(KernelRestartRun):
    allows_repeated_restarts = True

    def __init__(self, args):
        require(not getattr(args, 'repeat_restarts', False) or self.allows_repeated_restarts,
                'repeated boots are a separate experiment')
        super().__init__(args)
        for name in ('wifi_boot_restart.py', 'wifi_boot_service.py', 'wifi_measurements.py'):
            self.evidence['harness_sha256'][name] = digest(Path(__file__).with_name(name).read_bytes())

    @property
    def restart_rounds(self):
        return (1, 3, 5) if getattr(self.args, 'repeat_restarts', False) else super().restart_rounds

    @property
    def packets(self):
        # Leave room for three lost durable windows inside the original channel.
        return super().packets // 2 if getattr(self.args, 'repeat_restarts', False) else super().packets

    def make_router(self, spec, index):
        if index == 1:
            return BootRouter(spec, self.run, self.root, self.open_mesh)
        return super().make_router(spec, index)

    def before_launch(self):
        super().before_launch()
        self.nodes['n02'].arm_boot()
        self.evidence.update(automatic_service_boot=True, original_services_replaced=True)
        self.save()

    def restart_middle(self, *, wait_for_recovery=True):
        # Traffic is paused here. The saved pre-reset allowance predicts the loss
        # independently of the daemon that will reopen and update it at boot.
        self.boot_journal = self.state_json('n02', 'seller/ledger.json')
        self.boot_loss = recovered_exposure(self.boot_journal, self.expected_lost)
        super().restart_middle(wait_for_recovery=wait_for_recovery)

    def recovered_boot(self):
        self.monitor.check()
        node, state = self.nodes['n02'], self.evidence['restart']
        try:
            current = boot_id(node)
        except (RuntimeError, subprocess.TimeoutExpired):
            return None
        if current == state['old_boot_id']:
            return None
        if 'new_boot_id' not in state:
            state['new_boot_id'] = current
            node.guard_ready = False
        require(current == state['new_boot_id'], 'router reset more than once')
        observed = node.observe_service()
        original = self.original['n02']
        hashes = [line for line in original['hashes'].splitlines() if line.split()[1] != UCI]
        require(node.remote(['sha256sum', *[line.split()[1] for line in hashes]]).decode().splitlines() == hashes,
                'boot changed original accounts or networking')
        require(profile(node.remote, node.interface) == node.mesh, 'boot changed the mesh interface')
        wireless = json.loads(node.remote(['ubus', 'call', 'network.wireless', 'status']))
        aps = [i['ifname'] for radio in wireless.values() if radio['up']
               for i in radio.get('interfaces', []) if i['config']['mode'] == 'ap']
        require(sorted(aps) == original['access_points_up'], 'boot did not restore access points')
        node.management_check(heartbeat=False)
        node.remote(['uclient-fetch', '-q', '-T', '5', '-O', '/dev/null', 'https://example.com'], timeout=10)
        return observed

    def resume_middle(self):
        node, state = self.nodes['n02'], self.evidence['restart']
        if state.get('after'):
            return
        require(not state.get('restage_attempted'), 'RAM observation staging already attempted')
        observed = eventually('installed service automatically reopened the paid account', self.recovered_boot, 180)
        state.update(automatic_boot_observed=observed, pre_reset_journal=self.boot_journal,
                     expected_lost_msat=self.boot_loss, boot_observed_at=time.monotonic())
        self.expected_lost = self.boot_loss
        require(node.remote(['sha256sum', node.config, node.state + '/identity.key']).decode()
                == state['account_identity'], 'boot changed the paid identity or configuration')
        state['restage_attempted'] = True
        self.save()
        # The daemon is already running under procd. Only stage observation and
        # cleanup tools; never launch or initialize another paid process.
        node.stage_runtime(self.args.binary.read_bytes())
        node.boot_observed = True
        node.process_binary = node.original_binary
        node.write(node.temporary + '/process.pid', str(observed['instance']['pid']).encode())
        node.write(node.temporary + '/process.log', b'')
        state['restaged'] = True
        self.monitor_nodes(self.nodes)
        state['management_resumed_at'] = time.monotonic()
        state['after'] = self.middle_sample()
        require(state['after']['npub'] == state['before']['npub'] == node.npub,
                'automatic service boot replaced the paid identity')
        self.save()


if __name__ == '__main__':
    main(BootRestartRun)
