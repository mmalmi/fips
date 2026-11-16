"""Installed paid-service boot and forwarding while the original mint is stalled."""

from pathlib import Path
import shlex
import time

from .paid_settlement import require
from .remote_mint import RemoteMint
from .wifi_boot_restart import BootRestartRun
from .wifi_remote import digest
from .wifi_restart_load import main


class BootMintOutageRun(BootRestartRun):
    allows_repeated_restarts = False
    def __init__(self, args):
        super().__init__(args)
        require(isinstance(self.mint, RemoteMint), 'mint outage requires the owned Linux mint')
        self.evidence['harness_sha256']['wifi_boot_mint_outage.py'] = digest(Path(__file__).read_bytes())
        self.evidence['mint_outage'] = {'samples': []}

    def stalled(self):
        observed = self.mint.stall_status()
        require(observed['phase'] == 'stalled', 'mint recovered before the paid outage workload ended')
        self.evidence['mint_outage']['samples'].append({**observed, 'observed_at': time.monotonic()})
        return observed

    def unavailable(self):
        self.stalled()
        result = {}
        for name, node in self.nodes.items():
            command = ('uclient-fetch -q -T 2 -O /dev/null '
                       + shlex.quote(self.mint_url + '/v1/info')
                       + '; status=$?; printf "%s" "$status"')
            result[name] = int(node.remote('set +e; ' + command, timeout=6))
            require(result[name] != 0, 'stalled mint answered a router HTTP request')
        self.stalled()
        return result

    def restart_middle(self, *, wait_for_recovery=True):
        outage = self.evidence['mint_outage']
        outage['attempted_at'] = time.monotonic()
        self.save()
        outage['started'] = self.mint.stall()
        outage['before_reset'] = self.unavailable()
        self.save()
        super().restart_middle(wait_for_recovery=wait_for_recovery)
        outage['after_boot'] = self.unavailable()
        self.save()

    def middle_sample(self):
        if self.mint.stall_attempted and 'resumed' not in self.evidence['mint_outage']:
            self.stalled()
        return super().middle_sample()

    def restore_middle(self):
        # Restore the mint before financial cleanup, including an ambiguous launch.
        outage = self.evidence['mint_outage']
        try:
            if self.mint.stall_attempted and 'resumed' not in outage:
                outage['resumed'] = self.mint.release_stall()
                outage['report_after_outage'] = self.mint.request({'type': 'report'})
                self.save()
        finally:
            super().restore_middle()

    def exercise(self):
        super().exercise()
        outage = self.evidence['mint_outage']
        require(outage['resumed']['reason'] == 'released', 'mint outage expired before deliberate recovery')
        require(outage['started']['pid'] == outage['resumed']['pid']
                and outage['started']['start_ticks'] == outage['resumed']['start_ticks'],
                'mint outage replaced the original process')


if __name__ == '__main__':
    main(BootMintOutageRun)
