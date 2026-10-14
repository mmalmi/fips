"""Shared guarded process interruption for physical account-recovery scenarios."""

from pathlib import Path

from .paid_relay import eventually
from .paid_settlement import require
from .paid_wifi import PaidWifiRun
from .wifi_measurements import snapshot
from .wifi_remote import digest
from .wifi_restart import crash_profile


class RouterAccountRecovery(PaidWifiRun):
    def __init__(self, args):
        super().__init__(args)
        self.crash_attempts = []
        self.samples = {}
        self.evidence.update(physical_power_loss=False, physical_process_interruption=True)
        for name in ('wifi_account_recovery.py', 'wifi_restart.py'):
            self.evidence['harness_sha256'][name] = digest(Path(__file__).with_name(name).read_bytes())

    def recovery_ready(self):
        return self.ready(line=True)

    def interruption_metadata(self):
        return {'processes_before': {name: row['host_process'] for name, row in self.samples.items()}}

    def interrupt_participants(self, *, exclude=()):
        evidence = self.evidence[self.interruption_key]
        evidence['crashes'] = {}
        for name, node in self.nodes.items():
            if name in exclude:
                continue
            # Save dispatch intent first; never repeat an uncertain signal.
            self.crash_attempts.append(name)
            evidence['crash_attempts'] = list(self.crash_attempts)
            self.save()
            evidence['crashes'][name] = crash_profile(node, self.samples[name])
            self.save()
        self.phase('selected relay processes stopped while the committed mint reply is withheld')

    def launch(self, name):
        node = self.nodes[name]
        node.start()
        after = eventually('original router identity after restart',
                           lambda: snapshot(node, name, native_counters=True), 60)
        old, new = self.samples[name]['host_process'], after['host_process']
        require(after['npub'] == node.npub and old['host'] == new['host']
                and self.restarted_epoch(name, old, new),
                'account recovery did not retain identity in a new process epoch')
        self.evidence.setdefault('restarted_processes', {})[name] = new
        self.save()

    def restarted_epoch(self, name, old, new):
        return new['start_ticks'] > old['start_ticks']

    def restore_controls(self):
        for name in self.crash_attempts:
            node = self.nodes[name]
            try:
                self.ctl(name, 'status')
            except RuntimeError:
                node.remote(['sh', node.temporary + '/guard.sh', 'stopped'])
                self.launch(name)
