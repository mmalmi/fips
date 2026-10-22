"""Real retained receipts and spent receiver cleanup on the guarded radio line.

A--R--B uses native radio; an independent payer and destination use explicit LAN
UDP edges into R and B. Every proof is created by ordinary mint/wallet commands.
"""

from functools import partial
import json
from pathlib import Path
import signal
import shutil
from types import SimpleNamespace

from .paid_finances import financial_snapshot
from .paid_relay import eventually
from .paid_settlement import check_mint, collect_settled_wallets, require
from .receiver_history import circulate, WALLET_BYTES
from .remote_mint import RemoteMint
from .wifi_diamond_checks import listener
from .wifi_discovery import WifiRun
from .wifi_profiles import configure_stopped
from .wifi_remote import digest
from .wifi_retirement import RetirementRun
from .wifi_retirement_purchase import PurchaseRetirementRun
from . import wifi_receiver_custody as custody
from .wifi_receiver_workload import ReceiverWorkload, CHANNEL_LIFETIMES

INITIAL = {'n01': 2048, 'n02': 0, 'n03': 0, 'source': 1024, 'destination': 0}
LIMITS = {'n01': 960, 'n02': 1024, 'n03': 32, 'source': 64, 'destination': 32}
SNAPSHOT_BUDGET = 2 * 1024 * 1024 * 1024
RECOVERY_RESERVE = 512 * 1024 * 1024


class ReceiverRetirementRun(ReceiverWorkload, PurchaseRetirementRun):
    auxiliary_hosts = {'source': 'n01', 'destination': 'n03'}
    expected_links = {'n01': {'n02': 'ethernet'},
                      'n02': {'n01': 'ethernet', 'n03': 'ethernet', 'source': 'udp'},
                      'n03': {'n02': 'ethernet', 'destination': 'udp'},
                      'source': {'n02': 'udp'}, 'destination': {'n03': 'udp'}}
    quote_max_units = 4 * 1024 * 1024

    def __init__(self, args):
        super().__init__(args)
        self.intents, self.reports, self.owners, self.providers = {}, {}, {}, {}
        self.old, self.old_inputs, self.operations, self.held_nodes = set(), set(), set(), []
        self.custody_root = self.root / 'custody'
        self.custody_root.mkdir(mode=0o700)
        self.snapshot_count = 0
        self.snapshot_bytes = 0
        self.snapshot_budget_refused = self.recovering = False
        require(shutil.disk_usage(self.root).free >= SNAPSHOT_BUDGET + 256 * 1024 * 1024,
                'receiver fixture requires its bounded snapshot budget and temporary read headroom before funding')
        self.stopped_names = set(INITIAL)
        self.retained_history = None
        self.evidence.update(receiver_history={}, physical_power_loss=False,
                             sqlite_hold_sha256=digest(args.sqlite_hold.read_bytes()),
                             cleanup_deadline_seconds=35, traffic_packets=84,
                             traffic_rate_pps=3, traffic_payload_bytes=1000,
                             synthetic_profile_equivalence=False, history_wallet_command_timeout_seconds=330)
        for name in ('wifi_receiver_retirement.py', 'wifi_receiver_workload.py',
                     'wifi_receiver_custody.py', 'wifi_receiver_window.py', 'wifi_receiver_observer.py',
                     'wifi_receiver_numeric.py', 'wifi_authorization_trace.py', 'receiver_history.py', 'wifi_retirement.py'):
            self.evidence['harness_sha256'][name] = digest(Path(__file__).with_name(name).read_bytes())

    @property
    def buyer_budget(self):
        return 2048

    def budget(self, name):
        return 2048 if name == 'n01' else 1024

    def create_mint(self, args):
        require(args.mint_host, 'receiver history requires one explicit remote test mint')
        return RemoteMint(json.loads(args.mint_host.read_text()), args.mint_binary,
                          self.run, self.root, args.mint_address,
                          max_issued_sat=3072, receiver_history=True)

    def initial_balances(self):
        return INITIAL.copy()

    def terms(self, name, config):
        config['return_allowance'] = False
        config['terms'].update(billing='forwarding_data', buyer_budget_sat=self.budget(name),
                               fee_msat_per_kib=256 if name in ('n02', 'n03') else 32,
                               max_rate_msat_per_kib=2048, quote_max_units=self.quote_max_units,
                               # The paced 960-sat setup exceeds a 60-second quote.
                               # Onward setup also needs time for bounded restart recovery.
                               quote_lifetime_secs=360 if name == 'n02' else 180 if name == 'n03' else 60,
                               wallet_capacity_bytes=WALLET_BYTES)
        config['terms']['controller'].update(channel_lifetime_secs=CHANNEL_LIFETIMES.get(name, 120),
            channel_capacity_sat=960 if name in ('n01', 'n02') else 64 if name == 'source' else 32,
            max_locked_sat=LIMITS[name], max_wallet_spend_sat=LIMITS[name], max_funding_overhead_sat=0)
        if name == 'n02':
            config['terms'].update(window_msat=64_000, grace_msat=64_000)
        config['funding_request_budget'] = {'burst': 128, 'requests_per_minute': 60_000}
        return config

    def profile_config(self, node):
        name, = [name for name, profile in self.nodes.items() if node is profile]
        config = self.terms(name, RetirementRun.profile_config(self, node))
        if name in ('n02', 'n03'):
            config['transports']['udp'] = self.udp_config(name)
        return config

    def udp_config(self, name):
        config = super().udp_config(name)
        # Pin isolated listeners across the stopped custody observations.
        # A collision fails startup before any replacement funding is possible.
        self.udp_port = 20000 + int(self.run[:6], 16) % 30000
        config['bind_addr'] = self.addresses[name] + ':' + str(self.udp_port)
        return config

    def stop_profile(self, name):
        profile = self.participants()[name]
        getattr(profile, 'owner', profile).stop(profile)
        self.stopped_names.add(name)

    def snapshot(self, name, label):
        require(name in self.stopped_names, 'custody copy requires a stopped exact candidate')
        self.monitor.check()
        limit = SNAPSHOT_BUDGET if self.recovering or self.snapshot_budget_refused else SNAPSHOT_BUDGET - RECOVERY_RESERVE
        if self.snapshot_bytes + custody.MAX_SNAPSHOT_BYTES > limit:
            self.snapshot_budget_refused = True
            self.evidence['receiver_history']['snapshot_budget_refused'] = True
            self.save()
            raise RuntimeError('snapshot evidence budget reached; retain originals and reserve remaining space for recovery')
        self.snapshot_count += 1
        archive = custody.saved(self.participants()[name], self.custody_root,
                                f'{self.snapshot_count:04d}-{name}-{label}')
        self.snapshot_bytes += archive.stat().st_size
        self.evidence['receiver_history']['snapshot_disk'] = {
            'bytes': self.snapshot_bytes, 'maximum_bytes': SNAPSHOT_BUDGET,
            'recovery_reserve_bytes': RECOVERY_RESERVE, 'files': self.snapshot_count}
        self.save()
        return archive

    def stop_snapshot(self, name, label):
        self.stop_profile(name)
        return self.snapshot(name, label)

    def restart(self, name):
        require(name in self.stopped_names, 'never duplicate an existing candidate launch')
        self.participants()[name].start()
        self.stopped_names.remove(name)
        eventually('same guarded receiver profile resumed', lambda: self.ctl(name, 'status'), 45)
        eventually('same five-profile radio topology resumed', self.fork_ready, 90)

    def before_launch(self):
        for name, host in self.auxiliary_hosts.items():
            profile = self.extra[name]
            config = self.terms(name, RetirementRun.profile_config(self, self.nodes[host]))
            config.update(state_directory=profile.state, transports={'udp': self.udp_config(host)})
            config['transports']['udp']['bind_addr'] = self.addresses[host] + ':' + str(self.udp_port + 1)
            profile.prepare(config)
        for node in self.nodes.values():
            node.remote(['uclient-fetch', '-q', '-T', '5', '-O', '/dev/null', self.mint_url + '/v1/info'])
        for name, profile in self.participants().items():
            initial = profile.control('balance', action='wallet')
            require(initial['balance_sat'] == 0 and initial['mint_url'] == self.mint_url,
                    'receiver scenario requires fresh empty wallets')
            if INITIAL[name]:
                grant = self.mint.request({'type': 'issue', 'id': name, 'amount_sat': INITIAL[name]})
                require(grant['amount_sat'] == INITIAL[name] and grant['mint_url'] == self.mint_url,
                        'original bounded test grant changed')
                profile.control('import', action='wallet', token=grant['token'])
            require(profile.control('balance', action='wallet')['balance_sat'] == INITIAL[name],
                    'initial account allocation changed')
        check_mint(self.mint.request({'type': 'report'}), 0, issued_sat=3072)

        def record(value):
            self.evidence['receiver_history']['setup'] = value
            self.save()

        try:
            self.evidence['receiver_history']['setup_result'] = circulate(
                [SimpleNamespace(state=node.state, export_saved=node.export_saved,
                                 control=partial(node.control, operation_timeout=330))
                 for node in (self.nodes['n01'], self.nodes['n02'])],
                lambda: custody.counts(self.snapshot('n02', 'circulation')), record,
                self.args.receiver_history_rows, setup_seconds=6 * 3600,
                before_recovery=self.wait_for_history_wallets)
            archives = {name: self.snapshot(name, 'history-ready') for name in INITIAL}
            self.evidence['receiver_history']['setup_audit'] = custody.audit(archives, self.mint_url, 3072)
            self.retained_history = custody.retained(archives['n02'], self.args.receiver_history_rows)
            self.evidence['receiver_history']['retained'] = self.retained_history
            self.phase('original circulation returned all value; real receipt history audited')
        except Exception:
            # Only collect after ordinary circulation itself returned the borrowed
            # original. Otherwise preserve the pending tuple/token and live mint.
            if self.evidence['receiver_history'].get('setup', {}).get('returned_original_value'):
                self.collect_stopped({})
            raise

    def wait_for_history_wallets(self):
        # Losing SSH does not stop its remote wallet command. Let that original
        # owner finish before retrying the saved export/import identity.
        for node in (self.nodes['n01'], self.nodes['n02']):
            node.remote(f'''set -eu
test -f {node.state}/owner.lock
exec 9<>{node.state}/owner.lock
for attempt in $(seq 1 330); do
  if flock -n -x 9; then flock -u 9; exit 0; fi
  sleep 1
done
exit 1
''', timeout=340)

    def discovery_adapter(self, name, adapters):
        if name in ('n02', 'n03'):
            udp, = [item for item in adapters if item['type'] == 'udp']
            self.listeners[name] = listener(udp['local_addr'], self.addresses[name])
            adapters = [item for item in adapters if item['type'] != 'udp']
        return WifiRun.discovery_adapter(self, name, adapters)

    def assert_finances(self):
        current = eventually('consistent original receiver financial policy', self.finances)
        for name, row in current.items():
            require(not row['funding'] and not row['signed'] and not row['credited']
                    and not any(row['budget'].values()) and row['remaining'] == self.budget(name),
                    'radio discovery created financial authority')
        return current

    def form_line(self):
        self.stopped_names.difference_update(self.nodes)
        WifiRun.form_line(self)
        for name, peer in (('source', 'n02'), ('destination', 'n03')):
            profile = self.extra[name]
            configure_stopped(profile, neighbors=[{'npub': self.nodes[peer].npub,
                'addresses': [{'transport': 'udp', 'addr': self.listeners[peer]}]}])
            profile.start()
            self.stopped_names.remove(name)
            eventually('same bounded auxiliary profile ready', lambda: self.ctl(name, 'status'), 45)
            adapter, = profile.native({'command': 'show_transports'})['data']['transports']
            self.listeners[name] = listener(adapter['local_addr'], self.addresses[self.auxiliary_hosts[name]])
        self.phase('independent payer reaches the receiver over UDP; onward forwarding uses radio',
                   topology=eventually('exact five-profile receiver topology', self.fork_ready, 90))

    def collect_stopped(self, settled):
        self.recovering = True
        archives = {name: self.stop_snapshot(name, 'pre-collection') for name in INITIAL}
        self.evidence['receiver_history']['final_audit'] = custody.audit(archives, self.mint_url, 3072)
        if self.retained_history is not None:
            custody.unchanged(archives['n02'], self.retained_history)
        starts = {name: custody.export_start(archive) for name, archive in archives.items()}
        prior_exports = {name: (self.participants()[name].control('acknowledge_exports',
            action='wallet', through=start - 1, operation_timeout=330)['requested_sat'] if start > 1 else 0)
            for name, start in starts.items()}
        require(set(self.participants()) == set(INITIAL) and set(self.reports) == set(self.owners) == set(self.providers),
                'collection account or original channel roster changed')
        # This tail needs only the conservation inputs. Each heterogeneous
        # 960/32/64-sat channel was checked against its own original intent.
        fixture = SimpleNamespace(issued_sat=sum(INITIAL.values()), initial_balances=INITIAL,
                                  channel_providers=self.providers)
        view = SimpleNamespace(nodes=self.participants(), state_json=self.state_json, evidence=self.evidence)
        collect_settled_wallets(view, settled, self.reports, self.owners, self.mint_url,
            execute=partial(self.account_execute, operation_timeout=330), stop=lambda _name: None,
            export_path=lambda name, relative: self.participants()[name].state + '/' + relative,
            fixture=fixture, max_export_sat=32, export_start=starts.__getitem__)
        amounts = self.evidence['phases'][-1]['settlement_collection']['collected_by_node']
        recovery = self.evidence['receiver_history']['collection_recovery'] = (
            self.evidence['phases'][-1]['settlement_collection']['collection_recovery'])
        for name, amount in amounts.items():
            if not amount:
                continue
            acknowledged = recovery[name]['acknowledged']
            require(acknowledged['requested_sat'] == acknowledged['cost']['wallet_debit_sat']
                    == prior_exports[name] + amount and acknowledged['cost']['swap_fee_sat'] == 0,
                    'final collection changed gross original export costs')
        final_archives = {name: self.snapshot(name, 'collected-original-custody') for name in INITIAL}
        self.evidence['receiver_history']['collected_audit'] = custody.audit(final_archives, self.mint_url, 0)
        for name, archive in final_archives.items():
            require(custody.export_start(archive) == starts[name] + (amounts[name] + 31) // 32,
                    'final original export prefix or pending native ownership changed')
        if self.retained_history is not None:
            custody.unchanged(final_archives['n02'], self.retained_history)
            self.evidence['receiver_history']['retained_fingerprints_after_collection'] = True
        self.phase('all 3072 original test sats collected; every guarded test wallet empty',
                   export_starts=starts)

    def exercise(self):
        try:
            self.form_line()
            self.receiver_case()
        except Exception as error:
            self.evidence['receiver_history']['acceptance_failure'] = str(error)
            self.save()
            raise
        finally:
            signal.alarm(0)
            self.release_holds(self.held_nodes)
            self.close_originals()
            self.collect_stopped(financial_snapshot(
                SimpleNamespace(nodes=self.participants(), ctl=self.ctl, state_json=self.state_json), wallet=None))
