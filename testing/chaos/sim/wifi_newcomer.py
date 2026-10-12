"""One fresh paying radio identity at capacity, retaining the disconnected account."""

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import signal
import threading

from .paid_faults import capture_probe
from .paid_finances import payments_credited
from .paid_relay import PaidRelayRun, eventually
from .paid_settlement import (check_mint, collect_settled_wallets, require,
                              validate_finances, validate_report)
from .remote_mint import RemoteMint
from .wifi_active_outage import peer_sessions
from .wifi_crowded import CrowdedWifiRun
from .wifi_discovery import WifiRun, validate_unfunded
from .wifi_measurements import snapshot
from .wifi_newcomer_accounts import NewcomerAccounts
from .wifi_profiles import configure_stopped
from .wifi_remote import digest


class NewcomerWifiRun(CrowdedWifiRun):
    def __init__(self, args):
        if (getattr(args, 'crowded_rejoin', 0) != 1 or getattr(args, 'crowded_pressure', 0)
                or not getattr(args, 'mint_host', None)):
            raise ValueError('paying newcomer requires one crowded rejoin and an explicit remote test mint')
        super().__init__(args)
        self.source = self.nodes['n03'].add_profile('newcomer')
        self.accounts = NewcomerAccounts(self)
        self.source_started = False
        self.collection = None
        self.evidence.update(acceptance_kind='paying_new_radio_identity', issued_sat=512,
                             newcomer_uses_radio=True, old_channel_retained=True)
        for name in ('wifi_newcomer.py', 'wifi_newcomer_accounts.py'):
            self.evidence['harness_sha256'][name] = digest(Path(__file__).with_name(name).read_bytes())

    def create_mint(self, args):
        return RemoteMint(json.loads(args.mint_host.read_text()), args.mint_binary,
                          self.run, self.root, args.mint_address, max_issued_sat=512)

    def setup(self):
        self.mint_url = self.mint.start()
        self.evidence['mint_process'] = self.mint.info
        self.phase('fresh test mint started with a 512-sat issuance cap')
        WifiRun.setup(self)

    def before_launch(self):
        config = self.profile_config(self.nodes['n03'])
        config['state_directory'] = self.source.state
        self.source.prepare(config)
        super().before_launch()
        token = self.mint.grant('newcomer')
        self.source.control('import', action='wallet', token=token)
        balance = self.source.control('balance', action='wallet')
        require(balance['mint_url'] == self.mint_url and balance['unit'] == 'sat'
                and balance['balance_sat'] == 128, 'newcomer initial funding differs')
        require(self.source.npub not in {node.npub for node in self.nodes.values()} | {self.idle.npub},
                'newcomer identity is not fresh')
        self.evidence['newcomer_identity'] = self.source.npub
        self.phase('four stopped fresh accounts hold 128 test sats each; idle competitor has zero')

    def ctl(self, name, kind, **fields):
        if name == 'source':
            self.check_forwards()
            self.monitor.check()
            return self.source.control(kind, **fields)
        return super().ctl(name, kind, **fields)

    def provider_peers(self, useful):
        require(not self.useful.done(), 'useful direct traffic stopped')
        report = self.nodes['n02'].native({'command': 'show_peers'})
        require(report['status'] == 'ok', 'provider peer observation failed')
        peers = report['data']['peers']
        require(len(peers) <= 2, 'newcomer exceeded the provider peer cap')
        kept = [peer for peer in peers if peer['npub'] == self.nodes['n01'].npub]
        require(len(kept) == 1 and kept[0]['connectivity'] == 'connected'
                and kept[0]['authenticated_at_ms'] == useful['authenticated_at_ms'],
                'newcomer displaced the useful incumbent')
        return peers

    def wait_roster(self, useful, other, transport):
        def ready():
            peers = self.provider_peers(useful)
            self.evidence['last_newcomer_roster'] = peers
            self.save()
            wanted = {self.nodes['n01'].npub: 'ethernet', other.npub: transport}
            return peers if (len(peers) == 2 and {peer['npub'] for peer in peers} == set(wanted)
                and all(peer['connectivity'] == 'connected'
                        and peer['transport_type'] == wanted[peer['npub']] for peer in peers)) else None
        return eventually('exact provider roster at the two-peer cap', ready, 150)

    def probe_newcomer(self, source, destination, *, loss=False):
        data = dict(source=source, destination=destination, unpaid=loss)
        self.evidence.setdefault('newcomer_probes', []).append(data)
        try:
            capture_probe(self.accounts, source, destination, eventually, data,
                          loss=loss, measure_latency=False)
        finally:
            self.save()

    def admission(self):
        useful = peer_sessions(self)['n02'][self.nodes['n01'].npub]
        def owners():
            result = {}
            for name in ('n01', 'n02'):
                state = snapshot(self.nodes[name], name)['host_process']
                result[name] = (state['pid'], state['start_ticks'])
            return result
        original_processes = owners()
        self.useful = self.useful_pool.submit(self.keep_useful, self.useful_stop, self.useful_packets)
        eventually('fresh useful direct traffic', lambda: self.useful_flowing(self.useful_packets, 0), 10)
        radio = self.nodes['n03']
        resumed = False
        try:
            radio.mesh_down()
            eventually('original radio departure', lambda: self.ready(line=True, isolated=True), 100)
            configure_stopped(self.idle, neighbors=[dict(npub=self.nodes['n02'].npub,
                addresses=[dict(transport='udp', addr=self.provider_udp)])])
            self.idle.start()
            crowded = self.wait_roster(useful, self.idle, 'udp')
            self.phase('useful radio incumbent and idle competitor occupy both slots', peers=crowded)
            self.accounts.freeze('n03')
            old = self.accounts.snapshot_hashes('n03')
            self.source.start()
            self.source_started = True
            eventually('newcomer admin socket', lambda: self.ctl('source', 'status'), 60)
            validate_unfunded(self.ctl('source', 'status'))
            radio.mesh_up()
            resumed = True
            admitted = self.wait_roster(useful, self.source, 'ethernet')
            adapters = self.source.native({'command': 'show_transports'})
            require(adapters['status'] == 'ok' and len(adapters['data']['transports']) == 1
                    and adapters['data']['transports'][0]['type'] == 'ethernet',
                    'newcomer has a non-radio carrier shortcut')
            peers = self.ctl('source', 'status')['peers']
            require(len(peers) == 1 and peers[0]['npub'] == self.nodes['n02'].npub
                    and peers[0]['connected'] and peers[0]['transport'] == 'ethernet',
                    'newcomer has an unexpected direct neighbor')
            self.phase('fresh radio identity replaces idle competitor', peers=admitted)
            initial, _ = eventually('newcomer initial financial accounts', self.accounts.fixture)
            self.probe_newcomer('source', 'n01', loss=True)
            self.accounts.buy('n01', 'source')
            self.accounts.buy('source', 'n01')
            for pair in (('n01', 'source'), ('source', 'n01')):
                self.probe_newcomer(*pair)

            def paid():
                financial, fixture = self.accounts.fixture()
                advanced = all(financial[name]['authorized'] > initial[name]['authorized']
                               for name in ('n01', 'source'))
                return (financial, fixture) if advanced and payments_credited(financial) else None

            financial, _ = eventually('newcomer bidirectional automatic payments', paid, 90)
            self.provider_peers(useful)
            self.accounts.unchanged('n03')
            require(self.accounts.snapshot_hashes('n03') == old, 'retired account changed')
            require(owners() == original_processes,
                    'newcomer restarted the incumbent or provider')
            validate_unfunded(self.idle.control('status'))
            require(self.idle.monetary_journals() == self.idle_financial, 'idle competitor acquired authority')
            self.phase('new radio buyer paid; original disconnected account and incumbent channel retained',
                       financial=financial, retired_journal_sha256=old)
        finally:
            if not resumed:
                radio.mesh_up()

    def close_accounts(self):
        before, fixture = eventually('all acknowledged newcomer channels before settlement', self.accounts.fixture)
        reports = {}
        check_mint(self.mint.request({'type': 'report'}), 0, issued_sat=512)

        def settle(name):
            for report in self.ctl(name, 'settle')['settlements']:
                key = report['channel_id']
                require(fixture.channel_owners.get(key) == name and key not in reports,
                        'newcomer settlement changed a channel owner')
                reports[key] = validate_report(report)

        settle('source')
        self.accounts.freeze('source')
        self.idle.stop()
        if 'n03' in self.accounts.frozen:
            self.accounts.resume('n03')
        eventually('original paid radio neighbors restored', lambda: self.ready(line=True), 100)
        self.probe('n01', 'n03', 'original retained channel still delivers after the newcomer leaves')
        self.probe('n03', 'n01', 'original buyer still pays after returning')
        for name in self.nodes:
            settle(name)
        require(set(reports) == set(fixture.channel_owners), 'newcomer settlement omitted a channel')
        after = eventually('settled newcomer account observation', self.accounts.finances)
        validate_finances(before, after, reports, fixture=fixture)
        self.useful_stop.set()
        self.useful.result(timeout=20)
        collect_settled_wallets(self.accounts, after, reports, fixture.channel_owners, self.mint_url,
            execute=self.accounts.execute, stop=self.accounts.stop,
            export_path=lambda name, relative: self.accounts.nodes[name].state + '/' + relative,
            fixture=fixture)
        self.collection = self.evidence['phases'][-1]['settlement_collection']
        self.phase('all 512 test sats collected; four wallets empty')

    def exercise(self):
        self.form_line()
        discovered = self.assert_finances()
        PaidRelayRun.unpaid_probe(self, discovered)
        for source, destination in (('n01', 'n03'), ('n03', 'n01')):
            self.accounts.buy(source, destination)
        funded = eventually('initial paid radio accounts', self.finances)
        self.channel_anchor = self.paid_streams(funded, 'original radio buyers pay before newcomer admission')
        self.useful_stop = threading.Event()
        self.useful_packets = self.evidence['useful_packets'] = []
        self.useful = None
        with ThreadPoolExecutor(max_workers=1) as self.useful_pool:
            try:
                self.admission()
            except Exception as error:
                self.evidence['acceptance_failure'] = str(error)
                self.save()
                raise
            finally:
                signal.alarm(0)
                try:
                    if self.source_started:
                        self.close_accounts()
                finally:
                    self.useful_stop.set()
        require(self.collection is not None, 'newcomer collection did not finish')
        self.verify_shortcuts()
