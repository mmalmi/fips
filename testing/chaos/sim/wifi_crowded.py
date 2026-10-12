"""Crowded ordinary radio admission using the existing paid Wi-Fi lifecycle."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import secrets
import threading
import time

from .paid_relay import eventually, relay_config
from .paid_settlement import require
from .paid_wifi import PaidWifiRun
from .wifi_active_outage import peer_sessions, processes
from .wifi_diamond_checks import listener, management_address
from .wifi_discovery import validate_unfunded
from .wifi_profiles import configure_stopped
from .wifi_remote import digest


class CrowdedWifiRun(PaidWifiRun):
    def __init__(self, args):
        if any(getattr(args, name, False) for name in (
                'active_outage', 'streams', 'interrupted_promotion', 'carrier_pressure_port')):
            raise ValueError('crowded rejoin is a separate paid Wi-Fi scenario')
        self.cycles = getattr(args, 'crowded_rejoin', 1)
        if type(self.cycles) is not int or not 1 <= self.cycles <= 3:
            raise ValueError('crowded rejoin requires one to three cycles')
        super().__init__(args)
        self.idle = self.nodes['n03'].add_profile('idle')
        self.addresses = {}
        self.provider_udp = None
        self.evidence.update(acceptance_kind='paid_crowded_radio_rejoin',
                             provider_peer_cap=2, minimum_idle_secs=2,
                             rotation_interval_secs=2, auxiliary_funded=False)
        self.evidence['crowded_harness_sha256'] = digest(Path(__file__).read_bytes())

    def participants(self):
        return {**self.nodes, 'idle': self.idle}

    def mesh_peers(self, name, peers):
        if name != 'n02':
            return peers
        auxiliary = [peer for peer in peers if peer['npub'] == self.idle.npub]
        require(len(auxiliary) <= 1 and all(peer['transport'] == 'udp' for peer in auxiliary),
                'idle competitor has an unexpected carrier')
        return [peer for peer in peers if peer['npub'] != self.idle.npub]

    def udp_config(self, name):
        node = self.nodes[name]
        address = management_address(node.remote([
            'ip', '-o', '-4', 'addr', 'show', 'dev', node.management, 'scope', 'global',
        ]), node.management)
        require(name not in self.addresses or self.addresses[name] == address,
                'management address changed')
        self.addresses[name] = address
        return dict(bind_addr=address + ':0', bind_interface=node.management,
                    advertise_on_nostr=False)

    def profile_config(self, node):
        config = super().profile_config(node)
        if node is self.nodes['n02']:
            config.update(max_peers=2, neighbor_rotation=dict(idle_secs=2, interval_secs=2))
            config['transports']['udp'] = self.udp_config('n02')
        return config

    def before_launch(self):
        config = relay_config([], self.mint_url)
        config.update(state_directory=self.idle.state,
                      transports={'udp': self.udp_config('n03')})
        self.idle.prepare(config)
        require(self.idle.control('balance', action='wallet')['balance_sat'] == 0,
                'idle candidate must remain unfunded')
        self.idle_financial = self.idle.monetary_journals()
        self.evidence['auxiliary_identity'] = self.idle.npub
        super().before_launch()

    def discovery_adapter(self, name, adapters):
        if name == 'n02':
            udp = [a for a in adapters if a['type'] == 'udp']
            require(len(adapters) == 2 and len(udp) == 1, 'provider has an unexpected transport')
            address = listener(udp[0]['local_addr'], self.addresses[name])
            require(self.provider_udp in (None, address), 'provider listener changed')
            self.provider_udp = address
            adapters = [a for a in adapters if a['type'] == 'ethernet']
        return super().discovery_adapter(name, adapters)

    def exercise(self):
        self.useful_stop = threading.Event()
        self.useful_packets = self.evidence['useful_packets'] = []
        self.useful = None
        with ThreadPoolExecutor(max_workers=1) as self.useful_pool:
            try:
                super().exercise()
            finally:
                self.useful_stop.set()

    def collect(self):
        self.useful_stop.set()
        error = None
        if self.useful is not None:
            try:
                self.useful.result(timeout=20)
            except Exception as failure:
                error = failure
                self.evidence['useful_error'] = str(failure)
            self.evidence['useful_finished_at'] = time.monotonic()
            self.save()
        result = super().collect()
        if error is not None and 'acceptance_failure' not in self.evidence:
            raise error
        return result

    def keep_useful(self, stop, packets):
        # Ordinary data does not take the probe's shared sender/receiver permit.
        # Keep it running through paid probes and financial observations, too.
        while not stop.is_set() and len(packets) < 3600:
            payload = secrets.token_hex(64)
            current = dict(at=time.monotonic(), sha256=digest(payload.encode()),
                           bytes=len(payload), observed=False)
            packets.append(current)
            current['sent'] = self.ctl('n02', 'send', destination=self.nodes['n01'].npub,
                                       payload=payload, operation_timeout=5)
            require(current['sent'].get('queued') is True, 'useful data was not queued')
            deadline = time.monotonic() + 0.75
            while not stop.is_set():
                current['received'] = self.ctl('n01', 'status', operation_timeout=5)['received']
                if current['received']['last_sha256'] == current['sha256']:
                    current.update(observed=True, observed_at=time.monotonic())
                    break
                if time.monotonic() >= deadline or stop.wait(0.05):
                    break
            stop.wait(0.25)
        require(stop.is_set(), 'useful traffic exceeded the bounded trial')
        return packets

    def useful_flowing(self, packets, after):
        fresh = [packet for packet in packets[after:] if packet['observed']]
        if len(fresh) >= 2 and time.monotonic() - fresh[-1]['observed_at'] <= 2:
            return fresh[-2:]
        return None

    def mesh_outage(self):
        rounds = self.evidence['crowded_rejoins'] = []
        original = peer_sessions(self)['n02'][self.nodes['n01'].npub]
        owners = processes(self)
        self.useful = self.useful_pool.submit(self.keep_useful, self.useful_stop, self.useful_packets)
        for index in range(self.cycles):
            self.rejoin_round(original, index == 0)
            data = rounds[-1]
            require(data['processes_before'] == owners,
                    'repeated crowding restarted an original relay')
            require(data['idle_pid_before'] == rounds[0]['idle_pid_before'],
                    'repeated crowding restarted the idle competitor')
            if index + 1 < self.cycles:
                current = self.assert_finances()
                data['paid_between_rounds'] = self.paid_streams(
                    current, 'original channels pay between crowded rejoins')
                self.retain_channels(self.channel_anchor, data['paid_between_rounds'])
            self.save()

    def rejoin_round(self, original, start_idle):
        data = dict(passed=False, processes_before=processes(self), samples=[],
                    useful_start=len(self.useful_packets))
        self.evidence['crowded_rejoins'].append(data)
        data['useful_original'] = original
        radio = self.nodes['n03']
        resumed = False

        def observed():
            if self.useful.done():
                self.useful.result()
                raise RuntimeError('useful-neighbor stream stopped prematurely')
            reply = self.nodes['n02'].native({'command': 'show_peers'})
            require(reply['status'] == 'ok', 'provider native observation failed')
            peers = reply['data']['peers']
            require(len(data['samples']) < 1280, 'crowded observations exceeded their bound')
            data['samples'].append(dict(at=time.monotonic(), peers=peers))
            self.save()
            require(len(peers) <= 2, 'provider exceeded its configured peer cap')
            kept = [p for p in peers if p['npub'] == self.nodes['n01'].npub]
            require(len(kept) == 1 and kept[0]['connectivity'] == 'connected'
                    and kept[0]['authenticated_at_ms'] == original['authenticated_at_ms'],
                    'crowded admission replaced the useful original peer')
            return peers

        try:
            data['before_cut'] = eventually('fresh useful direct application traffic',
                lambda: self.useful_flowing(self.useful_packets, data['useful_start']), 10)
            observed()
            data['cut_started'] = time.monotonic()
            self.save()
            radio.mesh_down()
            data['isolated'] = eventually('radio peer removal while useful traffic continues',
                lambda: observed() and self.ready(line=True, isolated=True), 100)
            if start_idle:
                configure_stopped(self.idle, neighbors=[dict(
                    npub=self.nodes['n02'].npub,
                    addresses=[dict(transport='udp', addr=self.provider_udp)],
                )])
                self.idle.start()

            def crowded():
                peers = observed()
                wanted = {self.nodes['n01'].npub: 'ethernet', self.idle.npub: 'udp'}
                return peers if (len(peers) == 2 and {p['npub'] for p in peers} == set(wanted)
                    and all(p['connectivity'] == 'connected'
                            and p['transport_type'] == wanted[p['npub']] for p in peers)) else None

            data['full_roster'] = eventually('unfunded idle peer fills the last slot', crowded, 60)
            data['idle_pid_before'] = self.idle.remote(['cat', self.idle.temporary + '/process.pid']).decode()
            self.phase('useful radio peer and idle UDP peer occupy both provider slots')
            data['financial_during_outage'] = self.assert_finances()
            data['rejoin_started'] = time.monotonic()
            radio.mesh_up()
            resumed = True
            data['rejoined'] = eventually('returning radio replaces idle peer at capacity',
                lambda: observed() and self.ready(line=True), 150)
            data['rejoin_observed'] = time.monotonic()
            # Protect the newly useful radio edge with actual paid delivery.
            self.probe('n01', 'n03', 'fresh paid stream crosses the crowded replacement')
            observed()
            status = self.idle.control('status')
            validate_unfunded(status)
            require(not status['watched_routes'] and self.idle.monetary_journals() == self.idle_financial,
                    'idle candidate acquired payment authority')
            data['idle_pid_after'] = self.idle.remote(['cat', self.idle.temporary + '/process.pid']).decode()
            require(data['idle_pid_before'] == data['idle_pid_after'], 'idle process was replaced')
        except Exception as error:
            data['failure'] = str(error)
            self.record_probe_failure('crowded radio rejoin', error,
                dict(source='n02', destination='n01', useful_packets=self.useful_packets[-8:]))
            raise
        finally:
            errors = []
            try:
                if 'cut_started' in data and not resumed:
                    radio.mesh_up()
            except Exception as error:
                errors.append(error)
            data['useful_end'] = len(self.useful_packets)
            data['cleanup_errors'] = [str(error) for error in errors]
            self.save()
            if errors and 'failure' not in data:
                raise errors[0]
        data['processes_after'] = processes(self)
        require(data['processes_before'] == data['processes_after'], 'crowded test restarted a paid relay')
        self.verify_open_profiles()
        data['passed'] = True
        self.phase('same paid identities survived crowded physical radio rejoin')
