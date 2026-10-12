"""Finite authenticated join pressure while the original radio route carries data."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import time

from . import wifi_probes as probes
from .paid_relay import eventually, relay_config
from .paid_settlement import require
from .wifi_active_outage import authenticated_peers, peer_sessions, processes
from .wifi_discovery import validate_unfunded
from .wifi_measurements import snapshot
from .wifi_priority_checks import submitted
from .wifi_profiles import configure_stopped
from .wifi_remote import digest


def check_sample(sample, original):
    """Check the provider epoch and finite trial ceilings, not long-term bounds."""
    status = sample['native']['status']['data']
    require(status['peer_count'] == 2 and status['connection_count'] <= 8,
            'join pressure exceeded the peer cap or trial connection ceiling')
    require(sample['host_process']['peak_rss_kib'] <= 64 * 1024,
            'provider exceeded the trial memory ceiling')
    require(sample['host_process']['pid'] == original['host_process']['pid']
            and sample['host_process']['start_ticks'] == original['host_process']['start_ticks'],
            'provider restarted during join pressure')


class AdmissionPressure:
    def __init__(self, run):
        self.run = run
        self.useful = None
        self.peers = {'idle': run.idle}
        self.hosts = {}
        for index in range(7):
            name = 'pressure-' + str(index + 1)
            host = 'n01' if index % 2 == 0 else 'n03'
            self.hosts[name] = host
            self.peers[name] = run.nodes[host].add_profile(name)
        self.original = {}
        run.evidence['admission_pressure_harness_sha256'] = digest(Path(__file__).read_bytes())

    def prepare(self):
        for name, host in self.hosts.items():
            peer = self.peers[name]
            config = relay_config([], self.run.mint_url)
            config.update(state_directory=peer.state, transports={'udp': self.run.udp_config(host)})
            peer.prepare(config)
            require(peer.control('balance', action='wallet')['balance_sat'] == 0,
                    'join-pressure candidate must remain unfunded')
            self.original[name] = peer.monetary_journals()
        self.original['idle'] = self.run.idle_financial

    def observe_candidates(self, target, result):
        for name, peer in self.peers.items():
            status = peer.control('status')
            row = result[name] = dict(status=status)
            validate_unfunded(status)
            # Only the provider's roster establishes admission. A former peer
            # can retain its own view of a link after the provider removes it.
            require(not status['watched_routes'] and len(status['peers']) <= 1
                    and all(p['npub'] == self.run.nodes['n02'].npub
                            and (p['transport'] == 'udp'
                                 or (not p['connected'] and p['transport'] is None))
                            for p in status['peers']),
                    'candidate retained an unexpected neighbor or route')
            routing = row['routing'] = peer.native({'command': 'show_routing'})
            require(routing['status'] == 'ok', 'candidate retry observation failed')
            retries = routing['data']['retries']
            require(len(retries) <= 1 and all(p['node_addr'] == target for p in retries),
                    'candidate retried an unexpected neighbor')
            transports = row['transports'] = peer.native({'command': 'show_transports'})
            require(transports['status'] == 'ok', 'candidate transport observation failed')
            adapters = transports['data']['transports']
            require(len(adapters) == 1 and adapters[0]['type'] == 'udp',
                    'candidate has an unexpected transport')
            row['udp_packets_sent'] = adapters[0]['stats']['packets_sent']
        return result

    def exercise(self):
        run = self.run
        evidence = run.evidence['admission_pressure'] = dict(
            candidate_count=8, seconds=120, rate=1, payload_bytes=40, samples=[], passed=False)
        useful = evidence['useful_packets'] = []
        self.useful = run.useful_pool.submit(run.keep_useful, run.useful_stop, useful, 'n03')
        eventually('fresh direct application traffic to the leaf', lambda: run.useful_flowing(useful, 0), 10)
        directions = (('n01', 'n03'), ('n03', 'n01'))
        shapes = [probes.arm(run, source, destination, 120, 40, lifetime_secs=150)
                  for source, destination in directions]
        evidence['shapes'] = shapes
        before = run.assert_finances()
        owners = processes(run)
        evidence['processes_before'] = owners
        senders = []
        with ThreadPoolExecutor(max_workers=2) as pool:
            try:
                for (source, destination), shape in zip(directions, shapes):
                    senders.append(pool.submit(probes.send, run, source, destination, shape, 1,
                                               max_duration_secs=120, operation_timeout=150))
                for (source, destination), shape in zip(directions, shapes):
                    eventually('paid stream active before join pressure', lambda: (
                        probes.receive(run, source, destination, shape)['unique_packets'] >= 2), 15)
                original_peers = authenticated_peers(peer_sessions(run))
                evidence['peer_anchor'] = original_peers
                first = snapshot(run.nodes['n02'], 'n02', native_counters=True)
                target = first['native']['status']['data']['node_addr']
                for name in self.hosts:
                    peer = self.peers[name]
                    configure_stopped(peer, neighbors=[dict(npub=run.nodes['n02'].npub,
                        addresses=[dict(transport='udp', addr=run.provider_udp)])])
                    peer.start()
                    eventually('pressure candidate control ready', lambda: peer.control('status'), 20)
                evidence['started'] = time.monotonic()
                while not all(future.done() for future in senders):
                    require(len(evidence['samples']) < 16, 'join-pressure sample limit exceeded')
                    run.monitor.check()
                    if self.useful.done():
                        self.useful.result()
                        raise RuntimeError('useful leaf traffic stopped before join pressure completed')
                    sample = dict(at=time.monotonic(), candidates={}, native_peers={})
                    evidence['samples'].append(sample)
                    try:
                        current = sample['provider'] = snapshot(run.nodes['n02'], 'n02', native_counters=True)
                        check_sample(current, first)
                        sample['peers'] = peer_sessions(run, evidence=sample['native_peers'])
                        require(authenticated_peers(sample['peers']) == original_peers,
                                'join pressure replaced an original paid neighbor')
                        sample['received'] = [probes.receive(run, source, destination, shape)
                                             for (source, destination), shape in zip(directions, shapes)]
                        self.observe_candidates(target, sample['candidates'])
                    finally:
                        run.save()
                    time.sleep(15)
            finally:
                # A lost diagnostic reply never authorizes repeating its finite send.
                evidence['senders'] = []
                for future in senders:
                    try:
                        evidence['senders'].append(future.result(timeout=150))
                    except Exception as error:
                        evidence['senders'].append({'error': str(error)})
                run.save()
        for sender, shape in zip(evidence['senders'], shapes):
            submitted(sender, shape)
        evidence['received'] = [probes.receive(run, source, destination, shape, complete=True)
                               for (source, destination), shape in zip(directions, shapes)]
        require(evidence['samples'][-1]['at'] - evidence['started'] >= 90,
                'join pressure did not overlap ninety seconds of paid delivery')
        for name, peer in self.peers.items():
            if name in self.hosts:
                packets = [sample['candidates'][name]['udp_packets_sent'] for sample in evidence['samples']]
                require(packets == sorted(packets) and len(set(packets)) >= 3,
                        'fresh candidate did not send join traffic across three observations')
            require(peer.monetary_journals() == self.original[name],
                    'unfunded candidate acquired payment authority')
        evidence['processes_after'] = processes(run)
        require(evidence['processes_after'] == owners, 'join pressure restarted a paid relay')
        evidence['native_peers_after'] = {}
        evidence['peers_after'] = peer_sessions(run, evidence=evidence['native_peers_after'])
        require(authenticated_peers(evidence['peers_after']) == original_peers,
                'join pressure replaced an original paid neighbor before completion')
        paid = run.paid_streams(before, 'original channels pay after sustained join pressure')
        run.retain_channels(run.channel_anchor, paid)
        evidence['passed'] = True
        run.phase('eight unfunded candidates leave the active paid radio route intact')
