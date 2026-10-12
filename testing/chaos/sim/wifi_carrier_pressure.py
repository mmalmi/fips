"""Paid radio traffic alongside bounded rejected-carrier pressure."""

import ipaddress
from pathlib import Path
import signal

from .carrier_pressure import CarrierPressure
from .paid_finances import payment_progress
from .paid_relay import PaidRelayRun, eventually
from .paid_settlement import original_channels, require
from .paid_wifi import PaidWifiRun
from .paid_wifi_forwarding import listeners
from .stream_probe import duplex, validate_stream
from .restart_finances import QUOTE_UNITS, retained_finances
from .wifi_measurements import snapshot
from .wifi_remote import digest


class WifiCarrierPressureRun(PaidWifiRun):
    transport_type = 'tcp'

    def __init__(self, args):
        require(type(args.carrier_pressure_port) is int and 1024 <= args.carrier_pressure_port <= 65535,
                'carrier pressure requires an unprivileged port')
        require(not any(getattr(args, key, None) for key in (
            'streams', 'active_outage', 'root_outage', 'brief_outage', 'outage_node',
            'recovery_timing', 'beacon_interval_secs', 'interrupted_promotion')),
            'carrier pressure uses its own bounded stream scenario')
        self.transport_type = getattr(args, 'carrier_pressure_transport', 'tcp')
        require(self.transport_type in ('tcp', 'websocket', 'udp'), 'unsupported pressure transport')
        self.pressure_type = CarrierPressure
        if self.transport_type == 'websocket':
            from .websocket_pressure import WebsocketPressure
            self.pressure_type = WebsocketPressure
        if self.transport_type == 'udp':
            from .udp_pressure import UdpPressure
            self.pressure_type = UdpPressure
        super().__init__(args)
        self.address = None
        self.evidence['carrier_windows'] = []
        self.evidence['pressure_transport'] = self.transport_type
        for name in ('carrier_pressure.py', 'wifi_carrier_pressure.py', 'websocket_pressure.py',
                     'udp_pressure.py', 'stream_probe.py'):
            self.evidence['harness_sha256'][name] = digest(Path(__file__).with_name(name).read_bytes())

    def profile_config(self, node):
        config = super().profile_config(node)
        config['return_allowance'] = False
        config['terms'].update(fee_msat_per_kib=1, max_rate_msat_per_kib=1,
                               quote_max_units=QUOTE_UNITS)
        if node is self.nodes['n02']:
            addresses = node.remote(['ip', '-o', '-4', 'addr', 'show', 'dev', node.management]).decode()
            assigned = [str(ipaddress.ip_interface(line.split()[3]).ip)
                        for line in addresses.splitlines() if ' scope global ' in line]
            require(len(assigned) == 1 and ipaddress.ip_address(assigned[0]).is_private,
                    'middle router needs one private management address')
            self.address = (assigned[0], self.args.carrier_pressure_port)
            protocol = 'udp' if self.transport_type == 'udp' else 'tcp'
            require(not listeners(node, self.address[1], protocol), 'test carrier port is already occupied')
            listener = {'bind_addr': '%s:%s' % self.address, 'max_inbound_connections': 8}
            if self.transport_type == 'tcp':
                listener.update(first_frame_timeout_ms=1000, advertise_on_nostr=False)
            elif self.transport_type == 'websocket':
                listener.update(max_connections=8, connect_timeout_ms=5000,
                                ping_interval_secs=0, idle_timeout_secs=0)
            else:
                listener = {'bind_addr': listener['bind_addr']}
            config['transports'][self.transport_type] = {'rejections': listener}
        return config

    def carrier_stats(self):
        transports = self.nodes['n02'].native({'command': 'show_transports'})['data']['transports']
        candidates = [item for item in transports if item['type'] == self.transport_type]
        require(len(candidates) == 1 and candidates[0]['name'] == 'rejections',
                'missing unique test carrier transport')
        return candidates[0]['stats']

    def pool_size(self, stats):
        if self.transport_type == 'udp':
            return 0  # UDP has no connection pool; native admission is checked separately.
        if self.transport_type == 'tcp':
            return stats['pool_inbound'] + stats['pool_outbound']
        return stats['connections_opened'] - stats['connections_closed']

    def discovery_adapter(self, name, adapters):
        if name == 'n02':
            extra = [item for item in adapters if item['type'] == self.transport_type]
            require(len(extra) == 1 and extra[0]['name'] == 'rejections'
                    and self.pool_size(extra[0]['stats']) == 0,
                    'unexpected carrier during mesh discovery')
            adapters = [item for item in adapters if item['type'] != self.transport_type]
        return super().discovery_adapter(name, adapters)

    def retain_channels(self, prior, current):
        return retained_finances(prior, current, dict.fromkeys(prior['n02']['credited'], 0))

    def window(self, label, pressure=None):
        prior = eventually('stream financial baseline', self.finances)
        row = {'label': label, 'passed': False, 'carrier_before': self.carrier_stats(),
               'before': snapshot(self.nodes['n02'], 'n02', native_counters=self.transport_type == 'udp')}
        self.evidence['carrier_windows'].append(row)
        self.save()

        def observe():
            statuses = self.ready(line=True)
            require(statuses, 'paid stream left the physical radio line')
            sample = {'carrier': self.carrier_stats(),
                      'endpoints': {name: statuses[name]['stream_probe'] for name in ('n01', 'n03')},
                      'bridge': snapshot(self.nodes['n02'], 'n02', native_counters=self.transport_type == 'udp')}
            if pressure:
                sample['pressure'] = pressure.observe()
            return sample

        try:
            if pressure:
                pressure.start()
            duplex(self, row, label=label, count=4 * 1024 * 1024, duration=30,
                   rate=256 * 1024, observe=observe)
        finally:
            try:
                if pressure:
                    pressure.finish()
            finally:
                if pressure:
                    row['rejections'] = [item for rows in pressure.rows for item in rows]
                row['carrier_after'] = self.carrier_stats()
                row['after'] = snapshot(self.nodes['n02'], 'n02', native_counters=self.transport_type == 'udp')
                self.save()
        for name, report in row['results'].items():
            validate_stream(report, row['shapes'][name])
        require(row['before']['host_process']['pid'] == row['after']['host_process']['pid']
                and row['before']['host_process']['start_ticks'] == row['after']['host_process']['start_ticks'],
                'pressure restarted the forwarding process')
        require(self.pool_size(row['carrier_after']) == 0,
                'rejected carriers retained pool entries')
        if pressure and self.transport_type == 'udp':
            pressure.validate(row)
        elif pressure:
            rows = row['rejections']
            require(len(rows) >= 24 and {item['kind'] for item in rows} == set(pressure.records),
                    'missing bounded pressure cases')
            self.validate_rejections(row)
            require(len(row['samples']) >= 3 and all(0 <= self.pool_size(sample['carrier']) <= 8
                    for sample in row['samples']), 'missing bounded live pressure observations')
            require(any(sample['pressure']['closed'] >= len(pressure.records) and all(
                probe and probe['received_bytes'] > 0 for probe in sample['endpoints'].values())
                for sample in row['samples']), 'no paid delivery observed while pressure was active')

        def paid():
            current = self.finances()
            self.retain_channels(prior, current)
            return payment_progress(current, prior)

        row['financial'] = eventually('automatic payment and provider credit during stream', paid, 45)
        row['passed'] = True
        self.phase(label + ': exact paid duplex delivered and credited')

    def validate_rejections(self, row):
        before, after = row['carrier_before'], row['carrier_after']
        count = len(row['rejections'])
        progressed = (('packets_recv', 'connections_accepted') if self.transport_type == 'tcp'
                      else ('connections_opened', 'connections_closed'))
        unchanged = (('connections_rejected', 'first_frame_timeouts') if self.transport_type == 'tcp'
                     else ('connections_rejected', 'invalid_frames', 'frames_received', 'frames_sent'))
        require(all(after[key] - before[key] == count for key in progressed)
                and all(after[key] == before[key] for key in unchanged),
                'connections closed outside the intended rejection path')

    def exercise(self):
        self.form_line()
        PaidRelayRun.unpaid_probe(self, self.assert_finances())
        for source, destination in (('n01', 'n03'), ('n03', 'n01')):
            self.ctl(source, 'buy', destination=self.nodes[destination].npub)
        self.channel_anchor = eventually('original funded channels', self.finances)
        original_channels(self.nodes, self.channel_anchor)
        try:
            if self.transport_type == 'udp':
                for rate in (2000, 10000):
                    self.window('udp-' + str(rate), self.pressure_type(self.address, rate=rate))
            else:
                self.window('pressure', self.pressure_type(self.address))
            self.window('recovered')
            self.verify_shortcuts()
        finally:
            signal.alarm(0)
            self.collect()
