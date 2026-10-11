"""Known-index TCP rejection beside paid radio traffic on the same relay."""

from pathlib import Path
import time

from .carrier_pressure import CarrierPressure
from .paid_relay import eventually, relay_config
from .paid_settlement import require
from .wifi_carrier_pressure import WifiCarrierPressureRun
from .wifi_discovery import validate_unfunded
from .wifi_remote import digest


class WifiCarrierOwnerRun(WifiCarrierPressureRun):
    def __init__(self, args):
        super().__init__(args)
        require(self.transport_type == 'tcp', 'known carrier acceptance requires TCP')
        self.owner = self.nodes['n01'].add_profile('tcp-owner')
        self.owner_started = False
        self.evidence['owner_windows'] = []
        self.evidence['harness_sha256']['wifi_carrier_owner.py'] = digest(Path(__file__).read_bytes())

    def before_launch(self):
        config = relay_config([], self.mint_url)
        config.update(state_directory=self.owner.state,
                      transports={'tcp': {'bind_addr': '127.0.0.1:0', 'advertise_on_nostr': False}},
                      neighbors=[{'npub': self.nodes['n02'].npub,
                                  'addresses': [{'transport': 'tcp', 'addr': '%s:%s' % self.address}]}])
        config['terms'].update(fee_msat_per_kib=0, max_rate_msat_per_kib=0)
        self.owner.prepare(config)
        self.owner_journals = self.owner.monetary_journals()
        super().before_launch()

    def mesh_peers(self, name, peers):
        if name == 'n02' and self.owner_started:
            owner = [peer for peer in peers if peer['npub'] == self.owner.npub]
            require(len(owner) == 1 and owner[0]['connected'] and owner[0]['transport'] == 'tcp',
                    'the original TCP owner disappeared or changed transport')
            peers = [peer for peer in peers if peer['npub'] != self.owner.npub]
        return peers

    def pool_size(self, stats):
        return super().pool_size(stats) - int(self.owner_started)

    def owner_session(self):
        status = self.owner.control('status')
        validate_unfunded(status)
        require(self.owner.monetary_journals() == self.owner_journals,
                'the TCP-only owner changed financial authority')
        peers = status['peers']
        require(len(peers) == 1 and peers[0]['npub'] == self.nodes['n02'].npub
                and peers[0]['connected'] and peers[0]['transport'] == 'tcp',
                'the TCP-only owner has an unexpected route')
        peers = self.nodes['n02'].native({'command': 'show_peers'})['data']['peers']
        owner = [peer for peer in peers if peer['npub'] == self.owner.npub]
        require(len(owner) == 1 and owner[0]['connectivity'] == 'connected'
                and owner[0]['transport_type'] == 'tcp' and not owner[0].get('rekey_in_progress'),
                'the established TCP owner was disrupted')
        peer = owner[0]
        require(len(peer['our_session_index']) == 8, 'missing live TCP receiver index')
        return {key: peer[key] for key in ('npub', 'link_id', 'authenticated_at_ms',
                                           'our_session_index', 'last_seen_ms')}

    def window(self, label, pressure=None):
        if not self.owner_started:
            self.owner.start()
            eventually('authenticated TCP owner', self.owner_session, 60)
            self.owner_started = True
            # Invalid ciphertext must be tested beyond the fresh-session grace.
            self.phase('TCP owner established; waiting for the recovery grace to expire')
            time.sleep(31)
        before = self.owner_session()
        if pressure:
            pressure = CarrierPressure(self.address, int(before['our_session_index'], 16))
        row = {'label': label, 'before': before}
        self.evidence['owner_windows'].append(row)
        super().window(label, pressure)
        row['after'] = after = self.owner_session()
        require({k: v for k, v in before.items() if k != 'last_seen_ms'}
                == {k: v for k, v in after.items() if k != 'last_seen_ms'},
                'pressure changed the original authenticated TCP session')
        require(after['last_seen_ms'] > before['last_seen_ms'],
                'no authenticated TCP traffic survived the pressure window')
        self.save()

    def validate_rejections(self, row):
        before, after = row['carrier_before'], row['carrier_after']
        count = len(row['rejections'])
        # The established owner continues sending encrypted control records.
        require(after['packets_recv'] - before['packets_recv'] >= count
                and after['connections_accepted'] - before['connections_accepted'] == count
                and all(after[key] == before[key] for key in ('connections_rejected', 'first_frame_timeouts')),
                'connections closed outside the intended rejection path')
