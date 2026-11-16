"""Keep both wireless paths connected while the cheaper path loses frames."""

import math
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import time

from .paid_diamond import PaidDiamondRun
from .paid_settlement import require
from .wifi_diamond_checks import counter
from .wifi_diamond_selection import FEES, FULL_QUOTA, POLICY, current_purchase
from .wifi_frame_loss import FrameLoss, loss_delta
from .wifi_remote import digest


def impaired_carrier(observation, destination, provider):
    first = current_purchase(observation['before'], destination)
    last = current_purchase(observation['after'], destination)
    quality = observation['quality']
    value = quality['quality']
    loss = value['loss_rate']
    return (first is not None and first == last and first['provider'] == provider
            and first['contract']['max_units'] == FULL_QUOTA
            and first['contract']['price'] == {'msat': FEES['n01'], 'per_bytes': 1024}
            and quality['price_selection'] == POLICY
            and quality['feedback_window_ms'] == POLICY['feedback_timeout_ms']
            and value['next_hop'] == provider and value['receiver_reports_enabled'] is True
            and value['has_recent_delivery_feedback'] is True
            and value['delivery_feedback_timed_out'] is False
            and type(loss) in (int, float) and math.isfinite(loss)
            and POLICY['max_loss_percent'] / 100 < loss <= 1
            and counter(value['sent_packets']) > 0 and counter(value['sent_bytes']) > 0)


class QualityDiamondRun(PaidDiamondRun):
    def __init__(self, args):
        require(not args.active_failover, 'loss selection cannot also cut the radio')
        super().__init__(args)
        self.peer_anchor = None
        self.fault = None
        self.sampling_loss = False
        self.evidence['quality_switch'] = {'every': 2, 'samples': []}
        for name in ('paid_quality_diamond.py', 'wifi_frame_loss.py'):
            self.evidence['harness_sha256'][name] = digest(Path(__file__).with_name(name).read_bytes())

    def peer_snapshot(self):
        states = self.topology()
        epochs = {}
        for name, profile in self.accounts.nodes.items():
            reply = profile.native({'command': 'show_peers'})
            require(reply['status'] == 'ok', 'native peer observation failed')
            peers = reply['data']['peers']
            wanted = {peer['npub']: peer['transport'] for peer in states[name]['peers']}
            require(len(peers) == len(wanted) and {p['npub'] for p in peers} == set(wanted),
                    'native peers differ from the connected diamond')
            epochs[name] = {}
            for peer in peers:
                require(peer['connectivity'] == 'connected'
                        and peer['transport_type'] == wanted[peer['npub']],
                        'quality selection lost a connected path')
                epochs[name][peer['npub']] = {
                    key: counter(peer[key]) for key in ('link_id', 'authenticated_at_ms')}
        if self.peer_anchor is not None:
            require(epochs == self.peer_anchor, 'quality selection replaced an original peer or link')
        return epochs

    def observe(self):
        observation = super().observe()
        if self.peer_anchor is not None:
            self.record_quality(observation)['peers'] = self.peer_snapshot()
            self.save()
        return observation

    def record_quality(self, observation):
        sample = {'at': time.monotonic(), 'observation': observation, 'filter': self.fault.observe()}
        sample['impaired_carrier'] = sample['filter']['enabled'] and impaired_carrier(
            observation, self.nodes['n03'].node_addr, self.nodes['n01'].node_addr)
        self.evidence['quality_switch']['samples'].append(sample)
        self.save()
        return sample

    def send_batch(self, shape, rate):
        if not self.sampling_loss:
            return super().send_batch(shape, rate)
        # Selection can finish before a burst drains. Observe during this same
        # finite send; never replay a send whose control reply is uncertain.
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(super().send_batch, shape, rate)
            try:
                while not future.done():
                    self.record_quality(super().observe())
                    time.sleep(0.1)
            finally:
                sent = future.result(timeout=35)
        return sent

    def provider_transition(self, before_cut):
        evidence = self.evidence['quality_switch']
        self.peer_anchor = self.peer_snapshot()
        evidence['original_peers'] = self.peer_anchor
        # n03 needs no excluded neighbor; its new owned table only hosts this fault.
        evidence['table'] = self.nodes['n03'].install_filter()
        self.fault = FrameLoss(self.nodes['n03'], self.nodes['n01'].mac, every=2)
        try:
            evidence['enable_attempted_at'] = time.monotonic()
            self.save()
            evidence['enabled'] = self.fault.enable()
            self.sampling_loss = True
            self.drive_route('n02', before_cut, 'loss_failover')
            evidence['alternative_accepted_at'] = time.monotonic()
            evidence['after'] = self.fault.observe()
            require(loss_delta(evidence['enabled'], evidence['after']) > 0,
                    'alternative selection lacks actual filtered frames')
            require(any(row['impaired_carrier'] for row in evidence['samples']),
                    'alternative selection lacks fresh loss feedback on the cheaper full agreement')
            self.financial_checkpoint(2)
            return self.ctl('source', 'status')
        finally:
            self.sampling_loss = False
            evidence['cleared'] = self.fault.clear()
            evidence['clear_finished_at'] = time.monotonic()
            self.save()
