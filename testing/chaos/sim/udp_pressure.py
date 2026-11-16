"""Paced UDP rejection traffic from 64 source ports to one owned bench listener."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import ipaddress
import random
import socket
import struct
import threading
import time

from .carrier_pressure import RECORDS
from .paid_settlement import require
from .wifi_admission_pressure import check_sample


class UdpPressure:
    """Bounded packets and memory, with no IP aliases, spoofing or per-packet log."""

    def __init__(self, address, *, rate=2000, duration=45):
        require(ipaddress.ip_address(address[0]).version == 4
                and ipaddress.ip_address(address[0]).is_private
                and type(address[1]) is int and 1024 <= address[1] <= 65535,
                'UDP pressure needs a private IPv4 bench listener')
        require(type(rate) is int and 100 <= rate <= 10000
                and type(duration) is int and 1 <= duration <= 45,
                'UDP pressure exceeds its finite rate or duration bound')
        self.address, self.rate, self.duration = address, rate, duration
        self.stop = threading.Event()
        self.pool = ThreadPoolExecutor(max_workers=1)
        self.job = None
        self.started = self.ended = None
        self.ports = []
        # Same FMP shapes as the rejected TCP cases. Random Noise bytes exercise
        # admission and authentication failure, rather than just an all-zero key.
        rng = random.Random(497)
        self.records = {kind: wire[:8] + rng.randbytes(len(wire) - 8)
                        if kind == 'msg1' else wire for kind, wire in RECORDS.items()}
        self.rows = [[{'kind': kind, 'sent': 0, 'bytes': 0} for kind in self.records]]

    def start(self):
        require(self.job is None, 'UDP pressure cannot be replayed')
        self.job = self.pool.submit(self.worker)

    def worker(self):
        with ExitStack() as stack:
            clients = [stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
                       for _ in range(64)]
            for client in clients:
                client.settimeout(0.2)
                client.bind(('0.0.0.0', 0))
            self.ports = [client.getsockname()[1] for client in clients]
            records = list(self.records.values())
            self.started = time.monotonic()
            count = 0
            try:
                # Do not catch up after a delayed tick: the controller must not
                # accidentally turn a scheduling pause into an unbounded burst.
                for _ in range(self.duration * 100):
                    if self.stop.is_set():
                        return
                    tick = time.monotonic()
                    if tick - self.started >= self.duration:
                        break
                    for _ in range(self.rate // 100):
                        index = count % len(records)
                        wire = records[index]
                        if index == 0:
                            wire = wire[:4] + struct.pack('<I', count + 1) + wire[8:]
                        size = clients[count % len(clients)].sendto(wire, self.address)
                        require(size == len(wire), 'partial UDP pressure datagram')
                        self.rows[0][index]['sent'] += 1
                        self.rows[0][index]['bytes'] += size
                        count += 1
                    if self.stop.wait(max(0, 0.01 - (time.monotonic() - tick))):
                        return
                raise TimeoutError('UDP pressure exhausted its finite window before paid traffic finished')
            finally:
                self.ended = time.monotonic()

    def observe(self):
        if self.job.done():
            self.job.result()
            raise RuntimeError('UDP pressure ended before the paid stream')
        return {'sent': sum(row['sent'] for row in self.rows[0]),
                'bytes': sum(row['bytes'] for row in self.rows[0]),
                'source_ports': len(self.ports), 'target_pps': self.rate}

    def finish(self):
        self.stop.set()
        self.pool.shutdown(wait=True)
        if self.job is not None:
            self.job.result()

    def validate(self, row):
        sent = sum(item['sent'] for item in row['rejections'])
        elapsed = self.ended - self.started
        received = row['carrier_after']['packets_recv'] - row['carrier_before']['packets_recv']
        samples = row['samples']
        row['udp_pressure'] = dict(target_pps=self.rate, sent=sent, received=received,
                                   seconds=elapsed, actual_pps=sent / elapsed,
                                   distinct_source_ports=len(set(self.ports)))
        require(len(set(self.ports)) == 64 and elapsed >= 10
                and sent / elapsed >= 0.75 * self.rate and received >= 0.5 * sent,
                'insufficient sustained UDP ingress pressure')
        require(len(samples) >= 3 and all(item['sent'] > 0 for item in row['rejections']),
                'missing UDP pressure cases or live samples')
        for sample in [row['before'], row['after'], *(s['bridge'] for s in samples)]:
            check_sample(sample, row['before'])
        advancing = [sample for sample in samples if sample['pressure']['sent'] >= self.rate
                     and all(probe and probe['received_bytes'] > 0
                             for probe in sample['endpoints'].values())]
        require(len(advancing) >= 2
                and advancing[-1]['pressure']['sent'] > advancing[0]['pressure']['sent']
                and all(advancing[-1]['endpoints'][name]['received_bytes']
                        > advancing[0]['endpoints'][name]['received_bytes']
                        for name in ('n01', 'n03')),
                'no sustained paid delivery during UDP pressure')
