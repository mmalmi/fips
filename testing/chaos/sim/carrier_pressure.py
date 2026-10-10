"""Finite rejected-record pressure against one explicitly owned TCP listener."""

from concurrent.futures import ThreadPoolExecutor
import socket
import struct
import threading
import time


# Complete FMP records: invalid Noise initiation, unsolicited response, unknown
# encrypted receiver. These must reach Node rejection, not framing timeout.
RECORDS = {
    'msg1': struct.pack('<BBHI', 1, 0, 110, 77) + bytes(106),
    'msg2': struct.pack('<BBHII', 2, 0, 65, 77, 0xffffffff) + bytes(57),
    'unrouted': struct.pack('<BBHI', 0, 0, 0, 0xffffffff) + bytes(24),
}


def rejected(address, record, timeout=2):
    started = time.monotonic()
    with socket.create_connection(address, timeout=timeout) as client:
        client.sendall(record)
        try:
            if client.recv(1):
                raise RuntimeError('rejected record received unexpected response data')
        except ConnectionResetError:
            pass
    return time.monotonic() - started


class CarrierPressure:
    """Four bounded workers; timeout or early worker exhaustion fails the run."""

    def __init__(self, address):
        self.address = address
        self.stop = threading.Event()
        self.rows = [[] for _ in range(4)]
        self.pool = ThreadPoolExecutor(max_workers=4)
        self.jobs = []

    def start(self):
        self.jobs = [self.pool.submit(self.worker, rows) for rows in self.rows]

    def worker(self, rows):
        records = list(RECORDS.items())
        for index in range(1024):
            if self.stop.is_set():
                return
            kind, wire = records[index % len(records)]
            rows.append({'kind': kind, 'close_seconds': rejected(self.address, wire)})
            # At most 16 new connections/s across four workers, below the stock
            # OpenWrt SYN limit. This checks FIPS rejection, not firewall load.
            self.stop.wait(0.25)

    def observe(self):
        for job in self.jobs:
            if job.done():
                job.result()
                raise RuntimeError('pressure worker ended before the stream')
        return {'closed': sum(map(len, self.rows))}

    def finish(self):
        self.stop.set()
        self.pool.shutdown(wait=True)
        for job in self.jobs:
            job.result()
        return [row for rows in self.rows for row in rows]
