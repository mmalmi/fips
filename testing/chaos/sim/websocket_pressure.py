"""Discovery-only WebSocket clients must expire while they remain responsive."""

import struct
import time

from websockets.exceptions import ConnectionClosed
from websockets.sync.client import connect

from .carrier_pressure import CarrierPressure
from .paid_settlement import require


# Existing LocalKeyHint v1 codec: version, big-endian nonce, optional x-only key.
REQUEST = struct.pack('>BQ', 1, 317)
RESPONSE = REQUEST + bytes([9]) * 32
PRELUDES = ('ping', 'pong', 'hint_request', 'hint_response')


def expired_prelude(address, kind, *, minimum=4.5, timeout=7):
    require(kind in PRELUDES, 'unknown prelude scenario')
    with connect('ws://%s:%s/fips' % address, proxy=None, compression=None,
                 ping_interval=None, ping_timeout=None, open_timeout=2,
                 close_timeout=1, max_size=256, max_queue=8) as client:
        started = time.monotonic()
        client.send(REQUEST)
        response = client.recv(timeout=1)
        require(isinstance(response, bytes) and len(response) == 41 and response[:9] == REQUEST,
                'test listener did not answer the nonce-bound key hint')
        sent = 0
        try:
            while time.monotonic() - started < timeout:
                tick = time.monotonic()
                if kind == 'ping':
                    client.ping(b'prelude')
                elif kind == 'pong':
                    client.pong(b'prelude')
                else:
                    client.send(REQUEST if kind == 'hint_request' else RESPONSE)
                sent += 1
                try:
                    reply = client.recv(timeout=0.05)
                    require(kind == 'hint_request' and isinstance(reply, bytes)
                            and len(reply) == 41 and reply[:9] == REQUEST,
                            'unexpected application data on discovery-only connection')
                except TimeoutError:
                    pass
                time.sleep(max(0, 0.05 - (time.monotonic() - tick)))
        except ConnectionClosed:
            elapsed = time.monotonic() - started
            require(minimum <= elapsed <= timeout and sent >= 2,
                    'prelude connection closed outside its startup deadline window')
            return {'close_seconds': elapsed, 'messages_sent': sent, 'hint_verified': True}
        raise TimeoutError('discovery-only WebSocket retained its connection slot')


class WebsocketPressure(CarrierPressure):
    records = dict(zip(PRELUDES, PRELUDES))

    def probe(self, kind):
        return expired_prelude(self.address, kind)
