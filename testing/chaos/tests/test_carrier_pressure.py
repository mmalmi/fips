"""Real sockets distinguish rejection from the slot leak the bench detects."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import socket
import sys
import threading
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim.carrier_pressure import RECORDS, rejected
from sim.wifi_carrier_pressure import WifiCarrierPressureRun

try:
    from websockets.exceptions import ConnectionClosed
    from websockets.sync.server import serve
    from sim.websocket_pressure import PRELUDES, REQUEST, RESPONSE, expired_prelude
except ImportError:
    serve = None


class CarrierPressureTests(unittest.TestCase):
    def test_closed_records_pass_but_a_retained_socket_or_response_fails(self):
        for mode in ('close', 'hold', 'response'):
            with self.subTest(mode=mode), socket.socket() as listener:
                listener.bind(('127.0.0.1', 0))
                listener.listen()
                listener.settimeout(2)
                release = threading.Event()

                def server():
                    with listener.accept()[0] as client:
                        client.settimeout(2)
                        wire = b''
                        while len(wire) < len(RECORDS['msg2']):
                            chunk = client.recv(1024)
                            self.assertTrue(chunk)
                            wire += chunk
                        self.assertEqual(wire, RECORDS['msg2'])
                        if mode == 'hold':
                            self.assertTrue(release.wait(2))
                        elif mode == 'response':
                            client.sendall(b'x')

                with ThreadPoolExecutor(max_workers=1) as pool:
                    job = pool.submit(server)
                    try:
                        if mode == 'hold':
                            with self.assertRaises(socket.timeout):
                                rejected(listener.getsockname(), RECORDS['msg2'], timeout=0.1)
                        elif mode == 'response':
                            with self.assertRaisesRegex(RuntimeError, 'unexpected response'):
                                rejected(listener.getsockname(), RECORDS['msg2'])
                        else:
                            self.assertGreater(rejected(listener.getsockname(), RECORDS['msg2']), 0)
                    finally:
                        release.set()
                        job.result(timeout=2)

    def test_extra_transport_cannot_hide_a_mesh_shortcut(self):
        run = object.__new__(WifiCarrierPressureRun)
        from types import SimpleNamespace
        run.nodes = {'n02': SimpleNamespace(interface='mesh0')}
        mesh = {'type': 'ethernet', 'name': 'mesh0'}
        for transport, opened, closed in (('tcp', 'pool_inbound', 'pool_outbound'),
                                          ('websocket', 'connections_opened', 'connections_closed')):
            run.transport_type = transport
            carrier = {'type': transport, 'name': 'rejections', 'stats': {opened: 0, closed: 0}}
            self.assertIs(run.discovery_adapter('n02', [mesh, carrier]), mesh)
            for extra in ([mesh, carrier, {'type': 'udp'}], [mesh, carrier, carrier],
                          [mesh, {**carrier, 'stats': {opened: 1, closed: 0}}]):
                with self.subTest(extra=extra), self.assertRaises(RuntimeError):
                    run.discovery_adapter('n02', extra)

    @unittest.skipUnless(serve, 'WebSocket bench requires websockets 15.x')
    def test_responsive_preludes_expire_but_early_close_or_retained_slot_fails(self):
        cases = [(kind, 'expire') for kind in PRELUDES]
        cases += [('ping', mode) for mode in ('early', 'hold', 'data', 'bad_hint')]
        for kind, mode in cases:
            with self.subTest(kind=kind, mode=mode), socket.socket() as listener:
                listener.bind(('127.0.0.1', 0))
                listener.listen()
                release, done = threading.Event(), threading.Event()
                errors = []

                def handler(client):
                    try:
                        self.assertEqual(client.recv(timeout=1), REQUEST)
                        client.send(b'wrong' if mode == 'bad_hint' else RESPONSE)
                        if mode == 'hold':
                            self.assertTrue(release.wait(2))
                        elif mode == 'data':
                            client.send(b'unexpected application data')
                        elif mode == 'expire':
                            until = time.monotonic() + 0.25
                            while time.monotonic() < until:
                                try:
                                    data = client.recv(timeout=0.02)
                                    self.assertIn(data, (REQUEST, RESPONSE))
                                    if data == REQUEST:
                                        client.send(RESPONSE)
                                except TimeoutError:
                                    pass
                    except ConnectionClosed:
                        pass
                    except BaseException as error:
                        errors.append(error)
                    finally:
                        done.set()

                with serve(handler, sock=listener, ping_interval=None, close_timeout=0.2) as server:
                    with ThreadPoolExecutor(max_workers=1) as pool:
                        job = pool.submit(server.serve_forever)
                        try:
                            probe = lambda: expired_prelude(listener.getsockname(), kind,
                                                             minimum=0.15, timeout=0.6)
                            if mode == 'expire':
                                self.assertTrue(probe()['hint_verified'])
                            else:
                                error = TimeoutError if mode == 'hold' else RuntimeError
                                with self.assertRaises(error):
                                    probe()
                        finally:
                            release.set()
                            server.shutdown()
                            job.result(timeout=2)
                            self.assertTrue(done.wait(2))
                        self.assertFalse(errors, errors)

    def test_discovery_stats_reject_unexpected_fips_records_or_admission_failures(self):
        run = object.__new__(WifiCarrierPressureRun)
        run.transport_type = 'websocket'
        before = dict.fromkeys(('connections_opened', 'connections_closed', 'connections_rejected',
                                'invalid_frames', 'frames_received', 'frames_sent'), 0)
        after = dict(before, connections_opened=4, connections_closed=4)
        row = {'carrier_before': before, 'carrier_after': after, 'rejections': [None] * 4}
        run.validate_rejections(row)
        for key in after:
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                run.validate_rejections({**row, 'carrier_after': {**after, key: after[key] + 1}})


if __name__ == '__main__':
    unittest.main()
