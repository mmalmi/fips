"""Real sockets distinguish rejection from the slot leak the bench detects."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import socket
import sys
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim.carrier_pressure import RECORDS, rejected
from sim.wifi_carrier_pressure import WifiCarrierPressureRun


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
        tcp = {'type': 'tcp', 'name': 'rejections', 'stats': {'pool_inbound': 0, 'pool_outbound': 0}}
        self.assertIs(run.discovery_adapter('n02', [mesh, tcp]), mesh)
        for extra in ([mesh, tcp, {'type': 'udp'}], [mesh, tcp, tcp],
                      [mesh, {**tcp, 'stats': {'pool_inbound': 1, 'pool_outbound': 0}}]):
            with self.subTest(extra=extra), self.assertRaises(RuntimeError):
                run.discovery_adapter('n02', extra)


if __name__ == '__main__':
    unittest.main()
