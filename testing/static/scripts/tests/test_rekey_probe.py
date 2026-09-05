#!/usr/bin/env python3
"""Exercise the production probe loop with a delayed local datagram echo."""

import importlib.util
import io
import socket
import tempfile
import threading
import unittest
from pathlib import Path


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parents[1] / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    import sys
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


PROBE = load("rekey_probe")
ANALYZER = load("analyze_rekey_probes")


class ProbeDrainTests(unittest.TestCase):
    def test_stop_drains_delayed_reply_and_still_reports_a_real_loss(self):
        for drop in (False, True):
            with self.subTest(drop=drop), socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as server, \
                    socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as client:
                server.bind(("::1", 0))
                server.settimeout(2)
                client.connect(server.getsockname())
                stop = threading.Event()
                observed_stop = threading.Event()
                errors = []

                def should_stop():
                    if stop.is_set():
                        observed_stop.set()
                        return True
                    return False

                def echo():
                    try:
                        packet, address = server.recvfrom(4096)
                        stop.set()
                        if not observed_stop.wait(2):
                            raise TimeoutError("probe never observed stop request")
                        if not drop:
                            server.sendto(bytes([129]) + packet[1:], address)
                    except Exception as error:
                        errors.append(error)

                receiver = threading.Thread(target=echo)
                receiver.start()
                output = io.StringIO()
                try:
                    PROBE.run_probe(client, "::1", 0.5, should_stop, output, drain_timeout=0.1)
                finally:
                    receiver.join(2)
                self.assertFalse(receiver.is_alive())
                self.assertEqual(errors, [])
                with tempfile.TemporaryDirectory() as tmp:
                    path = Path(tmp) / "a-to-b.log"
                    path.write_text(output.getvalue())
                    result = ANALYZER.parse_probe(path)
                self.assertEqual(result.transmitted, 1)
                self.assertEqual(result.passed, not drop)
                self.assertEqual(result.missing_sequences, [1] if drop else [])


if __name__ == "__main__":
    unittest.main()
