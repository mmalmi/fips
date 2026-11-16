"""A stale guest identity must never signal an unrelated live process."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from sim.guest_system import Guest


@unittest.skipUnless(hasattr(os, 'pidfd_open'), 'requires Linux pidfds')
class GuestOwnershipTests(unittest.TestCase):
    def test_power_cut_refuses_another_uuid_or_image(self):
        with tempfile.TemporaryDirectory() as directory:
            process = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)',
                                        'actual-uuid', 'another-image'])
            try:
                guest = Guest.__new__(Guest)
                guest.root = Path(directory)
                guest.qemu = sys.executable
                guest.process = process
                for identity in ('wrong-uuid', 'actual-uuid'):
                    with self.subTest(identity=identity):
                        guest.uuid = identity
                        with self.assertRaisesRegex(RuntimeError, 'owned guest arguments changed'):
                            guest.cut_power()
                        self.assertIsNone(process.poll())
            finally:
                process.terminate()
                process.wait(timeout=5)


if __name__ == '__main__':
    unittest.main()
