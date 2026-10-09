"""A refused full-disk restart must prove the storage error and keep journals."""

from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

from sim.wifi_full_state import FullStateRun, validate_journals


class FullStateTests(unittest.TestCase):
    def test_journal_evidence_cannot_be_omitted_or_replaced(self):
        original = dict(controller='one', buyer='two', seller='three')
        validate_journals(original, dict(original))
        for changed in ({}, {**original, 'seller': 'replaced'}):
            with self.assertRaises(RuntimeError):
                validate_journals(original, changed)

    @unittest.skipUnless(Path('/proc/self/stat').exists(), 'Linux process inspection')
    def test_restart_requires_full_volume_and_expected_storage_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / 'relay'
            (root / 'guard.sh').write_text('#!/bin/sh\nexit 0\n')

            def guarded(command, **kwargs):
                command = "df() { printf 'Filesystem Blocks Used Available\\n/test 1 1 %s\\n' " + str(available) + "; }\n" + command
                result = subprocess.run(['sh', '-eu', '-c', command], capture_output=True,
                                        timeout=kwargs['timeout'])
                if result.returncode:
                    raise RuntimeError(result.stderr.decode())
                return result.stdout

            node = SimpleNamespace(temporary=str(root), binary=str(binary),
                                   config=str(root / 'config'), volume=str(root), guarded=guarded)
            run = SimpleNamespace(fault_node='n02', nodes={'n02': node})
            for code, error, available in ((1, 'os error 28', 0),
                    (1, 'fips-relay: failed to open Cashu wallet database', 0),
                    (0, 'os error 28', 0), (1, 'unrelated error', 0), (1, 'os error 28', 1)):
                binary.write_text(f'#!/bin/sh\necho "{error}" >&2\nexit {code}\n')
                binary.chmod(0o700)
                with self.subTest(code=code, error=error):
                    if code == 1 and error != 'unrelated error' and available == 0:
                        self.assertEqual(FullStateRun.refuse_restart(run), {'exit_code': 1})
                    else:
                        with self.assertRaises(RuntimeError):
                            FullStateRun.refuse_restart(run)
