"""Process ownership evidence and one-shot dispatch, without touching a device."""
from contextlib import nullcontext
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim.phone_restart import force_stop


class PhoneRestartTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.phone = Mock(root=Path(self.temp.name), package='org.fips.relaybench.acceptance.trial2')
        self.phone.locked.side_effect = nullcontext
        self.phone.shell.side_effect = self.shell
        self.phone.status.return_value = {'customer': {'configured': True, 'running': True}}
        self.alive = True
        self.pid = b'123'
        self.dispatched = 0
        self.uncertain = False

    def shell(self, *command):
        if command[:2] == ('sh', '-c'):
            return self.pid if self.alive else b''
        if command == ('run-as', self.phone.package, 'cat', '/proc/123/cmdline'):
            return self.phone.package.encode() + b'\0'
        if command == ('run-as', self.phone.package, 'cat', '/proc/123/stat'):
            return ('123 (bench) S ' + '0 ' * 18 + '4000').encode()
        self.assertEqual(command, ('am', 'force-stop', self.phone.package))
        self.assertEqual(json.loads((self.phone.root / 'process-stop-intent.json').read_text()),
                         {'pid': 123, 'start_ticks': 4000, 'package': self.phone.package})
        self.dispatched += 1
        if self.uncertain:
            raise RuntimeError('uncertain device response')
        self.alive = False
        return b''

    def test_stop_records_epoch_and_cannot_target_a_later_reopened_process(self):
        result = force_stop(self.phone)
        self.assertTrue(result['absent_after_stop'])
        self.assertEqual(result['before']['start_ticks'], 4000)
        self.alive = True
        with self.assertRaises(FileExistsError):
            force_stop(self.phone)
        self.assertEqual(self.dispatched, 1)

    def test_absent_or_ambiguous_process_is_not_a_successful_crash(self):
        for value in (b'', b'123 456', b'unknown'):
            self.pid = value
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                force_stop(self.phone)
        self.assertEqual(self.dispatched, 0)

    def test_uncertain_dispatch_retains_intent_and_never_repeats(self):
        self.uncertain = True
        with self.assertRaises(RuntimeError):
            force_stop(self.phone)
        with self.assertRaises(FileExistsError):
            force_stop(self.phone)
        self.assertEqual(self.dispatched, 1)
        self.assertFalse((self.phone.root / 'process-stop-result.json').exists())
