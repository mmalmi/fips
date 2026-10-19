"""Exercise the real shell protocol locally; no SSH hosts or finances are used."""

import copy
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from sim.wifi_receiver_numeric import NumericReaders, worker


# This small jsonfilter stand-in preserves its documented type/value behavior.
# A hardware qualification must also exercise the installed jsonfilter binary.
FILTER = r'''
import json, re, sys, time
from pathlib import Path
args=sys.argv[1:]; expressions=[]; source=None
for index in range(0,len(args)):
    if args[index] in ('-i','-s'):
        source=json.loads(Path(args[index+1]).read_text()) if args[index]=='-i' else json.loads(args[index+1])
        if args[index]=='-i' and Path(args[index+1]+'.stall').exists(): time.sleep(20)
    if args[index] in ('-e','-t'): expressions.append((args[index],args[index+1]))
def values(expression):
    rows=[source]
    parts=re.findall(r'\.([a-z_]+)|\["([A-Za-z0-9_-]+)"\]|\[@\.terms\.id="([A-Za-z0-9_-]+)"\]',expression)
    for field,key,channel in parts:
        if channel:
            rows=[r for array in rows if isinstance(array,list) for r in array
                  if isinstance(r,dict) and r.get('terms',{}).get('id')==channel]
        else:
            rows=[r[field or key] for r in rows if isinstance(r,dict) and (field or key) in r]
    return rows
def typename(value):
    return {dict:'object',list:'array',str:'string',int:'int',bool:'boolean',float:'double',type(None):'null'}[type(value)]
for option,expression in expressions:
    rows=values(expression)
    if not rows: sys.exit(1)
    if option=='-t': print('\\ '.join(typename(v) for v in rows))
    else:
        for value in rows: print(value if isinstance(value,str) else json.dumps(value))
'''

SSH = r'''
import os, shlex, sys
args=shlex.split(sys.argv[-1])
assert args[:4]==['exec','setsid','sh','-c']
# Popen already placed this local stand-in into its own process group.
os.execv('/bin/bash',['bash','-c',args[4]])
'''


class NumericReaderTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.binary = self.root / 'bin'
        self.binary.mkdir()
        for name, source in [('jsonfilter', FILTER), ('ssh', SSH)]:
            file = self.binary / name
            file.write_text('#!' + sys.executable + '\n' + source)
            file.chmod(0o700)
        self.state = self.root / 'state'
        for parent in ('buyer', 'wallet', 'seller'):
            (self.state / parent).mkdir(parents=True)
        self.buyer = {'channels': {'channel': {'terms': {'id': 'channel'}, 'authorized_sat': 8}}}
        self.signer = {'payments': {'channel': {'balance': 7, 'payment_count': 2, 'signature': 'PRIVATE-SIGNATURE'}},
                       'funding': {'private': 'PRIVATE-FUNDING'}}
        self.seller = {'ledger': {'channels': [{'terms': {'id': 'channel'}, 'usage': {'paid_msat': 7000}}]}}
        self.save()
        self.ssh_calls = []

        def ssh_args():
            self.ssh_calls.append(1)
            return [str(self.binary / 'ssh')]

        self.owner = SimpleNamespace(host='unused-test-host', ssh_args=ssh_args, state=str(self.state))
        self.profile = SimpleNamespace(owner=self.owner, state=str(self.state))
        self.run = SimpleNamespace(participants=lambda: {'source': self.profile, 'n02': self.owner})
        self.env = patch.dict(os.environ, PATH=str(self.binary) + ':' + os.environ['PATH'])
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.temporary.cleanup()

    def save(self):
        for path, value in [('buyer/buyer.json', self.buyer), ('wallet/spilman-client.json', self.signer),
                            ('seller/ledger.json', self.seller)]:
            temporary = self.state / (path + '.new')
            temporary.write_text(json.dumps(value))
            temporary.replace(self.state / path)

    def test_sessions_persist_reopen_atomic_files_and_keep_signed_distinct(self):
        with NumericReaders(self.run) as readers:
            self.assertEqual(readers.payment('source', 'channel'), {'authorized_sat': 8, 'signed_sat': 7})
            self.buyer['channels']['channel']['authorized_sat'] = 9
            self.signer['payments']['channel']['balance'] = 8
            self.save()
            self.assertEqual(readers.payment('source', 'channel'), {'authorized_sat': 9, 'signed_sat': 8})
            self.assertEqual(readers.credit('n02', 'channel'), 7000)
            self.assertEqual(len(self.ssh_calls), 2)
        for reader in readers.readers.values():
            self.assertTrue(reader.receipt['reaped'])
            self.assertFalse(reader.receipt['forced'])
            self.assertEqual(reader.receipt['exit_code'], 0)
            with self.assertRaises(ProcessLookupError):
                os.killpg(reader.process.pid, 0)
        self.assertTrue(all(row['cleanup']['exit_code'] == 0 and row['cleanup']['group_absent']
                            for row in readers.cleanup_receipts))
        with self.assertRaisesRegex(RuntimeError, 'closed'):
            readers.payment('source', 'channel')

    def test_wrong_schema_numeric_types_channel_and_duplicate_rows_fail_closed(self):
        cases = [
            ('buyer', lambda: self.buyer['channels']['channel'].update(authorized_sat='8')),
            ('buyer', lambda: self.buyer['channels']['channel'].update(authorized_sat=True)),
            ('buyer', lambda: self.buyer['channels']['channel']['terms'].update(id='other')),
            ('signer', lambda: self.signer['payments']['channel'].update(balance=-1)),
            ('signer', lambda: self.signer['payments']['channel'].update(balance=1.5)),
            ('signer', lambda: self.signer['payments']['channel'].update(balance=1 << 64)),
            ('signer', lambda: self.signer['payments']['channel'].update(signature=None)),
            ('signer', lambda: self.signer['payments']['channel'].update(payment_count=0)),
            ('seller', lambda: self.seller['ledger']['channels'].append(copy.deepcopy(self.seller['ledger']['channels'][0]))),
        ]
        original = copy.deepcopy((self.buyer, self.signer, self.seller))
        for name, mutate in cases:
            with self.subTest(name=name):
                self.buyer, self.signer, self.seller = copy.deepcopy(original)
                mutate()
                self.save()
                with self.assertRaises(RuntimeError), NumericReaders(self.run) as readers:
                    with self.assertRaises(RuntimeError) as error:
                        readers.credit('n02', 'channel') if name == 'seller' else readers.payment('source', 'channel')
                    self.assertNotIn('PRIVATE', str(error.exception))
                    with self.assertRaisesRegex(RuntimeError, 'unavailable'):
                        readers.credit('n02', 'channel') if name == 'seller' else readers.payment('source', 'channel')

    def test_missing_or_malformed_original_never_becomes_zero(self):
        for value in ('{', '{}'):
            (self.state / 'wallet/spilman-client.json').write_text(value)
            with self.assertRaises(RuntimeError), NumericReaders(self.run) as readers:
                with self.assertRaises(RuntimeError):
                    readers.payment('source', 'channel')

    def test_timeout_is_terminal_and_owned_group_is_stopped(self):
        (self.state / 'buyer/buyer.json.stall').touch()
        with patch('sim.wifi_receiver_numeric.READ_SECONDS', .1):
            with self.assertRaisesRegex(RuntimeError, 'cleanup failed'), NumericReaders(self.run) as readers:
                with self.assertRaises(TimeoutError):
                    readers.payment('source', 'channel')
                with self.assertRaisesRegex(RuntimeError, 'unavailable'):
                    readers.payment('source', 'channel')
        reader, = readers.readers.values()
        self.assertTrue(reader.receipt['reaped'])
        self.assertTrue(reader.receipt['forced'])

    def test_remote_lifetime_and_session_count_are_bounded(self):
        with patch('sim.wifi_receiver_numeric.LIFETIME_SECONDS', 1):
            with self.assertRaisesRegex(RuntimeError, 'cleanup failed'), NumericReaders(self.run) as readers:
                with self.assertRaises(RuntimeError):
                    readers.payment('source', 'channel')
        with patch('sim.wifi_receiver_numeric.MAX_READERS', 1), NumericReaders(self.run) as readers:
            readers.credit('n02', 'channel')
            with self.assertRaisesRegex(RuntimeError, 'session limit'):
                readers.payment('source', 'channel')

    def test_invalid_keys_never_launch_a_process(self):
        for channel in ('', '../channel', 'channel\n', 'x' * 129, '";echo PRIVATE'):
            with self.subTest(channel=channel), self.assertRaises(ValueError):
                worker(str(self.state), channel, 'payment')
        self.assertEqual(self.ssh_calls, [])

    def test_one_cleanup_failure_does_not_skip_other_owned_sessions(self):
        first = SimpleNamespace(close=Mock(side_effect=RuntimeError('owned failure')))
        second = SimpleNamespace(close=Mock())
        readers = NumericReaders(self.run)
        readers.readers = {1: first, 2: second}
        with self.assertRaisesRegex(RuntimeError, 'cleanup failed'):
            readers.__exit__(None, None, None)
        first.close.assert_called_once()
        second.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
