"""Reject erased liability, false signer failure and unrelated payment progress."""

import copy
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

from sim.wifi_signer_storage import StorageRouter, retained, validate_blocked
from tests.test_wifi_restart_load import accounts


class SignerStorageTests(unittest.TestCase):
    @unittest.skipUnless(Path('/proc/self/mountinfo').exists(), 'Linux mount inspection')
    def test_restore_accepts_payment_replacing_snapshot_after_unmount(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wallet, temporary = root / 'state/wallet', root / 'temporary'
            wallet.mkdir(parents=True)
            temporary.mkdir()
            snapshot = wallet / 'spilman-client.json'
            snapshot.write_text('before')
            original = snapshot.stat()
            (temporary / 'storage-identity').write_text(
                f'{os.major(original.st_dev)}:{os.minor(original.st_dev)}:{original.st_ino}\n')
            (temporary / 'storage-armed').touch()
            replacement = wallet / 'replacement'
            replacement.write_text('automatic payment')
            replacement.replace(snapshot)
            node = SimpleNamespace(state=str(wallet.parent), temporary=str(temporary))
            script = StorageRouter.storage_script(node)
            result = subprocess.run(['sh', '-s', 'restore'], input=script, text=True,
                                    capture_output=True, check=True)
            self.assertIn('"restored":true', result.stdout)
            self.assertEqual(snapshot.read_text(), 'automatic payment')
            self.assertFalse((temporary / 'storage-armed').exists())
            subprocess.run(['sh', '-s', 'restore'], input=script, text=True,
                           capture_output=True, check=True)

    def scenario(self):
        before = accounts()
        blocked = copy.deepcopy(before)
        source = blocked['n01']
        channel = 'channel-n01'
        source['signed'][channel] += 1
        source['signed_after'][channel] += 1
        source['authorized'] += 1
        source['remaining'] -= 1
        opposite = copy.deepcopy(blocked)
        source = opposite['n03']
        other = 'channel-n03'
        source['signed'][other] += 1
        source['signed_after'][other] += 1
        source['authorized'] += 1
        source['remaining'] -= 1
        opposite['n02']['credited'][other] += 1000
        opposite['n02']['seller_channels'][other]['paid_msat'] += 1000
        return before, blocked, opposite, channel

    def test_pending_authorization_survives_without_a_second_buyer_stalling(self):
        before, blocked, opposite, channel = self.scenario()
        validate_blocked(before, blocked, opposite, channel, 'saved', 'saved')
        recovered = copy.deepcopy(opposite)
        recovered['n02']['credited'][channel] = recovered['n01']['signed'][channel] * 1000
        recovered['n02']['seller_channels'][channel]['paid_msat'] = recovered['n02']['credited'][channel]
        retained(before, recovered)

    def test_bad_financial_or_snapshot_evidence_is_rejected(self):
        for edit in (
            lambda b, x, y: y['n01'].update(remaining=64),
            lambda b, x, y: y['n01']['funding'].clear(),
            lambda b, x, y: x['n02']['credited'].update({'channel-n01': 6000}),
            lambda b, x, y: y.update(n03=copy.deepcopy(b['n03'])),
            lambda b, x, y: x['n01']['signed'].update({'channel-n01': b['n01']['signed']['channel-n01']}),
        ):
            before, blocked, opposite, channel = self.scenario()
            edit(before, blocked, opposite)
            with self.assertRaises(RuntimeError):
                validate_blocked(before, blocked, opposite, channel, 'saved', 'saved')
        before, blocked, opposite, channel = self.scenario()
        with self.assertRaisesRegex(RuntimeError, 'saved snapshot'):
            validate_blocked(before, blocked, opposite, channel, 'saved', 'changed')
