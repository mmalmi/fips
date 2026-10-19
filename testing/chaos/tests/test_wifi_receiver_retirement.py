"""Reject false cleanup progress and preserve stopped WAL/export custody."""

import copy
import io
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from sim import wifi_receiver_custody as custody
from sim.remote_mint import RemoteMint
from sim.wifi_receiver_window import exposure, progress
from sim.wifi_receiver_retirement import ReceiverRetirementRun, SNAPSHOT_BUDGET, RECOVERY_RESERVE


class ReceiverWindowTests(unittest.TestCase):
    def test_progress_includes_whole_sat_credit_and_first_and_last_partial_windows(self):
        def sample(at, value, pending=True):
            return dict(elapsed_us=at, delivered=value, payments=[{'authorized_sat': value}] * 2,
                        credits=[value * 1000] * 2, cleanup_pending=pending)
        baseline = sample(0, 0)
        samples = [sample(1_000_000, 1), sample(2_000_000, 2), sample(3_000_000, 3, False)]
        result = progress(baseline, samples)
        self.assertTrue(result['within_limit'])
        self.assertTrue(result['all_counters_advanced'])
        self.assertTrue(result['progress_between_unfinished_cleanup_samples'])
        changed = copy.deepcopy(samples)
        for row in changed:
            row['credits'][1] = 0
        self.assertFalse(progress(baseline, changed)['all_counters_advanced'])
        self.assertFalse(progress(baseline, changed)['within_limit'])
        for changed in ([sample(2_000_001, 1), sample(3_000_000, 2)],
                        [*samples, sample(5_000_001, 3, False)]):
            self.assertFalse(progress(baseline, changed)['within_limit'])

    def test_exposure_uses_accepted_tariffs_and_refuses_capacity_or_cadence_failure(self):
        def state(index, cost):
            return {'payment_progress': {str(index): {'evidence_msat': cost}},
                    'purchases': [{'channel': {'id': str(index), 'capacity_sat': 64 if index == 0 else 32},
                                   'contract': {'price': {'msat': 512 if index == 0 else 256, 'per_bytes': 1024}}}]}
        before = [state(0, 0), state(1, 0)]
        warm = [state(0, 620), state(1, 310)]
        valid = exposure(before, warm, warm, ['0', '1'], 92)
        self.assertEqual(valid['hops'][1]['minimum_payload_msat'], 250)
        with self.assertRaisesRegex(RuntimeError, 'capacity'):
            exposure(before, warm, warm, ['0', '1'], 110)
        slow = copy.deepcopy(warm)
        slow[1]['purchases'][0]['contract']['price']['msat'] = 32
        with self.assertRaisesRegex(RuntimeError, 'cadence'):
            exposure(before, slow, slow, ['0', '1'], 92)


class StoppedCustodyTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == 'linux', 'router flock command requires Linux')
    def test_remote_recovery_waits_for_the_original_wallet_owner(self):
        import fcntl
        with tempfile.TemporaryDirectory() as directory:
            with (Path(directory) / 'owner.lock').open('w') as owner:
                fcntl.flock(owner, fcntl.LOCK_EX)
                release = threading.Timer(0.3, lambda: fcntl.flock(owner, fcntl.LOCK_UN))
                release.start()
                node = SimpleNamespace(state=directory, remote=lambda command, **_: subprocess.run(
                    ['sh', '-c', command], check=True, capture_output=True, timeout=5))
                run = object.__new__(ReceiverRetirementRun)
                run.nodes = {'n01': node, 'n02': node}
                started = time.monotonic()
                try:
                    run.wait_for_history_wallets()
                    self.assertGreaterEqual(time.monotonic() - started, 0.25)
                finally:
                    release.join()

    def test_snapshot_limit_preserves_existing_evidence_and_reserves_recovery_space(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / 'original.tar'
            original.write_bytes(b'original evidence')
            run = object.__new__(ReceiverRetirementRun)
            run.stopped_names, run.snapshot_count = {'n02'}, 0
            run.snapshot_budget_refused = run.recovering = False
            run.snapshot_bytes = SNAPSHOT_BUDGET - RECOVERY_RESERVE - custody.MAX_SNAPSHOT_BYTES + 1
            run.monitor, run.save = Mock(), Mock()
            run.evidence = {'receiver_history': {}}
            run.custody_root = root
            run.participants = Mock(return_value={'n02': object()})
            with patch.object(custody, 'saved', return_value=original) as save:
                with self.assertRaisesRegex(RuntimeError, 'evidence budget reached'):
                    run.snapshot('n02', 'new')
                save.assert_not_called()
                self.assertTrue(run.snapshot_budget_refused)
                run.snapshot('n02', 'recovery')
                save.assert_called_once()
                run.snapshot_bytes = SNAPSHOT_BUDGET
                with self.assertRaisesRegex(RuntimeError, 'evidence budget reached'):
                    run.snapshot('n02', 'over-cap')
            self.assertEqual(original.read_bytes(), b'original evidence')

    def test_copy_includes_wal_and_preserves_exact_receipts_and_durable_export_floor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / 'state' / custody.WALLET
            database.parent.mkdir(parents=True)
            with sqlite3.connect(database) as db:
                db.execute('PRAGMA journal_mode=WAL')
                db.execute('CREATE TABLE wallet_storage_total(id INTEGER,maximum INTEGER,charged INTEGER)')
                db.execute('INSERT INTO wallet_storage_total VALUES(1,20971520,1000)')
                db.execute('CREATE TABLE wallet_storage_accounts(reserved INTEGER,used INTEGER)')
                db.execute('CREATE TABLE proof(y BLOB,state TEXT)')
                y = b'\x02' * 33
                db.execute('INSERT INTO proof VALUES(?,?)', (y, 'SPENT'))
                db.execute('CREATE TABLE transactions(id BLOB,ys BLOB,direction TEXT,status TEXT,amount INTEGER,fee INTEGER)')
                db.execute("INSERT INTO transactions VALUES(?,?, 'Incoming','completed',1,0)", (b'receipt', y))
                db.execute('CREATE TABLE wallet_sagas(id TEXT)')
                db.execute('CREATE TABLE kv_store(primary_namespace TEXT,secondary_namespace TEXT,key TEXT,value BLOB)')
                sends = {'entries': {}, 'sequences': {'fips-exports': {'through': 137}}}
                db.execute("INSERT INTO kv_store VALUES('cashu_service','send_requests','journal',?)", (json.dumps(sends),))
                db.commit()
                output = io.BytesIO()
                with tarfile.open(fileobj=output, mode='w') as archive:
                    for name in (custody.WALLET, custody.WALLET + '-wal'):
                        archive.add(root / 'state' / name, arcname=name)
                profile = SimpleNamespace(state='/state', config='/profile.json', temporary='/guard',
                                          guarded=Mock(return_value=output.getvalue()))
                saved = custody.saved(profile, root, 'original')
                self.assertIn('can-start /profile.json', profile.guarded.call_args.args[0])
                self.assertEqual(custody.counts(saved)['proof_rows'], 1)
                self.assertEqual(custody.export_start(saved), 138)
                retained = custody.retained(saved, 1)
                custody.unchanged(saved, retained)
                with self.assertRaisesRegex(RuntimeError, 'preserve the original'):
                    custody.saved(profile, root, 'original')
                changed = copy.deepcopy(retained)
                changed['proofs'][y.hex()] = 'different'
                with self.assertRaisesRegex(RuntimeError, 'retained proof changed'):
                    custody.unchanged(saved, changed)
                with self.assertRaises(sqlite3.OperationalError):
                    with custody.opened(saved) as (_, readonly):
                        readonly.execute('DELETE FROM proof')
                self.assertEqual(saved.read_bytes(), output.getvalue())
                self.assertEqual(saved.stat().st_mode & 0o777, 0o600)

    def test_collection_recovers_consumed_exports_before_final_custody_audit(self):
        run = object.__new__(ReceiverRetirementRun)
        names = ('n01', 'n02', 'n03', 'source', 'destination')
        starts = dict(zip(names, (2, 4, 1, 1, 1)))
        current_starts = starts.copy()
        amounts = dict(zip(names, (64, 1, 0, 0, 0)))
        calls = []

        def control(name, kind, **fields):
            calls.append((name, kind, fields))
            if kind == 'recover':
                return dict(recovery_pass_complete=True, minted_amount=0, finalized_melts=0)
            self.assertEqual(kind, 'acknowledge_exports')
            prior = starts[name] - 1
            total = prior + (amounts[name] if fields['through'] > prior else 0)
            current_starts[name] = fields['through'] + 1
            return dict(requested_sat=total, cost=dict(wallet_debit_sat=total, swap_fee_sat=0))

        profiles = {name: SimpleNamespace(state='/' + name, control=Mock(
            side_effect=lambda kind, name=name, **fields: control(name, kind, **fields))) for name in names}
        run.participants = Mock(return_value=profiles)
        run.stop_snapshot = Mock(side_effect=lambda name, _label: name)
        run.snapshot = Mock(side_effect=lambda name, _label: name)
        run.state_json, run.account_execute, run.phase = Mock(), Mock(), Mock()
        run.reports, run.owners, run.providers = {}, {}, {}
        run.retained_history, run.mint_url = {'original': 'fingerprints'}, 'http://test-mint'
        run.evidence = {'receiver_history': {}, 'phases': []}

        def collected(*_args, **_kwargs):
            run.evidence['phases'].append({'settlement_collection': {'collected_by_node': amounts}})

        with patch('sim.wifi_receiver_retirement.collect_settled_wallets', side_effect=collected), \
                patch.object(custody, 'export_start', side_effect=current_starts.__getitem__), \
                patch.object(custody, 'unchanged') as unchanged, patch.object(custody, 'audit') as audit:
            run.collect_stopped({})
        for name in ('n01', 'n02'):
            sequence = [(kind, fields) for node, kind, fields in calls if node == name]
            self.assertEqual([kind for kind, _ in sequence], ['acknowledge_exports', 'recover', 'acknowledge_exports'])
            self.assertEqual(sequence[1][1], {'action': 'wallet', 'operation_timeout': 330})
            self.assertEqual(sequence[-1][1]['through'], starts[name] - 1 + (amounts[name] + 31) // 32)
        self.assertEqual(audit.call_args.args[2], 0)
        self.assertEqual(unchanged.call_count, 2)
        self.assertTrue(run.evidence['receiver_history']['retained_fingerprints_after_collection'])

    def test_3072_issuance_requires_explicit_receiver_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / 'mint'
            binary.write_bytes(b'\x7fELF\x02\x01' + b'\0' * 12 + b'\xb7\0')
            args = ({'host': 'lab', 'state_parent': '/tmp/bench'}, binary,
                    '123456789abc', root, '192.0.2.10')
            with self.assertRaisesRegex(ValueError, 'capped'):
                RemoteMint(*args, max_issued_sat=3072)
            with self.assertRaisesRegex(ValueError, 'exactly 3072'):
                RemoteMint(*args, max_issued_sat=512, receiver_history=True)
            mint = RemoteMint(*args, max_issued_sat=3072, receiver_history=True)
            self.assertTrue(mint.settings['receiver_history_keyset'])
            self.assertEqual(mint.settings['max_issued_sat'], 3072)
