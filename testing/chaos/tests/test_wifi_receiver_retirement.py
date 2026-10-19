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
from sim.wifi_receiver_workload import ReceiverWorkload, TRANSIT_SETUP_SECONDS


class ReceiverWorkloadTests(unittest.TestCase):
    def test_final_observation_fits_earliest_preparation_service_window(self):
        run = ReceiverRetirementRun.__new__(ReceiverRetirementRun)
        configs = {name: run.terms(name, {'terms': {'controller': {}}})['terms']
                   for name in ('source', 'n02', 'n03')}
        # Preparation, retirement eligibility, held probe and the full observation.
        self.assertGreaterEqual(TRANSIT_SETUP_SECONDS, 6 * 11 + 45)
        required_seconds = TRANSIT_SETUP_SECONDS + 3 + 3 + 37
        for buyer, provider in [('source', 'n02'), ('n02', 'n03')]:
            service = min(configs[buyer]['controller']['channel_lifetime_secs'] // 2,
                          configs[provider]['quote_lifetime_secs'])
            with self.subTest(buyer=buyer):
                self.assertGreaterEqual(service, required_seconds)

    def test_retirement_waits_for_original_prefix_deadlines_only(self):
        run = ReceiverWorkload()
        run.old = {'first', 'second'}
        run.intents = {'first': {'refund_after_unix': 100},
                       'second': {'refund_after_unix': 120},
                       'current': {'refund_after_unix': 500}}
        run.until = Mock()
        run.journal = Mock(return_value={'funding': {}})
        with patch('sim.wifi_receiver_workload.maintenance_idle', return_value=True):
            run.retired_prefix()
        run.until.assert_called_once_with(121)
        self.assertEqual(run.old, {'first', 'second'})

    def test_incomplete_burst_keeps_both_packet_counts_without_replaying_send(self):
        shape = dict(stream_id='original', packet_count=2, payload_bytes=1000)
        sender = dict(stream_id='original', requested_packets=2, submitted_packets=2,
                      submitted_bytes=2000, stopped_reason=None)
        receiver = dict(stream_id='original', source='buyer', expected_packets=2,
                        payload_bytes=1000, unique_packets=1, unique_bytes=1000,
                        missing_packets=1, duplicate_packets=0, invalid_packets=0, latency=None)
        run = ReceiverWorkload()
        run.evidence, run.save = {'receiver_history': {}}, Mock()
        run.record_probe_failure = Mock()
        run.ctl = Mock(return_value={'probe': receiver})
        run.participants = lambda: {'buyer': SimpleNamespace(npub='buyer')}
        with patch('sim.wifi_receiver_workload.probes.arm', return_value=shape), \
                patch('sim.wifi_receiver_workload.probes.send', return_value=sender) as send, \
                patch('sim.wifi_receiver_workload.eventually', side_effect=lambda _, check, __: check()):
            with self.assertRaisesRegex(RuntimeError, 'delivery is incomplete'):
                run.send('buyer', 'destination', 2, 1000, 128)
        send.assert_called_once()
        record, = run.evidence['receiver_history']['traffic']
        self.assertEqual((record['sender'], record['receiver']), (sender, receiver))
        self.assertIn('delivery is incomplete', record['failure'])
        run.record_probe_failure.assert_called_once_with(
            'receiver paid traffic', unittest.mock.ANY, record)
        self.assertEqual(run.save.call_count, 2)

    def test_restart_warmup_preserves_loss_and_never_replays_an_uncertain_send(self):
        run = ReceiverWorkload()
        run.evidence, run.save = {'receiver_history': {}}, Mock()
        run.ctl = Mock(return_value={'payment_progress': {'original': {'evidence_msat': 260}}})
        run.participants = lambda: {'buyer': SimpleNamespace(npub='buyer')}
        current = {'payment_progress': {'original': {'evidence_msat': 520}}}
        run.payment = Mock(return_value=current)

        def attempt(identifier, delivered):
            return dict(sender=dict(stream_id=identifier, requested_packets=1, submitted_packets=1,
                                    submitted_bytes=1000, stopped_reason=None),
                        receiver=dict(stream_id=identifier, source='buyer', expected_packets=1,
                                      payload_bytes=1000, unique_packets=delivered, unique_bytes=1000 * delivered,
                                      missing_packets=1-delivered, duplicate_packets=0, invalid_packets=0,
                                      latency=None))

        lost, delivered = attempt('first', 0), attempt('second', 1)
        with patch('sim.wifi_receiver_workload.stream', side_effect=[lost, delivered]) as send:
            self.assertEqual(run.warmup_payment('buyer', 'destination', 'original'), (current, 260))
        self.assertEqual(send.call_count, 2)
        self.assertEqual([row['receiver']['unique_packets'] for row in
                          run.evidence['receiver_history']['warmup']], [0, 1])
        run.payment.assert_called_once_with('buyer', 'original')
        with patch('sim.wifi_receiver_workload.stream', side_effect=TimeoutError('lost reply')) as send:
            with self.assertRaisesRegex(TimeoutError, 'lost reply'):
                run.warmup_payment('buyer', 'destination', 'original')
        send.assert_called_once()
        with patch('sim.wifi_receiver_workload.stream', return_value=lost) as send:
            with self.assertRaisesRegex(RuntimeError, 'native session warmup failed'):
                run.warmup_payment('buyer', 'destination', 'original')
        self.assertEqual(send.call_count, 6)

    def test_exact_payment_finishes_with_delayed_warmup_usage_and_small_tail_packets(self):
        for warmup_packets in (1, 6):
            with self.subTest(warmup_packets=warmup_packets):
                run = ReceiverWorkload()
                charged = warmup_packets * 260
                batches = []

                def status(*_):
                    return {'payment_progress': {'original': {
                        'evidence_msat': charged, 'authorized_sat': (charged + 999) // 1000}}}

                def send(owner, destination, count, size, rate):
                    nonlocal charged
                    self.assertLess(len(batches), 6, 'setup exhausted its bounded transfer allowance')
                    self.assertLessEqual(rate, 32, 'custody preparation exceeded the observed receiver pace')
                    charged += count * (260 if size == 1000 else 20)
                    self.assertLessEqual(charged, 32_000, 'exact payment target overshot')
                    record = dict(count=count, size=size)
                    batches.append(record)
                    return record

                run.warmup_payment = Mock(return_value=(status(), charged))
                run.send, run.payment, run.save = send, status, Mock()
                run.earn('buyer', 'destination', 'original', 32)
                self.assertEqual(status()['payment_progress']['original']['authorized_sat'], 32)
                self.assertTrue(any(row['size'] == 40 for row in batches))

    def test_transit_calibration_excludes_previous_billable_warmup_attempts(self):
        run = ReceiverWorkload()
        run.transit, run.guard = 'source-channel', 'relay-channel'
        run.evidence = {'receiver_history': {}}
        def state(channel, unit, capacity, count):
            return {'payment_progress': {channel: {'evidence_msat': count * unit}},
                    'purchases': [{'channel': {'id': channel, 'capacity_sat': capacity},
                                   'contract': {'price': {'msat': unit, 'per_bytes': 1024}}}]}
        before = [state(run.transit, 520, 64, 6), state(run.guard, 260, 32, 6)]
        after = [state(run.transit, 520, 64, 7), state(run.guard, 260, 32, 7)]
        run.warmup_payment = Mock(return_value=(before[0], 6 * 520))
        run.payment = Mock(side_effect=[before[1], *after])
        run.send = Mock()
        self.assertEqual(run.warm_transit(), (before, after))
        run.warmup_payment.assert_called_once_with('source', 'destination', run.transit)
        run.send.assert_called_once_with('source', 'destination', 1, 1000, 1)
        measured = run.evidence['receiver_history']['exposure']['hops']
        self.assertEqual([row['calibrated_warmup_msat'] for row in measured], [520, 260])

    def test_full_reports_match_after_provider_release_without_replaying_settlement(self):
        terms = {'id': 'original', 'capacity_sat': 960}
        report = dict(channel_id='original', value_after_stage1_sat=960, signed_sat=92,
                      paid_sat=92, refunded_sat=868, receiver_fee_reserve_sat=0, fee_sat=0)
        buyer = dict(channel=terms, report=report, refunded=True, wallet_refund_sat=868)
        run = ReceiverWorkload()
        run.owners, run.providers = {'original': 'buyer'}, {'original': 'seller'}
        run.intents = {'original': {'funded': {'terms': terms}}}
        run.reports, run.evidence = {}, {'receiver_history': {}}
        run.mutate, run.save = Mock(), Mock()
        seller = iter([dict(released=False, report=report), dict(released=True, report=report)])
        run.journal = lambda name: ({'buyer_settlements': {'original': buyer}} if name == 'buyer'
                                   else {'seller_settlements': {'original': next(seller)}})
        run.settle_channel('original', 92)
        self.assertEqual(run.reports['original']['paid_sat'], 92)
        run.mutate.assert_called_once_with('buyer', 'settle', channel='original')
        for changed in (dict(report, paid_sat=91, refunded_sat=869), dict(report, signed_sat=91)):
            run.journal = lambda name: ({'buyer_settlements': {'original': buyer}} if name == 'buyer'
                                       else {'seller_settlements': {'original': dict(released=True, report=changed)}})
            with self.assertRaisesRegex(RuntimeError, 'settled payment or provider payout differs'):
                run.settle_channel('original', 92)


class ReceiverWindowTests(unittest.TestCase):
    def test_progress_includes_whole_sat_credit_and_first_and_last_partial_windows(self):
        def sample(at, value, pending=True):
            return dict(elapsed_us=at, delivered=value, payments=[{'authorized_sat': value}] * 2,
                        counter_reads=[dict(started_us=at, finished_us=at) for _ in range(5)],
                        credits=[value * 1000] * 2, cleanup_pending=pending)
        baseline = sample(0, 0)
        samples = [sample(1_000_000, 1), sample(2_000_000, 2), sample(3_000_000, 3, False)]
        custody_samples = [dict(started_us=0, elapsed_us=100_000, cleanup_pending=True),
                           dict(started_us=3_000_000, elapsed_us=3_100_000, cleanup_pending=True)]
        result = progress(baseline, samples, custody_samples)
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
    def test_collection_deadline_reaches_original_and_auxiliary_wallets_once(self):
        run = object.__new__(ReceiverRetirementRun)
        run.check_forwards, run.monitor = Mock(), Mock()
        run.nodes = {'n01': SimpleNamespace(control=Mock())}
        run.extra = {'source': SimpleNamespace(control=Mock())}
        body = {'type': 'export', 'id': 1, 'amount_sat': 32}
        for name, profile in run.participants().items():
            for timeout in (45, 330):
                with self.subTest(name=name, timeout=timeout):
                    run.account_execute(name, 'fips-relay', 'wallet', body,
                                        operation_timeout=timeout)
                    profile.control.assert_called_once_with('export', action='wallet',
                        operation_timeout=timeout, id=1, amount_sat=32)
                    profile.control.reset_mock()
        self.assertEqual(body, {'type': 'export', 'id': 1, 'amount_sat': 32})

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
