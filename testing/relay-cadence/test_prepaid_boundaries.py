"""Opt-in prepaid usage boundaries retain every observed interval, without live funds."""
import copy
import unittest

from analyze import analyze_rows, diagnose_rows, markdown
from test_analyze import complete_report
from test_service_carrier import report as instrument_carriers


CONTRACT = 'prepaid-usage-v1'
BOUNDARIES = ('before_guard', 'before', 'after', 'after_guard')


def trial_snapshots(rows, trial=0):
    return [row['data'][boundary] for row in rows if row.get('trial') == trial and 'data' in row
            for boundary in BOUNDARIES]


def report():
    rows = instrument_carriers(complete_report())
    rows[0]['boundary_accounting'] = CONTRACT
    # Complete, monotonically sampled loopback peer counters. The original
    # synthetic report only carries sent_bytes; v1 must not invent the rest.
    for trial in range(8):
        for index, nodes in enumerate(trial_snapshots(rows, trial)):
            for node in nodes:
                node['measurements']['process_cpu_ns'] += index * 123
                for peer in node['peers']:
                    peer['sent_bytes'] += index * 7
                    peer.update(received_bytes=index * 17, sent_packets=index * 2,
                                received_packets=index * 3)
    return rows


def prepaid_step(rows, boundary_index, amount=1):
    """Consume existing credit without changing authorization or acknowledgment."""
    for nodes in trial_snapshots(rows)[boundary_index:]:
        nodes[0]['payment_progress']['forward-0']['evidence_msat'] += amount


class PrepaidBoundaryTests(unittest.TestCase):
    def reject(self, rows, pattern=None):
        for analyze in (analyze_rows, diagnose_rows):
            with self.subTest(analyzer=analyze.__name__):
                if pattern:
                    with self.assertRaisesRegex(ValueError, pattern):
                        analyze(rows)
                else:
                    with self.assertRaises((ValueError, KeyError, TypeError)):
                        analyze(rows)

    def test_each_prepaid_gap_is_recorded_and_legacy_still_rejects(self):
        for boundary in (1, 3, 4, 15):
            with self.subTest(boundary=boundary):
                rows = report()
                prepaid_step(rows, boundary)
                original = copy.deepcopy(rows)
                _, windows, _ = analyze_rows(rows)
                final = windows[3]['observed_trial_costs']
                self.assertEqual(final['prepaid_usage_msat']['forward-0'], 1)
                self.assertEqual(rows, original)
                rows[0].pop('boundary_accounting')
                self.reject(rows, 'payment evidence changed')

    def test_contract_is_explicit_typed_and_schema_two_only(self):
        for value in (None, True, 1, [], {}, 'prepaid-usage-v2', 'strict'):
            rows = report()
            rows[0]['boundary_accounting'] = value
            with self.subTest(value=value):
                self.reject(rows, 'boundary accounting')
        rows = report()
        rows[0]['schema'] = 3
        self.reject(rows, 'schema 2')
        rows = report()
        rows[0]['payment_service_carrier'] = False
        self.reject(rows, 'carrier')

    def test_covered_evidence_only_does_not_allow_financial_changes(self):
        for field, value in (('evidence_msat', 10001), ('evidence_msat', 9998),
                             ('authorized_sat', 9), ('acknowledged_msat', 11000),
                             ('in_flight', True), ('acknowledged_msat', None)):
            rows = report()
            trial_snapshots(rows)[1][0]['payment_progress']['forward-0'][field] = value
            with self.subTest(field=field, value=value):
                self.reject(rows)

    def test_prepaid_usage_is_credit_bounded_not_a_one_msat_tolerance(self):
        rows = report()
        for nodes in trial_snapshots(rows):
            nodes[0]['payment_progress']['forward-0']['evidence_msat'] -= 100
        prepaid_step(rows, 4, 101)
        _, windows, _ = analyze_rows(rows)
        self.assertEqual(windows[3]['observed_trial_costs']['prepaid_usage_msat']['forward-0'], 101)
        prepaid_step(rows, 4, 1)
        self.reject(rows, 'unreconciled')

    def test_all_financial_types_and_required_fields_remain_strict(self):
        for field in ('evidence_msat', 'authorized_sat', 'acknowledged_msat'):
            for value in (-1, True, None, 1.5, '10000'):
                rows = report()
                trial_snapshots(rows)[3][0]['payment_progress']['forward-0'][field] = value
                with self.subTest(field=field, value=value):
                    self.reject(rows)
        for field in ('evidence_msat', 'authorized_sat', 'acknowledged_msat', 'in_flight'):
            rows = report()
            trial_snapshots(rows)[15][0]['payment_progress']['forward-0'].pop(field)
            with self.subTest(missing=field):
                self.reject(rows)

    def test_original_zero_payment_and_durable_gap_guards_remain(self):
        for boundary in (1, 3, 4, 15):
            for change in ('payment', 'records', 'durable'):
                rows = report()
                for nodes in trial_snapshots(rows)[boundary:]:
                    node = nodes[0]
                    if change == 'records':
                        node['control_traffic'][2]['counters']['stream_bytes_sent'] += 1
                    else:
                        name = 'payment_usage' if change == 'payment' else 'other'
                        counters = node['measurements']['operations'][name]
                        if change == 'payment':
                            counters['spans'] += 1
                            counters['cpu_samples'] += 1
                        else:
                            counters['journal_syncs'] += 1
                with self.subTest(boundary=boundary, change=change):
                    self.reject(rows)

    def test_all_observed_costs_telescope_without_changing_workload_costs(self):
        rows = report()
        original = copy.deepcopy(rows)
        metadata, windows, grouped = analyze_rows(rows)
        trial = windows[:4]
        intervals = [v for row in trial for v in row['observed_intervals'].values()]
        self.assertEqual(len(intervals), 15)
        final = trial[-1]['observed_trial_costs']
        self.assertEqual(final['interval_count'], 15)
        self.assertTrue(final['telescopes'])
        self.assertEqual(sum(v['total']['process_cpu_ns'] for v in intervals),
                         final['total']['process_cpu_ns'])
        self.assertEqual(final['total']['process_cpu_ns'], 5 * (400000 + 15 * 123))
        self.assertEqual(final['total']['links']['sent_packets'], 8 * 15 * 2)
        self.assertEqual(final['total']['service_carrier']['discarded_outputs'], 5 * 15)
        self.assertGreater(trial[0]['observed_intervals']['before_guard_to_before']
                           ['total']['process_cpu_ns'], 0)
        self.assertEqual(final['nodes']['100']['operations']['payment_update']['spans'], 3)
        self.assertEqual(final['nodes']['100']['journals']['journal_writes'], 7 * 3)
        legacy = copy.deepcopy(rows)
        legacy[0].pop('boundary_accounting')
        _, old, _ = analyze_rows(legacy)
        for current, prior in zip(windows, old):
            for key, value in prior.items():
                self.assertEqual(current[key], value, key)
        self.assertEqual(rows, original)
        # The old table would silently omit the newly measured overhead.
        with self.assertRaisesRegex(ValueError, 'JSON'):
            markdown(metadata, grouped)

    def test_new_contract_also_rejects_open_stop_work_without_journal_writes(self):
        for name in ('payment_open', 'payment_stop'):
            for boundary in (1, 3, 4, 15):
                rows = report()
                for nodes in trial_snapshots(rows)[boundary:]:
                    c = nodes[0]['measurements']['operations'][name]
                    c['spans'] += 1
                    c['cpu_samples'] += 1
                    c['thread_cpu_ns'] += 123
                    c['elapsed_ns'] += 456
                with self.subTest(operation=name, boundary=boundary):
                    self.reject(rows, 'payment work outside')
                    rows[0].pop('boundary_accounting')
                    analyze_rows(rows)  # Preserve the historical strict contract.

    def test_nonpayment_cpu_overhead_and_large_counter_deltas_are_exact(self):
        rows = report()
        for index, nodes in enumerate(trial_snapshots(rows)):
            for node in nodes:
                node['measurements']['process_cpu_ns'] += 2**60
                c = node['measurements']['operations']['other']
                c['thread_cpu_ns'] += 2**60 + index
                c['elapsed_ns'] += 2**60 + 2 * index
                c['spans'] += index
                c['cpu_samples'] += index
        _, windows, _ = analyze_rows(rows)
        final = windows[3]['observed_trial_costs']
        self.assertEqual(final['total']['operations']['other']['thread_cpu_ns'], 5 * (3000 + 15))
        self.assertIs(type(final['total']['process_cpu_ns']), int)
        guard = windows[3]['observed_intervals']['after_to_after_guard']
        self.assertEqual(guard['total']['operations']['other']['spans'], 5)
        self.assertEqual(guard['total']['operations']['other']['thread_cpu_ns'], 5)
        self.assertEqual(guard['total']['operations']['other']['elapsed_ns'], 10)
        self.assertEqual(guard['total']['journals']['journal_writes'], 0)

    def test_every_operation_and_link_counter_is_monotonic_in_final_guard(self):
        for field in ('spans', 'cpu_samples', 'thread_cpu_ns', 'elapsed_ns',
                      'journal_writes', 'journal_bytes_written', 'journal_syncs', 'journal_commits'):
            rows = report()
            trial_snapshots(rows)[15][0]['measurements']['operations']['other'][field] = 0
            with self.subTest(operation_counter=field):
                self.reject(rows)
        for field in ('sent_bytes', 'received_bytes', 'sent_packets', 'received_packets'):
            for value in (0, -1, True, None, 1.5, '100'):
                rows = report()
                trial_snapshots(rows)[15][0]['peers'][0][field] = value
                with self.subTest(link_counter=field, value=value):
                    self.reject(rows)

    def test_new_contract_preserves_delivery_financial_and_tail_rejections(self):
        rows = report()
        rows[1]['data']['observation_elapsed_ms'] = 10999
        self.reject(rows, 'three-second')
        rows = report()
        rows[5]['collected_sat'] -= 1
        self.reject(rows, 'conservation')
        rows = report()
        p = rows[2]['data']['probes'][0]['receiver']
        p['unique_packets'] -= 1
        p['missing_packets'] += 1
        p['unique_bytes'] -= 1000
        # Corrupt timing cannot be laundered by diagnostic delivery-loss mode.
        self.reject(rows)

    def test_topology_process_and_counter_changes_in_gaps_are_rejected(self):
        def mutate(nodes, kind):
            n = nodes[0]
            if kind == 'process': n['measurements']['process_id'] = 999
            elif kind == 'channel': n['payment_progress']['other'] = n['payment_progress'].pop('forward-0')
            elif kind == 'peer': n['peers'][0]['npub'] = 'replacement'
            elif kind == 'epoch': n['peers'][0]['link_id'] += 1
            elif kind == 'duplicate': n['peers'].append(copy.deepcopy(n['peers'][0]))
            elif kind == 'missing': n['peers'][0].pop('received_bytes')
            elif kind == 'reset': n['peers'][0]['received_bytes'] = 0
            elif kind == 'cpu': n['measurements']['process_cpu_ns'] = 0
        for boundary in (3, 4, 15):
            for kind in ('process', 'channel', 'peer', 'epoch', 'duplicate', 'missing', 'reset', 'cpu'):
                rows = report()
                mutate(trial_snapshots(rows)[boundary], kind)
                with self.subTest(boundary=boundary, kind=kind):
                    self.reject(rows)


if __name__ == '__main__':
    unittest.main()
