"""Paid radio evidence and test-fund recovery without live hardware or money."""

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim.paid_settlement import settle_and_collect
from sim.paid_wifi import PaidWifiRun, reconciled_channels, retain_channels
from sim.wifi_crowded import CrowdedWifiRun
from sim.wifi_admission_pressure import AdmissionPressure, check_sample
from sim.paid_faults import validate_unpaid_probe
from sim.paid_wifi_mint import LocalMint
from tests.test_paid_faults import finances
from tests.test_paid_settlement import FakeRun, NODES


def accounts():
    data = finances()
    for node, state in data.items():
        funded = 0 if node == "n02" else 32
        state.pop("wallet")
        state["funding"] = {node: (node, f"operation-{node}")} if funded else {}
        state["budget"] = {"locked_sat": funded, "wallet_debited_sat": funded,
                           "exposure_sat": funded, "pending_reserved_sat": 0,
                           "wallet_refunded_sat": 0}
    return data


class PaidWifiTests(unittest.TestCase):
    def test_final_rejoin_check_uses_the_configured_quote_limit(self):
        service = object.__new__(PaidWifiRun)
        service.args, service.evidence = SimpleNamespace(), {}
        service.nodes = {name: SimpleNamespace(npub=name) for name in ('n01', 'n02', 'n03')}
        service.quote_max_units = 60_000
        before, paid = accounts(), accounts()
        paid['n01'].update(remaining=46, authorized=18, signed={'n01': 18},
                           signed_after={'n01': 18}, buyer_units={'n01': 35_000})
        paid['n02']['credited']['n01'] = 18_000
        paid['n02']['seller_channels']['n01'].update(
            paid_msat=18_000, submitted_msat=17_500, reserved_msat=17_500)
        paid['n02']['seller_units']['n01'] = 35_000
        service.form_line, service.mesh_outage, service.verify_shortcuts = Mock(), Mock(), Mock()
        service.assert_finances, service.finances = Mock(return_value=before), Mock(return_value=before)
        service.paid_streams = Mock(side_effect=[before, paid])
        service.ctl = Mock(side_effect=lambda name, _kind, **_fields: dict(npub=name))
        service.phase, service.save = Mock(), Mock()
        service.collect = Mock(return_value=dict(settled_wallet_balances=dict(n01=127, n02=130, n03=127)))
        with patch('sim.paid_wifi.PaidRelayRun.unpaid_probe'):
            service.exercise()
        service.verify_shortcuts.assert_called_once_with()
        service.collect.assert_called_once_with()

    def test_mint_selection_keeps_the_existing_local_and_remote_adapters(self):
        service = object.__new__(PaidWifiRun)
        service.run, service.root = "a" * 12, Path("/private/output")
        args = SimpleNamespace(mint_binary=Path("/mint"), mint_address="127.0.0.1",
                               mint_host=None, mint_ssh_forward=True)
        with patch("sim.paid_wifi.LocalMint") as local, patch("sim.paid_wifi.RemoteMint") as remote:
            self.assertIs(service.create_mint(args), local.return_value)
            local.assert_called_once_with(args.mint_binary, args.mint_address, service.root)
            remote.assert_not_called()
            args.mint_host = Mock()
            args.mint_host.read_text.return_value = '{"host":"private-mint"}'
            args.mint_address, args.mint_ssh_forward = "192.0.2.1", False
            self.assertIs(service.create_mint(args), remote.return_value)
            remote.assert_called_once_with({"host": "private-mint"}, args.mint_binary,
                                           service.run, service.root, args.mint_address,
                                           max_issued_sat=384)
            self.assertEqual(local.call_count, 1)

    def test_conflicting_mint_modes_fail_before_creating_any_run(self):
        args = SimpleNamespace(mint_host=Path("/remote.json"), mint_ssh_forward=True,
                               mint_address="127.0.0.1")
        with patch("sim.paid_wifi.WifiRun.__init__") as setup, \
                self.assertRaisesRegex(ValueError, "separate choices"):
            PaidWifiRun(args)
        setup.assert_not_called()

    def test_outage_selection_is_validated_before_creating_any_run(self):
        for active, target in ((False, "n02"), (False, "n03"), (True, "n04")):
            args = SimpleNamespace(active_outage=active, outage_node=target)
            with self.subTest(active=active, target=target), \
                    patch("sim.paid_wifi.WifiRun.__init__") as setup, \
                    self.assertRaisesRegex(ValueError, "outage"):
                PaidWifiRun(args)
            setup.assert_not_called()

    def test_root_outage_rejects_conflicting_modes_before_creating_any_run(self):
        for field, value in (('active_outage', False), ('outage_node', 'n02'),
                             ('brief_outage', True), ('streams', True), ('interrupted_promotion', True)):
            args = SimpleNamespace(root_outage=True, active_outage=True)
            setattr(args, field, value)
            with self.subTest(field=field), patch('sim.paid_wifi.WifiRun.__init__') as setup, \
                    self.assertRaises(ValueError):
                PaidWifiRun(args)
            setup.assert_not_called()

    def test_crowded_rejoin_rejects_other_scenarios_before_any_setup(self):
        for field in ('active_outage', 'streams', 'interrupted_promotion', 'carrier_pressure_port'):
            args = SimpleNamespace(**{field: True})
            with self.subTest(field=field), patch('sim.paid_wifi.PaidWifiRun.__init__') as setup, \
                    self.assertRaisesRegex(ValueError, 'separate paid Wi-Fi scenario'):
                CrowdedWifiRun(args)
            setup.assert_not_called()

    def test_crowded_rejoin_command_selects_the_shared_paid_lifecycle(self):
        from sim.paid_wifi import main
        argv = ['paid_wifi', '--inventory', '/inventory', '--binary', '/relay',
                '--mint-binary', '/mint', '--mint-address', '127.0.0.1',
                '--output', '/output', '--crowded-rejoin']
        for extra, count in (([], 1), (['3'], 3)):
            with self.subTest(count=count), patch.object(sys, 'argv', argv + extra), \
                    patch('sim.paid_wifi.signal.signal'), patch('sim.paid_wifi.signal.alarm'), \
                    patch('sim.wifi_crowded.CrowdedWifiRun') as run:
                main()
            run.assert_called_once()
            self.assertEqual(run.call_args.args[0].crowded_rejoin, count)
            run.return_value.execute.assert_called_once_with()

    def test_crowded_rejoin_bounds_cycles_before_any_setup(self):
        for count in (0, 4, True):
            with self.subTest(count=count), patch('sim.paid_wifi.PaidWifiRun.__init__') as setup, \
                    self.assertRaisesRegex(ValueError, 'one to three cycles'):
                CrowdedWifiRun(SimpleNamespace(crowded_rejoin=count))
            setup.assert_not_called()

    def test_join_pressure_registers_all_candidates_before_guard_setup(self):
        run = SimpleNamespace(nodes={name: Mock() for name in ('n01', 'n02', 'n03')},
                              idle=Mock(), evidence={})
        pressure = AdmissionPressure(run)
        self.assertEqual(len(pressure.peers), 8)
        self.assertIs(pressure.peers['idle'], run.idle)
        self.assertEqual(run.nodes['n01'].add_profile.call_count, 4)
        self.assertEqual(run.nodes['n03'].add_profile.call_count, 3)
        run.nodes['n02'].add_profile.assert_not_called()
        for count in (2, 3):
            with self.subTest(count=count), patch('sim.paid_wifi.PaidWifiRun.__init__') as setup, \
                    self.assertRaisesRegex(ValueError, 'exactly one crowded rejoin'):
                CrowdedWifiRun(SimpleNamespace(crowded_rejoin=count, crowded_pressure=True))
            setup.assert_not_called()

    def test_join_pressure_rejects_process_changes_and_exceeded_trial_ceilings(self):
        first = dict(native=dict(status=dict(data=dict(peer_count=2, connection_count=2))),
                     host_process=dict(pid=10, start_ticks=100, peak_rss_kib=12_000))
        check_sample(copy.deepcopy(first), first)
        for path, field, value in ((('native', 'status', 'data'), 'peer_count', 3),
                                   (('native', 'status', 'data'), 'connection_count', 9),
                                   (('host_process',), 'pid', 11),
                                   (('host_process',), 'start_ticks', 101),
                                   (('host_process',), 'peak_rss_kib', 65_537)):
            changed = copy.deepcopy(first)
            row = changed
            for key in path:
                row = row[key]
            row[field] = value
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                check_sample(changed, first)

    def test_candidate_view_is_recorded_without_claiming_provider_admission(self):
        pressure = object.__new__(AdmissionPressure)
        pressure.run = SimpleNamespace(nodes={'n02': SimpleNamespace(npub='provider')})
        peer = Mock()
        pressure.peers = {'idle': peer}
        status = dict(purchases=[], history=[], locked_sat=0, remaining_budget_sat=64,
                      funding_budget={}, watched_routes=[],
                      peers=[dict(npub='provider', connected=False, transport='udp')])
        peer.control.return_value = status
        peer.native.side_effect = lambda command: dict(status='ok', data=(dict(retries=[])
            if command['command'] == 'show_routing' else
            dict(transports=[dict(type='udp', stats=dict(packets_sent=3))])))
        for connected, transport in ((False, None), (False, 'udp'), (True, 'udp')):
            status['peers'][0]['connected'] = connected
            status['peers'][0]['transport'] = transport
            observed = {}
            pressure.observe_candidates('provider-address', observed)
            self.assertIs(observed['idle']['status'], status)
        status['peers'][0]['npub'] = 'unexpected'
        observed = {}
        with self.assertRaisesRegex(RuntimeError, 'unexpected neighbor'):
            pressure.observe_candidates('provider-address', observed)
        self.assertIs(observed['idle']['status'], status)

    def test_crowded_partition_allows_only_the_known_udp_competitor(self):
        service = object.__new__(CrowdedWifiRun)
        service.nodes = {name: SimpleNamespace(npub=name) for name in ('n01', 'n02', 'n03')}
        service.idle = SimpleNamespace(npub='idle')
        service.monitor, service.save, service.evidence = Mock(), Mock(), {}
        peer = lambda name, transport='ethernet': dict(npub=name, transport=transport, connected=True)
        states = {'n01': {'peers': [peer('n02')]},
                  'n02': {'peers': [peer('n01'), peer('idle', 'udp')]}, 'n03': {'peers': []}}
        service.ctl = lambda name, _: states[name]
        self.assertIsNot(service.ready(line=True, isolated=True), False)
        self.assertFalse(service.ready(line=True))
        states['n03']['peers'] = [peer('n02')]
        self.assertFalse(service.ready(line=True, isolated=True))
        states['n03']['peers'] = []
        states['n02']['peers'][-1] = peer('unknown', 'udp')
        self.assertFalse(service.ready(line=True, isolated=True))
        states['n02']['peers'][-1] = peer('idle')
        with self.assertRaisesRegex(RuntimeError, 'unexpected carrier'):
            service.ready(line=True, isolated=True)

    def test_partition_anchor_waits_for_pending_signature_to_be_credited(self):
        prior, pending = accounts(), accounts()
        pending["n01"].update(remaining=60, authorized=4, signed={"n01": 4}, signed_after={"n01": 4})
        self.assertIsNone(reconciled_channels(prior, pending))
        pending["n02"]["credited"]["n01"] = 4000
        pending["n02"]["seller_channels"]["n01"]["paid_msat"] = 4000
        self.assertIs(reconciled_channels(prior, pending), pending)
        retain_channels(pending, copy.deepcopy(pending))

    def test_useful_flow_requires_new_and_recent_confirmed_payloads(self):
        service = object.__new__(CrowdedWifiRun)
        packets = [dict(observed=True, observed_at=9), dict(observed=False),
                   dict(observed=True, observed_at=10)]
        with patch('sim.wifi_crowded.time.monotonic', return_value=10):
            self.assertFalse(service.useful_flowing(packets, 1))
            self.assertEqual(service.useful_flowing(packets, 0), [packets[0], packets[2]])
        with patch('sim.wifi_crowded.time.monotonic', return_value=13):
            self.assertFalse(service.useful_flowing(packets, 0))

    def test_useful_data_retains_partial_evidence_without_taking_probe_controls(self):
        service = object.__new__(CrowdedWifiRun)
        service.nodes = {'n03': SimpleNamespace(npub='useful')}
        packets, stop = [], threading.Event()
        def control(_name, kind, **fields):
            if kind == 'send':
                self.assertEqual(fields['destination'], 'useful')
                self.assertEqual(hashlib.sha256(fields['payload'].encode()).hexdigest(),
                                 packets[-1]['sha256'])
                return {'queued': True}
            if len(packets) == 1:
                return {'received': {'last_sha256': packets[0]['sha256']}}
            raise RuntimeError('observation failed')
        service.ctl = Mock(side_effect=control)
        with self.assertRaisesRegex(RuntimeError, 'observation failed'):
            service.keep_useful(stop, packets, 'n03')
        self.assertEqual(packets[0]['sent'], {'queued': True})
        self.assertTrue(packets[0]['observed'])
        self.assertFalse(packets[1]['observed'])
        self.assertEqual([call.args[:2] for call in service.ctl.call_args_list],
                         [('n02', 'send'), ('n03', 'status')] * 2)
        self.assertEqual(len(service.ctl.call_args_list[0].kwargs['payload']), 128)

    def test_useful_traffic_survives_all_paid_checks_and_stops_before_collection(self):
        service = object.__new__(CrowdedWifiRun)
        competitor = Mock()
        service.nodes = {'n01': SimpleNamespace(npub='useful', auxiliary_profiles={'idle': competitor})}
        service.evidence, service.ready = {}, Mock(return_value=True)
        service.cycles, service.channel_anchor = 3, {}
        service.save, service.assert_finances, service.retain_channels = Mock(), Mock(), Mock()
        running = threading.Event()
        def useful(stop, packets):
            running.set()
            self.assertTrue(stop.wait(2))
            return packets
        service.keep_useful = useful
        def rejoin(_original, _first):
            self.assertTrue(running.wait(1))
            self.assertFalse(service.useful_stop.is_set())
            service.evidence['crowded_rejoins'].append(dict(processes_before={}, idle_pid_before=1))
        service.rejoin_round = Mock(side_effect=rejoin)
        def paid(*_args):
            self.assertFalse(service.useful_stop.is_set())
            return {}
        service.paid_streams = Mock(side_effect=paid)
        def exercise():
            service.mesh_outage()
            paid()  # Final paid verification also runs after mesh_outage returns.
            self.assertEqual(service.collect(), {'collected': 384})
        def collect():
            competitor.stop.assert_called_once_with()
            service.ready.assert_called_once_with(line=True)
            self.assertTrue(service.useful_stop.is_set())
            self.assertTrue(service.useful.done())
            return {'collected': 384}
        with patch('sim.wifi_crowded.peer_sessions', return_value={'n02': {'useful': {}}}), \
                patch('sim.wifi_crowded.processes', return_value={}), \
                patch.object(PaidWifiRun, 'exercise', side_effect=exercise), \
                patch.object(PaidWifiRun, 'collect', side_effect=collect):
            service.exercise()
        self.assertEqual(service.rejoin_round.call_count, 3)
        self.assertEqual(service.paid_streams.call_count, 2)
        service.evidence['acceptance_failure'] = 'first failure'
        service.useful = Mock()
        service.useful.result.side_effect = RuntimeError('sender failed during cleanup')
        service.pressure = SimpleNamespace(useful=Mock())
        with patch.object(PaidWifiRun, 'collect', return_value={'collected': 384}):
            self.assertEqual(service.collect(), {'collected': 384})
        self.assertEqual(service.evidence['acceptance_failure'], 'first failure')
        self.assertEqual(service.evidence['useful_error'], 'sender failed during cleanup')
        service.pressure.useful.result.assert_called_once_with(timeout=20)

    def test_failed_probe_retains_partial_delivery_despite_an_observer_failure(self):
        service = object.__new__(PaidWifiRun)
        service.nodes, service.evidence = {'n01': None, 'n02': None}, {}
        service.save, service.phase = Mock(), Mock()
        service.ctl = Mock(side_effect=[{'peers': []}, RuntimeError('observer unavailable')])

        def fail(_run, _source, _destination, _wait, evidence, **_kwargs):
            evidence.update(sent={'submitted_packets': 8}, received={'unique_packets': 7})
            raise RuntimeError('probe delivery failed')

        with patch('sim.wifi_discovery.capture_probe', side_effect=fail), \
                self.assertRaisesRegex(RuntimeError, 'probe delivery failed'):
            service.probe('n01', 'n02', 'test stream')
        failed = service.evidence['failed_probe']
        self.assertEqual(failed['received']['unique_packets'], 7)
        self.assertEqual(failed['sent']['submitted_packets'], 8)
        self.assertEqual(failed['states']['n01'], {'peers': []})
        self.assertEqual(failed['states']['n02'], {'error': 'observer unavailable'})
        service.phase.assert_not_called()

    def test_unpaid_denial_rejects_failed_or_incomplete_submission(self):
        sent = {"stream_id": "fresh", "requested_packets": 4, "submitted_packets": 4,
                "submitted_bytes": 1024, "stopped_reason": None}
        validate_unpaid_probe(sent, "fresh")
        for changed in ({"submitted_packets": 0, "submitted_bytes": 0, "stopped_reason": "no route"},
                        {"stopped_reason": "endpoint closed"}, {"stream_id": "stale"},
                        {"submitted_packets": 3, "submitted_bytes": 768}):
            with self.subTest(changed=changed), self.assertRaises(RuntimeError):
                validate_unpaid_probe({**sent, **changed}, "fresh")

    def test_live_accounting_does_not_require_or_fabricate_wallet_balances(self):
        prior = accounts()
        retain_channels(prior, copy.deepcopy(prior))
        self.assertTrue(all("wallet" not in state for state in prior.values()))

    def test_rejoin_rejects_changed_funding_budget_credit_or_exposure(self):
        def funding(value):
            value["n01"]["funding"]["n01"] = ("n01", "other-operation")
        def budget(value):
            value["n01"]["remaining"] = 64
        def credit(value):
            value["n02"]["credited"]["n01"] = 4000
        def exposure(value):
            value["n02"]["seller_channels"]["n01"]["reserved_msat"] = 12000
        def route(value):
            value["n01"]["buyer_units"] = {"replacement": 2528}
        for mutate in (funding, budget, credit, exposure, route):
            with self.subTest(case=mutate.__name__):
                prior, current = accounts(), accounts()
                mutate(current)
                with self.assertRaises(RuntimeError):
                    retain_channels(prior, current)

    def test_shared_settlement_uses_supplied_process_and_export_path_adapters(self):
        run = FakeRun()
        execute = run.execute
        run.execute = Mock(side_effect=AssertionError("container execution must not be used"))
        stopped = Mock()
        def path(name, relative):
            return f"/etc/test/{name}/{relative}"
        def adapt(kind, result):
            if kind == "export":
                name = result["operation_id"].removeprefix("export-")
                result["path"] = path(name, "exports/1.json")
            return result
        run.transform = adapt
        settle_and_collect(run, run.prior, execute=execute, stop=stopped, export_path=path)
        self.assertEqual([call.args[0] for call in stopped.call_args_list], list(NODES))
        self.assertEqual(run.collected, 384)
        self.assertEqual(run.balances, dict.fromkeys(NODES, 0))
        self.assertNotIn("private-token", json.dumps(run.evidence))


class MintRecoveryTests(unittest.TestCase):
    def mint(self, issued, collected, conserved=True):
        mint = object.__new__(LocalMint)
        mint.process = Mock(returncode=0)
        mint.info = {"pid": 123, "config": "/private/retained-config"}
        mint.request = Mock(return_value={"issued_sat": issued, "collected_sat": collected,
                                          "conserved": conserved})
        return mint

    def test_outstanding_or_unreconciled_test_money_preserves_the_same_mint(self):
        for issued, collected, conserved in ((384, 0, True), (384, 383, True), (384, 384, False)):
            mint = self.mint(issued, collected, conserved)
            result = mint.finish()
            self.assertTrue(result["retained_for_recovery"])
            self.assertEqual(result["pid"], 123)
            mint.process.terminate.assert_not_called()

    def test_only_conserved_and_collected_money_allows_orderly_mint_stop(self):
        mint = self.mint(384, 384)
        self.assertFalse(mint.finish()["retained_for_recovery"])
        mint.process.terminate.assert_called_once_with()
        mint.process.wait.assert_called_once_with(timeout=20)

    def test_uncertain_report_does_not_stop_or_replace_the_mint(self):
        mint = self.mint(384, 0)
        mint.request.side_effect = subprocess.TimeoutExpired("control", 90)
        with self.assertRaises(subprocess.TimeoutExpired):
            mint.finish()
        mint.process.terminate.assert_not_called()

    def test_uncertain_grant_is_not_automatically_retried(self):
        mint = self.mint(0, 0)
        mint.request.side_effect = RuntimeError("uncertain grant result")
        with self.assertRaises(RuntimeError):
            mint.grant("n01")
        mint.request.assert_called_once_with({"type": "issue", "id": "n01", "amount_sat": 128})


if __name__ == "__main__":
    unittest.main()
