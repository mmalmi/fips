"""Ownership and interrupted open-radio switching through the real Linux guard."""

import json
from pathlib import Path
import shutil
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim import wifi_mesh
from sim.wifi_discovery import WifiRun
from sim.wifi_open import helpers, snapshot
from sim.wifi_remote import original_ethernet
from tests import test_wifi_discovery as base
from tests.wifi_open_support import UBUS, IW, IP


@unittest.skipUnless(sys.platform == 'linux' and shutil.which('flock'), 'needs Linux procfs and flock')
class OpenGuardTests(unittest.TestCase):
    local = base.GuardTests.local
    start_guard = base.GuardTests.start_guard
    mutations = base.GuardTests.mutations
    tearDown = base.GuardTests.tearDown

    def setUp(self):
        base.GuardTests.setUp(self)
        self.node.open_mesh = 'fips-open-test'
        self.node.original_ethertypes = [0x2121]
        self.saved = {'networks': {'2': {'mode': '5', 'mesh_fwding': '0', 'key_mgmt': 'SAE',
                                      'ssid': '"mesh"', 'frequency': '5180'}},
                      'current': 2, 'globals': {'max_peer_links': 99, 'mesh_max_inactivity': 300,
                                               'user_mpm': 1},
                      'kernel': {'mesh_max_peer_links': 32, 'mesh_plink_timeout': 1800,
                                 'mesh_fwding': 0}}
        self.mesh_state.write_text(json.dumps(self.saved))
        for name, script in (('ubus', UBUS), ('iw', IW), ('ip', IP)):
            path = self.root / 'bin' / name
            path.write_text('#!' + sys.executable + '\n' + script)
            path.chmod(0o700)
        self.node.mesh['open_limits'] = snapshot(self.local, 'mesh0')
        with patch('sim.wifi_mesh.SYS_NET', Path(self.env['MESH_NET']).parent), patch(
                'sim.wifi_mesh.JOIN_ATTEMPTS', 1):
            script = wifi_mesh.helpers('mesh0', self.node.mesh) + helpers(
                'mesh0', self.node.mesh, self.node.temporary, self.node.open_mesh, self.node.open_owner,
                self.node.original_table, self.node.table_owner)
        (self.remote / 'mesh.sh').write_text(script)
        self.guard.write_bytes(self.node.guard_script())

    def state(self):
        return json.loads(self.mesh_state.read_text())

    def change(self, mutate):
        state = self.state()
        mutate(state)
        self.mesh_state.write_text(json.dumps(state))

    def begin(self):
        self.start_guard()
        self.node.begin_open_mesh()
        state = self.state()
        self.assertEqual(state['current'], 3)
        self.assertEqual(state['networks']['3']['key_mgmt'], 'NONE')
        self.assertEqual(state['networks']['2'], self.saved['networks']['2'])
        self.assertEqual(state['globals']['max_peer_links'], 8)
        self.assertEqual(state['kernel']['mesh_max_peer_links'], 8)
        self.assertEqual(state['kernel']['mesh_fwding'], 0)
        self.assertEqual((self.remote / 'open-phase').read_text().strip(), 'active')

    def cleanup(self):
        self.local(['sh', str(self.guard), 'cleanup'])

    def assert_restored(self):
        self.assertEqual(self.state(), self.saved)
        self.assertFalse((self.remote / 'open-armed').exists())
        self.assertFalse((self.remote / 'original-isolated').exists())
        self.assertNotIn(self.node.original_table, json.loads(self.tables.read_text()))

    def assert_retained(self):
        self.assertTrue((self.remote / 'open-armed').exists())
        self.assertTrue((self.remote / 'original-isolated').exists())
        self.assertEqual(json.loads(self.tables.read_text())[self.node.original_table], self.node.table_owner)

    def test_open_join_outage_rejoin_and_cleanup_restore_original_exactly(self):
        self.begin()
        self.node.mesh_down()
        self.assertIsNone(self.state()['current'])
        self.node.mesh_up()
        self.assertEqual(self.state()['current'], 3)
        self.assertEqual(self.state()['kernel']['mesh_max_peer_links'], 8)
        self.cleanup()
        self.assert_restored()
        commands = self.mesh_log.read_text()
        self.assertNotIn('SAVE_CONFIG', commands)
        self.assertNotIn('RECONFIGURE', commands)
        self.assertNotIn('GET_NETWORK 2 psk', commands)
        self.assertNotIn('SET_NETWORK 2', commands)

    def test_original_isolation_is_installed_before_the_first_network_mutation(self):
        self.start_guard()
        original = self.node.guarded
        rules = []
        def guarded(command, *args, **kwargs):
            if args and args[0]:
                rules.append(args[0].decode())
            if command.endswith('open_begin'):
                self.assertIn(self.node.original_table, json.loads(self.tables.read_text()))
                self.assertEqual(self.state(), self.saved)
            return original(command, *args, **kwargs)
        self.node.guarded = guarded
        self.node.begin_open_mesh()
        self.assertEqual(len(rules), 1)
        for direction in ('ingress', 'egress'):
            self.assertIn(f'type filter hook {direction} device "mesh0"', rules[0])
            self.assertIn(f'{direction} ether type 0x2121 counter drop', rules[0])
        self.assertNotIn('0x88b5', rules[0])
        self.cleanup()
        self.assert_restored()

    def test_original_table_collision_never_opens_radio_or_deletes_foreign_rules(self):
        self.start_guard()
        self.tables.write_text(json.dumps({self.node.original_table: 'foreign-owner'}))
        with self.assertRaises(RuntimeError):
            self.node.begin_open_mesh()
        self.cleanup()
        self.assertEqual(self.state(), self.saved)
        self.assertEqual(json.loads(self.tables.read_text())[self.node.original_table], 'foreign-owner')
        self.assertFalse((self.remote / 'open-armed').exists())

    def test_unsupported_egress_fails_before_allocating_a_network(self):
        self.start_guard()
        # Model nft's atomic rejection of an unsupported hook, before any table exists.
        script = base.NFT.replace('text=sys.stdin.read();m=',
                                  "text=sys.stdin.read()\n if 'hook egress' in text:sys.exit(1)\n m=")
        (self.root / 'bin' / 'nft').write_text('#!' + sys.executable + '\n' + script)
        with self.assertRaises(RuntimeError):
            self.node.begin_open_mesh()
        self.assertEqual(self.state(), self.saved)
        self.assertNotIn('ADD_NETWORK', self.mesh_log.read_text())
        self.assertFalse((self.remote / 'open-armed').exists())
        self.assertEqual(json.loads(self.tables.read_text()), {})

    def test_lost_add_reply_preserves_ambiguous_disabled_network_and_isolation(self):
        self.env['OPEN_LOST_REPLY'] = 'ADD_NETWORK'
        self.start_guard()
        with self.assertRaises(RuntimeError):
            self.node.begin_open_mesh()
        self.cleanup()
        self.assert_retained()
        self.assertEqual(self.state()['current'], 2)
        self.assertEqual(self.state()['networks']['3'], {})
        self.assertNotIn('REMOVE_NETWORK', self.mesh_log.read_text())

    def test_crash_before_ownership_tag_preserves_ambiguous_network(self):
        self.env['OPEN_FAIL_BEFORE'] = f'SET_NETWORK 3 id_str {self.node.open_owner.encode().hex()}'
        self.start_guard()
        with self.assertRaises(RuntimeError):
            self.node.begin_open_mesh()
        self.cleanup()
        self.assert_retained()
        self.assertEqual(self.state()['current'], 2)
        self.assertIn('3', self.state()['networks'])

    def test_lost_reply_after_tag_or_partial_configuration_restores_owned_profile(self):
        self.env['OPEN_LOST_REPLY'] = 'SET_NETWORK 3 mode 5'
        self.start_guard()
        with self.assertRaises(RuntimeError):
            self.node.begin_open_mesh()
        self.cleanup()
        self.assert_restored()

    def test_lost_tag_reply_still_has_owned_recovery_evidence(self):
        self.env['OPEN_LOST_REPLY'] = f'SET_NETWORK 3 id_str {self.node.open_owner.encode().hex()}'
        self.start_guard()
        with self.assertRaises(RuntimeError):
            self.node.begin_open_mesh()
        self.cleanup()
        self.assert_restored()

    def test_failed_add_with_no_new_network_restores_cleanly(self):
        self.env['OPEN_FAIL_BEFORE'] = 'ADD_NETWORK'
        self.start_guard()
        with self.assertRaises(RuntimeError):
            self.node.begin_open_mesh()
        self.cleanup()
        self.assert_restored()

    def test_partial_limit_update_restores_saved_limits(self):
        self.env['OPEN_LOST_REPLY'] = 'SET max_peer_links 8'
        self.start_guard()
        with self.assertRaises(RuntimeError):
            self.node.begin_open_mesh()
        self.cleanup()
        self.assert_restored()

    def test_lost_reply_after_original_departure_restores_profile_and_limits(self):
        self.env['OPEN_LOST_REPLY'] = 'MESH_GROUP_REMOVE mesh0'
        self.start_guard()
        with self.assertRaises(RuntimeError):
            self.node.begin_open_mesh()
        self.env.pop('OPEN_LOST_REPLY')
        self.cleanup()
        self.assert_restored()

    def test_lost_reply_after_open_join_restores_original_profile(self):
        self.env['OPEN_LOST_REPLY'] = 'MESH_GROUP_ADD 3'
        self.start_guard()
        with self.assertRaises(RuntimeError):
            self.node.begin_open_mesh()
        self.cleanup()
        self.assert_restored()

    def test_expired_lease_restores_open_mesh_and_fences_late_rejoin(self):
        self.begin()
        (self.remote / 'heartbeat').write_text('0')
        with self.assertRaises(RuntimeError):
            self.node.mesh_down()
        self.local(['sh', str(self.guard)])
        self.assert_restored()
        with self.assertRaises(RuntimeError):
            self.node.mesh_up()

    def test_changed_owner_or_foreign_network_is_never_removed(self):
        self.begin()
        self.change(lambda s: s['networks']['3'].update(id_str='"someone-else"'))
        before = self.state()
        self.cleanup()
        self.assert_retained()
        self.assertEqual(self.state(), before)
        self.assertNotIn('REMOVE_NETWORK', self.mesh_log.read_text())

    def test_an_extra_network_blocks_restoration_without_mutation(self):
        self.begin()
        self.change(lambda s: s['networks'].update({'4': {'id_str': '"foreign"'}}))
        before = self.state()
        self.cleanup()
        self.assert_retained()
        self.assertEqual(self.state(), before)

    def test_changed_original_profile_or_limits_keeps_isolation(self):
        self.begin()
        self.change(lambda s: s['globals'].update(max_peer_links=7))
        before = self.state()
        self.cleanup()
        self.assert_retained()
        self.assertEqual(self.state(), before)

    def test_changed_original_sae_profile_is_not_rewritten(self):
        self.begin()
        self.change(lambda s: s['networks']['2'].update(key_mgmt='NONE'))
        before = self.state()
        self.cleanup()
        self.assert_retained()
        self.assertEqual(self.state(), before)

    def test_runtime_observation_rejects_limits_changed_after_convergence(self):
        self.begin()
        self.assertEqual(self.node.verify_open_mesh()['key_mgmt'], 'NONE')
        self.change(lambda s: s['kernel'].update(mesh_max_peer_links=32))
        with self.assertRaises(RuntimeError):
            self.node.verify_open_mesh()
        self.cleanup()
        self.assert_restored()

    def test_runtime_observation_rejects_key_management_changed_after_convergence(self):
        self.begin()
        self.change(lambda s: s['networks']['3'].update(key_mgmt='SAE'))
        with self.assertRaises(RuntimeError):
            self.node.verify_open_mesh()
        self.cleanup()
        self.assert_restored()

    def test_disabled_original_kernel_inactivity_is_restored_exactly(self):
        self.saved['kernel']['mesh_plink_timeout'] = 0
        self.mesh_state.write_text(json.dumps(self.saved))
        self.node.mesh['open_limits'] = snapshot(self.local, 'mesh0')
        with patch('sim.wifi_mesh.SYS_NET', Path(self.env['MESH_NET']).parent), patch(
                'sim.wifi_mesh.JOIN_ATTEMPTS', 1):
            script = wifi_mesh.helpers('mesh0', self.node.mesh) + helpers(
                'mesh0', self.node.mesh, self.node.temporary, self.node.open_mesh, self.node.open_owner,
                self.node.original_table, self.node.table_owner)
        (self.remote / 'mesh.sh').write_text(script)
        self.begin()
        self.cleanup()
        self.assert_restored()

    def test_changed_interface_is_not_reconfigured(self):
        self.begin()
        (Path(self.env['MESH_NET']) / 'ifindex').write_text('7')
        before = self.state()
        self.cleanup()
        self.assert_retained()
        self.assertEqual(self.state(), before)

    def test_failed_original_join_retains_isolation_and_retry_recovers(self):
        self.begin()
        self.env['OPEN_FAIL_BEFORE'] = 'MESH_GROUP_ADD 2'
        self.cleanup()
        self.assert_retained()
        self.assertIsNone(self.state()['current'])
        self.env.pop('OPEN_FAIL_BEFORE')
        self.cleanup()
        self.assert_restored()

    def test_lost_remove_reply_is_recoverable_without_removing_another_network(self):
        self.begin()
        self.env['OPEN_LOST_REPLY'] = 'REMOVE_NETWORK 3'
        self.cleanup()
        self.assert_retained()
        self.assertEqual(set(self.state()['networks']), {'2'})
        self.env.pop('OPEN_LOST_REPLY')
        self.cleanup()
        self.assert_restored()

    def test_unexplained_missing_owned_network_does_not_claim_restoration(self):
        self.begin()
        self.node.mesh_down()
        self.change(lambda s: s['networks'].pop('3'))
        self.cleanup()
        self.assert_retained()

    def test_rejoin_refuses_missing_original_isolation(self):
        self.begin()
        self.node.mesh_down()
        self.tables.write_text('{}')
        with self.assertRaises(RuntimeError):
            self.node.mesh_up()
        self.assertIsNone(self.state()['current'])
        # Restoration to SAE is allowed even if an external actor removed isolation.
        self.cleanup()
        self.assertEqual(self.state(), self.saved)


class OpenSequenceTests(unittest.TestCase):
    def test_original_ethernet_accepts_exact_legacy_and_modern_default_semantics(self):
        expected = [{'interface': 'mesh0', 'ethertype': 0x2121}]
        self.assertEqual(original_ethernet({'ethernet_interfaces': ['mesh0']}), expected)
        for value in ({'interface': 'mesh0'}, {'interface': 'mesh0', 'ethertype': None}):
            for ethernet in (value, {'mesh': value}):
                self.assertEqual(original_ethernet({'transports': {'ethernet': ethernet}}), expected)
        self.assertEqual(original_ethernet({'transports': {'ethernet': {
            'interface': 'mesh0', 'ethertype': 0x8888}}})[0]['ethertype'], 0x8888)
        with self.assertRaises(RuntimeError):
            original_ethernet({'ethernet_interfaces': ['mesh0'], 'transports': {}})

    def test_kernel_timeout_requires_the_exact_seconds_unit(self):
        for invalid in ('0', '60 ms', '60 seconds extra', '-1 seconds'):
            with patch('sim.wifi_open.control', return_value='1'):
                remote = Mock(side_effect=[b'8', invalid.encode()])
                with self.assertRaises(RuntimeError):
                    snapshot(remote, 'mesh0')

    def fixture(self, opened):
        run = object.__new__(WifiRun)
        run.open_mesh = 'fips-open-test' if opened else None
        run.financial = {}
        run.before_launch = Mock()
        run.phase = Mock()
        events = []
        run.nodes = {}
        for name in ('n01', 'n02', 'n03'):
            run.nodes[name] = SimpleNamespace(
                npub=name, begin_open_mesh=lambda name=name: events.append(('radio', name)),
                start=lambda name=name: events.append(('start', name)),
                monetary_journals=lambda: {}, verify_open_mesh=lambda: {'key_mgmt': 'NONE'})
        def ctl(name, _kind):
            events.append(('status', name))
            other = 'n02' if name == 'n01' else 'n01'
            return {'peers': [{'npub': other, 'connected': True, 'transport': 'ethernet'}]}
        run.ctl = ctl
        return run, events

    def test_third_radio_joins_only_after_first_two_are_authenticated(self):
        run, events = self.fixture(True)
        run.launch_profiles()
        third = events.index(('radio', 'n03'))
        for name in ('n01', 'n02'):
            self.assertLess(events.index(('start', name)), third)
            self.assertGreaterEqual(events[:third].count(('status', name)), 2)
        run.before_launch.assert_called_once_with()
        self.assertEqual(set(run.financial), set(run.nodes))

    def test_default_sae_path_never_switches_the_radio(self):
        run, events = self.fixture(False)
        run.launch_profiles()
        self.assertFalse(any(kind == 'radio' for kind, _name in events))
        self.assertEqual([name for kind, name in events if kind == 'start'], list(run.nodes))


if __name__ == '__main__':
    unittest.main()
