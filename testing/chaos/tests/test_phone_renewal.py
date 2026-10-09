"""Bounded renewal selection, authority and restoration checks without devices."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim import phone_network
from sim.phone_diagnostics import control
from sim.phone_renewal import PhoneRenewalRun, input_hashes, successor


class PhoneRenewalTests(unittest.TestCase):
    def test_selector_binds_all_original_inputs_and_rejects_duplicates(self):
        funding = {'funding_proofs_json': json.dumps([{'secret': 'original'}, {'secret': 'second'}])}
        wallet = {'funding': {'old': funding}}
        self.assertEqual(input_hashes(wallet, 'old'),
                         [hashlib.sha256(s.encode()).hexdigest() for s in ('original', 'second')])
        for proofs in ([], [{'secret': 'same'}] * 2, [{'secret': str(i)} for i in range(129)]):
            funding['funding_proofs_json'] = json.dumps(proofs)
            with self.assertRaises(RuntimeError):
                input_hashes(wallet, 'old')

    def test_successor_preserves_authority_and_changes_only_channel_and_expiry(self):
        original = {'channel': {'id': 'old', 'capacity_sat': 32}, 'provider': 'same',
                    'contract': {'destination': 'destination', 'next_hop': 'hop', 'price': 1,
                                 'max_units': 128, 'billing': 'forwarding_data', 'expires_unix': 180}}
        self.assertIsNone(successor({'purchases': [original]}, original))
        replacement = copy.deepcopy(original)
        replacement['channel']['id'] = 'new'
        replacement['contract']['expires_unix'] = 330
        self.assertEqual(successor({'purchases': [replacement]}, original), replacement)
        for field in ('destination', 'next_hop', 'price', 'max_units', 'billing', 'expires_unix'):
            bad = copy.deepcopy(replacement)
            bad['contract'][field] = 0
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                successor({'purchases': [bad]}, original)

    def test_releases_only_owned_committed_barrier_and_never_rearms_it(self):
        run = PhoneRenewalRun.__new__(PhoneRenewalRun)
        run.evidence = {'phone_renewal': {}}
        run.save = Mock()
        run.fault_generation = 7
        run.fault = Mock(side_effect=[{'generation': 7, 'phase': 'held'},
                                     {'generation': 7, 'phase': 'released'}])
        run.release()
        self.assertIsNone(run.fault_generation)
        self.assertEqual(run.fault.call_args_list[-1].kwargs, {'generation': 7})
        run.release()
        self.assertEqual(run.fault.call_count, 2)
        for status in ({'generation': 8, 'phase': 'held'}, {'generation': 7, 'phase': 'armed'}):
            run.fault_generation = 7
            run.fault = Mock(return_value=status)
            with self.assertRaises(RuntimeError):
                run.release()
            run.fault.assert_called_once_with('status')

    def test_wifi_failure_enables_radio_after_device_guard_is_installed(self):
        run = Mock(customer={'ssid': 'fixture', 'cidr': '192.0.2.1/24'})
        run.phone.serial = 'usb-device'
        commands = []
        def shell(*args):
            commands.append(args)
            if args[:3] == ('cmd', 'wifi', 'status'):
                return b'Wifi is enabled'
            if args[:2] == ('sh', '-c'):
                self.assertIn('sleep 45', args[2])
                self.assertIn('svc wifi enable', args[2])
                return b'123\n'
            if args == ('svc', 'wifi', 'disable'):
                raise RuntimeError('lost disable reply')
            return b''
        run.phone.shell.side_effect = shell
        with patch('sim.phone_network.port', return_value=12345):
            with self.assertRaisesRegex(RuntimeError, 'lost disable'):
                phone_network.reconnect(run, {})
        self.assertEqual(commands[-1], ('svc', 'wifi', 'enable'))
        self.assertEqual(commands[-3][:2], ('sh', '-c'))

    def test_pause_is_one_mutation_without_new_phone_protocol(self):
        with patch('sim.phone_diagnostics._dispatch', return_value={'paused': True}) as dispatch:
            self.assertEqual(control(Mock(), 'pause_renewals'), {'paused': True})
            self.assertEqual(dispatch.call_args.args[1], {'type': 'pause_renewals'})
            self.assertIs(dispatch.call_args.kwargs['read_only'], False)
            with self.assertRaises(RuntimeError):
                control(Mock(), 'pause_renewals', probe={})
            self.assertEqual(dispatch.call_count, 1)


if __name__ == '__main__':
    unittest.main()
