"""Only an isolated mesh on explicitly enabled channels may run handover."""

from types import SimpleNamespace
import unittest

from sim.wifi_channel import options, usable_frequencies


class ChannelTests(unittest.TestCase):
    def test_regulatory_flags_and_disabled_channels_are_not_accepted(self):
        text = '''Frequencies:
          * 5180.0 MHz [36] (23.0 dBm)
          * 5200 MHz [40] (23 dBm) (no IR)
          * 5260.0 MHz [52] (20.0 dBm) (radar detection)
          * 5745 MHz [149] (13 dBm)
          * 5885.0 MHz [177] (disabled)
          * 5905.0 MHz [181] (13.0 dBm) (unknown restriction)
        '''
        self.assertEqual(usable_frequencies(text), {5180, 5745})

    def test_invalid_or_mixed_modes_fail_before_creating_a_run(self):
        self.assertIsNone(options(SimpleNamespace()))
        self.assertEqual(options(SimpleNamespace(handover_frequency=5745, open_mesh=True)), 5745)
        for extra in ({'open_mesh': False}, {'handover_frequency': True},
                      {'handover_frequency': -1}, {'streams': True}, {'active_outage': True},
                      {'crowded_rejoin': 1}, {'interrupted_promotion': True}):
            args = {'handover_frequency': 5745, 'open_mesh': True, **extra}
            with self.subTest(extra=extra), self.assertRaises(RuntimeError):
                options(SimpleNamespace(**args))
