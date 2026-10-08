"""Exercise the shared interruption checks and recovery ordering without devices."""

import copy
from pathlib import Path
import sys
from threading import Event
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim.committed_settlement import CommittedSettlement


class Run(CommittedSettlement):
    def __init__(self):
        self.nodes = dict.fromkeys(('n01', 'n02', 'n03'))
        self.evidence, self.events = {}, []
        self.stopped = Event()
        self.barrier = dict(phase='idle', generation=0, swaps=10, swap_attempts=10, restores=0)
        self.mint = SimpleNamespace(request=self.fault)
        self.journals = {name: dict(funding={'original': name}, next_funding=1,
                                   buyer_settlements={}, seller_settlements={}) for name in self.nodes}
        self.report = dict(channel_id='channel', value_after_stage1_sat=32, paid_sat=7,
                           receiver_fee_reserve_sat=0, refunded_sat=25, fee_sat=0)

    def fault(self, body):
        action = body['command']['action']
        if action == 'arm_swap_reply':
            self.barrier.update(phase='armed', generation=1)
        elif action == 'release':
            assert body['command']['generation'] == self.barrier['generation']
            assert self.barrier['phase'] == 'held'
            self.barrier['phase'] = 'released'
        else:
            assert action == 'status'
        return dict(self.barrier)

    def ctl(self, name, kind):
        assert (name, kind) == ('n01', 'settle')
        self.events.append('settle')
        common = dict(channel={'id': 'channel'}, payment={'balance': 7}, report=None, released=False)
        self.journals['n01']['buyer_settlements']['channel'] = dict(common, refunded=False, wallet_refund_sat=None)
        self.journals['n02']['seller_settlements']['channel'] = copy.deepcopy(common)
        self.barrier.update(phase='held', swaps=11, swap_attempts=11)
        assert self.stopped.wait(2), 'fixture interruption never arrived'
        raise RuntimeError('original process interrupted')

    def interruption_metadata(self):
        return {'scope': 'owned-participants'}

    def interrupt_participants(self):
        assert self.barrier['phase'] == 'held'
        self.events.append('cut')
        self.stopped.set()

    def state_json(self, name, relative):
        assert relative == 'controller/controller.json'
        return copy.deepcopy(self.journals[name])

    def launch(self, name):
        self.events.append('launch:' + name)
        if name == 'n02':
            self.journals[name]['seller_settlements']['channel']['report'] = dict(self.report)
            self.barrier['restores'] += 1
        elif name == 'n01':
            self.journals[name]['buyer_settlements']['channel'].update(
                report=dict(self.report), released=True, refunded=True, wallet_refund_sat=self.report['refunded_sat'])
            self.journals['n02']['seller_settlements']['channel']['released'] = True

    def recovery_ready(self):
        return True

    def save(self):
        pass

    def interrupt(self):
        return self.interrupt_settlement({'n01': {'funding': {'request': ('channel', 'operation')}}})


class CommittedSettlementTests(unittest.TestCase):
    def test_provider_recovers_before_buyer_without_another_settle(self):
        run = Run()
        channel, pending = run.interrupt()
        self.assertEqual(run.barrier['phase'], 'released')
        run.recover_settlement(channel, pending)
        self.assertEqual(run.events, ['settle', 'cut', 'launch:n02', 'launch:n01', 'launch:n03'])
        self.assertEqual(run.evidence['automatic_settlement_recovery']['report'], run.report)

    def test_changed_durable_intent_prevents_restart(self):
        run = Run()
        channel, pending = run.interrupt()
        run.journals['n01']['next_funding'] += 1
        with self.assertRaisesRegex(RuntimeError, 'durable settlement intent'):
            run.recover_settlement(channel, pending)
        self.assertEqual(run.events, ['settle', 'cut'])

    def test_recovered_report_must_match_original_payment(self):
        run = Run()
        channel, pending = run.interrupt()
        run.report.update(paid_sat=8, refunded_sat=24)
        with self.assertRaisesRegex(RuntimeError, 'original settlement'):
            run.recover_settlement(channel, pending)
        self.assertEqual(run.events, ['settle', 'cut', 'launch:n02'])


if __name__ == '__main__':
    unittest.main()
