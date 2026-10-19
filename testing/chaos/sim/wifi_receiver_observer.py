"""Bounded independent readers for progress and exact original proof custody."""

from concurrent.futures import ThreadPoolExecutor
import time

from . import wifi_probes as probes
from . import wifi_receiver_custody as custody
from .paid_settlement import require


class ReceiverObserver:
    def __init__(self, run, shape, started):
        self.run, self.shape, self.started = run, shape, started
        self.readers = ThreadPoolExecutor(max_workers=5)
        self.custody_readers = ThreadPoolExecutor(max_workers=2)
        self.pending = {}

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.readers.shutdown(wait=True)
        self.custody_readers.shutdown(wait=True)

    def read(self, call):
        started = int((time.monotonic() - self.started) * 1_000_000)
        value = call()
        finished = int((time.monotonic() - self.started) * 1_000_000)
        return dict(value=value, started_us=started, finished_us=finished)

    @staticmethod
    def timing(result):
        return {key: result[key] for key in ('started_us', 'finished_us')}

    def progress(self):
        run = self.run
        actions = [lambda: probes.receive(run, 'source', 'destination', self.shape),
                   lambda: run.ctl('source', 'status', operation_timeout=3),
                   lambda: run.ctl('n02', 'status', operation_timeout=3),
                   lambda: run.credit('n02', run.transit),
                   lambda: run.credit('n03', run.guard)]
        pending = [self.readers.submit(self.read, call) for call in actions]
        results = [future.result(timeout=5) for future in pending]
        received, source, relay, credit1, credit2 = [result['value'] for result in results]
        return dict(elapsed_us=max(result['finished_us'] for result in results),
                    counter_reads=[self.timing(result) for result in results],
                    delivered=received['unique_packets'], credits=[credit1, credit2],
                    payments=[source['payment_progress'][run.transit],
                              relay['payment_progress'][run.guard]])

    def start_custody(self):
        require(not self.pending, 'original custody observations cannot overlap')
        run = self.run
        self.pending = {name: self.custody_readers.submit(self.read, call) for name, call in
                        (('journal', run.journal),
                         ('proofs', lambda: custody.live(run.nodes['n02'], run.originals)))}

    def poll_custody(self):
        if not self.pending or not all(future.done() for future in self.pending.values()):
            return None
        results = {name: future.result(timeout=0) for name, future in self.pending.items()}
        self.pending = {}
        run = self.run
        journal, remaining = results['journal']['value'], results['proofs']['value']
        require(any(row == run.intents[run.guard] for row in journal['funding'].values()),
                'cleanup changed the original active guard funding')
        require(all(remaining.get(key) == 'SPENT' for key in run.guard_inputs)
                and all(remaining.get(key) == 'UNSPENT' for key in run.unspent),
                'cleanup changed the exact guard or spendable original identities')
        retained = run.incoming in journal['seller_settlements']
        return dict(started_us=min(result['started_us'] for result in results.values()),
                    elapsed_us=max(result['finished_us'] for result in results.values()),
                    reads={name: self.timing(result) for name, result in results.items()},
                    receiver_retained=retained, remaining_originals=len(remaining),
                    cleanup_pending=retained or len(remaining) != 63)
