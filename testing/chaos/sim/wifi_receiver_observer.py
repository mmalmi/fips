"""Bounded independent readers for progress and exact original proof custody."""

from concurrent.futures import ThreadPoolExecutor
import json
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
        self.progress_pending, self.latest = {}, [None] * 5
        self.last_custody_started = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.readers.shutdown(wait=True)
        self.custody_readers.shutdown(wait=True)

    def read(self, call, *, optional=False):
        started = int((time.monotonic() - self.started) * 1_000_000)
        try:
            result = dict(value=call())
        except custody.ReadUnavailable as error:
            if not optional:
                raise
            result = dict(missing=True, error=type(error.__cause__).__name__)
        finished = int((time.monotonic() - self.started) * 1_000_000)
        return dict(result, started_us=started, finished_us=finished)

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
        for index, call in enumerate(actions):
            if index not in self.progress_pending:
                self.progress_pending[index] = self.readers.submit(self.read, call)
        # Only the pre-send baseline waits for every reader. During the one
        # stream, keep one bounded read per counter and restart ready readers.
        initial = all(result is None for result in self.latest)
        ready = [index for index, future in self.progress_pending.items() if initial or future.done()]
        if not ready:
            return None
        for index in ready:
            self.latest[index] = self.progress_pending.pop(index).result(timeout=5 if initial else 0)
        received, source, relay, credit1, credit2 = [result['value'] for result in self.latest]
        sample = dict(elapsed_us=int((time.monotonic() - self.started) * 1_000_000),
                    counter_reads=[self.timing(result) for result in self.latest], updated_counters=ready,
                    delivered=received['unique_packets'], credits=[credit1, credit2],
                    payments=[source['payment_progress'][run.transit],
                              relay['payment_progress'][run.guard]])
        for index in ready:
            self.progress_pending[index] = self.readers.submit(self.read, actions[index])
        return sample

    def journal(self):
        self.run.check_forwards()
        node = self.run.nodes['n02']
        return json.loads(custody.remote_read(node, ['cat', node.state + '/controller/controller.json']))

    def start_custody(self):
        now = time.monotonic()
        if self.pending or (self.last_custody_started is not None and now - self.last_custody_started < 1):
            return False
        self.last_custody_started = now
        run = self.run
        self.pending = {name: self.custody_readers.submit(self.read, call, optional=True) for name, call in
                        (('journal', self.journal),
                         ('proofs', lambda: custody.live(run.nodes['n02'], run.originals)))}
        return True

    def poll_custody(self):
        if not self.pending or not all(future.done() for future in self.pending.values()):
            return None
        results = {name: future.result(timeout=0) for name, future in self.pending.items()}
        self.pending = {}
        run = self.run
        missing = [name for name, result in results.items() if result.get('missing')]
        row = dict(started_us=min(result['started_us'] for result in results.values()),
                    elapsed_us=max(result['finished_us'] for result in results.values()),
                    reads={name: self.timing(result) for name, result in results.items()},
                    complete=not missing, missing_reads=missing)
        # Available identity evidence remains mandatory even if its companion
        # read failed. Missing evidence can never stand in for a custody check.
        if 'journal' not in missing:
            journal = results['journal']['value']
            require(any(value == run.intents[run.guard] for value in journal['funding'].values()),
                    'cleanup changed the original active guard funding')
        if 'proofs' not in missing:
            remaining = results['proofs']['value']
            require(all(remaining.get(key) == 'SPENT' for key in run.guard_inputs)
                    and all(remaining.get(key) == 'UNSPENT' for key in run.unspent),
                    'cleanup changed the exact guard or spendable original identities')
        if missing:
            return dict(row, unavailable={name: results[name]['error'] for name in missing})
        retained = run.incoming in journal['seller_settlements']
        return dict(row, receiver_retained=retained, remaining_originals=len(remaining),
                    cleanup_pending=retained or len(remaining) != 63)
