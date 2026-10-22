"""Bounded independent readers for progress and exact original proof custody."""

from concurrent.futures import ThreadPoolExecutor
from itertools import groupby
import json
from queue import Empty, Queue
from threading import Event, Lock
import time

from . import wifi_probes as probes
from . import wifi_receiver_custody as custody
from . import wifi_authorization_trace as authorization_trace
from .paid_settlement import require
from .wifi_receiver_numeric import NumericReaders

POLL_SECONDS = .025
MAX_PROGRESS_READS = 2048


class ReceiverObserver:
    def __init__(self, run, shape, started, record=None):
        self.run, self.shape, self.started = run, shape, started
        self.record = record
        self.readers = ThreadPoolExecutor(max_workers=5)
        self.custody_readers = ThreadPoolExecutor(max_workers=4)
        self.stopping, self.publication = Event(), Lock()
        self.events = Queue(maxsize=MAX_PROGRESS_READS)
        self.pending = {}
        self.progress_pending, self.latest = {}, [None] * 5
        self.status_pending = {}
        self.authorization_status = {}
        self.last_custody_started = None
        self.actions = None

    def __enter__(self):
        self.numeric = NumericReaders(self.run)
        self.numeric.__enter__()
        return self

    def __exit__(self, kind, error, trace):
        self.stopping.set()
        try:
            self.readers.shutdown(wait=True)
            self.custody_readers.shutdown(wait=True)
            if kind is None:
                self.check_progress()
        except BaseException as closing_error:
            self.numeric.__exit__(type(closing_error), closing_error, closing_error.__traceback__)
            raise
        else:
            return self.numeric.__exit__(kind, error, trace)
        finally:
            if self.record is not None:
                self.record['numeric_reader_closure'] = self.numeric.cleanup_receipts
                self.run.save()

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

    def sample(self, updated, elapsed):
        received, source, relay, credit1, credit2 = [result['value'] for result in self.latest]
        return dict(elapsed_us=elapsed,
                    counter_reads=[self.timing(result) for result in self.latest], updated_counters=updated,
                    delivered=received['unique_packets'], credits=[credit1, credit2],
                    payments=[source, relay])

    def baseline(self):
        require(self.actions is None, 'progress baseline cannot be restarted')
        run = self.run
        self.actions = [lambda: probes.receive(run, 'source', 'destination', self.shape, operation_timeout=3),
                        lambda: self.numeric.payment('source', run.transit),
                        lambda: self.numeric.payment('n02', run.guard),
                        lambda: self.numeric.credit('n02', run.transit),
                        lambda: self.numeric.credit('n03', run.guard)]
        futures = [self.readers.submit(self.read, call) for call in self.actions]
        self.latest = [future.result(timeout=5) for future in futures]
        return self.sample(list(range(5)), int((time.monotonic() - self.started) * 1_000_000))

    def start(self):
        require(self.actions is not None and not self.progress_pending, 'progress workers need one original baseline')
        self.progress_pending = {index: self.readers.submit(self.poll, index, call)
                                 for index, call in enumerate(self.actions)}

    def poll(self, index, call):
        while not self.stopping.is_set() and time.monotonic() - self.started < 35:
            result = self.read(call)
            # Publication order and its timestamp share one lock. Keep every
            # fresh read while the main thread releases the held SQLite writer.
            with self.publication:
                elapsed = int((time.monotonic() - self.started) * 1_000_000)
                self.events.put_nowait((elapsed, index, result))
            if self.stopping.wait(POLL_SECONDS):
                break

    def check_progress(self):
        for future in self.progress_pending.values():
            if future.done():
                future.result(timeout=0)

    def progress(self):
        events = []
        with self.publication:
            while True:
                try:
                    events.append(self.events.get_nowait())
                except Empty:
                    break
        samples = []
        for elapsed, group in groupby(events, lambda event: event[0]):
            updated = []
            for _, index, result in group:
                self.latest[index] = result
                updated.append(index)
            samples.append(self.sample(updated, elapsed))
        # Preserve completed observations before surfacing a reader failure.
        # Exit also checks failures if the caller reaches its terminal state.
        if not samples:
            self.check_progress()
        return samples

    def stop_and_drain(self):
        self.stopping.set()
        self.readers.shutdown(wait=True)
        return self.progress()

    def payment_status(self):
        if not self.status_pending:
            self.status_pending = {name: self.custody_readers.submit(self.read,
                lambda name=name, host=host, channel=channel:
                    authorization_trace.read_channel(self.run, name, host, channel, self.started, timeout=3))
                for name, host, channel in (('source', 'n01', self.run.transit), ('n02', 'n02', self.run.guard))}
        if not all(future.done() for future in self.status_pending.values()):
            return None
        results = {name: future.result(timeout=0) for name, future in self.status_pending.items()}
        self.status_pending = {}
        self.authorization_status = {name: reading['value'] for name, reading in results.items()}
        return {name: dict(reading, value=reading['value']['payment_progress']) for name, reading in results.items()}

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
