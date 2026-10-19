"""Bounded real receipt history on stopped wallets, using ordinary relay commands.

Router callers pass their existing RelayCommands profiles and an offline SQLite
observation callback. The native receiver fixture uses the local adapter below.
The observer reports counts/capacity only; no monetary database writes are used.
"""

import argparse
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import time

WALLET_BYTES = 20 * 1024 * 1024
HEADROOM = 4 * 1024 * 1024
BATCH = 64
SETUP_SECONDS = 3600


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def circulate(wallets, observe, record, rows, *, setup_seconds=SETUP_SECONDS,
              before_recovery=None):
    """Borrow one sat, retain genuine self-receipts, and return the original value.

    Profiles must be fresh and stopped. `observe` reads the receiver's original
    database after completed offline commands. `record` retains private evidence
    before each money action. A failed setup never silently becomes a smaller run.
    """
    require(type(rows) is int and 1 <= rows <= 5480, 'receipt count must be 1..5480')
    require(type(setup_seconds) is int and 1 <= setup_seconds <= 6 * 3600,
            'receipt preparation budget must be 1..21600 seconds')
    started = time.monotonic()
    ids, pending, completed = [0, 0], None, 0
    progress = []
    collection_passes = 0
    collection_limit = 2 * ((rows + BATCH - 1) // BATCH) + 4
    baseline = [p.control('balance', action='wallet')['balance_sat'] for p in wallets]
    require(baseline[0] >= 1 and baseline[1] == 0, 'borrow from a funded donor into an empty receiver')
    initial = observe()
    require(initial['receipts'] == initial['incomplete_operations'] == initial['proof_rows'] == 0,
            'history setup requires a fresh receiver wallet')

    def checkpoint(**fields):
        record(dict(export_ids=ids.copy(), pending=pending, completed_receives=completed,
                    elapsed_seconds=time.monotonic() - started, setup_limit_seconds=setup_seconds,
                    requested_receipts=rows, initial=initial, progress=progress.copy(),
                    admission_headroom_bytes=HEADROOM, later_channel_admission_proven=False,
                    collection_passes=collection_passes, collection_limit=collection_limit,
                    synthetic_profile_equivalence=False, **fields))

    def space():
        current = observe()
        require(current['capacity_bytes'] == WALLET_BYTES
                and current['charged_bytes'] + HEADROOM <= WALLET_BYTES,
                'chosen four MiB setup headroom guard reached before requested history completed')
        return current

    def resume():
        nonlocal pending, completed
        if pending is None:
            return
        source, target, number = pending
        sent = wallets[source].control('export', action='wallet', id=number, amount_sat=1)
        expected = wallets[source].state + f'/exports/{number}.json'
        require(sent['path'] == expected, 'export changed its original custody path')
        original = json.loads(wallets[source].remote(['cat', expected]))
        require(original['amount_sat'] == 1, 'original export amount changed')
        received = wallets[target].control('import', action='wallet', token=original['token'])
        require(received['amount_sat'] == 1, 'received value differs from the original export')
        completed += target == 1
        pending = None
        checkpoint()

    def transfer(source, target):
        nonlocal pending
        require(pending is None, 'resume original transfer before allocating a new request')
        ids[source] += 1
        pending = (source, target, ids[source])
        checkpoint()
        resume()

    def acknowledge(index):
        if ids[index]:
            result = wallets[index].control('acknowledge_exports', action='wallet', through=ids[index])
            require(result['requested_sat'] == ids[index]
                    and result['cost']['wallet_debit_sat'] == ids[index]
                    and result['cost']['swap_fee_sat'] == 0, 'original zero-fee gross costs changed')

    failure = None
    recovery_failure = None
    native_recovery = None
    try:
        space()
        transfer(0, 1)
        acknowledge(0)
        for _ in range(1, rows):
            require(time.monotonic() - started < setup_seconds,
                    'receipt setup time budget reached between original transfers')
            if ids[1] % BATCH == 0:
                progress.append(space())
                checkpoint()
            transfer(1, 1)
            if ids[1] % BATCH == 0:
                acknowledge(1)
    except Exception as error:
        failure = str(error)
    finally:
        try:
            if failure is not None and before_recovery is not None:
                before_recovery()
            # Retry only the saved original identity/token. If the mint/storage
            # remains unavailable, retain it and all export files for recovery.
            resume()
            acknowledge(0)
            acknowledge(1)
            balance = wallets[1].control('balance', action='wallet')['balance_sat']
            require(balance in (0, 1), 'receiver has an unexpected circulation balance')
            if balance:
                transfer(1, 0)
            # The final token is consumed in the donor's wallet. Reconcile that
            # original send with the mint before collecting its native custody.
            native_recovery = wallets[1].control('recover', action='wallet')
            require(native_recovery['recovery_pass_complete'] and native_recovery['minted_amount'] == 0
                    and native_recovery['finalized_melts'] == 0,
                    'original send recovery is incomplete or resumed unexpected funding')
            acknowledge(1)
            after = [p.control('balance', action='wallet')['balance_sat'] for p in wallets]
            require(after == baseline, 'circulation did not return the original balances')
            # Acknowledgement visits bounded archive pages. Finish ordinary
            # eligible collection before freezing receipt-owned history; the
            # final returned token is not protected by an incoming receipt here.
            for _ in range(collection_limit):
                if observe()['unowned_proof_rows'] == 0:
                    break
                acknowledge(1)
                collection_passes += 1
            require(observe()['unowned_proof_rows'] == 0,
                    'ordinary collection did not leave only receipt-owned proof history')
        except Exception as error:
            recovery_failure = str(error)
        try:
            final = observe()
        except Exception as error:
            final = {'observation_error': str(error)}
            recovery_failure = recovery_failure or 'final custody observation failed'
        checkpoint(error=failure, recovery_error=recovery_failure, final=final,
                   native_recovery=native_recovery,
                   returned_original_value=recovery_failure is None)
    require(recovery_failure is None, 'original circulation needs recovery; preserve its saved evidence')
    require(failure is None, f'bounded history setup failed after returning its original value: {failure}')
    require(completed == rows and final['receipts'] == rows
            and final['incomplete_operations'] == 0,
            'history must contain exactly the requested distinct completed incoming receipts')
    return dict(rows=rows, elapsed_seconds=time.monotonic() - started, final=final,
                returned_original_value=True, synthetic_profile_equivalence=False)


def observe_sqlite(path):
    with sqlite3.connect(path.as_uri() + '?mode=ro', uri=True) as db:
        maximum, charged = db.execute('SELECT maximum,charged FROM wallet_storage_total WHERE id=1').fetchone()
        reserved, used = db.execute('SELECT coalesce(sum(reserved),0),coalesce(sum(used),0) '
                                    'FROM wallet_storage_accounts').fetchone()
        counts = {key: db.execute(f'SELECT count(*) FROM {table}').fetchone()[0]
                  for key, table in [('receipts', 'transactions'), ('proof_rows', 'proof'),
                                     ('incomplete_operations', 'wallet_sagas')]}
        owned = set()
        for (ys,) in db.execute("SELECT ys FROM transactions WHERE direction='Incoming' AND status='completed'"):
            require(len(ys) % 33 == 0, 'invalid compressed proof identities in original receipt')
            owned.update(ys[offset:offset + 33] for offset in range(0, len(ys), 33))
        unowned = sum(y not in owned for (y,) in db.execute('SELECT y FROM proof'))
    return dict(capacity_bytes=maximum, charged_bytes=charged,
                account_reserved_bytes=reserved, account_used_bytes=used,
                unowned_proof_rows=unowned, **counts)


class LocalWallet:
    def __init__(self, binary, config):
        self.binary, self.config = binary, config
        self.state = json.loads(config.read_text())['state_directory']

    def control(self, kind, *, action, **fields):
        # An uncertain command timeout retains the original identity/token for
        # recovery, never a replacement send. Check setup time between transfers.
        try:
            result = subprocess.run([self.binary, action, str(self.config)],
                                    input=json.dumps(dict(type=kind, **fields)).encode(),
                                    capture_output=True, timeout=330)
        except subprocess.TimeoutExpired as error:
            with Path(self.state, 'history-errors.log').open('ab') as log:
                log.write(b'original command timed out\n' + (error.stderr or b''))
            raise RuntimeError('offline wallet command timed out; original evidence retained') from None
        if result.returncode:
            with Path(self.state, 'history-errors.log').open('ab') as log:
                log.write(result.stderr + b'\n')
            raise RuntimeError('offline wallet command failed; private error retained')
        return json.loads(result.stdout)

    def remote(self, command):
        require(command[0] == 'cat' and len(command) == 2, 'local adapter only reads original exports')
        return Path(command[1]).read_bytes()


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--donor', type=Path, required=True)
    parser.add_argument('--receiver', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--rows', type=int, required=True)
    args = parser.parse_args()
    wallets = [LocalWallet(args.binary, path) for path in (args.donor, args.receiver)]
    require(not args.output.exists(), 'preserve original history evidence; use a fresh run')

    def record(value):
        temporary = args.output.with_suffix('.new')
        with temporary.open('x') as stream:
            json.dump(value, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(0o600)
        temporary.replace(args.output)
        descriptor = os.open(args.output.parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    circulate(wallets, lambda: observe_sqlite(Path(wallets[1].state, 'wallet/cashu/wallet.sqlite')),
              record, args.rows)


if __name__ == '__main__':
    main()
