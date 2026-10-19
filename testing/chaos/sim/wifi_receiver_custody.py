"""Private, read-only custody observations for the real receiver router fixture."""

from contextlib import closing, contextmanager
import hashlib
import json
from pathlib import Path
import shlex
import sqlite3
import subprocess
import tarfile
import tempfile
import uuid
from urllib.request import Request, urlopen

from .paid_settlement import require
from .receiver_history import observe_sqlite

WALLET = 'wallet/cashu/wallet.sqlite'
RECEIVER = 'receiver/spilman-receiver.sqlite'
FILES = (WALLET, WALLET + '-wal', RECEIVER, RECEIVER + '-wal',
         'wallet/spilman-client.json', 'controller/controller.json')
MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024


class ReadUnavailable(RuntimeError):
    """A bounded remote read returned no usable response; its cause is unknown."""


def remote_read(profile, command, data=None):
    try:
        return profile.remote(command, data, timeout=3)
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        raise ReadUnavailable('bounded remote custody read unavailable') from error


def fingerprint(row):
    value = {key: val.hex() if isinstance(val, bytes) else val for key, val in dict(row).items()}
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def saved(profile, root, label):
    """Copy DB+WAL under the existing profile-start fence, with no writer running."""
    owner = getattr(profile, 'owner', profile)
    path = root / (label + '.tar')
    require(not path.exists(), 'preserve the original stopped custody snapshot')
    command = (shlex.join(['sh', owner.temporary + '/guard.sh', 'can-start', profile.config])
               + '\ncd ' + shlex.quote(profile.state) + '\nset --\n'
               + '\n'.join(f'if [ -f {shlex.quote(name)} ]; then set -- "$@" {shlex.quote(name)}; fi'
                           for name in FILES)
               + '\nbytes=0\nfor file do bytes=$((bytes + $(wc -c < "$file"))); done\n'
               + f'test "$bytes" -le {MAX_SNAPSHOT_BYTES - 16384}\n'
               + '\ntar -cf - "$@"')
    data = owner.guarded(command, timeout=30)
    require(len(data) <= MAX_SNAPSHOT_BYTES, 'stopped wallet snapshot exceeds fixture limit')
    with path.open('xb') as stream:
        stream.write(data)
    path.chmod(0o600)
    return path


@contextmanager
def opened(archive):
    # SQLite may create a local SHM while reading the copied WAL; the retained
    # archive and original remote database remain unchanged.
    with tempfile.TemporaryDirectory(prefix='receiver-custody-') as directory:
        root = Path(directory)
        with tarfile.open(archive, 'r:') as bundle:
            for item in bundle:
                require(item.name in FILES and item.isfile(), 'unexpected custody archive member')
                path = root / item.name
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with path.open('xb') as output:
                    output.write(bundle.extractfile(item).read())
                path.chmod(0o600)
        with closing(sqlite3.connect((root / WALLET).as_uri() + '?mode=ro', uri=True)) as db:
            db.row_factory = sqlite3.Row
            db.execute('PRAGMA query_only=ON')
            require(db.execute('PRAGMA quick_check').fetchone()[0] == 'ok', 'incoherent stopped wallet')
            yield root, db


def kv(db, namespace):
    value = db.execute("SELECT value FROM kv_store WHERE primary_namespace='cashu_service' "
                       "AND secondary_namespace=? AND key='journal'", (namespace,)).fetchone()
    return {} if value is None else json.loads(value[0])


def proofs(db):
    return {row['y'].hex(): dict(row) for row in db.execute('SELECT * FROM proof')}


def counts(archive):
    with opened(archive) as (root, _):
        return observe_sqlite(root / WALLET)


def export_start(archive):
    with opened(archive) as (_, db):
        sends = kv(db, 'send_requests')
        require(not sends.get('retirement') and not sends.get('entries'),
                'collection cannot skip unresolved original export/channel requests')
        floor = sends.get('sequences', {}).get('fips-exports', {}).get('through', 0)
        require(type(floor) is int and 0 <= floor < 2**64 - 1, 'invalid durable export floor')
        return floor + 1


def retained(archive, rows):
    with opened(archive) as (_, db):
        coins = proofs(db)
        receipts = {row['id'].hex(): dict(row) for row in db.execute('SELECT * FROM transactions')}
        require(len(receipts) == rows and not db.execute('SELECT 1 FROM wallet_sagas LIMIT 1').fetchone(),
                'retained history is incomplete or has unfinished native operations')
        owned = set()
        for receipt in receipts.values():
            require(receipt['direction'] == 'Incoming' and receipt['status'] == 'completed'
                    and receipt['amount'] == 1 and receipt['fee'] == 0 and len(receipt['ys']) % 33 == 0,
                    'retained history contains a non-original completed one-sat receive')
            owned.update(receipt['ys'][i:i + 33].hex() for i in range(0, len(receipt['ys']), 33))
        require(set(coins) <= owned and all(row['state'] in ('SPENT', 'PENDING_SPENT')
                                           for row in coins.values()), 'history has unowned or spendable proofs')
        sends = kv(db, 'send_requests')
        require(not sends.get('entries') and not sends.get('retirement'), 'history has pending native sends')
        return {'proofs': {key: fingerprint(row) for key, row in coins.items()},
                'receipts': {key: fingerprint(row) for key, row in receipts.items()}}


def unchanged(archive, original):
    with opened(archive) as (_, db):
        current = proofs(db)
        require(all(key in current and fingerprint(current[key]) == value
                    for key, value in original['proofs'].items()), 'genuine retained proof changed')
        receipts = {row['id'].hex(): fingerprint(row) for row in db.execute('SELECT * FROM transactions')}
        require(all(receipts.get(key) == value for key, value in original['receipts'].items()),
                'genuine retained receipt changed')


def payout(archive, channel, retained_history):
    with opened(archive) as (root, db):
        with closing(sqlite3.connect((root / RECEIVER).as_uri() + '?mode=ro', uri=True)) as receiver:
            state, encoded = receiver.execute('SELECT state,closed_json FROM spilman_channels '
                                               'WHERE channel_id=?', (channel,)).fetchone()
        closed = json.loads(encoded)
        require(state == 'Closed' and closed['receiver_sum'] == 959 and closed['sender_sum'] == 1,
                'original receiver payout differs')
        originals = json.loads(closed['receiver_proofs_json'])
        current = proofs(db)
        indexed = {(row['secret'], row['c'].hex()): key for key, row in current.items()}
        result = {}
        for proof in originals:
            key = indexed[(proof['secret'], proof['C'])]
            row = current[key]
            require(proof['amount'] == row['amount'] == 1 and row['state'] == 'UNSPENT'
                    and key not in result and row['keyset_id'] == proof['id']
                    and row['created_by_operation'] is None and row['derivation_index'] is None,
                    'payout proof identity or provenance changed')
            result[key] = row
        require(len(result) == 959 and set(result).isdisjoint(retained_history['proofs'])
                and set(current) == set(result) | set(retained_history['proofs']),
                'wallet differs from exact genuine history plus959 original payout proofs')
        return result


def inputs(archive, intent, originals):
    with opened(archive) as (_, db):
        operation = intent['funded']['wallet_operation_id']
        plans = [entry['preparation']['planned'] for entry in kv(db, 'send_requests')['entries'].values()
                 if entry['preparation']['planned']['operation_id'] == operation]
        require(len(plans) == 1, 'funding lacks its unique original wallet send')
        indexed = {(row['secret'], row['c'].hex()): key for key, row in originals.items()}
        result = set()
        for proof in plans[0]['proofs_to_swap'] + plans[0]['proofs_to_send']:
            key = indexed[(proof['secret'], proof['C'])]
            require(proof['amount'] == 1 and key not in result, 'original funding input changed')
            result.add(key)
        require(len(result) == 32, 'outgoing guard must consume32 distinct original payout coins')
        return result, operation


def original_states(archive, originals):
    with opened(archive) as (_, db):
        current = proofs(db)
        result = {}
        for key, original in originals.items():
            if key not in current:
                continue
            row = current[key]
            require(all(row[field] == original[field] for field in
                        ('y', 'mint_url', 'unit', 'amount', 'secret', 'c', 'keyset_id', 'p2pk_e')),
                    'original payout identity changed')
            result[key] = row['state']
        return result


def slots(archive):
    with opened(archive) as (_, db):
        history = kv(db, 'proof_history')
        queued = len(history['candidates'])
        reserved = sum(row['remaining'] for row in history['reservations'].values())
        require(reserved == 960 and queued + reserved + 64 <= 1024,
                'original960 plus planned64 receiver proofs exceed1024 history slots')
        return dict(queued=queued, reserved=reserved, planned=64, limit=1024)


def released_sends(archive, operations):
    with opened(archive) as (_, db):
        sends = kv(db, 'send_requests')
        require(all(entry['preparation']['planned']['operation_id'] not in operations
                    for entry in sends.get('entries', {}).values()), 'original SDK send owner retained')
        for table, column in (('wallet_sagas', 'id'), ('transactions', 'saga_id')):
            for (value,) in db.execute(f'SELECT {column} FROM {table}'):
                identifier = str(uuid.UUID(bytes=value)) if isinstance(value, bytes) else value
                require(identifier not in operations, 'original native send or outgoing receipt retained')


def live(profile, keys):
    keys = sorted(keys)
    require(0 < len(keys) <= 1024, 'live observation requires bounded exact original identities')
    raw = remote_read(profile, [profile.temporary + '/sqlite-hold', 'observe', profile.state + '/' + WALLET],
                      ('\n'.join(keys) + '\n').encode())
    states = json.loads(raw)['states']
    require(len(states) == len(keys), 'live proof observation changed original identity count')
    return {key: state for key, state in zip(keys, states) if state is not None}


def mint_states(mint, expected):
    keys = list(expected)
    for offset in range(0, len(keys), 128):
        part = keys[offset:offset + 128]
        request = Request(mint + '/v1/checkstate', json.dumps({'Ys': part}).encode(),
                          {'Content-Type': 'application/json'})
        with urlopen(request, timeout=10) as response:
            states = json.load(response)['states']
        require(len(states) == len(part) and {row['Y'] for row in states} == set(part),
                'mint proof audit omitted or duplicated an original')
        for row in states:
            saved = expected[row['Y']]
            wanted = 'UNSPENT' if saved == 'UNSPENT' else 'SPENT'
            require(saved in ('UNSPENT', 'SPENT', 'PENDING_SPENT') and row['state'] == wanted,
                    'wallet and actual mint state disagree')


def audit(archives, mint, expected):
    live_coins, total, rows = set(), 0, 0
    for archive in archives.values():
        with opened(archive) as (_, db):
            require(not db.execute('SELECT 1 FROM wallet_sagas LIMIT 1').fetchone(), 'unfinished native operation')
            coins = proofs(db)
        mint_states(mint, {key: row['state'] for key, row in coins.items()})
        for key, coin in coins.items():
            if coin['state'] == 'UNSPENT':
                require(key not in live_coins, 'duplicate spendable original across accounts')
                live_coins.add(key)
                total += coin['amount']
            rows += 1
    require(total == expected, 'original settled test value is not conserved')
    return dict(proof_rows=rows, spendable_proofs=len(live_coins), conserved_sat=total)
