"""Read bounded payment counters without transferring private signer journals.

Authorization is persisted before signing. The separate signed balance records
completed signature creation; neither counter proves provider acknowledgement.
The observer brackets each call with its controller monotonic read interval.
Payment readers require an already-paid baseline (payment_count > 0); an absent
original payment record must not be interpreted as a zero signed balance.
"""

import os
import re
import selectors
import shlex
import signal
import subprocess
import threading
import time

from .wifi_remote import checked_path


READ_SECONDS = 3
LIFETIME_SECONDS = 90
MAX_READERS = 4
MAX_REPLY_BYTES = 256
U64_MAX = (1 << 64) - 1


def worker(state, channel, kind):
    """Every jsonfilter invocation opens the current atomically replaced file."""
    checked_path(state)
    if not isinstance(channel, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', channel):
        raise ValueError('invalid numeric-reader channel')
    if kind not in ('payment', 'credit'):
        raise ValueError('invalid numeric-reader kind')

    def extract(path, parents, row, field, identity=None, signed=False):
        expressions = [('t', '@'), *[('t', p) for p in parents], ('t', row),
                       ('t', row + '.' + field)]
        types = ['object', *[t for _, t in parents.items()], 'object', 'int']
        if identity:
            expressions += [('t', row + '.' + identity), ('e', row + '.' + identity)]
            types += ['string', channel]
        if signed:
            expressions += [('t', row + '.signature'), ('t', row + '.payment_count'),
                            ('e', row + '.payment_count')]
            types += ['string', 'int']
        expressions.append(('e', row + '.' + field))
        args = ['jsonfilter', '-q', '-i', state + '/' + path]
        for option, expression in expressions:
            args += ['-' + option, expression]
        # Type and value come from one parse; checking type in a second process
        # could accidentally validate another generation of the atomic file.
        prefix = '\n'.join(types)
        result = (f'value=$({shlex.join(args)}) || exit 1\n'
                + "case \"$value\" in " + shlex.quote(prefix + '\n') + '*) ;; *) exit 1;; esac\n'
                + f'value=${{value#{shlex.quote(prefix + chr(10))}}}\n')
        if signed:
            result += ("count=${value%%'\n'*}\nvalue=${value#*'\n'}\n"
                       "case \"$count\" in ''|0|*[!0-9]*) exit 1;; esac\n")
        return result + "case \"$value\" in ''|*[!0-9]*) exit 1;; esac\n"

    if kind == 'payment':
        row = '@.channels["' + channel + '"]'
        read = extract('buyer/buyer.json', {'@.channels': 'object'}, row,
                       'authorized_sat', 'terms.id') + 'authorized=$value\n'
        row = '@.payments["' + channel + '"]'
        read += extract('wallet/spilman-client.json', {'@.payments': 'object'}, row,
                        'balance', signed=True) + 'signed=$value\n'
        reply = '"$request" "$authorized" "$signed"'
        formatting = '%s %s %s\\n'
    else:
        row = '@.ledger.channels[@.terms.id="' + channel + '"]'
        read = extract('seller/ledger.json', {'@.ledger': 'object', '@.ledger.channels': 'array'},
                       row, 'usage.paid_msat', 'terms.id')
        reply, formatting = '"$request" "$value"', '%s %s\\n'
    # setsid confines both the watchdog and all jsonfilter children. Normal EOF
    # or stop terminates that exact group; a dead controller cannot leave it alive.
    script = f'''set -efu
reader=$$
cleanup() {{
  trap '' HUP INT TERM
  kill -TERM -- -"$reader" 2>/dev/null || :
  wait "$watchdog" 2>/dev/null || :
}}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
(sleep {LIFETIME_SECONDS - 1}; kill -KILL -- -"$reader" 2>/dev/null) &
watchdog=$!
test "$(jsonfilter -q -s '{{"n":1,"s":"1"}}' -t '@.n' -t '@.s' -e '@.n')" = 'int
string
1' || exit 1
while IFS= read -r request; do
  [ "$request" != stop ] || exit 0
  case "$request" in ''|*[!0-9]*) exit 1;; esac
{read}  printf '{formatting}' {reply}
done
'''
    return 'exec setsid sh -c ' + shlex.quote(script)


class NumericReader:
    """One owned SSH process, one exact channel, no retry after uncertainty."""

    def __init__(self, profile, channel, kind):
        owner = getattr(profile, 'owner', profile)
        command = worker(profile.state, channel, kind)
        self.process = subprocess.Popen([*owner.ssh_args(), owner.host, command],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, start_new_session=True)
        self.kind, self.sequence = kind, 0
        self.expires = time.monotonic() + LIFETIME_SECONDS
        self.lock = threading.Lock()
        self.failed = self.closed = False
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.process.stdout, selectors.EVENT_READ)
        self.receipt = None

    def read(self):
        if not self.lock.acquire(blocking=False):
            raise RuntimeError('numeric reader called concurrently')
        try:
            if self.failed or self.closed or time.monotonic() >= self.expires:
                raise RuntimeError('numeric reader is unavailable')
            self.sequence += 1
            deadline = min(self.expires, time.monotonic() + READ_SECONDS)
            self.process.stdin.write(f'{self.sequence}\n'.encode())
            self.process.stdin.flush()
            raw = bytearray()
            while b'\n' not in raw:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not self.selector.select(remaining):
                    raise TimeoutError('numeric reader exceeded its read deadline')
                part = os.read(self.process.stdout.fileno(), MAX_REPLY_BYTES + 1 - len(raw))
                if not part:
                    raise RuntimeError('numeric reader exited before its reply')
                raw.extend(part)
                if len(raw) > MAX_REPLY_BYTES:
                    raise RuntimeError('numeric reader reply exceeded its bound')
            count = 3 if self.kind == 'payment' else 2
            fields = bytes(raw).rstrip(b'\n').split(b' ')
            if (len(fields) != count or bytes(raw).count(b'\n') != 1
                    or fields[0] != str(self.sequence).encode()
                    or any(not re.fullmatch(rb'0|[1-9][0-9]{0,19}', f) for f in fields[1:])):
                raise RuntimeError('numeric reader returned an invalid reply')
            numbers = [int(f) for f in fields[1:]]
            if any(value > U64_MAX for value in numbers):
                raise RuntimeError('numeric reader counter overflowed')
            return dict(authorized_sat=numbers[0], signed_sat=numbers[1]) if count == 3 else numbers[0]
        except BaseException:
            self.failed = True
            raise
        finally:
            self.lock.release()

    def close(self):
        if self.closed:
            return
        self.closed = True
        process, forced = self.process, False
        try:
            try:
                process.stdin.close()
            except BrokenPipeError:
                pass
            try:
                process.wait(timeout=READ_SECONDS)
            except subprocess.TimeoutExpired:
                forced = True
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=1)
        finally:
            self.selector.close()
            process.stdout.close()
        self.receipt = dict(pid=process.pid, exit_code=process.returncode, forced=forced,
                            reaped=process.returncode is not None, read_failed=self.failed)
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            self.receipt['group_absent'] = True
        else:
            self.receipt['group_absent'] = False
            raise RuntimeError('numeric reader process group remains present')
        if process.returncode != 0 or forced or self.failed:
            raise RuntimeError('numeric reader did not exit normally')


class NumericReaders:
    """At most two buyer and two provider sessions, independently serial calls."""

    def __init__(self, run):
        self.run, self.readers = run, {}
        self.lock, self.closed = threading.Lock(), False

    def __enter__(self):
        return self

    def reading(self, owner, channel, kind):
        key = (owner, channel, kind)
        with self.lock:
            if self.closed:
                raise RuntimeError('numeric readers are closed')
            if key not in self.readers:
                if len(self.readers) >= MAX_READERS:
                    raise RuntimeError('numeric reader session limit exceeded')
                self.readers[key] = NumericReader(self.run.participants()[owner], channel, kind)
            reader = self.readers[key]
        return reader.read()

    def payment(self, owner, channel):
        return self.reading(owner, channel, 'payment')

    def credit(self, provider, channel):
        return self.reading(provider, channel, 'credit')

    @property
    def cleanup_receipts(self):
        return [dict(owner=owner, channel_id=channel, kind=kind, cleanup=reader.receipt)
                for (owner, channel, kind), reader in self.readers.items()]

    def __exit__(self, *exception):
        with self.lock:
            self.closed = True
        errors = []
        for reader in self.readers.values():
            try:
                reader.close()
            except Exception as error:
                errors.append(error)
        if errors:
            if exception and exception[1] is not None:
                exception[1].add_note('numeric reader cleanup also failed; retain cleanup receipts')
                return False
            raise RuntimeError('numeric reader cleanup failed') from errors[0]
