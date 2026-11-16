"""Exercise the exact helper used to delay OpenWrt wallet writes."""

import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest


@unittest.skipUnless(os.environ.get('FIPS_SQLITE_HOLD'), 'requires built SQLite hold helper')
class SqliteHoldTests(unittest.TestCase):
    def test_readonly_original_identity_snapshot_sees_wal_and_refuses_ambiguous_input(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'wallet.sqlite'
            first, second, terminal, absent = (bytes([n]) * 33 for n in (2, 3, 4, 5))
            with sqlite3.connect(path) as db:
                db.execute('PRAGMA journal_mode=WAL')
                db.execute('CREATE TABLE proof (y BLOB PRIMARY KEY, state TEXT)')
                db.executemany('INSERT INTO proof VALUES (?,?)',
                               [(first, 'SPENT'), (second, 'UNSPENT'), (terminal, 'PENDING_SPENT')])
                db.commit()
                original = {p.name: p.read_bytes() for p in path.parent.glob('wallet.sqlite*')
                            if not p.name.endswith('-shm')}
                db.execute('BEGIN IMMEDIATE')
                argv = [os.environ['FIPS_SQLITE_HOLD'], 'observe', str(path)]
                supplied = '\n'.join(y.hex() for y in (first, second, terminal, absent)) + '\n'
                result = subprocess.run(argv, input=supplied, text=True, capture_output=True, timeout=3)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), {'states': ['SPENT', 'UNSPENT', 'PENDING_SPENT', None]})
                self.assertEqual(original, {p.name: p.read_bytes() for p in path.parent.glob('wallet.sqlite*')
                                           if not p.name.endswith('-shm')})
                for invalid in ('', first.hex(), first.hex() + '\n' + first.hex() + '\n',
                                'z' * 66 + '\n', supplied * 400):
                    failed = subprocess.run(argv, input=invalid, text=True, capture_output=True, timeout=3)
                    self.assertNotEqual(failed.returncode, 0)
                    self.assertEqual(failed.stdout, '')
                db.rollback()
            missing = path.parent / 'missing.sqlite'
            failed = subprocess.run([*argv[:-1], str(missing)], input=supplied,
                                    text=True, capture_output=True, timeout=3)
            self.assertNotEqual(failed.returncode, 0)
            self.assertFalse(missing.exists())

    def test_writer_contention_rolls_back_on_release_deadline_and_termination(self):
        binary = os.environ['FIPS_SQLITE_HOLD']
        for mode in ('requested', 'deadline', 'signal'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                path = Path(directory)
                database, release = path / 'wallet.sqlite', path / 'release'
                with sqlite3.connect(database, timeout=0) as db:
                    db.execute('PRAGMA journal_mode=WAL')
                    db.execute('CREATE TABLE evidence (value INTEGER)')
                    db.execute('INSERT INTO evidence VALUES (1)')
                    db.commit()
                    child = subprocess.Popen([binary, str(database), str(release),
                                              '1' if mode == 'deadline' else '420'],
                                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    try:
                        self.assertEqual(json.loads(child.stdout.readline()),
                                         {'locked': True, 'pid': child.pid})
                        self.assertEqual(db.execute('SELECT value FROM evidence').fetchall(), [(1,)])
                        with self.assertRaisesRegex(sqlite3.OperationalError, 'locked'):
                            db.execute('BEGIN IMMEDIATE')
                        if mode == 'requested':
                            release.touch()
                        elif mode == 'signal':
                            child.terminate()
                        output, error = child.communicate(timeout=5)
                        self.assertEqual(child.returncode, 0, error)
                        self.assertEqual(json.loads(output), {'released': True, 'reason': mode})
                        self.assertEqual(db.execute('SELECT value FROM evidence').fetchall(), [(1,)])
                        db.execute('BEGIN IMMEDIATE')
                        db.rollback()
                    finally:
                        if child.poll() is None:
                            child.kill()
                            child.communicate(timeout=5)

    def test_refuses_missing_database_or_already_released_hold(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            database, release = path / 'missing.sqlite', path / 'release'
            for released in (False, True):
                if released:
                    release.touch()
                result = subprocess.run([os.environ['FIPS_SQLITE_HOLD'], str(database),
                                         str(release), '1'], capture_output=True, timeout=5)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(database.exists())
            release.unlink()
            with sqlite3.connect(database):
                pass
            for seconds in ('0', '421', '-1', 'invalid'):
                result = subprocess.run([os.environ['FIPS_SQLITE_HOLD'], str(database),
                                         str(release), seconds], capture_output=True, timeout=5)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn(b'locked', result.stdout)
