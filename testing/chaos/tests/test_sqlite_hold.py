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
