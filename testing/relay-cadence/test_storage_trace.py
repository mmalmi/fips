"""Storage observations reject leaked payloads and incomplete syscall history."""

import unittest

from storage_trace import analyze, trace_options


PATHS = {"snapshot": ["/owned/wallet/client.json*"],
         "receiver": ["/owned/receiver/*.sqlite*"]}


def row(body, tid=11):
    return f"{tid} {body}\n"


class StorageTraceTests(unittest.TestCase):
    def test_counts_returned_bytes_and_syncs_without_counting_failed_requests(self):
        trace = "".join(row(s) for s in (
            'write(3</owned/wallet/client.json.new>, ""..., 20) = 20',
            'writev(3</owned/wallet/client.json.new>, [...], 2) = 40',
            'pwrite64(4</owned/receiver/payment.sqlite>, ""..., 20, 0) = 7',
            'pwrite64(4</owned/receiver/payment.sqlite>, ""..., 20, 0) = -1 ENOSPC (No space left on device)',
            'fsync(3</owned/wallet/client.json.new>) = 0',
            'fdatasync(4</owned/receiver/payment.sqlite>) = 0',
            'fsync(4</owned/receiver/payment.sqlite>) = -1 EIO (Input/output error)',
        ))
        result = analyze(trace.splitlines(), PATHS)
        self.assertEqual(result["categories"]["snapshot"], {
            "write_calls": 2, "write_bytes": 60, "write_errors": 0, "partial_scalar_writes": 0,
            "sync_calls": 1, "sync_errors": 0, "files_observed": 1,
        })
        self.assertEqual(result["categories"]["receiver"], {
            "write_calls": 1, "write_bytes": 7, "write_errors": 1, "partial_scalar_writes": 1,
            "sync_calls": 1, "sync_errors": 1, "files_observed": 1,
        })
        self.assertEqual(result["syscalls_observed"], 7)
        self.assertNotIn("/owned", str(result))

    def test_interleaved_threads_resume_only_their_own_syscall(self):
        trace = [
            '11 write(3</owned/wallet/client.json>, ""..., 5 <unfinished ...>',
            '12 pwrite64(4</owned/receiver/payment.sqlite>, ""..., 9, 0) = 9',
            '11 <... write resumed>) = 5',
        ]
        result = analyze(trace, PATHS)
        self.assertEqual(result["categories"]["snapshot"]["write_bytes"], 5)
        self.assertEqual(result["categories"]["receiver"]["write_bytes"], 9)

    def test_unknown_file_and_nonfile_operations_remain_visible(self):
        result = analyze([
            '11 write(3</other/file>, ""..., 3) = 3',
            '11 write(4<socket:[42]>, ""..., 7) = 7',
            '11 write(-1, NULL, 1)             = -1 EBADF (Bad file descriptor)',
        ], PATHS)
        self.assertEqual(result["categories"]["unmatched"]["write_bytes"], 3)
        self.assertEqual(result["categories"]["unattributed"]["write_bytes"], 7)
        self.assertEqual(result["categories"]["unattributed"]["write_errors"], 1)
        self.assertIsNone(result["capture_complete"])

    def test_rejects_payloads_unsupported_decoding_and_incomplete_history(self):
        cases = [
            ['11 write(3</owned/file>, "SECRET", 6) = 6'],
            ['11 writev(3</owned/file>, [{iov_base="SECRET", iov_len=6}], 1) = 6'],
            ['11 <... write resumed>) = 5'],
            ['11 write(3</owned/file>, ""..., 5 <unfinished ...>'],
            ['11 write(3</owned/file>, ""..., 5 <unfinished ...>', '11 <... fsync resumed>) = 0'],
            ['11 write(3</owned/file>, ""..., 5 <unfinished ...>', '11 fsync(3</owned/file>) = 0'],
            ['11 write(3</owned/file>, ""..., 5) = 6'],
            ['11 fsync(3</owned/file>) = 1'],
            ['11 write(3</owned/file>, ""..., 5) = ?'],
            ['11 openat(AT_FDCWD, "/owned/file", O_RDWR) = 3'],
            ['11 --- SIGTERM {si_signo=SIGTERM} ---'],
            ['11 write(3</owned/escaped\\040name>, ""..., 5) = 5'],
        ]
        for trace in cases:
            with self.subTest(trace=trace), self.assertRaises(ValueError):
                analyze(trace, PATHS)

    def test_path_categories_must_be_explicit_and_unambiguous(self):
        trace = ['11 write(3</owned/wallet/client.json>, ""..., 5) = 5']
        for paths in ({}, {"unmatched": ["/owned/*"]}, {"bad-label": ["/owned/*"]},
                      {"snapshot": ["relative/*"]}, {"snapshot": []},
                      {"a": ["/owned/*"], "b": ["/owned/wallet/*"]}):
            with self.subTest(paths=paths), self.assertRaises(ValueError):
                analyze(trace, paths)

    def test_empty_trace_cannot_establish_storage_measurement(self):
        with self.assertRaises(ValueError):
            analyze([], PATHS)

    def test_capture_options_suppress_payloads_signals_and_ambiguous_thread_prefixes(self):
        options = trace_options()
        self.assertIn("--string-limit=0", options)
        self.assertIn("--decode-fds=path", options)
        self.assertIn("--signal=none", options)
        self.assertIn("--always-show-pid", options)
        self.assertIn("--follow-forks", options)
        self.assertFalse(any(x.startswith("--write=") or x.startswith("--read=") for x in options))


if __name__ == "__main__":
    unittest.main()
