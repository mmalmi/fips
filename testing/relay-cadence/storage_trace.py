"""Count payload-suppressed strace writes; these are syscall bytes, not media wear."""

import argparse
from fnmatch import fnmatchcase
import json
from pathlib import Path
import re


WRITES = {"write", "writev", "pwrite64", "pwritev", "pwritev2"}
SYNCS = {"fsync", "fdatasync"}
PREFIX = re.compile(r"^(\d+) +(.*)$")
RESUMED = re.compile(r"^<\.\.\. (\w+) resumed>(.*)$")
CALL = re.compile(
    r'^(\w+)\((-?\d+)(?:<([^<>\\"\n]+)>)?(.*)\) += (-?\d+)'
    r'(?: ([A-Z][A-Z0-9_]+)(?: \([^\n]*\))?)?$'
)
BUFFER = r'(?:""(?:\.\.\.)?|0x[0-9a-f]+|NULL)'
WRITE_ARGS = re.compile(r", " + BUFFER + r", (\d+)$")
PWRITE_ARGS = re.compile(r", " + BUFFER + r", (\d+), -?\d+$")
VECTOR_ARGS = re.compile(r", \[(?:\.\.\.)?\], \d+$")
PVECTOR_ARGS = re.compile(r", \[(?:\.\.\.)?\], \d+, -?\d+$")
PVECTOR2_ARGS = re.compile(r", \[(?:\.\.\.)?\], \d+, -?\d+, [A-Z0-9_|]+$")


def trace_options():
    """Use only this bounded syscall set; never enable read/write data dumps."""
    return ["-qq", "--follow-forks", "--always-show-pid", "--string-limit=0",
            "--decode-fds=path", "--signal=none", "--trace=" + ",".join(sorted(WRITES | SYNCS))]


def categories(paths):
    if not isinstance(paths, dict) or not 1 <= len(paths) <= 32:
        raise ValueError("provide explicit file categories")
    for name, patterns in paths.items():
        if (not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", name)
                or name in ("unmatched", "unattributed") or not isinstance(patterns, list)
                or not 1 <= len(patterns) <= 32):
            raise ValueError("invalid file category")
        for pattern in patterns:
            if (not isinstance(pattern, str) or not pattern.startswith("/")
                    or len(pattern) > 4096 or any(c in pattern for c in '\n\r\\"<>')):
                raise ValueError("file patterns must be absolute, unescaped paths")
    return paths


def classify(path, paths):
    if path is None or not path.startswith("/"):
        return "unattributed"
    matches = [name for name, patterns in paths.items()
               if any(fnmatchcase(path, pattern) for pattern in patterns)]
    if len(matches) > 1:
        raise ValueError("file matches multiple categories")
    return matches[0] if matches else "unmatched"


def parse(body):
    match = CALL.fullmatch(body)
    if not match:
        raise ValueError("unsupported or unsuppressed syscall record")
    kind, fd, path, args, result, error = match.groups()
    result = int(result)
    if result < -1 or (result == -1) != (error is not None) or (int(fd) < 0 and result >= 0):
        raise ValueError("inconsistent syscall result")
    requested = None
    if kind in SYNCS:
        if args or result not in (-1, 0):
            raise ValueError("invalid sync record")
    elif kind in WRITES:
        shape = {"write": WRITE_ARGS, "pwrite64": PWRITE_ARGS,
                 "writev": VECTOR_ARGS, "pwritev": PVECTOR_ARGS,
                 "pwritev2": PVECTOR2_ARGS}[kind].fullmatch(args)
        if not shape:
            raise ValueError("write arguments are not payload-suppressed")
        if kind in ("write", "pwrite64"):
            requested = int(shape[1])
            if result > requested:
                raise ValueError("write result exceeds requested bytes")
    else:
        raise ValueError("syscall outside the declared capture set")
    return kind, path, result, requested


def analyze(lines, paths):
    paths = categories(paths)
    counters = {name: dict(write_calls=0, write_bytes=0, write_errors=0, partial_scalar_writes=0,
                           sync_calls=0, sync_errors=0)
                for name in (*paths, "unmatched", "unattributed")}
    files = {name: set() for name in counters}
    pending, count = {}, 0
    for number, line in enumerate(lines, 1):
        if len(line) > 65536 or number > 10_000_000:
            raise ValueError("trace exceeds bounded analyzer capacity")
        line = line.rstrip("\n")
        match = PREFIX.fullmatch(line)
        if not match or int(match[1]) == 0:
            raise ValueError(f"missing thread identity at trace line {number}")
        tid, body = match.groups()
        resumed = RESUMED.fullmatch(body)
        if resumed:
            prior = pending.pop(tid, None)
            if prior is None or prior.partition("(")[0] != resumed[1]:
                raise ValueError("unmatched resumed syscall")
            body = prior + resumed[2]
        elif tid in pending:
            raise ValueError("thread has an unfinished syscall")
        if body.endswith(" <unfinished ...>"):
            if resumed or len(pending) >= 4096:
                raise ValueError("invalid unfinished syscall history")
            pending[tid] = body.removesuffix(" <unfinished ...>")
            continue
        kind, path, result, requested = parse(body)
        category = classify(path, paths)
        current = counters[category]
        if path and path.startswith("/"):
            files[category].add(path)
            if len(files[category]) > 100_000:
                raise ValueError("too many observed file paths")
        count += 1
        if kind in WRITES:
            if result < 0:
                current["write_errors"] += 1
            else:
                current["write_calls"] += 1
                current["write_bytes"] += result
                current["partial_scalar_writes"] += int(requested is not None and result < requested)
        else:
            current["sync_errors" if result < 0 else "sync_calls"] += 1
    if pending or not count:
        raise ValueError("trace is incomplete or contains no observed syscalls")
    for name, value in counters.items():
        value["files_observed"] = len(files[name])
    return {"schema": 1, "scope": "observed write-like syscalls and syncs",
            "syscalls_observed": count, "categories": counters,
            "capture_complete": None, "physical_media_bytes": None,
            "sqlite_committed_changes": None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    parser.add_argument("--paths", type=Path, required=True,
                        help="private JSON mapping category names to absolute file globs")
    args = parser.parse_args()
    try:
        with args.trace.open() as stream:
            result = analyze(stream, json.loads(args.paths.read_text()))
    except (OSError, ValueError) as error:
        # Parsing errors describe the format, never echo payment-bearing input.
        parser.exit(1, f"storage trace rejected: {type(error).__name__}\n")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
