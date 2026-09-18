"""Read-only, process-bound resource samples for the three-router experiment.

OS I/O includes the whole relay process; it is not payment-attributed storage or
physical-media accounting. Kernels without proc I/O report unavailable counters,
never zeroes. Kernel-reported RSS/high-water readings remain raw observations.
"""

import json
import shlex
import time

from .wifi_remote import checked_path


PROC = "/proc"
OPERATIONS = {"other", "payment_sign", "payment_usage", "payment_update",
              "payment_open", "payment_stop", "window_checkpoint"}
COUNTERS = {"spans", "cpu_samples", "thread_cpu_ns", "elapsed_ns",
            "journal_bytes_written", "journal_writes", "journal_syncs", "journal_commits"}
IO_COUNTERS = ("read_bytes", "write_bytes", "rchar", "wchar", "syscr", "syscw")


def unsigned(value):
    if type(value) is not int or value < 0:
        raise ValueError("missing or invalid unsigned measurement")
    return value


def decimal(value):
    if not value or not value.isascii() or not value.isdecimal():
        raise ValueError("invalid process resource counter")
    return int(value)


def process_identity(stat):
    """Parse Linux stat field 22 without splitting the parenthesized comm."""
    prefix, close, tail = stat.strip().rpartition(") ")
    pid, opening, _ = prefix.partition(" (")
    fields = tail.split()
    if not close or not opening or len(fields) < 20 or len(fields[0]) != 1:
        raise ValueError("invalid process stat record")
    identity = decimal(pid), decimal(fields[19])
    if not all(identity):
        raise ValueError("invalid process epoch")
    return identity


def resource_fields(text, names, unit=None):
    values = {}
    for line in text.splitlines():
        name, separator, raw = line.partition(":")
        if name not in names:
            continue
        fields = raw.split()
        if (not separator or name in values or len(fields) != (2 if unit else 1)
                or (unit and fields[1] != unit)):
            raise ValueError("invalid or duplicate process resource field")
        values[name] = decimal(fields[0])
    if set(values) != set(names):
        raise ValueError("missing process resource field")
    return values


def validate_measurements(status, pid):
    value = status.get("measurements")
    if not isinstance(value, dict) or type(value.get("version")) is not int or value["version"] != 1:
        raise ValueError("measurement-enabled version 1 relay required")
    if unsigned(value.get("process_id")) != pid:
        raise ValueError("relay status came from a different process")
    unsigned(value.get("process_cpu_ns"))
    operations = value.get("operations")
    if not isinstance(operations, dict) or set(operations) != OPERATIONS:
        raise ValueError("missing or unsupported measurement operations")
    for counters in operations.values():
        if not isinstance(counters, dict) or set(counters) != COUNTERS:
            raise ValueError("missing or unsupported measurement counters")
        for counter in counters.values():
            unsigned(counter)


def command(node, native_counters=False):
    temporary = shlex.quote(checked_path(node.temporary))
    binary = shlex.quote(checked_path(node.binary))
    config = shlex.quote(checked_path(node.config))
    proc = shlex.quote(checked_path(PROC))
    native = (f"""native_status=$(printf '%s\\n' '{{"command":"show_status"}}' | {binary} native {config})
native_routing=$(printf '%s\\n' '{{"command":"show_routing"}}' | {binary} native {config})
""" if native_counters else "")
    extra = ' "$native_status" "$native_routing"' if native_counters else ""
    # Do not acquire operation.lock: reads must not delay the independent guard.
    # Buffer output until both identity checks succeed; no proc/config data is
    # written remotely. NUL framing preserves spaces and parentheses in comm.
    return f"""set -eu
pid=$(cat {temporary}/process.pid)
case "$pid" in ''|*[!0-9]*) exit 1;; esac
test "$pid" -gt 0
owned() {{
  test "$(cat {temporary}/process.pid)" = "$pid"
  test "$(readlink {proc}/$pid/exe)" = {binary}
  actual=$(sha256sum <{proc}/$pid/cmdline)
  expected=$(printf '%s\\000' {binary} run {config} | sha256sum)
  test "$actual" = "$expected"
}}
before=$(cat {proc}/$pid/stat)
owned
{native}relay=$(printf '%s\\n' '{{"type":"status"}}' | {binary} ctl {config})
resources=$(cat {proc}/$pid/status)
if test -e {proc}/$pid/io || test -L {proc}/$pid/io; then
  io=$(cat {proc}/$pid/io)
  availability=available
else
  io=''
  availability=unsupported
fi
owned
after=$(cat {proc}/$pid/stat)
printf '%s\\000' "$pid" "$before" "$after" "$resources" "$io" "$relay" "$availability"{extra}
"""


def snapshot(node, hostlabel, native_counters=False):
    """Return one normal status response with validated host/process evidence."""
    if hostlabel not in ("n01", "n02", "n03") or type(native_counters) is not bool:
        raise ValueError("invalid measurement host label")
    started = time.monotonic_ns()
    raw = node.remote(command(node, native_counters), timeout=45)
    finished = time.monotonic_ns()
    parts = raw.decode("utf-8").split("\0")
    if len(parts) != (10 if native_counters else 8) or parts[-1]:
        raise ValueError("invalid resource sample framing")
    pid = decimal(parts[0])
    before, after = process_identity(parts[1]), process_identity(parts[2])
    if before != after or before[0] != pid:
        raise ValueError("relay process epoch changed during sampling")
    memory = resource_fields(parts[3], ("VmRSS", "VmHWM"), "kB")
    if parts[6] == "available":
        io = resource_fields(parts[4], IO_COUNTERS)
    elif parts[6] == "unsupported" and not parts[4]:
        io = dict.fromkeys(IO_COUNTERS, None)
    else:
        raise ValueError("invalid process I/O availability evidence")
    if memory["VmRSS"] > memory["VmHWM"]:
        raise ValueError("RSS exceeds process high-water mark")
    status = json.loads(parts[5])
    if not isinstance(status, dict):
        raise ValueError("invalid relay status")
    validate_measurements(status, pid)
    if getattr(node, "npub", None) and status.get("npub") != node.npub:
        raise ValueError("relay status came from a different node")
    if native_counters:
        native = dict(zip(("status", "routing"), map(json.loads, parts[7:9])))
        if any(not isinstance(v, dict) or v.get("status") != "ok"
               or not isinstance(v.get("data"), dict) for v in native.values()):
            raise ValueError("native diagnostic request failed")
        identity = native["status"]["data"]
        if (identity.get("npub") != status.get("npub")
                or unsigned(identity.get("pid")) != pid
                or identity.get("exe_path") != node.binary):
            raise ValueError("native diagnostics came from a different process")
        status["native"] = native
    status["host_process"] = {"host": hostlabel, "pid": pid, "start_ticks": before[1],
                              "rss_kib": memory["VmRSS"], "peak_rss_kib": memory["VmHWM"],
                              "io_available": parts[6] == "available", **io}
    status["sample_timing"] = {"started_monotonic_ns": started, "finished_monotonic_ns": finished}
    return status
