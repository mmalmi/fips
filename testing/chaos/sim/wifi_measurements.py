"""Read-only, process-bound resource samples for the three-router experiment.

OS I/O includes the whole relay process; it is not payment-attributed storage or
physical-media accounting. Kernels without proc I/O report unavailable counters,
never zeroes. Kernel-reported RSS/high-water readings remain raw observations.
"""

import json
import math
import shlex
import time

from .wifi_remote import checked_path
from . import wifi_link_loss


PROC = "/proc"
DATAPLANE_DROP_LOG_FILTER = "warn,fips_core::node::handlers::rx_loop::dataplane=debug"
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
    if (not isinstance(value, dict) or type(value.get("version")) is not int
            or value["version"] not in (1, 2, 3)):
        raise ValueError("measurement-enabled version 1, 2 or 3 relay required")
    if unsigned(value.get("process_id")) != pid:
        raise ValueError("relay status came from a different process")
    unsigned(value.get("process_cpu_ns"))
    operations = value.get("operations")
    expected = OPERATIONS if value["version"] == 1 else OPERATIONS - {"payment_open", "payment_stop"}
    if value["version"] == 3:
        expected = expected | {"payment_exchange"}
    if not isinstance(operations, dict) or set(operations) != expected:
        raise ValueError("missing or unsupported measurement operations")
    if value["version"] >= 2:
        denials = value.get("admission_denials")
        if not isinstance(denials, dict) or set(denials) != {"credit_limit", "durable_window"}:
            raise ValueError("missing or unsupported admission counters")
        for counter in denials.values():
            unsigned(counter)
    for counters in operations.values():
        if not isinstance(counters, dict) or set(counters) != COUNTERS:
            raise ValueError("missing or unsupported measurement counters")
        for counter in counters.values():
            unsigned(counter)


def command(node, native_counters=False, drop_logs=False, link_loss=False, *, aqm_peer=None):
    if aqm_peer is not None and not link_loss:
        raise ValueError("AQM observation requires link-loss capture")
    temporary = shlex.quote(checked_path(node.temporary))
    binary = shlex.quote(checked_path(node.binary))
    process_binary = shlex.quote(checked_path(getattr(node, "process_binary", node.binary)))
    config = shlex.quote(checked_path(node.config))
    proc = shlex.quote(checked_path(PROC))
    native = (f"""native_status=$(printf '%s\\n' '{{"command":"show_status"}}' | {binary} native {config})
native_routing=$(printf '%s\\n' '{{"command":"show_routing"}}' | {binary} native {config})
native_transports=$(printf '%s\\n' '{{"command":"show_transports"}}' | {binary} native {config})
""" if native_counters else "")
    extra = ' "$native_status" "$native_routing" "$native_transports"' if native_counters else ""
    log_check = (f"""log_filter=$(tr '\\000' '\\n' <{proc}/$pid/environ | sed -n 's/^RUST_LOG=//p')
  test "$log_filter" = {shlex.quote(DATAPLANE_DROP_LOG_FILTER)}
""" if drop_logs else "")
    log_sample = (f"log_bytes=$(wc -c <{temporary}/process.log | tr -d '[:space:]')\n"
                  if drop_logs else "")
    if drop_logs:
        extra += ' "$log_filter" "$log_bytes"'
    link_sample = wifi_link_loss.command(node, PROC, aqm_peer) if link_loss else ""
    if link_loss:
        extra += "".join(f' "${field}"' for field in wifi_link_loss.fields(aqm_peer))
    # Do not acquire operation.lock: reads must not delay the independent guard.
    # Buffer output until both identity checks succeed; no proc/config data is
    # written remotely. NUL framing preserves spaces and parentheses in comm.
    return f"""set -eu
pid=$(cat {temporary}/process.pid)
case "$pid" in ''|*[!0-9]*) exit 1;; esac
test "$pid" -gt 0
owned() {{
  test "$(cat {temporary}/process.pid)" = "$pid"
  test "$(readlink {proc}/$pid/exe)" = {process_binary}
  actual=$(sha256sum <{proc}/$pid/cmdline)
  expected=$(printf '%s\\000' {process_binary} run {config} | sha256sum)
  test "$actual" = "$expected"
  {log_check}
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
{log_sample}{link_sample}owned
after=$(cat {proc}/$pid/stat)
printf '%s\\000' "$pid" "$before" "$after" "$resources" "$io" "$relay" "$availability"{extra}
"""


def snapshot(node, hostlabel, native_counters=False, drop_logs=False, link_loss=False, *, aqm_peer=None, timeout=45):
    """Return one normal status response with validated host/process evidence."""
    if (hostlabel not in ("n01", "n02", "n03") or type(native_counters) is not bool
            or type(drop_logs) is not bool or type(link_loss) is not bool):
        raise ValueError("invalid measurement host label")
    if aqm_peer is not None and (not link_loss or hostlabel != "n02"):
        raise ValueError("AQM observation requires middle-router link-loss capture")
    started = time.monotonic_ns()
    raw = node.remote(command(node, native_counters, drop_logs, link_loss, aqm_peer=aqm_peer), timeout=timeout)
    finished = time.monotonic_ns()
    parts = raw.decode("utf-8").split("\0")
    extra = len(wifi_link_loss.fields(aqm_peer)) if link_loss else 0
    if len(parts) != 8 + 3 * native_counters + 2 * drop_logs + extra or parts[-1]:
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
        native = dict(zip(("status", "routing", "transports"), map(json.loads, parts[7:10])))
        if any(not isinstance(v, dict) or v.get("status") != "ok"
               or not isinstance(v.get("data"), dict) for v in native.values()):
            raise ValueError("native diagnostic request failed")
        identity = native["status"]["data"]
        if (identity.get("npub") != status.get("npub")
                or unsigned(identity.get("pid")) != pid
                or identity.get("exe_path") != getattr(node, "process_binary", node.binary)):
            raise ValueError("native diagnostics came from a different process")
        status["native"] = native
    if drop_logs:
        start = 7 + 3 * native_counters
        log_filter, log_bytes = parts[start:start + 2]
        if log_filter != DATAPLANE_DROP_LOG_FILTER:
            raise ValueError("dataplane drop log filter differs from the pinned diagnostic")
        status["dataplane_log"] = {"filter": log_filter, "bytes": decimal(log_bytes)}
    if link_loss:
        start = 7 + 3 * native_counters + 2 * drop_logs
        status["link_loss"] = wifi_link_loss.parse(node, parts[start:-1], aqm_peer)
    status["host_process"] = {"host": hostlabel, "pid": pid, "start_ticks": before[1],
                              "rss_kib": memory["VmRSS"], "peak_rss_kib": memory["VmHWM"],
                              "io_available": parts[6] == "available", **io}
    status["sample_timing"] = {"started_monotonic_ns": started, "finished_monotonic_ns": finished}
    return status


def _finite(value):
    assert type(value) in (int, float) and math.isfinite(value) and value >= 0
    return value

def summarize_process_samples(rows, intent, expected):
    """Keep process epochs exact and report approximate memory-counter behavior."""
    hosts = {name: dict(samples=0, errors=0, live_profile_samples=0, unavailable_profiles=0,
                       maximum_capture_seconds=0, maximum_sample_gap_seconds=0,
                       maximum_recorded_rss_sum_kib=None, minimum_host_available_kib=None)
             for name in expected}
    epochs, last_time = {}, {}
    for row in rows:
        name = row['host']
        host = hosts[name]
        host['samples'] += 1
        start, end = _finite(row['started_monotonic']), _finite(row['finished_monotonic'])
        assert end >= start
        if name in last_time:
            assert start > last_time[name]
            host['maximum_sample_gap_seconds'] = max(host['maximum_sample_gap_seconds'], start-last_time[name])
        last_time[name] = start
        if 'observation_error' in row:
            host['errors'] += 1
            continue
        assert row['boot_id'] == intent['boot_ids'][name]
        device_start = _finite(row['device_uptime_start'])
        device_end = _finite(row['device_uptime_end'])
        assert device_end >= device_start
        host['maximum_capture_seconds'] = max(host['maximum_capture_seconds'], device_end-device_start)
        memory = row['host_memory_kib']
        available, total = _finite(memory['MemAvailable']), _finite(memory['MemTotal'])
        assert available <= total and total > 0
        assert host.setdefault('host_total_kib', total) == total
        previous = host['minimum_host_available_kib']
        host['minimum_host_available_kib'] = available if previous is None else min(previous, available)
        assert set(row['profiles']) == expected[name]
        rss_sum = 0
        for profile, sample in row['profiles'].items():
            if sample['state'] == 'unavailable':
                host['unavailable_profiles'] += 1
                continue
            assert sample['state'] == 'live'
            host['live_profile_samples'] += 1
            key = (name, profile, sample['pid'], sample['start_ticks'])
            assert all(type(value) is int and value > 0 for value in key[2:])
            assert process_identity(sample['stat_before']) == process_identity(sample['stat_after']) == key[2:]
            ticks = _finite(sample['cpu_ticks'])
            fields = sample['stat_after'].strip().rpartition(') ')[2].split()
            assert ticks == int(fields[11]) + int(fields[12])
            assert sample['cpu_seconds'] == ticks / intent['tick_hz'][name]
            rss, peak = _finite(sample['rss_kib']), _finite(sample['peak_rss_kib'])
            assert rss <= peak
            rss_sum += rss
            current = epochs.setdefault(key, dict(host=name, profile=profile, pid=key[2],
                start_ticks=key[3], samples=0, first_monotonic=start, last_monotonic=start,
                first_cpu_ticks=ticks, last_cpu_ticks=ticks, peak_rss_kib=peak,
                last_peak_rss_kib=peak, peak_counter_decreases=0))
            assert ticks >= current['last_cpu_ticks']
            if peak < current['last_peak_rss_kib']:
                current['peak_counter_decreases'] += 1
            current.update(samples=current['samples']+1, last_monotonic=end,
                           last_cpu_ticks=ticks, peak_rss_kib=max(peak, current['peak_rss_kib']),
                           last_peak_rss_kib=peak)
        assert row['observed_profile_rss_sum_kib'] == rss_sum
        if any(sample['state'] == 'live' for sample in row['profiles'].values()):
            host['maximum_recorded_rss_sum_kib'] = max(host['maximum_recorded_rss_sum_kib'] or 0, rss_sum)
    for epoch in epochs.values():
        epoch['observed_cpu_delta_seconds'] = (
            epoch['last_cpu_ticks']-epoch['first_cpu_ticks']) / intent['tick_hz'][epoch['host']]
    observed = {(row['host'], row['profile']) for row in epochs.values()}
    return dict(hosts=hosts, process_epochs=list(epochs.values()), memory_counters_approximate=True,
                missing_profiles=[name for host, names in expected.items() for name in sorted(names)
                                  if (host, name) not in observed],
                observed_cpu_delta_seconds=(sum(row['observed_cpu_delta_seconds'] for row in epochs.values())
                                            if epochs else None),
                scope='Whole-process CPU deltas between observed samples of the same epoch, excluding missed start/end intervals and epochs. Linux VmRSS/VmHWM are approximate; maxima refer to sampled readings. RSS sums can count shared pages more than once. No payment attribution, physical-media count, hard memory ceiling or complete phase coverage is inferred.')
