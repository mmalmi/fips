"""Bounded tracer supervisor, run only inside an owned diagnostic container."""

import json
import os
from pathlib import Path
import select
import signal
import subprocess
import time

from storage_trace import trace_options


ROOT = Path("/run/bench")
EXPECTED = b"/opt/bench/fips-relay\0run\0/run/bench/config.json\0"


def save(name, value):
    with (ROOT / name).open("x") as stream:
        json.dump(value, stream)


def tracers(pid):
    result = []
    for task in (Path("/proc") / str(pid) / "task").iterdir():
        try:
            fields = dict(line.split(":", 1) for line in (task / "status").read_text().splitlines())
            result.append(int(fields["TracerPid"]))
        except FileNotFoundError:
            # A task can exit while enumerating a live process's threads.
            continue
    return result


def target_alive(pid, descriptor):
    proc = Path("/proc") / str(pid)
    return (not select.select([descriptor], [], [], 0)[0]
            and os.readlink(proc / "exe") == "/opt/bench/fips-relay"
            and (proc / "cmdline").read_bytes() == EXPECTED)


def main():
    os.umask(0o077)
    result = {"accepted": False, "requested_stop": False}
    tracer = descriptor = None
    try:
        pid = int((ROOT / "process.pid").read_text())
        if pid <= 1:
            raise RuntimeError("invalid target PID")
        descriptor = os.pidfd_open(pid)
        if not target_alive(pid, descriptor) or any(tracers(pid)):
            raise RuntimeError("target identity or initial tracing state differs")
        trace = ROOT / "storage.trace"
        # Refuse reuse before strace opens its output with truncation semantics.
        with trace.open("x"):
            pass
        with (ROOT / "storage.stderr").open("x") as errors:
            tracer = subprocess.Popen(["strace", *trace_options(), "-o", str(trace),
                                       "-p", str(pid)], stderr=errors)
            deadline = time.monotonic() + 10
            while True:
                attached = tracers(pid)
                if attached and all(value == tracer.pid for value in attached):
                    break
                if tracer.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("tracer did not attach to every thread")
                time.sleep(0.05)
            save("storage.ready.json", {"target_pid": pid, "tracer_pid": tracer.pid,
                                        "threads_attached": len(attached)})
            deadline = time.monotonic() + 90
            while not (ROOT / "storage.stop").exists():
                if (tracer.poll() is not None or not target_alive(pid, descriptor)
                        or time.monotonic() >= deadline or trace.stat().st_size > 64 * 1024 * 1024):
                    raise RuntimeError("capture exceeded lifecycle or size bounds")
                time.sleep(0.05)
            result["requested_stop"] = True
            tracer.send_signal(signal.SIGINT)
            result["tracer_exit"] = tracer.wait(timeout=10)
        attached = tracers(pid)
        result.update(target_alive=target_alive(pid, descriptor),
                      detached=bool(attached) and not any(attached),
                      stderr_empty=(ROOT / "storage.stderr").stat().st_size == 0,
                      trace_bytes=trace.stat().st_size)
        result["accepted"] = (result["tracer_exit"] in (0, -signal.SIGINT)
                              and result["target_alive"] and result["detached"]
                              and result["stderr_empty"]
                              and 0 < result["trace_bytes"] <= 64 * 1024 * 1024)
    except Exception as error:
        result["failure"] = type(error).__name__
    finally:
        if tracer is not None and tracer.poll() is None:
            tracer.send_signal(signal.SIGINT)
            try:
                tracer.wait(timeout=10)
            except subprocess.TimeoutExpired:
                tracer.kill()
                tracer.wait(timeout=5)
        if descriptor is not None:
            os.close(descriptor)
        save("storage.done.json", result)
    return 0 if result["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
