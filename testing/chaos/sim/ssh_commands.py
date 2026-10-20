"""Shared SSH command boundary for explicitly configured bench hosts."""

from pathlib import Path
from contextlib import contextmanager
import shlex
import subprocess
import threading
import time


_REMOTE_SLOTS = {}
_REMOTE_LOCK = threading.Lock()


def remaining(deadline):
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise TimeoutError('SSH operation exceeded its deadline')
    return seconds


@contextmanager
def remote_slot(owner, timeout):
    """Bound per-host SSH pressure, including queue time in the caller's budget."""
    deadline = time.monotonic() + timeout
    config = getattr(owner, 'spec', {}).get('ssh_config')
    key = (owner.host, str(Path(config).resolve(strict=True)) if config else None)
    with _REMOTE_LOCK:
        gate = _REMOTE_SLOTS.setdefault(key, threading.BoundedSemaphore(3))
    if not gate.acquire(timeout=remaining(deadline)):
        raise TimeoutError('SSH capacity wait exceeded its deadline')
    try:
        remaining(deadline)
        yield deadline
    finally:
        gate.release()


class SshCommands:
    def ssh_args(self):
        # ConnectTimeout covers only setup. Detect a blackholed established
        # connection before the interruption harness waits 15 seconds for its
        # worker, while allowing healthy commands to remain silent. An existing
        # multiplex master would retain its own, potentially unbounded policy.
        args = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
                "-o", "ServerAliveInterval=2", "-o", "ServerAliveCountMax=3",
                "-o", "ControlMaster=no", "-o", "ControlPath=none"]
        if self.spec.get("ssh_config"):
            args += ["-F", str(Path(self.spec["ssh_config"]).resolve(strict=True))]
        return args

    def remote(self, command, data=None, timeout=20):
        with remote_slot(self, timeout) as deadline:
            args = self.ssh_args()
            args += [self.host, command if isinstance(command, str) else shlex.join(command)]
            result = subprocess.run(args, input=data, capture_output=True, timeout=remaining(deadline))
        if result.returncode:
            (self.output / "last-error.txt").write_bytes(result.stderr + b"\n" + result.stdout)
            raise RuntimeError(f"{self.host}: remote operation failed; private error saved")
        return result.stdout
