"""Shared SSH command boundary for explicitly configured bench hosts."""

from pathlib import Path
import shlex
import subprocess


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
        args = self.ssh_args()
        args += [self.host, command if isinstance(command, str) else shlex.join(command)]
        result = subprocess.run(args, input=data, capture_output=True, timeout=timeout)
        if result.returncode:
            (self.output / "last-error.txt").write_bytes(result.stderr + b"\n" + result.stdout)
            raise RuntimeError(f"{self.host}: remote operation failed; private error saved")
        return result.stdout
