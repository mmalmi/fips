"""Private Linux test-mint supervisor; also copied unchanged to the mint host.

Only the owner of a fresh run can start it. All controls share a file lock;
uncertain money operations retain their intent and are never automatically retried.
"""

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import sys
import time
from urllib.parse import urlsplit


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    with path.open("x") as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump(value, stream)
        stream.flush()
        os.fsync(stream.fileno())


def read(path):
    return json.loads(path.read_text())


def process_start(pid):
    # The command name may contain spaces or parentheses.
    return Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()[19]


class MintHost:
    def __init__(self, owner_path):
        self.owner_path = Path(owner_path)
        self.root = self.owner_path.parent
        self.owner = read(self.owner_path)
        self.binary = Path(self.owner["binary"])
        self.config = Path(self.owner["config"])
        self.settings = read(self.config)
        self.state = Path(self.settings["state_directory"])
        self.argv = [str(self.binary), "run", str(self.config)]

    @contextmanager
    def locked(self):
        with (self.root / "operation.lock").open("a") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            yield

    def files_match(self):
        if (digest(self.binary) != self.owner["binary_sha256"]
                or digest(self.config) != self.owner["config_sha256"]):
            raise RuntimeError("owned mint binary or configuration changed")

    def owned_process(self):
        self.files_match()
        info = read(self.root / "process.json")
        pid = info["pid"]
        descriptor = os.pidfd_open(pid)
        try:
            actual = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")[:-1]
            if (actual != [arg.encode() for arg in self.argv]
                    or process_start(pid) != info["start_ticks"]
                    or os.readlink(f"/proc/{pid}/exe") != str(self.binary)):
                raise RuntimeError("mint process identity changed; refusing control")
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor

    def serve(self):
        with self.locked():
            self.files_match()
            if self.state.exists() or (self.root / "launch.json").exists():
                raise RuntimeError("never restart an existing simulated mint")
            save(self.root / "launch.json", {"argv": self.argv})
            with (self.root / "mint.log").open("xb") as log:
                child = subprocess.Popen(self.argv, stdin=subprocess.DEVNULL,
                                         stdout=log, stderr=log)
            info = {"pid": child.pid, "start_ticks": process_start(child.pid)}
            save(self.root / "process.json", info)
        code = child.wait()
        save(self.root / "exit.json", {**info, "exit_code": code})

    def control(self, body):
        result = subprocess.run([str(self.binary), "ctl", str(self.config)],
                                input=json.dumps(body).encode(), capture_output=True, timeout=90)
        if result.returncode:
            # Token-bearing diagnostics remain on the private mint host.
            (self.root / "control-error.txt").write_bytes(result.stderr + b"\n" + result.stdout)
            raise RuntimeError("mint control failed; private evidence retained")
        return json.loads(result.stdout)

    def report(self):
        return self.validate_report(self.control({"type": "report"}))

    def validate_report(self, report):
        ready = read(self.state / "ready.json")
        url = urlsplit(report["url"])
        if (report.get("test_only") is not True or ready.get("test_only") is not True
                or report["url"] != ready["url"] or url.scheme != "http"
                or url.hostname != self.owner["address"] or not url.port
                or ready["max_issued_sat"] != self.settings["max_issued_sat"]):
            raise RuntimeError("mint report does not match the owned endpoint")
        for key in ("issued_sat", "collected_sat", "external_funding_sat", "total_accounted_sat"):
            if type(report.get(key)) is not int or not 0 <= report[key] <= self.settings["max_issued_sat"]:
                raise RuntimeError("invalid or uncapped mint accounting")
        if report["collected_sat"] > report["issued_sat"]:
            raise RuntimeError("collected amount exceeds issued test funds")
        return report

    def complete_stop(self, report):
        info = read(self.root / "process.json")
        if read(self.root / "exit.json") != {**info, "exit_code": 0}:
            raise RuntimeError("mint did not exit cleanly")
        try:
            if process_start(info["pid"]) == info["start_ticks"]:
                raise RuntimeError("owned mint process has not exited")
        except (FileNotFoundError, ProcessLookupError):
            pass
        result = {**report, "stopped": True, "retained_for_recovery": False}
        terminal = self.root / "stopped.json"
        if terminal.exists():
            if read(terminal) != result:
                raise RuntimeError("terminal proof changed")
        else:
            save(terminal, result)
        return result

    def request(self, body):
        with self.locked():
            if (self.root / "closing.json").exists():
                raise RuntimeError("mint is closing; controls are fenced")
            descriptor = self.owned_process()
            try:
                kind = body.get("type")
                if kind == "report":
                    return self.report()
                if kind == "issue":
                    name, amount = body.get("id"), body.get("amount_sat")
                    if (not isinstance(name, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", name)
                            or type(amount) is not int or not 1 <= amount <= self.settings["max_issued_sat"]):
                        raise ValueError("invalid bounded test grant")
                    attempt = "issue-" + name
                elif kind == "collect" and isinstance(body.get("token"), str):
                    attempt = "collect-" + hashlib.sha256(body["token"].encode()).hexdigest()
                else:
                    raise ValueError("unsupported mint control")
                # Save before submission. Reconcile a lost reply; never resend it.
                save(self.root / (attempt + ".json"), {"type": kind})
                result = self.control(body)
                if kind == "issue":
                    payment = read(self.state / "exports" / (name + ".json"))
                    ready = read(self.state / "ready.json")
                    if (result["amount_sat"] != amount or payment["amount_sat"] != amount
                            or payment["mint_url"] != ready["url"] or not payment.get("token")):
                        raise RuntimeError("test grant terms changed")
                    return payment
                return result
            finally:
                os.close(descriptor)

    def finish(self, stop_seconds=20):
        with self.locked():
            self.files_match()
            closing = self.root / "closing.json"
            saved = self.validate_report(read(closing)) if closing.exists() else None
            if saved is not None:
                if saved.get("conserved") is not True or saved["issued_sat"] != saved["collected_sat"]:
                    raise RuntimeError("closing proof is not fully collected")
                if (self.root / "exit.json").exists():
                    # A lost completion reply/checkpoint needs no new command to
                    # the dead child or to a process that has reused its PID.
                    return self.complete_stop(saved)
            descriptor = self.owned_process()
            try:
                report = self.report()
                if saved is not None and saved != report:
                    raise RuntimeError("mint accounting changed after the stop fence")
                if report.get("conserved") is not True or report["issued_sat"] != report["collected_sat"]:
                    return {**report, "retained_for_recovery": True, "stopped": False}
                # The lock and durable fence prevent issuance between this fresh
                # report and process exit, including a lost SSH reply.
                if saved is None:
                    save(closing, report)
                signal.pidfd_send_signal(descriptor, signal.SIGTERM)
                poll = select.poll()
                poll.register(descriptor, select.POLLIN)
                if not poll.poll(int(stop_seconds * 1000)):
                    raise RuntimeError("mint stop is uncertain; no terminal proof issued")
                deadline = time.monotonic() + 5
                while not (self.root / "exit.json").exists() and time.monotonic() < deadline:
                    time.sleep(0.05)
                return self.complete_stop(report)
            finally:
                os.close(descriptor)


def main():
    os.umask(0o077)
    mode, path = sys.argv[1:]
    host = MintHost(path)
    if mode == "serve":
        host.serve()
        return
    if mode == "request":
        raw = sys.stdin.buffer.read(64 * 1024 + 1)
        if len(raw) > 64 * 1024:
            raise ValueError("mint request too large")
        result = host.request(json.loads(raw))
    elif mode == "finish":
        result = host.finish()
    else:
        raise ValueError("unsupported host operation")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
