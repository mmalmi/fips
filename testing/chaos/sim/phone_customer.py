"""Exact-device acceptance UI actions with durable, non-replayed tap intents.

The app has no request IDs. Use one operator/adapter per phone, keep it in the
foreground, and reconcile an uncertain attempt before any further UI action.
Only verification markers are archived; account files are never changed here.
"""

import base64
from contextlib import contextmanager
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shlex
import subprocess
import time
import uuid
from xml.etree import ElementTree


PACKAGE = "org.fips.relaybench.acceptance"
ACTIVITY = "org.fips.relaybench.MainActivity"
SCHEME = "fipsbench-acceptance"
LABELS = {"setup": "Set up test account", "import": "Load test funds",
          "start": "Connect", "buy": "Buy forwarding", "send": "Send test data",
          "finish": "Settle and stop", "stop": "Stop",
          "export": "Prepare fund return", "status": "Refresh"}


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def save(path, value):
    with path.open("x") as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump(value, stream)
        stream.flush()
        os.fsync(stream.fileno())
    sync_directory(path.parent)


def checked_timeout(value):
    if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 120:
        raise ValueError("phone observation timeout must be between zero and 120 seconds")
    return value


class PhoneCustomer:
    def __init__(self, adb_path, serial, evidence_dir):
        self.adb_path = Path(adb_path).resolve(strict=True)
        if not self.adb_path.is_file() or not os.access(self.adb_path, os.X_OK):
            raise ValueError("an explicit executable adb path is required")
        if not isinstance(serial, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", serial):
            raise ValueError("an exact authorized device serial is required")
        self.serial = serial
        self.root = Path(evidence_dir)
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.root.stat().st_mode & 0o077:
            raise ValueError("phone evidence directory must be private")
        self.identity = {"adb": str(self.adb_path), "serial": serial, "package": PACKAGE}
        with self.locked():
            path = self.root / "identity.json"
            if path.exists():
                if json.loads(path.read_text()) != self.identity:
                    raise RuntimeError("phone evidence belongs to another device or adapter")
            else:
                save(path, self.identity)

    @contextmanager
    def locked(self):
        descriptor = os.open(self.root / "operation.lock", os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        finally:
            os.close(descriptor)

    def adb(self, *args, data=None, timeout=25):
        # Never log commands/stdout/stderr: setup links and app files are private.
        try:
            result = subprocess.run([str(self.adb_path), "-s", self.serial, *args],
                                    input=data, capture_output=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired):
            raise RuntimeError("phone command uncertain; inspect the saved attempt") from None
        if result.returncode:
            raise RuntimeError("phone command failed; inspect the saved attempt")
        return result.stdout

    def shell(self, *args, timeout=25):
        # stdin also keeps a secret setup URI out of host process arguments.
        return self.adb("shell", "sh", data=(shlex.join(args) + "\n").encode(), timeout=timeout)

    def check(self, foreground=True):
        if (self.adb("get-serialno").strip().decode() != self.serial
                or self.adb("get-state").strip() != b"device"):
            raise RuntimeError("authorized phone identity or connection changed")
        policy = self.shell("dumpsys", "window", "policy").decode()
        for key in ("showing", "inputRestricted"):
            values = re.findall(r"\b" + key + r"=(true|false)\b", policy)
            if not values or any(value != "false" for value in values):
                raise RuntimeError("phone must be freshly observed unlocked")
        if not self.shell("pm", "path", PACKAGE).strip().startswith(b"package:"):
            raise RuntimeError("acceptance package is not installed")
        self.shell("run-as", PACKAGE, "id", "-u")
        if foreground:
            activity = self.shell("dumpsys", "activity", "activities").decode()
            components = re.findall(r"(?:topResumedActivity|mResumedActivity)[^\n]*?\bu\d+\s+(\S+/\S+)", activity)
            if not components or any(item != PACKAGE + "/" + ACTIVITY for item in components):
                raise RuntimeError("acceptance activity must be in the foreground")

    def private(self, name):
        if name not in ("last-status.json", "last-action.json", "fund-return.json"):
            raise ValueError("unsupported acceptance output")
        return self.read_file("files/" + name)

    def read_file(self, path):
        value = self.shell("run-as", PACKAGE, "sh", "-c",
                           f"if [ -f {path} ]; then head -c 1048577 {path}; else printf null; fi")
        if len(value) > 1024 * 1024:
            raise RuntimeError("private acceptance output exceeds its limit")
        return json.loads(value)

    def account_file(self, relative):
        """Read an allowed journal relative to the candidate's client/state."""
        if relative not in ("buyer/buyer.json", "controller/controller.json", "seller/ledger.json"):
            if not re.fullmatch(r"exports/[A-Za-z0-9_-]{1,32}\.json", relative):
                raise ValueError("unsupported candidate account file")
        self.check()
        return self.read_file("files/client/state/" + relative)

    def ensure_ready(self):
        if (self.root / "pending.json").exists():
            raise RuntimeError("an unresolved phone attempt exists; reconcile it without replay")
        if ((self.root / "funding-intent.json").exists()
                and not (self.root / "funding-staged.json").exists()):
            raise RuntimeError("funding input staging is uncertain; inspect it without overwriting")

    def stage_funds(self, token):
        """Stage one private input; the app's Load test funds button imports it."""
        if not isinstance(token, str) or not 1 <= len(token.encode()) <= 64 * 1024:
            raise ValueError("invalid bounded test token")
        data = json.dumps({"token": token}).encode()
        if len(data) > 70_000:
            raise ValueError("funding input exceeds the app limit")
        with self.locked():
            self.ensure_ready()
            self.check()
            customer = (self.private("last-status.json") or {}).get("customer", {})
            if customer.get("configured") is not True or customer.get("running") is not False:
                raise RuntimeError("candidate must be configured and stopped before staging")
            self.point(LABELS["start"])
            if self.read_file("files/funding.json") is not None:
                raise RuntimeError("candidate funding input already exists")
            intent = {"sha256": hashlib.sha256(data).hexdigest()}
            save(self.root / "funding-intent.json", intent)
            self.check()
            command = ["run-as", PACKAGE, "sh", "-c", "umask 077; set -C; cat > files/funding.json"]
            self.adb("shell", shlex.join(command), data=data)
            if self.read_file("files/funding.json") != {"token": token}:
                raise RuntimeError("funding input is uncertain; inspect the existing file")
            save(self.root / "funding-staged.json", intent)

    def status(self):
        self.check()
        return self.private("last-status.json")

    def action(self):
        self.check()
        return self.private("last-action.json")

    def tree(self):
        path = "/data/local/tmp/fips-acceptance-" + uuid.uuid4().hex + ".xml"
        try:
            self.shell("uiautomator", "dump", path)
            return ElementTree.fromstring(self.shell("cat", path))
        finally:
            self.shell("rm", "-f", path)

    def point(self, label):
        matches = [node for node in self.tree().iter("node")
                   if node.get("text") == label and node.get("enabled") == "true"
                   and node.get("clickable") == "true" and node.get("package") == PACKAGE]
        if len(matches) != 1:
            raise RuntimeError("expected one exact enabled acceptance button")
        bounds = re.fullmatch(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", matches[0].get("bounds", ""))
        if not bounds:
            raise RuntimeError("invalid button bounds")
        left, top, right, bottom = map(int, bounds.groups())
        sizes = re.findall(r"(?:Physical|Override) size: (\d+)x(\d+)", self.shell("wm", "size").decode())
        if not sizes:
            raise RuntimeError("phone display bounds unavailable")
        width, height = map(int, sizes[-1])
        if not 0 <= left < right <= width or not 0 <= top < bottom <= height:
            raise RuntimeError("button is outside the phone display")
        return (left + right) // 2, (top + bottom) // 2

    def begin(self, action, **details):
        self.ensure_ready()
        identifier = uuid.uuid4().hex
        directory = self.root / identifier
        directory.mkdir(mode=0o700)
        intent = {"id": identifier, "action": action, "details": details,
                  "before": self.private("last-status.json"),
                  "previous_marker": self.private("last-action.json")}
        save(directory / "intent.json", intent)
        save(self.root / "pending.json", {"id": identifier})
        old = "files/last-action.json"
        archived = "files/acceptance-prior-" + identifier + ".json"
        self.shell("run-as", PACKAGE, "sh", "-c",
                   f"test ! -e {archived} && {{ if [ -e {old} ]; then mv {old} {archived}; fi; }} && test ! -e {old}")
        if self.private("last-action.json") is not None:
            raise RuntimeError("completion marker changed before the action")
        save(directory / "armed.json", {"marker_archived": True})
        return directory

    def wait(self, directory, timeout):
        intent = json.loads((directory / "intent.json").read_text())
        if not (directory / "armed.json").exists():
            raise RuntimeError("action preparation is uncertain; manual reconciliation required")
        completed = directory / "completed.json"
        deadline = time.monotonic() + timeout
        while True:
            self.check()
            if completed.exists():
                record = json.loads(completed.read_text())
                break
            marker = self.private("last-action.json")
            if marker is not None:
                if marker.get("action") != intent["action"]:
                    raise RuntimeError("unexpected completion; pending attempt retained")
                record = {"result": marker, "after": self.private("last-status.json")}
                if marker.get("ok") is not True:
                    if not (directory / "failed.json").exists():
                        save(directory / "failed.json", record)
                    raise RuntimeError("phone action failed; pending attempt retained for reconciliation")
                save(completed, record)
                break
            if time.monotonic() >= deadline:
                raise TimeoutError("phone action remains unconfirmed; do not repeat the tap")
            time.sleep(min(0.25, max(0, deadline - time.monotonic())))
        (self.root / "pending.json").unlink()
        sync_directory(self.root)
        return record["after"]

    def click(self, label, action, timeout=65):
        timeout = checked_timeout(timeout)
        if LABELS.get(action) != label:
            raise ValueError("label does not match the acceptance app action")
        with self.locked():
            self.check()
            self.ensure_ready()
            point = self.point(label)
            directory = self.begin(action, label=label, point=point)
            self.check()
            self.shell("input", "tap", *(str(value) for value in point))
            return self.wait(directory, timeout)

    def reconcile(self, timeout=10):
        timeout = checked_timeout(timeout)
        with self.locked():
            pending = json.loads((self.root / "pending.json").read_text())
            if not re.fullmatch(r"[0-9a-f]{32}", pending["id"]):
                raise RuntimeError("invalid pending phone identity")
            return self.wait(self.root / pending["id"], timeout)

    def preview(self, arguments, details, timeout):
        timeout = checked_timeout(timeout)
        with self.locked():
            self.check(foreground=False)
            directory = self.begin("preview", **details)
            # Plain launcher starts may only bring an existing task forward.
            # VIEW + SINGLE_TOP delivers onNewIntent to its current instance,
            # which runs the app's read-only preview and writes a fresh marker.
            self.shell("am", "start", "-W", "--activity-single-top", "-n", PACKAGE + "/" + ACTIVITY,
                       "-a", "android.intent.action.VIEW", *arguments)
            return self.wait(directory, timeout)

    def launch(self, timeout=20):
        """Open the acceptance app and observe its fresh read-only preview."""
        return self.preview((), {"launch": True}, timeout)

    def open_setup(self, profile, timeout=20):
        encoded = base64.urlsafe_b64encode(json.dumps(profile).encode()).decode().rstrip("=")
        if len(encoded) > 8192:
            raise ValueError("setup profile exceeds the app limit")
        uri = SCHEME + "://setup?profile=" + encoded
        return self.preview(("-d", uri), {"profile_sha256": hashlib.sha256(encoded.encode()).hexdigest()}, timeout)

    def screenshot(self, label):
        if not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", label):
            raise ValueError("invalid screenshot label")
        self.check()
        data = self.adb("exec-out", "screencap", "-p")
        if not data.startswith(b"\x89PNG\r\n\x1a\n"):
            raise RuntimeError("phone screenshot was not PNG")
        path = self.root / (label + ".png")
        with path.open("xb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
        return path
