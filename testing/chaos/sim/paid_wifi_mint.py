"""Own one local test mint; preserve it when test funds remain outstanding."""

import hashlib
import ipaddress
import json
from pathlib import Path
import subprocess

from .paid_relay import eventually, write_json


class LocalMint:
    def __init__(self, binary, address, root):
        self.binary = binary.resolve(strict=True)
        ip = ipaddress.ip_address(address)
        if not ip.is_private or ip.is_unspecified or ip.is_multicast:
            raise ValueError("test mint needs an assigned private or loopback address")
        self.root = root
        self.state = root / "mint-state"
        self.config = root / "mint.json"
        if len(str(self.state / "control.sock").encode()) > 100:
            raise ValueError("use a shorter output path for the private mint socket")
        self.bind = f"[{ip}]:0" if ip.version == 6 else f"{ip}:0"
        self.process = None
        self.info = {"binary_sha256": hashlib.sha256(self.binary.read_bytes()).hexdigest(),
                     "config": str(self.config), "state_directory": str(self.state)}

    def start(self):
        write_json(self.config, {"state_directory": str(self.state), "bind": self.bind,
                                 "max_issued_sat": 384})
        with (self.root / "mint.log").open("xb") as log:
            self.process = subprocess.Popen([str(self.binary), "run", str(self.config)],
                                            stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                            start_new_session=True)
        self.info["pid"] = self.process.pid
        write_json(self.root / "mint-process.json", self.info)
        report = eventually("local test mint startup", lambda: self.request({"type": "report"}), 60)
        if report["test_only"] is not True or report["issued_sat"] != 0 or not report["conserved"]:
            raise RuntimeError("mint did not start with fresh, conserved test accounts")
        self.info["url"] = report["url"]
        return report["url"]

    def request(self, body):
        if self.process.poll() is not None:
            raise RuntimeError("the owned test mint exited; never replace it during a funded run")
        result = subprocess.run([str(self.binary), "ctl", str(self.config)],
                                input=json.dumps(body).encode(), capture_output=True, timeout=90)
        if result.returncode:
            (self.root / "mint-last-error.txt").write_bytes(result.stderr + b"\n" + result.stdout)
            raise RuntimeError("test mint request failed; private error retained")
        return json.loads(result.stdout)

    def grant(self, name):
        # Issue is deliberately not automatically retried after an uncertain result.
        result = self.request({"type": "issue", "id": name, "amount_sat": 128})
        payment = json.loads((self.state / "exports" / f"{name}.json").read_text())
        if result["amount_sat"] != 128 or payment["amount_sat"] != 128:
            raise RuntimeError("test grant amount differs from the fixed fixture")
        return payment["token"]

    def finish(self):
        if self.process is None:
            return {"started": False}
        report = self.request({"type": "report"})
        if not report["conserved"] or report["issued_sat"] != report["collected_sat"]:
            # Simulated Lightning state lives in this process. Keep it and all
            # account/export evidence available for deliberate reconciliation.
            return {"retained_for_recovery": True, **self.info,
                    "issued_sat": report["issued_sat"], "collected_sat": report["collected_sat"]}
        self.process.terminate()
        self.process.wait(timeout=20)
        if self.process.returncode != 0:
            raise RuntimeError("the collected test mint did not stop cleanly")
        return {"retained_for_recovery": False, "stopped": True,
                "issued_sat": report["issued_sat"], "collected_sat": report["collected_sat"]}
