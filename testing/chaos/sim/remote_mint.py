"""One capped, fresh Linux mint shared by phones and routers at the same URL."""

import hashlib
import ipaddress
import json
from pathlib import Path
import re
import shlex

from . import mint_host
from .paid_relay import eventually, write_json
from .ssh_commands import SshCommands
from .wifi_remote import checked_name, checked_path


class RemoteMint(SshCommands):
    def __init__(self, spec, binary, run, root, address, max_issued_sat=512):
        if not re.fullmatch(r"[0-9a-f]{12}", run):
            raise ValueError("invalid mint run identity")
        ip = ipaddress.IPv4Address(address)
        if not ip.is_private or ip.is_loopback or ip.is_unspecified or ip.is_multicast:
            raise ValueError("mint requires an assigned private LAN address")
        if type(max_issued_sat) is not int or not 1 <= max_issued_sat <= 512:
            raise ValueError("phone acceptance issuance is capped at 512 test sats")
        self.spec, self.host = spec, checked_name(spec["host"])
        self.source = Path(binary).resolve(strict=True)
        header = self.source.read_bytes()[:20]
        if header[:6] != b"\x7fELF\x02\x01" or header[18:20] != b"\xb7\x00":
            raise ValueError("mint binary must be Linux ELF64 AArch64")
        self.root = checked_path(spec["state_parent"]) + "/phone-" + run
        self.temporary = "/tmp/fips-mint-" + run
        self.binary = self.temporary + "/fips-relay-test-mint"
        self.config = self.root + "/mint.json"
        self.helper = self.root + "/mint-host.py"
        self.owner = self.root + "/owner.json"
        state = self.root + "/mint-state"
        if len((state + "/control.sock").encode()) > 100:
            raise ValueError("mint control socket path is too long")
        self.settings = {"state_directory": state, "bind": f"{ip}:0",
                         "max_issued_sat": max_issued_sat}
        self.info = {"host": self.host, "binary": self.binary, "config": self.config,
                     "address": str(ip), "binary_sha256": hashlib.sha256(self.source.read_bytes()).hexdigest()}
        self.output = root / "mint-host"
        self.output.mkdir(mode=0o700)
        self.attempted = False
        self.url = None

    def write(self, path, content):
        self.remote("umask 077; set -C; cat > " + shlex.quote(path), content, timeout=90)

    def start(self):
        if self.attempted:
            raise RuntimeError("mint start was already attempted; inspect it instead of retrying")
        self.attempted = True
        write_json(self.output / "intent.json", self.info)
        # No service/network configuration changes; refuse another host/address.
        if self.remote(["uname", "-m"]).strip() != b"aarch64":
            raise RuntimeError("mint host is not AArch64 Linux")
        addresses = json.loads(self.remote(["ip", "-j", "-4", "addr", "show"]))
        if not any(item.get("local") == self.info["address"]
                   for link in addresses for item in link.get("addr_info", [])):
            raise RuntimeError("mint address is not assigned to the explicit host")
        self.remote(["python3", "-c", "import os,signal; assert hasattr(os,'pidfd_open') and hasattr(signal,'pidfd_send_signal')"])
        self.remote(f"umask 077; set -eu; mkdir -p {checked_path(self.spec['state_parent'])}; "
                    f"mkdir {self.root}; mkdir {self.temporary}")
        self.write(self.binary, self.source.read_bytes())
        self.remote(["chmod", "700", self.binary])
        config = json.dumps(self.settings).encode()
        self.info["config_sha256"] = hashlib.sha256(config).hexdigest()
        self.write(self.config, config)
        self.write(self.owner, json.dumps(self.info).encode())
        self.write(self.helper, Path(mint_host.__file__).read_bytes())
        # The supervisor owns the child and records its real exit status. Its
        # persistent launch record rejects a restart even after process loss.
        self.remote(f"nohup python3 {self.helper} serve {self.owner} "
                    f">{self.root}/supervisor.log 2>&1 </dev/null &")
        report = eventually("shared test mint readiness", lambda: self.request({"type": "report"}), 60)
        if report["issued_sat"] != 0 or report["collected_sat"] != 0 or report["conserved"] is not True:
            raise RuntimeError("shared test mint did not start fresh")
        self.url = report["url"]
        write_json(self.output / "ready.json", report)
        return self.url

    def request(self, body):
        return json.loads(self.remote(["python3", self.helper, "request", self.owner],
                                      json.dumps(body).encode(), timeout=100))

    def grant(self, name):
        payment = self.request({"type": "issue", "id": name, "amount_sat": 128})
        return payment["token"]

    def finish(self):
        result = json.loads(self.remote(["python3", self.helper, "finish", self.owner], timeout=120))
        if result.get("url") != self.url:
            raise RuntimeError("terminal mint URL differs from the pinned run")
        return result
