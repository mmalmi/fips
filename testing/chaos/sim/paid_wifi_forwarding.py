"""Owned SSH forwards for one test mint, retained with uncertain test funds."""

import json
import subprocess
from urllib.parse import urlsplit

from .paid_relay import eventually


LOOPBACKS = {"0100007F", "00000000000000000000000001000000"}


def finish_mint(run):
    """Clean up owned mint access, recording failure without masking router errors."""
    try:
        if run.forwards is not None:
            report = run.mint.request({"type": "report"})
            result = run.forwards.finish(report)
            run.evidence["mint_forward_cleanup"] = result
            if result.get("retained_for_recovery"):
                raise RuntimeError("outstanding test funds require the original mint forwards")
        result = run.mint.finish()
        run.evidence["mint_cleanup"] = result
        if result.get("retained_for_recovery"):
            run.evidence["passed"] = False
    except Exception as error:
        if run.forwards is not None:
            run.forwards.retain(type(error).__name__)
        run.evidence["mint_cleanup_error"] = type(error).__name__
        run.evidence["mint_retained_for_recovery"] = run.mint.info
        run.evidence["passed"] = False
    run.save()


def listeners(node, port):
    """OpenWrt exposes both address families in the kernel's native hex form."""
    rows = node.remote(["cat", "/proc/net/tcp", "/proc/net/tcp6"]).decode().splitlines()
    found = []
    for row in rows:
        fields = row.split()
        if not fields or fields[0] == "sl":
            continue
        address, number = fields[1].split(":")
        if fields[3] == "0A" and int(number, 16) == port:
            found.append(address.upper())
    return sorted(found)


class MintForwards:
    def __init__(self, nodes, url, root):
        parsed = urlsplit(url)
        if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or not parsed.port
                or parsed.username or parsed.password or parsed.path not in ("", "/")
                or parsed.query or parsed.fragment):
            raise ValueError("SSH mint forwarding requires an allocated IPv4 loopback URL")
        self.nodes, self.url, self.port, self.root = nodes, url.rstrip("/"), parsed.port, root
        self.children = {}
        self.info = {"url": self.url, "children": {}, "verified_before_issuance": False}
        self.record()

    def record(self):
        temporary = self.root / "mint-forwards.json.new"
        temporary.write_text(json.dumps(self.info, indent=2) + "\n")
        temporary.replace(self.root / "mint-forwards.json")

    def start(self):
        # Refuse collisions everywhere before creating any remote listener.
        for node in self.nodes.values():
            if listeners(node, self.port):
                raise RuntimeError("mint forward port already has a router listener")
        for name, node in self.nodes.items():
            args = node.ssh_args() + [
                "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "ControlPersist=no",
                "-o", "ExitOnForwardFailure=yes", "-o", "ServerAliveInterval=5",
                "-o", "ServerAliveCountMax=3", "-o", "ConnectionAttempts=1",
                "-o", "ForkAfterAuthentication=no", "-o", "PermitLocalCommand=no",
                "-o", "ForwardAgent=no", "-o", "ForwardX11=no", "-N", "-T"]
            effective = subprocess.run([*args, "-G", node.host], capture_output=True, timeout=10)
            if effective.returncode or any(row.split()[0] in ("localforward", "remoteforward", "dynamicforward")
                                           for row in effective.stdout.decode().splitlines() if row.split()):
                raise RuntimeError("mint SSH inventory has another forwarding rule or cannot be resolved")
            args += ["-R", f"127.0.0.1:{self.port}:127.0.0.1:{self.port}", node.host]
            with (self.root / f"mint-forward-{name}.log").open("xb") as log:
                child = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                         start_new_session=True)
            self.children[name] = child
            self.info["children"][name] = {"pid": child.pid, "argv": args}
            self.record()
        eventually("all private mint forwards", self.verify, 30)
        self.info["verified_before_issuance"] = True
        self.record()

    def check(self):
        if len(self.children) != len(self.nodes) or any(p.poll() is not None for p in self.children.values()):
            raise ValueError("an owned mint SSH forward exited; never replace it during a funded run")

    def retain(self, reason):
        self.info.update(retained_for_recovery=True, recovery_reason=reason)
        self.record()

    def verify(self):
        self.check()
        observations = {}
        for name, node in self.nodes.items():
            bound = listeners(node, self.port)
            if not bound:
                return False
            if "0100007F" not in bound or any(address not in LOOPBACKS for address in bound):
                raise ValueError("mint SSH forward is not exclusively loopback-bound")
            response = json.loads(node.remote(["uclient-fetch", "-q", "-T", "5", "-O", "-",
                                              self.url + "/v1/info"], timeout=10))
            if not isinstance(response, dict) or not response:
                raise ValueError("mint info response is missing")
            observations[name] = {"listeners": bound, "info_reachable": True}
        self.check()
        self.info["observations"] = observations
        return True

    def finish(self, report):
        if (report.get("conserved") is not True
                or report["issued_sat"] != report["collected_sat"]):
            self.retain("test funds are not fully conserved and collected")
            return self.info
        # Kill only our non-multiplexed Popen children. A failed stop or an
        # occupied remote port retains the mint and any remaining owned forwards.
        for name, child in self.children.items():
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=20)
            self.info["children"][name]["exit_code"] = child.returncode
            self.record()
            eventually("owned mint listener removal", lambda:
                       not listeners(self.nodes[name], self.port), 15)
        self.info.update(retained_for_recovery=False, stopped=True)
        self.record()
        return self.info
