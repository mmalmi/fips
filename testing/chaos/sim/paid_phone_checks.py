"""Explicit scenario boundaries and read-only phone network/account evidence."""

import ipaddress
import json
from pathlib import Path
import re
import shlex
import subprocess
from urllib.parse import urlsplit

from .paid_settlement import require
from .phone_customer import acceptance_identity, save
from .wifi_remote import checked_name


ORIGINAL_PACKAGE = "org.fips.relaybench"


def scenario(path, *, transit=False):
    value = json.loads(Path(path).read_text())
    require(value.get("version") == 1, "unsupported phone scenario version")
    phone, customer, mint = (value[key] for key in ("phone", "customer", "mint"))
    acceptance_identity(phone.get("instance"))
    require(all(isinstance(phone.get(key), str) and phone[key] for key in
                ("adb", "serial", "evidence_dir")), "phone identity and private evidence are required")
    require(Path(phone["adb"]).is_absolute() and Path(phone["evidence_dir"]).is_absolute(),
            "phone tool and evidence paths must be explicit absolute paths")
    require(re.fullmatch(r"[0-9a-f]{64}", phone.get("apk_sha256", "")) is not None,
            "the verified acceptance APK hash is required")
    checked_name(customer["interface"])
    guest = ipaddress.IPv4Interface(customer["cidr"])
    require(guest.ip.is_private and not guest.ip.is_loopback
            and guest.ip not in (guest.network.network_address, guest.network.broadcast_address),
            "customer network needs an explicit private router address")
    require(type(customer["entry_port"]) is int and 1024 <= customer["entry_port"] <= 65535,
            "invalid customer entry port")
    require(isinstance(customer["ssid"], str) and 1 <= len(customer["ssid"]) <= 32,
            "operator-selected customer SSID is required")
    if transit:
        addresses = value.get('router_addresses', {})
        require(set(addresses) == {'n01', 'n02', 'n03'} and len(set(addresses.values())) == 3,
                'transit requires three explicit distinct router addresses')
        require(all(ipaddress.IPv4Address(address) in guest.network
                    and ipaddress.IPv4Address(address) not in
                    (guest.network.network_address, guest.network.broadcast_address)
                    for address in addresses.values()) and addresses['n01'] == str(guest.ip),
                'transit routers must share the existing phone LAN')
        require(not customer.get('denied_tcp'), 'LAN transit does not test customer isolation')
    denied = customer.get("denied_tcp", [])
    require(isinstance(denied, list) and (transit or 1 <= len(denied) <= 4),
            "provide one to four explicit denied targets")
    labels, endpoints = set(), set()
    for target in denied:
        label, address, port = target["label"], ipaddress.IPv4Address(target["address"]), target["port"]
        require(re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,31}", label) is not None
                and label not in ("shared_mint", "shared_mint_after") and label not in labels,
                "invalid or duplicate network probe label")
        require(not address.is_loopback and not address.is_unspecified and not address.is_multicast
                and type(port) is int and 1 <= port <= 65535
                and (str(address), port) not in endpoints, "invalid or duplicate denied endpoint")
        labels.add(label)
        endpoints.add((str(address), port))
    require(isinstance(mint["ssh_spec"], dict), "explicit mint SSH inventory is required")
    ipaddress.IPv4Address(mint["address"])
    return value


def guest_source(phone, customer):
    """Observe the operator's selection; never change the phone Wi-Fi network."""
    phone.check()
    state = phone.shell("cmd", "wifi", "status").decode()
    match = re.search(r"IP: /(\d+\.\d+\.\d+\.\d+)", state)
    require('SSID: "' + customer["ssid"] + '"' in state and match is not None,
            "phone is not on the explicit customer Wi-Fi")
    source = ipaddress.IPv4Address(match[1])
    guest = ipaddress.IPv4Interface(customer["cidr"])
    require(source in guest.network and source not in
            (guest.ip, guest.network.network_address, guest.network.broadcast_address),
            "phone does not have a usable customer address")
    return str(source), state


def original_hashes(phone):
    # Do not hide find/sha256sum failures behind a final successful sort process.
    command = ("set -eu; files=$(find files -type f); test -n \"$files\"; "
               "printf '%s\\n' \"$files\" | while IFS= read -r file; do sha256sum \"$file\" || exit; done")
    installed = phone.shell('pm', 'list', 'packages', ORIGINAL_PACKAGE).decode().splitlines()
    pattern = re.escape(ORIGINAL_PACKAGE) + r'(?:\.acceptance(?:\.[a-z][a-z0-9]{0,23})?)?'
    require(all(row.startswith('package:') and re.fullmatch(pattern, row[8:]) for row in installed),
            'unexpected bench package inventory')
    packages = sorted(row[8:] for row in installed if row[8:] != phone.package)
    require(len(packages) == len(set(packages)) and ORIGINAL_PACKAGE in packages,
            'original bench account is missing or ambiguous')
    return b"".join(package.encode() + b"\n" + _account_hashes(phone, package, command)
                    for package in packages)


def _account_hashes(phone, package, command):
    data = phone.shell("run-as", package, "sh", "-c", command)
    rows = data.splitlines()
    require(bool(rows) and all(re.fullmatch(rb"[0-9a-f]{64}  files/.+", row) for row in rows),
            "original account hashes missing or malformed")
    paths = [row[66:] for row in rows]
    require(len(paths) == len(set(paths)), "original account hash paths are duplicated")
    return b"\n".join(sorted(rows)) + b"\n"


def installed_apk_hash(phone, expected):
    paths = phone.shell("pm", "path", phone.package).decode().splitlines()
    require(len(paths) == 1 and paths[0].startswith("package:/"),
            "acceptance needs the explicit single debug APK")
    path = paths[0][len("package:"):]
    actual = phone.shell("sha256sum", path).decode().split()
    require(len(actual) == 2 and actual[0] == expected and actual[1] == path,
            "installed acceptance APK differs from the verified artifact")
    return actual[0]


def probe_result(result):
    """A failed adb/tool/bind operation is unknown, never a denied connection."""
    marker = re.fullmatch(rb"FIPS_PROBE_EXIT=([0-9]+)\r?\n", result.stdout)
    require(result.returncode == 0 and marker is not None, "phone TCP probe completion is uncertain")
    code = int(marker[1])
    error = result.stderr.decode(errors="replace")
    require(code == 0 or (code == 1 and any(reason in error for reason in
            ("Connection refused", "Connection timed out", "Network is unreachable", "No route to host"))),
            "phone TCP probe failed outside its network connection")
    return code == 0


def check_customer_access(phone, customer, mint_url, output):
    source, _ = guest_source(phone, customer)
    mint = urlsplit(mint_url)
    allowed = {"label": "shared_mint", "address": mint.hostname, "port": mint.port}
    require(all((row["address"], row["port"]) != (mint.hostname, mint.port)
                for row in customer["denied_tcp"]), "denied target matches the allowed mint")
    checks = []
    for target in [allowed, *customer["denied_tcp"], {**allowed, "label": "shared_mint_after"}]:
        expected = target["label"] in ("shared_mint", "shared_mint_after")
        command = ["toybox", "nc", "-4", "-n", "-z", "-s", source, "-w", "2",
                   target["address"], str(target["port"])]
        script = shlex.join(command) + '; nc_code=$?; printf "FIPS_PROBE_EXIT=%s\\n" "$nc_code"; exit 0'
        phone.check()
        result = subprocess.run([str(phone.adb_path), "-s", phone.serial, "shell", script],
                                capture_output=True, timeout=8)
        save(output / ("network-" + target["label"] + ".json"), {
            "adb_exit": result.returncode, "stdout": result.stdout.decode(errors="replace"),
            "stderr": result.stderr.decode(errors="replace")})
        connected = probe_result(result)
        require(connected == expected, "customer TCP access differs for " + target["label"])
        checks.append({"target": target["label"], "connected": connected, "expected": expected})
    return checks
