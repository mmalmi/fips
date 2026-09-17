"""Ownership checks for explicitly scoped Docker acceptance runs."""

from __future__ import annotations

import json
import re
import subprocess

RUN_LABEL = "org.fips.chaos.run"


def validate_run_name(value: str) -> str:
    if not re.fullmatch(r"[a-f0-9]{8}", value):
        raise ValueError("run name must be eight lowercase hexadecimal characters")
    return value


def docker(args: list[str], *, data: str | None = None, timeout: int = 30) -> str:
    try:
        result = subprocess.run(
            ["docker", *args], input=data, capture_output=True, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Docker {args[0]} timed out") from None
    if result.returncode:
        # Request bodies may contain test tokens. Never include stdin or stdout.
        raise RuntimeError(f"Docker {args[0]} failed: {result.stderr.strip()[:500]}")
    return result.stdout.strip()


def inspect_owned(kind: str, reference: str, run_name: str) -> dict:
    validate_run_name(run_name)
    item = json.loads(docker([kind, "inspect", reference]))[0]
    labels = item.get("Labels") if kind == "network" else item["Config"].get("Labels")
    if (labels or {}).get(RUN_LABEL) != run_name:
        raise RuntimeError(f"refusing unowned {kind}: {reference}")
    return item


def refuse_name_collision(kind: str, name: str):
    # Listing must succeed; an inspect error could mean a broken Docker daemon.
    names = docker([kind, "ls", "-a", "--format", "{{.Names}}"] if kind == "container"
                   else [kind, "ls", "--format", "{{.Name}}"])
    if name in names.splitlines():
        raise RuntimeError(f"refusing existing {kind}: {name}")


class OwnedResources:
    """Remember exact created IDs; cleanup never sweeps by name or label."""

    def __init__(self, run_name: str):
        self.run_name = validate_run_name(run_name)
        self.created: list[tuple[str, str]] = []

    def remember(self, kind: str, identity: str):
        if not re.fullmatch(r"[a-f0-9]{64}", identity):
            raise RuntimeError("Docker did not return a full resource ID")
        # Creation already returned this exact ID. A failed inspection must not
        # forget it; deletion still requires a fresh ownership-label check.
        self.created.append((kind, identity))
        inspect_owned(kind, identity, self.run_name)

    def cleanup(self) -> list[str]:
        failures = []
        for kind, identity in reversed(self.created):
            try:
                inspect_owned(kind, identity, self.run_name)
                args = [kind, "rm"] + (["--force"] if kind == "container" else [])
                docker([*args, identity])
            except (RuntimeError, subprocess.TimeoutExpired) as error:
                failures.append(str(error))
        return failures
