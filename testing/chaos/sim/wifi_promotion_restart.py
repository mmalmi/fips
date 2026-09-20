"""Full source-process crash at the durable, held promotion boundary."""

import time

from .paid_relay import eventually
from .paid_settlement import require
from .wifi_diamond_checks import counter
from .wifi_measurements import snapshot
from .wifi_promotion_checks import barrier, held_boundary, watch
from .wifi_promotion_finances import journals
from .wifi_remote import digest
from .wifi_restart import crash_profile


SOURCE, PROVIDER, DESTINATION = "n01", "n02", "n03"


def require_restarted(before, after):
    first, last = before["host_process"], after["host_process"]
    require(before["npub"] == after["npub"] and first["host"] == last["host"] == SOURCE
            and counter(last["pid"]) > 1 and counter(first["pid"]) > 1
            and counter(last["start_ticks"]) > counter(first["start_ticks"]),
            "promotion source did not restart with its original identity on the same host")


def source_sample(run):
    run.monitor.check()
    run.check_forwards()
    node = run.nodes[SOURCE]
    sample = snapshot(node, SOURCE, native_counters=True)
    require(sample["npub"] == node.npub
            and list(bytes.fromhex(sample["native"]["status"]["data"]["node_addr"]))
            == node.node_addr, "restarted source changed its native identity")
    return sample


def crash_source(run, evidence, trial, captured, before):
    state = evidence["source_restart"] = {"before": before, "crash_attempted": True,
                                           "started": time.monotonic()}
    run.save()
    node = run.nodes[SOURCE]
    diagnostic = node.output / "last-error.txt"
    prior_error = ((diagnostic.stat().st_mtime_ns, digest(diagnostic.read_bytes()))
                   if diagnostic.exists() else None)
    try:
        state["crash"] = crash_profile(node, before)
    except Exception:
        # Preserve a fresh shared SSH diagnostic before cleanup overwrites it.
        # A concurrently failing management monitor can also write this file.
        try:
            if diagnostic.exists():
                data = diagnostic.read_bytes()
                fingerprint = (diagnostic.stat().st_mtime_ns, digest(data))
                if fingerprint != prior_error:
                    saved = node.output / "process-crash-error.txt"
                    with saved.open("xb") as output:
                        output.write(data)
                    saved.chmod(0o600)
                    state["crash_diagnostic_sha256"] = fingerprint[1]
        except Exception as error:
            state["crash_diagnostic_error"] = type(error).__name__
        raise
    # Read the stopped profile: a controller reload or a crash after normal
    # withdrawal cannot satisfy this exact pending-acceptance boundary.
    status = run.ctl(PROVIDER, "test_accept_barrier_status")
    barrier(status, run.nodes[SOURCE].npub, run.nodes[DESTINATION].npub, held=True)
    raw = journals(run)
    require(held_boundary(status, raw[SOURCE]["controller"], raw[PROVIDER]["controller"],
                          trial, run.nodes[DESTINATION].npub) == captured,
            "source stopped outside the original committed promotion boundary")
    state["stopped_boundary_verified"] = True
    state["pending_offer_id"] = captured["offer_id"]
    run.save()


def restart_source(run, evidence):
    state = evidence["source_restart"]
    require(state["stopped_boundary_verified"], "restart needs the verified stopped promotion boundary")
    state["start_attempted"] = True
    run.save()
    run.nodes[SOURCE].start()
    after = eventually("original source profile restarted", lambda: source_sample(run), 60)
    require_restarted(state["before"], after)
    watch(after, run.nodes[DESTINATION].npub)
    state["after"] = after
    state["completed"] = time.monotonic()
    run.phase("source process restarted from the original pending promotion and Watch")
    return after


def restore_source(run, evidence):
    """Cleanup only: recover control after an uncertain kill or launch reply."""
    state = evidence.get("source_restart")
    if not state or not state.get("crash_attempted"):
        return
    try:
        sample = source_sample(run)
    except RuntimeError:
        # The existing launcher checks the exact profile under its guard lock,
        # so an already dispatched launch cannot create a second candidate.
        state["cleanup_start_attempted"] = True
        run.nodes[SOURCE].start()
        sample = eventually("source control restored for financial closure",
                            lambda: source_sample(run), 60)
    state["cleanup_process"] = sample
