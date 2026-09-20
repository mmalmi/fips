"""One live middle-radio withdrawal while its real full acceptance is held."""

import signal
import time

from . import wifi_probes as probes
from .paid_relay import PaidRelayRun, eventually
from .paid_settlement import require
from .wifi_diamond_checks import require_same_process
from .wifi_diamond_selection import FULL_QUOTA, POLICY, paid_channel_progress
from .wifi_measurements import snapshot
from .wifi_priority_checks import submitted
from .wifi_promotion_checks import (
    CEILING, HOLD_MS, barrier, held_boundary, purchase, quality, watch, withdrawn,
)
from .wifi_promotion_finances import PromotionAccounts
from .wifi_promotion_restart import crash_source, restart_source, restore_source
from .wifi_remote import checked_path


SOURCE, PROVIDER, DESTINATION = "n01", "n02", "n03"


def process_samples(run, prior=None):
    samples = {}
    for name, node in run.nodes.items():
        run.monitor.check()
        run.check_forwards()
        sample = snapshot(node, name, native_counters=True)
        native = sample["native"]["status"]["data"]
        address = list(bytes.fromhex(native["node_addr"]))
        require(len(address) == 16 and native["npub"] == node.npub,
                "promotion native identity differs from prepared profile")
        node.node_addr = address
        if prior is not None:
            require_same_process(prior[name], sample)
        samples[name] = sample
    return samples


def barrier_status(run, *, held=False):
    status = run.ctl(PROVIDER, "test_accept_barrier_status")
    barrier(status, run.nodes[SOURCE].npub, run.nodes[DESTINATION].npub, held=held)
    return status


def route_quality(run):
    return run.ctl(SOURCE, "route_quality", destination=run.nodes[DESTINATION].npub)


def fresh_burst(run, evidence, label):
    shape = probes.arm(run, SOURCE, DESTINATION, 8, 128, round_trip=True)
    row = {"label": label, "shape": shape, "started": time.monotonic()}
    evidence.setdefault("bursts", []).append(row)
    run.save()  # One finite submission, including an uncertain sender response.
    row["sender"] = probes.send(run, SOURCE, DESTINATION, shape, 8, round_trip=True)
    submitted(row["sender"], shape)
    until = time.monotonic() + 1
    while True:
        row["receiver"] = probes.receive(run, SOURCE, DESTINATION, shape, round_trip=True)
        if row["receiver"]["unique_packets"] == shape["packet_count"] or time.monotonic() >= until:
            break
        time.sleep(0.1)
    row["completed"] = time.monotonic()
    run.save()
    return row


def qualify(run, evidence, trial):
    destination = run.nodes[DESTINATION].npub
    deadline, delivered = time.monotonic() + 30, 0
    for _ in range(8):
        require(time.monotonic() < deadline, "promotion warmup exceeded its finite deadline")
        row = fresh_burst(run, evidence, "trial warmup")
        delivered += row["receiver"]["unique_packets"]
        observed = route_quality(run)
        row["quality"] = observed
        status = barrier_status(run)
        row["barrier"] = status
        if delivered >= 8 and quality(observed, destination, trial["provider"], working=True):
            evidence["qualified_trial"] = {"quality": observed, "delivered_replies": delivered}
            run.save()
            return
        require(status["captured"] is None,
                "full promotion overtook the explicit native-quality observation")
    raise RuntimeError("bounded trial did not gain real qualifying native feedback")


def await_commit(run, accounts, evidence, trial):
    destination = run.nodes[DESTINATION].npub

    def captured():
        status = barrier_status(run)
        if status["held_responses"] == 0:
            return None
        barrier(status, run.nodes[SOURCE].npub, destination, held=True)
        raw, summary, _ = accounts.observe()
        record = held_boundary(status, raw[SOURCE]["controller"], raw[PROVIDER]["controller"],
                               trial, destination)
        accounts.anchor_trial(trial, raw)
        accounts.check(raw, summary)
        evidence["held_commit"] = {"barrier": status, **accounts.evidence(raw, summary)}
        return record

    result = eventually("real held full promotion with retired trial", captured, 25)
    run.phase("real full provider commitment held; original partly consumed trial retired")
    return result


def idle(run, evidence, provider):
    started = time.monotonic()
    rows = evidence["idle_quality"] = []
    while True:
        observed = route_quality(run)
        quality(observed, run.nodes[DESTINATION].npub, provider)
        rows.append({"at": time.monotonic(), "quality": observed})
        barrier_status(run, held=True)
        if time.monotonic() - started >= POLICY["feedback_timeout_ms"] / 1000:
            break
        time.sleep(0.5)
    evidence["idle_started"] = started
    evidence["idle_completed"] = time.monotonic()
    run.save()


def release(run, evidence, captured):
    before = barrier_status(run, held=True)
    evidence["before_release"] = before
    reply = run.ctl(PROVIDER, "test_accept_barrier_release")
    evidence["release"] = reply
    run.save()
    require(reply["active"] is False and reply["terminal_reason"] == "released"
            and reply["held_responses"] == 0 and reply["captured"] == captured
            and (reply["forwarded_replies"] + reply["closed_responders"]
                 - before["forwarded_replies"] - before["closed_responders"]) >= before["held_responses"],
            "stale acceptance release lost its original committed evidence")
    evidence["release_verified"] = True


def recover(run, accounts, evidence, trial, captured):
    destination, provider = run.nodes[DESTINATION].npub, trial["provider"]
    quality(route_quality(run), destination, provider, unknown=True)
    deadline = time.monotonic() + 120
    for index in range(16):
        require(time.monotonic() < deadline, "finite promotion recovery workload expired")
        started = time.monotonic()
        raw, before_money, _ = eventually("coherent promotion recovery accounts", accounts.observe, 15)
        before = run.ctl(SOURCE, "status")
        watch(before, destination)
        current = purchase(before, run.nodes[DESTINATION].node_addr, provider,
                           trial_quota=POLICY["trial_max_units"] - accounts.used)
        require(current is None or current["contract"]["id"] != captured["purchase"]["contract"]["id"],
                "stale withdrawn full acceptance became an active source route")
        row = fresh_burst(run, evidence, "automatic full recovery")
        observed = route_quality(run)
        after = run.ctl(SOURCE, "status")
        watch(after, destination)
        final = purchase(after, run.nodes[DESTINATION].node_addr, provider,
                         trial_quota=POLICY["trial_max_units"] - accounts.used)
        require(final is None or final["contract"]["id"] != captured["purchase"]["contract"]["id"],
                "stale withdrawn full acceptance became an active source route")
        row.update(before_purchase=current, after_purchase=final, quality=observed)
        if (current is not None and current == final and current["contract"]["max_units"] == FULL_QUOTA
                and current["contract"]["id"] not in (trial["contract"]["id"], captured["purchase"]["contract"]["id"])
                and row["receiver"]["unique_packets"] == row["shape"]["packet_count"]
                and quality(observed, destination, provider, working=True)):
            channel = current["channel"]["id"]
            prior_sat = before_money[SOURCE]["signed"].get(channel, 0)

            def credited():
                current_status = run.ctl(SOURCE, "status")
                watch(current_status, destination)
                require(purchase(current_status, run.nodes[DESTINATION].node_addr, provider,
                        trial_quota=POLICY["trial_max_units"] - accounts.used) == current,
                        "fresh recovered payload agreement changed during payment observation")
                latest_raw, money, _ = accounts.observe()
                if (paid_channel_progress(current_status, channel, prior_sat)
                        and money[PROVIDER]["credited"].get(channel, 0)
                        >= current_status["payment_progress"][channel]["authorized_sat"] * 1000):
                    return {"status": current_status, **accounts.evidence(latest_raw, money)}
                return None

            row["credited"] = eventually("automatic acknowledged payment for fresh full-route replies", credited, 20)
            evidence["recovered_purchase"] = current
            evidence["accepted_burst_index"] = len(evidence["bursts"]) - 1
            run.phase("same Watch delivers fresh full-route replies and pays automatically")
            return
        run.save()
        if index < 15:
            time.sleep(max(0, 5 - (time.monotonic() - started)))
    raise RuntimeError("same Watch did not automatically recover a working paid full route")



def restore_radio(radio):
    # mesh_up requires a marker which a successful but lost reply may have removed.
    # Observe the owned profile under the existing lease lock before rejoining it.
    restore = ("original_isolated; open_profile; "
               "if open_joined; then open_limited; else open_resume; fi"
               if radio.open_mesh else "mesh_restore")
    radio.guarded(f"{restore}; rm -f {checked_path(radio.temporary)}/mesh-down", timeout=60)


def finish_promotion(run, accounts, evidence, captured):
    cleanup = evidence["cleanup"] = {"errors": [], "collected": False,
                                     "accounts_retained_for_recovery": True}
    evidence["passed"] = False

    def attempt(stage, action):
        try:
            action()
            return True
        except Exception as error:
            cleanup["errors"].append({"stage": stage, "error": type(error).__name__})
            return False

    def release_remaining():
        if not evidence.get("arm_attempted") or evidence.get("release_verified"):
            return
        reply = run.ctl(PROVIDER, "test_accept_barrier_release")
        cleanup["barrier_release"] = reply
        require(reply["active"] is False and reply["held_responses"] == 0,
                "cleanup has not verified barrier quiescence")
        if reply["armed"]:
            require(reply["buyer"] == run.nodes[SOURCE].npub
                    and reply["destination"] == run.nodes[DESTINATION].npub
                    and reply["trial_max_units"] == POLICY["trial_max_units"]
                    and reply["hold_ms"] == HOLD_MS,
                    "cleanup barrier identity changed")
        if captured is not None:
            require(reply["captured"] == captured, "cleanup lost the original committed acceptance")

    def restored():
        radio = run.nodes[PROVIDER]
        profile = ("original_isolated; open_profile; open_joined; open_limited"
                   if radio.open_mesh else "mesh_profile; mesh_joined")
        radio.guarded(profile)
        cleanup["restored_peers"] = eventually("native line restored before financial closure",
                                               lambda: run.ready(line=True), 150)
        run.verify_open_profiles()

    # Each attempt is independent. In particular, evidence I/O or a failed pause
    # must not prevent releasing held bytes or restoring an owned radio.
    cleanup["source_control_restored"] = attempt("source_control", lambda: restore_source(run, evidence))
    cleanup["authority_paused"] = attempt("pause", accounts.pause)
    cleanup["barrier_quiescent"] = attempt("barrier_release", release_remaining)
    if evidence.get("cut_attempted"):
        cleanup["radio_restore_attempted"] = True
        attempt("save_before_restore", run.save)
        attempt("radio_restore", lambda: restore_radio(run.nodes[PROVIDER]))
    cleanup["connectivity_verified"] = attempt("connectivity", restored)
    if all(cleanup[key] for key in ("source_control_restored", "authority_paused",
                                   "barrier_quiescent", "connectivity_verified")):
        cleanup["collected"] = attempt("collection", accounts.collect)
        cleanup["accounts_retained_for_recovery"] = not cleanup["collected"]
    if not cleanup["errors"] and cleanup["collected"]:
        evidence["passed"] = evidence.get("recovery_passed", False)
    if not attempt("save_after_cleanup", run.save):
        evidence["passed"] = False
    if cleanup["errors"]:
        raise RuntimeError("promotion cleanup incomplete; inspect retained cleanup evidence")


def exercise(run):
    restart = getattr(run.args, "promotion_restart_source", False) is True
    evidence = {"passed": False, "live_only": not restart, "performance_comparable": False,
                "source_restart_requested": restart}
    run.evidence["interrupted_promotion"] = evidence
    run.form_line()
    discovered = run.assert_finances()
    PaidRelayRun.unpaid_probe(run, discovered)
    samples = evidence["processes_before"] = process_samples(run)
    available = run.ctl(PROVIDER, "test_accept_barrier_status")
    require(available["armed"] is False and available["active"] is False
            and available["captured"] is None, "fresh testbench acceptance barrier required")
    accounts = PromotionAccounts(run, {name: node.node_addr for name, node in run.nodes.items()})
    run.promotion_accounts = accounts
    radio = run.nodes[PROVIDER]
    captured = None
    try:
        # Ordinary reverse authorization carries real receiver feedback and replies.
        evidence["reverse_purchase"] = run.ctl(DESTINATION, "buy", destination=run.nodes[SOURCE].npub)
        evidence["arm_started"] = time.monotonic()
        evidence["arm_attempted"] = True
        run.save()
        evidence["armed"] = run.ctl(PROVIDER, "test_accept_barrier_arm", buyer=run.nodes[SOURCE].npub,
            destination=run.nodes[DESTINATION].npub, trial_max_units=POLICY["trial_max_units"], hold_ms=HOLD_MS)
        barrier(evidence["armed"], run.nodes[SOURCE].npub, run.nodes[DESTINATION].npub)
        accounts.watch_started = True
        evidence["watch_attempted"] = True
        run.save()
        opened = run.ctl(SOURCE, "watch", destination=run.nodes[DESTINATION].npub,
                         max_rate_msat_per_kib=CEILING)
        trial = opened["purchase"]
        require(trial["contract"]["max_units"] == POLICY["trial_max_units"],
                "one original Watch did not begin with the production trial")
        evidence["trial"] = trial
        qualify(run, evidence, trial)
        captured = await_commit(run, accounts, evidence, trial)
        idle(run, evidence, trial["provider"])
        require(time.monotonic() - evidence["arm_started"] < HOLD_MS / 1000 - 105,
                "barrier has insufficient remaining hold time for bounded native eviction")
        evidence["pre_cut_processes"] = process_samples(run, samples)
        barrier_status(run, held=True)
        if restart:
            crash_source(run, evidence, trial, captured, samples[SOURCE])
        evidence["cut_started"] = time.monotonic()
        run.save()
        evidence["cut_attempted"] = True
        radio.mesh_down()
        evidence["cut_completed"] = time.monotonic()
        if restart:
            samples = {**samples, SOURCE: restart_source(run, evidence)}
        evidence["isolated_peers"] = eventually("middle departure removes both native adjacencies",
            lambda: run.ready(line=True, isolated=True, outage_node=PROVIDER), 100)

        def withdrawal():
            barrier_status(run, held=True)
            raw, summary, _ = accounts.observe()
            if withdrawn(raw[SOURCE]["controller"], captured, run.nodes[DESTINATION].npub):
                observed = route_quality(run)
                quality(observed, run.nodes[DESTINATION].npub, trial["provider"], unknown=True)
                return {"quality": observed, **accounts.evidence(raw, summary)}
            return None

        evidence["withdrawn"] = eventually("normal Watch withdrawal of the held full offer", withdrawal, 20)
        evidence["withdrawal_observed"] = time.monotonic()
        release(run, evidence, captured)
        evidence["rejoin_attempted"] = True
        run.save()
        radio.mesh_up()
        evidence["rejoin_completed"] = time.monotonic()
        evidence["rejoined_peers"] = eventually("same middle process rejoins native line",
            lambda: run.ready(line=True), 150)
        run.verify_open_profiles()
        recover(run, accounts, evidence, trial, captured)
        evidence["processes_after"] = process_samples(run, samples)
        run.verify_shortcuts()
        evidence["recovery_passed"] = True
        run.save()
    except Exception as error:
        evidence["acceptance_failure"] = type(error).__name__ + ": " + str(error)
        run.save()
        raise
    finally:
        signal.alarm(0)
        finish_promotion(run, accounts, evidence, captured)
