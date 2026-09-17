"""Close the original paid channels and collect all isolated test money."""

from __future__ import annotations

from .run_scope import docker, inspect_owned


# A pidfd prevents PID reuse between identity inspection and signaling. This
# script runs only inside an ownership-checked container, never on the host.
STOP_RELAY = """
import os, select, signal
from pathlib import Path

pid = int(Path('/run/bench/process.pid').read_text().strip())
if pid <= 1:
    raise RuntimeError('invalid relay PID')
fd = os.pidfd_open(pid)
try:
    proc = Path('/proc') / str(pid)
    if os.readlink(proc / 'exe') != '/opt/bench/fips-relay':
        raise RuntimeError('recorded PID is not the relay executable')
    expected = b'/opt/bench/fips-relay\\0run\\0/run/bench/config.json\\0'
    if (proc / 'cmdline').read_bytes() != expected:
        raise RuntimeError('recorded PID is not the configured relay service')
    if select.select([fd], [], [], 0)[0]:
        raise RuntimeError('relay exited before orderly shutdown')
    signal.pidfd_send_signal(fd, signal.SIGTERM)
    if not select.select([fd], [], [], 45)[0]:
        raise RuntimeError('relay did not stop within the shutdown bound')
finally:
    os.close(fd)
print('stopped')
"""


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def amount(value):
    require(type(value) is int and value >= 0, "invalid monetary evidence")
    return value


def stop_relay(run, node):
    reference = run.containers[node]
    item = inspect_owned("container", reference, run.name)
    require(item["Id"] == reference, "container identity changed before shutdown")
    require(item["State"]["Running"] is True, "relay container is not running")
    result = docker(["exec", item["Id"], "python3", "-c", STOP_RELAY], timeout=55)
    require(result == "stopped", "relay shutdown was not confirmed")


def original_channels(nodes, finances):
    require(set(nodes) == {"n01", "n02", "n03"} == set(finances),
            "settlement requires the original three accounts")
    owners, operations = {}, set()
    for node in nodes:
        state = finances[node]
        budget = state["budget"]
        funded = 0 if node == "n02" else 32
        require(amount(budget["wallet_debited_sat"]) == amount(budget["locked_sat"])
                == amount(budget["exposure_sat"]) == funded
                and amount(budget["pending_reserved_sat"]) == 0
                and amount(budget["wallet_refunded_sat"]) == 0,
                "original funding budget differs from the fixed fixture")
        require(amount(state["authorized"]) == sum(amount(value) for value in state["signed"].values())
                and amount(state["remaining"]) + state["authorized"] == 64,
                "original buyer budget differs from retained authorization")
        for channel, operation in finances[node]["funding"].values():
            require(isinstance(channel, str) and bool(channel) and channel not in owners,
                    "original funding channel is missing or duplicated")
            require(isinstance(operation, str) and bool(operation) and operation not in operations,
                    "original funding operation is missing or duplicated")
            owners[channel] = node
            operations.add(operation)
        require(set(state["signed"]) == {channel for channel, _ in state["funding"].values()},
                "original authorization differs from funded channels")
    require(len(owners) == 2 and set(owners.values()) == {"n01", "n03"},
            "expected the original two endpoint-funded channels")
    return owners


def validate_report(report):
    fields = ("value_after_stage1_sat", "paid_sat", "receiver_fee_reserve_sat",
              "refunded_sat", "fee_sat")
    values = {key: amount(report[key]) for key in fields}
    require(values["value_after_stage1_sat"] == 32,
            "settlement changed original channel capacity")
    require(values["receiver_fee_reserve_sat"] == values["fee_sat"] == 0,
            "zero-fee fixture lost value to fees or reserves")
    require(values["paid_sat"] + values["refunded_sat"] == 32,
            "settlement does not return the full funded value")
    return {"channel_id": report["channel_id"], **values}


def validate_finances(before, after, reports):
    require(set(before) == set(after), "settlement changed the account set")
    for node, prior in before.items():
        current = after[node]
        require(current["funding"] == prior["funding"],
                "settlement changed original funding identities")
        old, new = prior["budget"], current["budget"]
        require(amount(new["locked_sat"]) == amount(new["pending_reserved_sat"]) == 0,
                "settlement left unresolved capital")
        require(amount(new["wallet_debited_sat"]) == amount(old["wallet_debited_sat"]),
                "settlement changed historical wallet debit")
        refunds = sum(reports[channel]["refunded_sat"] for channel, _ in prior["funding"].values())
        require(amount(old["wallet_refunded_sat"]) == 0
                and amount(new["wallet_refunded_sat"]) == refunds,
                "settlement refund differs from the original channels")
        require(amount(new["exposure_sat"]) == new["wallet_debited_sat"] - refunds,
                "settlement reset lifetime wallet spending")
        require(amount(current["remaining"]) <= amount(prior["remaining"])
                and amount(current["authorized"]) >= amount(prior["authorized"])
                and current["remaining"] + current["authorized"] == 64
                and set(current["signed"]) == set(prior["signed"])
                and sum(amount(value) for value in current["signed"].values()) == current["authorized"],
                "settlement reset the lifetime buyer budget")
        for channel, _ in prior["funding"].values():
            require(amount(current["signed"][channel]) == reports[channel]["paid_sat"],
                    "settled payment differs from retained authorization")


def check_mint(report, collected):
    require(report["test_only"] is True and report["conserved"] is True,
            "isolated mint accounting is not conserved")
    for field in ("issued_sat", "external_funding_sat", "total_accounted_sat"):
        require(amount(report[field]) == 384, "test mint issuance or accounting changed")
    require(amount(report["collected_sat"]) == collected, "test collection is incomplete")


def settle_and_collect(run, prior_finances):
    """Settle once, stop relays, then export/collect once without new funding."""
    owners = original_channels(run.nodes, prior_finances)
    initial = run.execute("mint", "fips-relay-test-mint", "ctl", {"type": "report"})
    check_mint(initial, 0)
    mint = initial["url"]
    reports = {}
    for node in run.nodes:
        result = run.ctl(node, "settle")
        for report in result["settlements"]:
            channel = report["channel_id"]
            require(owners.get(channel) == node and channel not in reports,
                    "settlement returned an unexpected or duplicate channel")
            reports[channel] = validate_report(report)
    require(set(reports) == set(owners), "settlement omitted an original channel")
    settled = run.finances()
    validate_finances(prior_finances, settled, reports)
    for node in run.nodes:
        stop_relay(run, node)

    balances, collections = {}, {}
    for node in run.nodes:
        balance = run.execute(node, "fips-relay", "wallet", {"type": "balance"})
        require(balance["mint_url"] == mint and balance["unit"] == "sat",
                "wallet balance has the wrong scope")
        balances[node] = amount(balance["balance_sat"])
    require(sum(balances.values()) == 384, "settled wallets do not hold all issued money")
    for node, balance in balances.items():
        if balance:
            export_id = f"collect-{node}"
            exported = run.execute(node, "fips-relay", "wallet", {
                "type": "export", "id": export_id, "amount_sat": balance})
            relative = f"exports/{export_id}.json"
            require(exported["path"] == f"/tmp/bench-state/{relative}"
                    and amount(exported["amount_sat"]) == balance,
                    "wallet export changed its reserved terms")
            payment = run.state_json(node, relative)
            require(payment["mint_url"] == mint and payment["unit"] == "sat"
                    and amount(payment["amount_sat"]) == balance
                    and amount(payment["send_fee_sat"]) == 0
                    and isinstance(exported["operation_id"], str) and bool(exported["operation_id"])
                    and payment["operation_id"] == exported["operation_id"],
                    "saved export differs from the zero-fee transfer")
            received = run.execute("mint", "fips-relay-test-mint", "ctl", {
                "type": "collect", "token": payment["token"]})
            require(received["mint_url"] == mint and received["unit"] == "sat"
                    and amount(received["amount_sat"]) == balance,
                    "collector did not redeem the full export")
            collections[node] = balance
        else:
            collections[node] = 0
        empty = run.execute(node, "fips-relay", "wallet", {"type": "balance"})
        require(empty["mint_url"] == mint and empty["unit"] == "sat"
                and amount(empty["balance_sat"]) == 0, "node wallet is not empty")
    final = run.execute("mint", "fips-relay-test-mint", "ctl", {"type": "report"})
    check_mint(final, 384)
    require(final["url"] == mint, "collector mint identity changed")
    # Evidence contains amounts and settlement terms, never bearer tokens.
    run.evidence["phases"].append({"settlement_collection": {
        "settlements": list(reports.values()), "settled_wallet_balances": balances,
        "collected_by_node": collections, "final_wallet_balances": dict.fromkeys(run.nodes, 0),
        "financial": settled,
    }})
    run.evidence["mint"] = {key: final[key] for key in (
        "test_only", "issued_sat", "collected_sat", "external_funding_sat",
        "total_accounted_sat", "conserved")}
