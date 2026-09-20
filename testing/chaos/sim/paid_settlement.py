"""Close the original paid channels and collect all isolated test money."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

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


@dataclass(frozen=True)
class SettlementFixture:
    """Explicit, acknowledged accounts and channels; never discover funding here.

    The caller verifies raw funding terms and rejects unresolved intents before
    freezing channel ownership; a financial summary alone cannot establish this.
    Optional provider identities also require exact per-wallet conservation.
    """

    initial_balances: Mapping[str, int]
    buyer_budgets: Mapping[str, int]
    channel_capacity_sat: int
    channel_owners: Mapping[str, str]
    channel_providers: Mapping[str, str] | None = None

    def __post_init__(self):
        for field in ("initial_balances", "buyer_budgets", "channel_owners", "channel_providers"):
            value = getattr(self, field)
            if field == "channel_providers" and value is None:
                continue
            require(isinstance(value, Mapping), "fixture policy requires explicit mappings")
            object.__setattr__(self, field, MappingProxyType(dict(value)))
        accounts = set(self.initial_balances)
        require(accounts and accounts == set(self.buyer_budgets)
                and all(isinstance(name, str) and name for name in accounts),
                "fixture account or buyer-budget set differs")
        require(sum(amount(value) for value in self.initial_balances.values()) > 0
                and all(amount(value) > 0 for value in self.buyer_budgets.values())
                and amount(self.channel_capacity_sat) > 0, "invalid fixture amount or budget")
        require(all(isinstance(channel, str) and channel
                    and isinstance(owner, str) and owner in accounts
                    for channel, owner in self.channel_owners.items()), "invalid original channel owner")
        if self.channel_providers is not None:
            require(set(self.channel_providers) == set(self.channel_owners)
                    and all(isinstance(provider, str) and provider in accounts
                            and provider != self.channel_owners[channel]
                            for channel, provider in self.channel_providers.items()),
                    "fixture provider graph differs from original channels")

    @property
    def issued_sat(self):
        return sum(self.initial_balances.values())

    def check_providers(self, finances):
        if self.channel_providers is not None:
            for node, state in finances.items():
                expected = {channel for channel, provider in self.channel_providers.items()
                            if provider == node}
                require(set(state["credited"]) == expected,
                        "provider accounts differ from original channels")


def stop_relay(run, node):
    reference = run.containers[node]
    item = inspect_owned("container", reference, run.name)
    require(item["Id"] == reference, "container identity changed before shutdown")
    require(item["State"]["Running"] is True, "relay container is not running")
    result = docker(["exec", item["Id"], "python3", "-c", STOP_RELAY], timeout=55)
    require(result == "stopped", "relay shutdown was not confirmed")


def original_channels(nodes, finances, *, fixture=None):
    accounts = {"n01", "n02", "n03"} if fixture is None else set(fixture.initial_balances)
    require(set(nodes) == accounts == set(finances),
            "settlement requires the original accounts")
    owners, operations = {}, set()
    for node in nodes:
        state = finances[node]
        budget = state["budget"]
        funded = ((0 if node == "n02" else 32) if fixture is None else
                  sum(owner == node for owner in fixture.channel_owners.values())
                  * fixture.channel_capacity_sat)
        require(amount(budget["wallet_debited_sat"]) == amount(budget["locked_sat"])
                == amount(budget["exposure_sat"]) == funded
                and amount(budget["pending_reserved_sat"]) == 0
                and amount(budget["wallet_refunded_sat"]) == 0,
                "original funding budget differs from the fixed fixture")
        require(amount(state["authorized"]) == sum(amount(value) for value in state["signed"].values())
                and amount(state["remaining"]) + state["authorized"]
                == (64 if fixture is None else fixture.buyer_budgets[node]),
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
    if fixture is None:
        require(len(owners) == 2 and set(owners.values()) == {"n01", "n03"},
                "expected the original two endpoint-funded channels")
    else:
        require(owners == fixture.channel_owners, "funding differs from frozen original channels")
        fixture.check_providers(finances)
    return owners


def validate_report(report, *, capacity_sat=32):
    fields = ("value_after_stage1_sat", "paid_sat", "receiver_fee_reserve_sat",
              "refunded_sat", "fee_sat")
    values = {key: amount(report[key]) for key in fields}
    require(values["value_after_stage1_sat"] == capacity_sat,
            "settlement changed original channel capacity")
    require(values["receiver_fee_reserve_sat"] == values["fee_sat"] == 0,
            "zero-fee fixture lost value to fees or reserves")
    require(values["paid_sat"] + values["refunded_sat"] == capacity_sat,
            "settlement does not return the full funded value")
    return {"channel_id": report["channel_id"], **values}


def validate_finances(before, after, reports, *, fixture=None):
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
                and current["remaining"] + current["authorized"]
                == (64 if fixture is None else fixture.buyer_budgets[node])
                and set(current["signed"]) == set(prior["signed"])
                and sum(amount(value) for value in current["signed"].values()) == current["authorized"],
                "settlement reset the lifetime buyer budget")
        for channel, _ in prior["funding"].values():
            require(amount(current["signed"][channel]) == reports[channel]["paid_sat"],
                    "settled payment differs from retained authorization")
    if fixture is not None:
        fixture.check_providers(after)
        for channel, provider in (fixture.channel_providers or {}).items():
            require(amount(after[provider]["credited"][channel]) == reports[channel]["paid_sat"] * 1000,
                    "settled provider credit differs from retained payment")


def check_mint(report, collected, *, issued_sat=384):
    require(report["test_only"] is True and report["conserved"] is True,
            "isolated mint accounting is not conserved")
    for field in ("issued_sat", "external_funding_sat", "total_accounted_sat"):
        require(amount(report[field]) == issued_sat, "test mint issuance or accounting changed")
    require(amount(report["collected_sat"]) == collected, "test collection is incomplete")


def settle_and_collect(run, prior_finances, *, execute=None, stop=None, export_path=None, fixture=None):
    """Settle once, stop relays, then export/collect once without new funding."""
    execute = execute or run.execute
    stop = stop or (lambda node: stop_relay(run, node))
    export_path = export_path or (lambda _node, relative: f"/tmp/bench-state/{relative}")
    owners = original_channels(run.nodes, prior_finances, fixture=fixture)
    issued = 384 if fixture is None else fixture.issued_sat
    capacity = 32 if fixture is None else fixture.channel_capacity_sat
    initial = execute("mint", "fips-relay-test-mint", "ctl", {"type": "report"})
    check_mint(initial, 0, issued_sat=issued)
    mint = initial["url"]
    reports = {}
    for node in run.nodes:
        result = run.ctl(node, "settle")
        for report in result["settlements"]:
            channel = report["channel_id"]
            require(owners.get(channel) == node and channel not in reports,
                    "settlement returned an unexpected or duplicate channel")
            reports[channel] = validate_report(report, capacity_sat=capacity)
    require(set(reports) == set(owners), "settlement omitted an original channel")
    settled = run.finances()
    validate_finances(prior_finances, settled, reports, fixture=fixture)
    collect_settled_wallets(run, settled, reports, owners, mint, execute=execute, stop=stop,
                           export_path=export_path, fixture=fixture)


def collect_settled_wallets(run, settled, reports, owners, mint, *, execute, stop,
                           export_path, fixture=None):
    """Collect only after the caller has verified every channel's final settlement.

    This tail neither discovers funding nor relaxes the caller's financial
    checks. A promotion fixture can include a previously verified refund.
    """
    issued = 384 if fixture is None else fixture.issued_sat
    for node in run.nodes:
        stop(node)

    balances, collections = {}, {}
    for node in run.nodes:
        balance = execute(node, "fips-relay", "wallet", {"type": "balance"})
        require(balance["mint_url"] == mint and balance["unit"] == "sat",
                "wallet balance has the wrong scope")
        balances[node] = amount(balance["balance_sat"])
    require(sum(balances.values()) == issued, "settled wallets do not hold all issued money")
    if fixture is not None and fixture.channel_providers is not None:
        expected = dict(fixture.initial_balances)
        for channel, owner in owners.items():
            paid = reports[channel]["paid_sat"]
            expected[owner] -= paid
            expected[fixture.channel_providers[channel]] += paid
        require(balances == expected, "settled wallet distribution differs from verified payments")
    for node, balance in balances.items():
        if balance:
            export_id = f"collect-{node}"
            exported = execute(node, "fips-relay", "wallet", {
                "type": "export", "id": export_id, "amount_sat": balance})
            relative = f"exports/{export_id}.json"
            require(exported["path"] == export_path(node, relative)
                    and amount(exported["amount_sat"]) == balance,
                    "wallet export changed its reserved terms")
            payment = run.state_json(node, relative)
            require(payment["mint_url"] == mint and payment["unit"] == "sat"
                    and amount(payment["amount_sat"]) == balance
                    and amount(payment["send_fee_sat"]) == 0
                    and isinstance(exported["operation_id"], str) and bool(exported["operation_id"])
                    and payment["operation_id"] == exported["operation_id"],
                    "saved export differs from the zero-fee transfer")
            received = execute("mint", "fips-relay-test-mint", "ctl", {
                "type": "collect", "token": payment["token"]})
            require(received["mint_url"] == mint and received["unit"] == "sat"
                    and amount(received["amount_sat"]) == balance,
                    "collector did not redeem the full export")
            collections[node] = balance
        else:
            collections[node] = 0
        empty = execute(node, "fips-relay", "wallet", {"type": "balance"})
        require(empty["mint_url"] == mint and empty["unit"] == "sat"
                and amount(empty["balance_sat"]) == 0, "node wallet is not empty")
    final = execute("mint", "fips-relay-test-mint", "ctl", {"type": "report"})
    check_mint(final, issued, issued_sat=issued)
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
