"""Read-only anchors for the fresh source-funded physical diamond.

Capture raw journals before the shared financial_snapshot. Profiles must expose
node_addr bound to their verified native process identity. Keep each validated
raw snapshot unchanged and pass it as previous on subsequent observations.
This helper neither issues funds nor settles channels; the shared collector owns
those operations. Initial stopped-wallet balances remain a runner precondition.
"""

from .paid_phone_finances import _address, _ledger, _mapping, _text, _zero
from .paid_settlement import SettlementFixture, amount, original_channels, require


ACCOUNTS = ("source", "n01", "n02", "n03")
PROVIDERS = ("n01", "n02")


def _accounts(profiles, journals):
    require(set(profiles) == set(journals) == set(ACCOUNTS), "diamond account set changed")
    identities = {name: _address(profile.node_addr) for name, profile in profiles.items()}
    require(len(set(identities.values())) == 4, "diamond identities are duplicated")
    mint = _text(journals["source"]["controller"]["policy"]["mint_url"], "mint URL")
    for name, state in journals.items():
        controller, buyer = state["controller"], state["buyer"]
        require(_address(controller["local"]) == _address(buyer["local"]) == identities[name],
                "journal identity differs from verified profile")
        policy = controller["policy"]
        require(policy["mint_url"] == mint and policy["renewal"] is None
                and amount(policy["max_funding_overhead_sat"]) == 0,
                "diamond mint, renewal or funding-fee policy differs")
        require(amount(buyer["total_budget_sat"]) == (128 if name == "source" else 64),
                "diamond lifetime buyer budget differs")
        if name == "source":
            require(amount(policy["channel_capacity_sat"]) == 64
                    and amount(policy["max_locked_sat"]) == amount(policy["max_wallet_spend_sat"]) == 128,
                    "source capital policy differs from the fixed fixture")
        require(not controller["buyer_settlements"] and not controller["seller_settlements"]
                and not controller["renewals"], "diamond already has settlement or renewal work")
        require(_zero(buyer.get("history")) and _zero(_ledger(state).get("history")),
                "diamond has retired financial accounts")
        history = controller.get("history") or {}
        require(history.get("pending") is None and _zero(history.get("channels"))
                and _zero(history.get("seller")), "diamond has financial history or pending retirement")
    return identities, mint


def _channels(journals, identities, mint, expected_count):
    channels, operations, providers = {}, set(), set()
    for name, state in journals.items():
        funding = _mapping(state["controller"]["funding"], "funding")
        require(len(funding) == (expected_count if name == "source" else 0),
                "diamond funding count differs from acknowledged channels")
        for key, intent in funding.items():
            require(intent["id"] == key and intent["funded"] is not None,
                    "diamond funding intent is unresolved or changed")
            funded = intent["funded"]
            terms, cost = funded["terms"], funded["wallet_cost"]
            channel = _text(terms["id"], "channel ID")
            operation = _text(funded["wallet_operation_id"], "funding operation")
            address = _address(intent["provider"])
            provider = next((n for n in PROVIDERS if identities[n] == address), None)
            require(provider is not None and provider not in providers
                    and channel not in channels and operation not in operations,
                    "diamond provider, channel or funding operation is unknown or duplicated")
            require(_address(terms["buyer"]) == identities["source"] and terms["mint_url"] == mint,
                    "funded channel buyer or mint differs")
            require(amount(terms["capacity_sat"]) == amount(intent["capacity_sat"])
                    == amount(intent["max_wallet_debit_sat"]) == amount(cost["token_amount_sat"])
                    == amount(cost["wallet_debit_sat"]) == 64 and amount(cost["swap_fee_sat"]) == 0,
                    "original 64-sat zero-fee funding terms changed")
            require(amount(terms["expires_unix"]) == amount(intent["expires_unix"])
                    and amount(intent["created_unix"]) < terms["expires_unix"]
                    and 0 < amount(terms["grace_msat"]) == amount(intent["grace_msat"]) <= 64_000
                    and funded["opening"]["channel_id"] == channel
                    and amount(funded["opening"]["balance"]) == 0,
                    "funding intent and opening terms differ")
            channels[channel] = {"provider": provider, "terms": terms, "funding_id": key}
            operations.add(operation)
            providers.add(provider)
    return channels


def _ledgers(journals, identities, channels):
    sellers = {}
    for name, state in journals.items():
        buyer = state["buyer"]
        require(set(buyer["channels"]) == (set(channels) if name == "source" else set()),
                "buyer channel set differs from source-only funding")
        for channel, own in buyer["channels"].items():
            saved = channels[channel]
            require(own["terms"] == saved["terms"]
                    and _address(own["provider"]) == identities[saved["provider"]]
                    and amount(own["authorized_sat"]) <= 64,
                    "buyer channel terms, provider or authorization differs")
        require(sum(amount(row["authorized_sat"]) for row in buyer["channels"].values())
                <= buyer["total_budget_sat"], "buyer exceeds lifetime budget")
        rows = _ledger(state)["channels"]
        require(type(rows) is list, "seller channels are not an array")
        actual = {}
        for row in rows:
            channel = row["terms"]["id"]
            require(channel not in actual, "duplicate seller channel")
            actual[channel] = row
        expected = {channel for channel, saved in channels.items() if saved["provider"] == name}
        require(set(actual) == expected, "seller channel set differs from original providers")
        for channel, row in actual.items():
            require(row["terms"] == channels[channel]["terms"], "seller channel terms differ")
            usage = row["usage"]
            paid = amount(usage["paid_msat"])
            require(paid <= 64_000 and amount(usage["lost_msat"]) == 0
                    and amount(usage["submitted_msat"]) <= amount(usage["reserved_msat"])
                    <= min(64_000, paid + row["terms"]["grace_msat"]),
                    "seller exposure exceeds original channel allowance")
        sellers[name] = actual
    return sellers


def _work(journals, identities, channels):
    for name, state in journals.items():
        controller = state["controller"]
        outgoing = _mapping(controller["outgoing"], "outgoing routes")
        requested = _mapping(controller["requested"], "requested routes")
        require(name == "source" or not outgoing and not requested,
                "unfunded provider or destination acquired outgoing authority")
        offers, covered = {}, set()
        for row in outgoing.values():
            purchase = row["purchase"]
            channel = purchase["channel"]["id"]
            require(channel in channels and row["accepted"] is True,
                    "outgoing purchase is unresolved or uses an unknown channel")
            saved = channels[channel]
            require(purchase["channel"] == saved["terms"]
                    and _address(purchase["provider"]) == identities[saved["provider"]]
                    and row["funding_id"] == saved["funding_id"],
                    "acknowledged purchase differs from original funding")
            offer_id = _text(row["offer"]["id"], "acknowledged offer ID")
            require(offer_id not in offers, "duplicate acknowledged offer")
            offers[offer_id] = row["offer"]
            covered.add(channel)
        require(all(offers.get(key) == offer for key, offer in requested.items()),
                "requested route lacks acknowledged funding")
        for watch in controller["watched_routes"].values():
            require(watch["pending"] is None, "watched route has a pending purchase")
        for change in controller["route_changes"].values():
            offer = change["offer"]
            require(offers.get(offer["id"]) == offer, "route change is not acknowledged")
        history = controller.get("history") or {}
        retired = set(history.get("buyers", []))
        require(retired <= (set(channels) if name == "source" else set()),
                "retired routing refers to unknown buyer channels")
        if name == "source":
            require(covered | retired == set(channels), "funded channel lacks an accepted purchase")
        incoming = list(controller["incoming"].values())
        historic_sales = history.get("sellers", {})
        for row in incoming:
            require(row["phase"] in ("Active", "Stopped"), "provider acceptance is unfinished")
        for terms in [row["channel"] for row in incoming] + list(historic_sales.values()):
            saved = channels.get(terms["id"])
            require(saved is not None and saved["provider"] == name and saved["terms"] == terms,
                    "incoming channel differs from original source funding")


def _snapshot(profiles, journals, expected_count):
    require(type(expected_count) is int and 0 <= expected_count <= 2,
            "expected zero, one or two acknowledged diamond channels")
    identities, mint = _accounts(profiles, journals)
    channels = _channels(journals, identities, mint, expected_count)
    sellers = _ledgers(journals, identities, channels)
    _work(journals, identities, channels)
    return channels, sellers


def _retain(profiles, previous, journals):
    count = len(previous["source"]["controller"]["funding"])
    _, old_sellers = _snapshot(profiles, previous, count)
    for name, prior in previous.items():
        old, current = prior["controller"], journals[name]["controller"]
        require(old["policy"] == current["policy"], "diamond authority policy changed")
        require(all(current["funding"].get(key) == value for key, value in old["funding"].items()),
                "original funding intent, channel or operation was replaced")
        for channel, row in prior["buyer"]["channels"].items():
            current_row = journals[name]["buyer"]["channels"][channel]
            require(amount(current_row["authorized_sat"]) >= row["authorized_sat"],
                    "original channel authorization decreased")
    return old_sellers


def freeze_fixture(profiles, raw_journals, finances, expected_count, *, previous=None):
    """Validate raw funding plus a later shared financial_snapshot for closure.

    A zero-channel fixture is valid only before any unresolved purchase intent.
    Previous raw snapshots retain immutable funding evidence across growth/reuse.
    Returned policy contains no signed payments or bearer proofs.
    """
    try:
        channels, sellers = _snapshot(profiles, raw_journals, expected_count)
        if previous is not None:
            old_sellers = _retain(profiles, previous, raw_journals)
            for name, rows in old_sellers.items():
                for channel, row in rows.items():
                    require(sellers[name][channel]["usage"]["paid_msat"] >= row["usage"]["paid_msat"],
                            "original provider credit decreased")
        policy = SettlementFixture(
            initial_balances={name: 128 if name == "source" else 0 for name in ACCOUNTS},
            buyer_budgets={name: 128 if name == "source" else 64 for name in ACCOUNTS},
            channel_capacity_sat=64, channel_owners=dict.fromkeys(channels, "source"),
            channel_providers={channel: saved["provider"] for channel, saved in channels.items()},
        )
        original_channels(profiles, finances, fixture=policy)
        for name, state in raw_journals.items():
            summary = finances[name]
            expected = {key: (row["funded"]["terms"]["id"], row["funded"]["wallet_operation_id"])
                        for key, row in state["controller"]["funding"].items()}
            require(summary["funding"] == expected, "financial summary changed raw funding evidence")
            require(set(summary["signed_after"]) == set(state["buyer"]["channels"]),
                    "financial summary gained an unanchored channel during sampling")
            for channel, row in state["buyer"]["channels"].items():
                require(row["authorized_sat"] <= amount(summary["signed"][channel])
                        <= amount(summary["signed_after"][channel]) <= 64,
                        "financial summary precedes raw authorization or exceeds capacity")
            for channel, row in sellers[name].items():
                require(row["usage"]["paid_msat"] <= amount(summary["credited"][channel])
                        <= amount(finances["source"]["signed_after"][channel]) * 1000,
                        "financial summary precedes raw credit or exceeds retained signature")
        return policy
    except (KeyError, TypeError, IndexError, AttributeError) as error:
        raise RuntimeError("missing or malformed diamond financial evidence") from error
