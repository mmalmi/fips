"""Shared paid-route observations from individually atomic local journals."""


def financial_snapshot(run, *, wallet):
    """Read live accounting; pass None when a live wallet snapshot is unavailable."""
    result = {}
    for node in run.nodes:
        status = run.ctl(node, "status")
        buyer = run.state_json(node, "buyer/buyer.json")
        controller = run.state_json(node, "controller/controller.json")
        seller = run.state_json(node, "seller/ledger.json")["ledger"]
        authorized = sum(channel["authorized_sat"] for channel in buyer["channels"].values())
        if status["remaining_budget_sat"] != buyer["total_budget_sat"] - authorized:
            # Journals and status are individually atomic, not one snapshot.
            raise RuntimeError("financial observation changed during sampling")
        funding = {key: (item["funded"]["terms"]["id"], item["funded"]["wallet_operation_id"])
                   for key, item in controller["funding"].items() if item["funded"] is not None}
        result[node] = {
            "funding": funding, "budget": status["funding_budget"],
            "remaining": status["remaining_budget_sat"], "authorized": authorized,
            "signed": {key: item["authorized_sat"] for key, item in buyer["channels"].items()},
            "credited": {item["terms"]["id"]: item["usage"]["paid_msat"] for item in seller["channels"]},
            "seller_channels": {item["terms"]["id"]: item["usage"] for item in seller["channels"]},
            "buyer_units": {key: item["submitted_units"] for key, item in buyer["quotes"].items()},
            "buyer_observed_units": {key: item["observed_units"] for key, item in buyer["quotes"].items()},
            "seller_units": {item["contract"]["id"]: item["usage"]["submitted_units"] for item in seller["accounts"]},
            "seller_unconfirmed_units": {item["contract"]["id"]: item["usage"]["unconfirmed_units"] for item in seller["accounts"]},
        }
        if wallet is not None:
            result[node]["wallet"] = wallet(node)
    # Provider credit can advance after an earlier buyer read. Bracket it
    # with a later durable authorization, without demanding an idle mesh.
    for node in run.nodes:
        buyer = run.state_json(node, "buyer/buyer.json")
        result[node]["signed_after"] = {
            key: item["authorized_sat"] for key, item in buyer["channels"].items()}
    return result


def payments_credited(current):
    """Whether every observed signature is already reflected in provider credit."""
    credited = {key: value for state in current.values() for key, value in state["credited"].items()}
    return all(credited.get(key, -1) >= value * 1000
               for state in current.values() for key, value in state["signed"].items())


def payment_progress(current, prior, *, sources=("n01", "n03")):
    """Require provider credit and increased authorization from every source."""
    advanced = all(current[node]["authorized"] > prior[node]["authorized"] for node in sources)
    return current if payments_credited(current) and advanced else None
