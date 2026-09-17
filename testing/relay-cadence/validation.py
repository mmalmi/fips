"""Acceptance rules for the fixed clean-link experiment, not impaired trials."""

PAYMENT_PORT = 44743
PAYMENT_OPERATIONS = ("payment_sign", "payment_usage", "payment_update")
OPERATIONS = {"other", *PAYMENT_OPERATIONS, "payment_open", "payment_stop", "window_checkpoint"}
COUNTERS = {"spans", "cpu_samples", "thread_cpu_ns", "elapsed_ns",
            "journal_bytes_written", "journal_writes", "journal_syncs", "journal_commits"}
POLICIES = (250, 500, 1000, 2000, 2000, 1000, 500, 250)
WORKLOADS = {"idle": [], "bursty": [64] * 8, "steady": [3200], "high_rate": [32000]}


def unsigned(value):
    if type(value) is not int or value < 0:
        raise ValueError("expected nonnegative integer evidence")
    return value


def validate_measurements(before, after):
    if before["version"] != 1 or after["version"] != 1:
        raise ValueError("unsupported measurement counter version")
    if before["process_id"] != after["process_id"]:
        raise ValueError("a service restarted during measurement")
    if unsigned(after["process_cpu_ns"]) < unsigned(before["process_cpu_ns"]):
        raise ValueError("process CPU counter reset")
    if set(before["operations"]) != OPERATIONS or set(after["operations"]) != OPERATIONS:
        raise ValueError("measurement operations changed or are missing")
    for name, prior in before["operations"].items():
        current = after["operations"][name]
        if set(prior) != COUNTERS or set(current) != COUNTERS:
            raise ValueError("measurement counters changed or are missing")
        for key in COUNTERS:
            if unsigned(current[key]) < unsigned(prior[key]):
                raise ValueError(f"measurement counter reset: {name}.{key}")


def quiet_boundary(nodes):
    """Acknowledged credit must cover current local evidence and signed liability."""
    if len(nodes) != 5:
        raise ValueError("expected five measured service processes")
    channels = {}
    processes = set()
    for index, node in enumerate(nodes):
        process = unsigned(node["measurements"]["process_id"])
        if not process or process in processes:
            raise ValueError("expected distinct measured service processes")
        processes.add(process)
        if node["last_error"] is not None:
            raise ValueError("controller error at measurement boundary")
        progress = node["payment_progress"]
        if not isinstance(progress, dict):
            raise ValueError("missing payment progress")
        for channel, state in progress.items():
            if not isinstance(channel, str) or not channel or channel in channels:
                raise ValueError("duplicate or invalid payment channel")
            evidence = unsigned(state["evidence_msat"])
            authorized = unsigned(state["authorized_sat"]) * 1000
            acknowledged = unsigned(state["acknowledged_msat"])
            if state["in_flight"] is not False or acknowledged < max(evidence, authorized):
                raise ValueError("unreconciled payment work at measurement boundary")
            channels[channel] = index
    if len(channels) != 6:
        raise ValueError("expected six reconciled paying channels")
    return channels


def payment_counters(node):
    services = node["control_traffic"]
    ports = [service["service_port"] for service in services]
    if len(ports) != len(set(ports)) or ports.count(PAYMENT_PORT) != 1:
        raise ValueError("missing or duplicate payment control counters")
    return next(s["counters"] for s in services if s["service_port"] == PAYMENT_PORT)


def validate_gap(previous, current):
    """No payment or durability work may escape into the unmeasured gap."""
    if quiet_boundary(previous) != quiet_boundary(current):
        raise ValueError("paying channels changed between workloads")
    for before, after in zip(previous, current):
        validate_measurements(before["measurements"], after["measurements"])
        if before["payment_progress"] != after["payment_progress"]:
            raise ValueError("payment evidence changed outside measurement windows")
        if payment_counters(before) != payment_counters(after):
            raise ValueError("payment traffic outside measurement windows")
        for name, counters in before["measurements"]["operations"].items():
            latest = after["measurements"]["operations"][name]
            if name in PAYMENT_OPERATIONS and counters != latest:
                raise ValueError("payment work outside measurement windows")
            for key in ("journal_writes", "journal_bytes_written", "journal_syncs", "journal_commits"):
                if counters[key] != latest[key]:
                    raise ValueError("durable work outside measurement windows")


def validate_probe(probe, count):
    sent, received = probe["sender"], probe["receiver"]
    if sent["stopped_reason"] is not None:
        raise ValueError("probe sender stopped")
    if sent["stream_id"] != received["stream_id"]:
        raise ValueError("probe stream identity changed")
    for value in (sent["requested_packets"], sent["submitted_packets"],
                  received["expected_packets"], received["unique_packets"]):
        if unsigned(value) != count:
            raise ValueError("clean-link probe has partial submission or delivery loss")
    if received["payload_bytes"] != 1000:
        raise ValueError("offered packet size changed")
    for value in (sent["submitted_bytes"], received["unique_bytes"]):
        if unsigned(value) != count * 1000:
            raise ValueError("probe byte accounting differs from workload")
    for key in ("missing_packets", "duplicate_packets", "invalid_packets"):
        if unsigned(received[key]) != 0:
            raise ValueError("clean-link probe is missing, duplicated or invalid")
    if unsigned(received["latency"]["invalid_timestamps"]) != 0:
        raise ValueError("clean-link latency has invalid timestamps")


def validate_idle(result):
    for key in ("payment_requests", "payment_record_bytes", "signs", "updates",
                "payment_cpu_ms", "journal_writes", "journal_bytes", "journal_syncs"):
        if result[key] != 0:
            raise ValueError(f"idle work did not quiesce: {key}")
