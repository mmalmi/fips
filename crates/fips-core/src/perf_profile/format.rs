pub(super) fn fmt_ns(ns: u64) -> String {
    if ns >= 1_000_000_000 {
        format!("{:.1}s", ns as f64 / 1_000_000_000.0)
    } else if ns >= 1_000_000 {
        format!("{:.1}ms", ns as f64 / 1_000_000.0)
    } else if ns >= 1_000 {
        format!("{:.1}us", ns as f64 / 1_000.0)
    } else {
        format!("{ns}ns")
    }
}

pub(super) fn fmt_rate_per_sec(count: u64, interval_secs: u64) -> String {
    let interval_secs = interval_secs.max(1);
    if count.is_multiple_of(interval_secs) {
        return (count / interval_secs).to_string();
    }
    let rate = count as f64 / interval_secs as f64;
    let formatted = format!("{rate:.3}");
    formatted
        .trim_end_matches('0')
        .trim_end_matches('.')
        .to_string()
}
