use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState};
use serde_json::Value;

/// Render the standard placeholder used while a tab is waiting for data.
pub fn render_waiting(frame: &mut Frame, area: Rect) {
    frame.render_widget(
        Paragraph::new("  Waiting for data...").style(Style::default().fg(Color::DarkGray)),
        area,
    );
}

/// Render the standard table scrollbar when there are rows to navigate.
pub fn render_scrollbar(frame: &mut Frame, area: Rect, row_count: usize, selected: Option<usize>) {
    if row_count == 0 {
        return;
    }
    let mut state = ScrollbarState::new(row_count).position(selected.unwrap_or(0));
    frame.render_stateful_widget(
        Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(None)
            .end_symbol(None),
        area,
        &mut state,
    );
}

/// Extract a string field from JSON, returning "-" if missing.
pub fn str_field<'a>(data: &'a Value, key: &str) -> &'a str {
    data.get(key).and_then(|v| v.as_str()).unwrap_or("-")
}

/// Extract a u64 field from JSON, returning "-" if missing.
pub fn u64_field(data: &Value, key: &str) -> String {
    data.get(key)
        .and_then(|v| v.as_u64())
        .map(|n| n.to_string())
        .unwrap_or_else(|| "-".into())
}

/// Truncate a hex string to the given length, adding "..." if truncated.
pub fn truncate_hex(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

/// Format bytes-per-second with engineering units (B/s, KB/s, MB/s, GB/s) and 3 significant digits.
pub fn format_throughput(bytes_per_sec: f64) -> String {
    if bytes_per_sec < 0.0 {
        return "0 B/s".into();
    }
    let (scaled, unit) = if bytes_per_sec < 1_000.0 {
        (bytes_per_sec, "B/s")
    } else if bytes_per_sec < 1_000_000.0 {
        (bytes_per_sec / 1_000.0, "KB/s")
    } else if bytes_per_sec < 1_000_000_000.0 {
        (bytes_per_sec / 1_000_000.0, "MB/s")
    } else {
        (bytes_per_sec / 1_000_000_000.0, "GB/s")
    };
    let decimals = if scaled >= 100.0 {
        0
    } else if scaled >= 10.0 {
        1
    } else {
        2
    };
    format!("{:.prec$} {unit}", scaled, prec = decimals)
}

/// Extract a nested f64 field and format as engineering-unit throughput.
pub fn nested_throughput(data: &Value, outer: &str, inner: &str) -> String {
    data.get(outer)
        .and_then(|o| o.get(inner))
        .and_then(|v| v.as_f64())
        .map(format_throughput)
        .unwrap_or_else(|| "-".into())
}

/// Format a byte count as human-readable (B, KB, MB, GB).
pub fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes}B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1}KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1}MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2}GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

/// Format seconds as human-readable uptime (e.g., "3d 2h 15m 4s").
pub fn format_uptime(secs: u64) -> String {
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let mins = (secs % 3600) / 60;
    let s = secs % 60;

    if days > 0 {
        format!("{days}d {hours}h {mins}m {s}s")
    } else if hours > 0 {
        format!("{hours}h {mins}m {s}s")
    } else if mins > 0 {
        format!("{mins}m {s}s")
    } else {
        format!("{s}s")
    }
}

/// Format millisecond timestamp as relative duration from now (e.g., "3.2s ago").
pub fn format_elapsed_ms(ms: u64) -> String {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    if ms == 0 || ms > now_ms {
        return "-".into();
    }
    format_duration_ms(now_ms - ms)
}

/// Get a nested string field.
pub fn nested_str(data: &Value, outer: &str, inner: &str) -> String {
    data.get(outer)
        .and_then(|o| o.get(inner))
        .and_then(|v| v.as_str())
        .unwrap_or("-")
        .to_string()
}

/// Get a nested field value (e.g., "stats.packets_sent").
pub fn nested_u64(data: &Value, outer: &str, inner: &str) -> String {
    data.get(outer)
        .and_then(|o| o.get(inner))
        .and_then(|v| v.as_u64())
        .map(|n| n.to_string())
        .unwrap_or_else(|| "-".into())
}

/// Get a nested f64 field formatted to given decimal places.
pub fn nested_f64(data: &Value, outer: &str, inner: &str, decimals: usize) -> String {
    data.get(outer)
        .and_then(|o| o.get(inner))
        .and_then(|v| v.as_f64())
        .map(|n| format!("{:.prec$}", n, prec = decimals))
        .unwrap_or_else(|| "-".into())
}

/// Get a nested f64 field, preferring `preferred` key with fallback to `fallback` key.
pub fn nested_f64_prefer(
    data: &Value,
    outer: &str,
    preferred: &str,
    fallback: &str,
    decimals: usize,
) -> String {
    data.get(outer)
        .and_then(|o| o.get(preferred).or_else(|| o.get(fallback)))
        .and_then(|v| v.as_f64())
        .map(|n| format!("{:.prec$}", n, prec = decimals))
        .unwrap_or_else(|| "-".into())
}

/// Extract a bool field from JSON, returning "yes"/"no" or "-" if missing.
pub fn bool_field(data: &Value, key: &str) -> &'static str {
    data.get(key)
        .and_then(|v| v.as_bool())
        .map(|b| if b { "yes" } else { "no" })
        .unwrap_or("-")
}

/// Format a duration in milliseconds as compact string (e.g., "42ms", "3.2s", "5.0m").
pub fn format_duration_ms(ms: u64) -> String {
    if ms < 1000 {
        format!("{ms}ms")
    } else if ms < 60_000 {
        format!("{:.1}s", ms as f64 / 1000.0)
    } else if ms < 3_600_000 {
        format!("{:.1}m", ms as f64 / 60_000.0)
    } else {
        format!("{:.1}h", ms as f64 / 3_600_000.0)
    }
}

/// Section header line for detail views.
pub fn section_header(title: &str) -> Line<'static> {
    Line::from(Span::styled(
        format!("  {title}"),
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    ))
}

/// Key-value line for detail views.
pub fn kv_line(key: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("    {key}: "), Style::default().fg(Color::DarkGray)),
        Span::raw(value.to_string()),
    ])
}

/// Format a forwarding counter as "N pkts (formatted_bytes)".
pub fn forwarding_line(data: &Value, label: &str, pkt_key: &str, byte_key: &str) -> Line<'static> {
    let pkts = data
        .get("forwarding")
        .and_then(|f| f.get(pkt_key))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let bytes = data
        .get("forwarding")
        .and_then(|f| f.get(byte_key))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    kv_line(label, &format!("{} pkts ({})", pkts, format_bytes(bytes)))
}

/// Render a sequence of values as Unicode block characters.
///
/// Returns an empty string for empty input. Constant series render as a
/// mid-level row. Used inline beside metric values in the dashboard and
/// as the per-column renderer for the Graphs tab.
pub fn sparkline(values: &[f64]) -> String {
    const BLOCKS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    if values.is_empty() {
        return String::new();
    }
    let (min, max) = values
        .iter()
        .fold((f64::INFINITY, f64::NEG_INFINITY), |(lo, hi), &v| {
            (lo.min(v), hi.max(v))
        });
    let range = max - min;
    values
        .iter()
        .map(|&v| {
            if !range.is_finite() || range <= 0.0 {
                BLOCKS[3]
            } else {
                let norm = ((v - min) / range).clamp(0.0, 1.0);
                let idx = (norm * (BLOCKS.len() as f64 - 1.0)).round() as usize;
                BLOCKS[idx.min(BLOCKS.len() - 1)]
            }
        })
        .collect()
}

/// Extract a `Vec<f64>` from a nested JSON array (e.g., `sparklines.mesh_size`).
pub fn nested_f64_array(data: &Value, outer: &str, inner: &str) -> Vec<f64> {
    data.get(outer)
        .and_then(|o| o.get(inner))
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_f64()).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uptime_formatting_preserves_boundaries() {
        assert_eq!(format_uptime(59), "59s");
        assert_eq!(format_uptime(60), "1m 0s");
        assert_eq!(format_uptime(3600), "1h 0m 0s");
        assert_eq!(format_uptime(86400), "1d 0h 0m 0s");
    }

    #[test]
    fn forwarding_line_preserves_values_and_missing_defaults() {
        let data = serde_json::json!({"forwarding": {"packets": 7, "bytes": 2048}});
        let line = forwarding_line(&data, "Sent", "packets", "bytes");
        let text = line
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<String>();
        assert_eq!(text, "    Sent: 7 pkts (2.0KB)");

        let missing = forwarding_line(&Value::Null, "Sent", "packets", "bytes");
        let text = missing
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<String>();
        assert_eq!(text, "    Sent: 0 pkts (0B)");
    }
}
