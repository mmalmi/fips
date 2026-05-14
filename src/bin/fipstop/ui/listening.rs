use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Span;
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};
use serde_json::Value;

pub fn draw(frame: &mut Frame, payload: Option<&Value>, area: Rect) {
    let payload = match payload {
        Some(payload) => payload,
        None => {
            let block = Block::default()
                .borders(Borders::ALL)
                .title(" Listening on fips0 ");
            let inner = block.inner(area);
            frame.render_widget(block, area);
            frame.render_widget(
                Paragraph::new(Span::styled(
                    "  loading...",
                    Style::default().fg(Color::DarkGray),
                )),
                inner,
            );
            return;
        }
    };

    let firewall_active = payload
        .get("firewall_active")
        .and_then(|value| value.as_bool())
        .unwrap_or(true);
    let sockets = payload
        .get("sockets")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default();

    let title: Span<'static> = if firewall_active {
        Span::raw(" Listening on fips0 ")
    } else {
        Span::styled(
            " Listening on fips0  firewall inactive: all listeners exposed ",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
    };

    let block = Block::default().borders(Borders::ALL).title(title);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if sockets.is_empty() {
        frame.render_widget(
            Paragraph::new(Span::styled(
                "  no listeners reachable from fips0",
                Style::default().fg(Color::DarkGray),
            )),
            inner,
        );
        return;
    }

    let header = Row::new(vec![
        Cell::from("Proto"),
        Cell::from("Port"),
        Cell::from("Process"),
        Cell::from("State"),
    ])
    .style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = sockets.iter().map(build_row).collect();
    let table = Table::new(
        rows,
        [
            Constraint::Length(5),
            Constraint::Length(6),
            Constraint::Min(8),
            Constraint::Length(8),
        ],
    )
    .header(header)
    .column_spacing(1);

    frame.render_widget(table, inner);
}

fn build_row(socket: &Value) -> Row<'static> {
    let proto = socket
        .get("proto")
        .and_then(|value| value.as_str())
        .unwrap_or("-")
        .to_string();
    let port = socket
        .get("port")
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    let pid = socket.get("pid").and_then(|value| value.as_u64());
    let process = socket.get("process").and_then(|value| value.as_str());
    let wildcard = socket
        .get("wildcard_bind")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let filter = socket
        .get("filter")
        .and_then(|value| value.as_str())
        .unwrap_or("drop");

    let mut process_label = match (pid, process) {
        (Some(pid), Some(name)) => format!("{name}({pid})"),
        (Some(pid), None) => format!("?({pid})"),
        _ => "?".to_string(),
    };
    if wildcard && pid.is_some() {
        process_label.push_str(" *");
    }

    let (state_text, row_style): (&str, Style) = match filter {
        "accept" | "no_firewall" => ("OPEN", Style::default()),
        "drop" => ("filt", Style::default().fg(Color::DarkGray)),
        "unknown" => ("filt?", Style::default().fg(Color::DarkGray)),
        _ => ("?", Style::default().fg(Color::DarkGray)),
    };

    Row::new(vec![
        Cell::from(format!(" {proto}")),
        Cell::from(port.to_string()),
        Cell::from(process_label),
        Cell::from(state_text.to_string()),
    ])
    .style(row_style)
}
