use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, Row, Table};

use crate::app::{App, Pane};
use crate::ui::colors;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let highlight_border = if app.active_pane == Pane::PacketList {
        Color::Cyan
    } else {
        Color::DarkGray
    };

    let block = Block::default()
        .title(" Packet List ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(highlight_border));

    let header = Row::new(vec!["No.", "Time", "Source", "Destination", "Proto", "Len", "Info"])
        .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD));

    let first_ts = app
        .filtered_indices
        .first()
        .and_then(|&i| app.packets.get(i))
        .map(|p| p.raw.timestamp);

    let rows: Vec<Row> = app
        .filtered_indices
        .iter()
        .enumerate()
        .map(|(display_idx, &pkt_idx)| {
            let pkt = &app.packets[pkt_idx];
            let ts = first_ts
                .map(|ft| {
                    let d = pkt.raw.timestamp.signed_duration_since(ft);
                    d.num_microseconds().unwrap_or(0) as f64 / 1_000_000.0
                })
                .unwrap_or(0.0);

            let proto = pkt.top_protocol();
            let fg = colors::protocol_fg(proto);

            let style = if display_idx == app.selected_index {
                Style::default()
                    .fg(Color::Black)
                    .bg(fg)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(fg)
            };

            Row::new(vec![
                format!("{}", pkt.index),
                format!("{ts:.6}"),
                pkt.source_addr(),
                pkt.dest_addr(),
                proto.short_name().to_string(),
                format!("{}", pkt.raw.original_length),
                pkt.summary(),
            ])
            .style(style)
        })
        .collect();

    // Calculate visible window for scrolling
    let visible_height = area.height.saturating_sub(3) as usize; // borders + header
    let scroll_offset = if app.selected_index >= visible_height {
        app.selected_index - visible_height + 1
    } else {
        0
    };

    let visible_rows: Vec<Row> = rows.into_iter().skip(scroll_offset).collect();

    let widths = [
        ratatui::layout::Constraint::Length(6),
        ratatui::layout::Constraint::Length(12),
        ratatui::layout::Constraint::Length(16),
        ratatui::layout::Constraint::Length(16),
        ratatui::layout::Constraint::Length(6),
        ratatui::layout::Constraint::Length(5),
        ratatui::layout::Constraint::Min(20),
    ];

    let table = Table::new(visible_rows, widths)
        .header(header)
        .block(block);

    f.render_widget(table, area);
}
