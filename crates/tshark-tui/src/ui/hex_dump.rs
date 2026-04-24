use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::app::{App, Pane};

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let highlight_border = if app.active_pane == Pane::HexDump {
        Color::Cyan
    } else {
        Color::DarkGray
    };

    let block = Block::default()
        .title(" Hex Dump ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(highlight_border));

    let pkt = match app.selected_packet() {
        Some(p) => p,
        None => {
            let para = Paragraph::new("No packet selected")
                .style(Style::default().fg(Color::DarkGray))
                .block(block);
            f.render_widget(para, area);
            return;
        }
    };

    let data = &pkt.raw.data;
    let highlight_range = &app.selected_field_range;
    let visible_height = area.height.saturating_sub(2) as usize;

    let mut lines: Vec<Line> = Vec::new();

    for row_start in (0..data.len()).step_by(16) {
        let mut spans = Vec::new();

        // Offset
        spans.push(Span::styled(
            format!("{:04x}   ", row_start),
            Style::default().fg(Color::DarkGray),
        ));

        // Hex bytes
        for i in 0..16 {
            let pos = row_start + i;
            if pos < data.len() {
                let is_highlighted = highlight_range
                    .as_ref()
                    .map(|r| pos >= r.start && pos < r.end)
                    .unwrap_or(false);

                let style = if is_highlighted {
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::White)
                };

                spans.push(Span::styled(format!("{:02x} ", data[pos]), style));
            } else {
                spans.push(Span::raw("   "));
            }
            if i == 7 {
                spans.push(Span::raw(" "));
            }
        }

        spans.push(Span::raw("  "));

        // ASCII
        for i in 0..16 {
            let pos = row_start + i;
            if pos < data.len() {
                let b = data[pos];
                let ch = if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '.'
                };

                let is_highlighted = highlight_range
                    .as_ref()
                    .map(|r| pos >= r.start && pos < r.end)
                    .unwrap_or(false);

                let style = if is_highlighted {
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Green)
                };

                spans.push(Span::styled(format!("{ch}"), style));
            }
        }

        lines.push(Line::from(spans));
    }

    let scroll = app.hex_scroll.min(lines.len().saturating_sub(visible_height));
    let visible: Vec<Line> = lines.into_iter().skip(scroll).collect();

    let para = Paragraph::new(visible).block(block);
    f.render_widget(para, area);
}
