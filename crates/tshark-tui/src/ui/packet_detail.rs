use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::app::{App, DetailLine, Pane};

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let highlight_border = if app.active_pane == Pane::PacketDetail {
        Color::Cyan
    } else {
        Color::DarkGray
    };

    let block = Block::default()
        .title(" Packet Detail ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(highlight_border));

    let detail_lines = app.detail_lines();

    if detail_lines.is_empty() {
        let para = Paragraph::new("No packet selected")
            .style(Style::default().fg(Color::DarkGray))
            .block(block);
        f.render_widget(para, area);
        return;
    }

    let visible_height = area.height.saturating_sub(2) as usize;
    let scroll_offset = if app.active_pane == Pane::PacketDetail && app.detail_cursor >= visible_height {
        app.detail_cursor - visible_height + 1
    } else {
        app.detail_scroll
    };

    let lines: Vec<Line> = detail_lines
        .iter()
        .enumerate()
        .skip(scroll_offset)
        .map(|(idx, line)| {
            let is_cursor = app.active_pane == Pane::PacketDetail && idx == app.detail_cursor;
            match line {
                DetailLine::Layer { text, .. } => {
                    let style = if is_cursor {
                        Style::default().fg(Color::Black).bg(Color::White).add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
                    };
                    Line::from(Span::styled(text.as_str(), style))
                }
                DetailLine::Field { text, .. } => {
                    let style = if is_cursor {
                        Style::default().fg(Color::Black).bg(Color::Yellow)
                    } else {
                        Style::default().fg(Color::White)
                    };
                    Line::from(Span::styled(text.as_str(), style))
                }
            }
        })
        .collect();

    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, area);
}
