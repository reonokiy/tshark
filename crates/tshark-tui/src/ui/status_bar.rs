use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::app::App;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let total = app.packets.len();
    let displayed = app.filtered_indices.len();

    let capturing = if app.capture_rx.is_some() {
        " [Capturing]"
    } else {
        ""
    };

    let auto = if app.auto_scroll { " [Follow]" } else { "" };

    let pane_name = match app.active_pane {
        crate::app::Pane::PacketList => "List",
        crate::app::Pane::PacketDetail => "Detail",
        crate::app::Pane::HexDump => "Hex",
    };

    let line = Line::from(vec![
        Span::styled(
            format!(" Packets: {total} | Displayed: {displayed}{capturing}{auto} "),
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        ),
        Span::raw(" | "),
        Span::styled(
            format!("Pane: {pane_name}"),
            Style::default().fg(Color::Cyan),
        ),
        Span::raw(" | "),
        Span::styled(
            "q:quit  /:filter  Tab:pane  j/k:nav  Enter:expand  f:follow",
            Style::default().fg(Color::DarkGray),
        ),
    ]);

    let para = Paragraph::new(line).style(Style::default().bg(Color::DarkGray));
    f.render_widget(para, area);
}
