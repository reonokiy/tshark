use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::app::{App, AppMode};

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let (label_style, text) = match app.mode {
        AppMode::FilterEdit => {
            let style = Style::default().fg(Color::Black).bg(Color::Cyan);
            (style, app.filter_text_editing.as_str())
        }
        AppMode::Normal => {
            let style = if app.filter_error.is_some() {
                Style::default().fg(Color::Black).bg(Color::Red)
            } else if !app.filter_text.is_empty() {
                Style::default().fg(Color::Black).bg(Color::Green)
            } else {
                Style::default().fg(Color::DarkGray)
            };
            (style, app.filter_text.as_str())
        }
    };

    let display_text = if text.is_empty() && app.mode == AppMode::Normal {
        "Press / to filter"
    } else {
        text
    };

    let line = Line::from(vec![
        Span::styled(" Filter: ", label_style.add_modifier(Modifier::BOLD)),
        Span::styled(display_text, Style::default().fg(Color::White)),
    ]);

    let error_msg = app.filter_error.as_deref().unwrap_or("");
    let para = if !error_msg.is_empty() && app.mode == AppMode::Normal {
        let err_line = Line::from(vec![
            Span::styled(" Filter: ", label_style.add_modifier(Modifier::BOLD)),
            Span::styled(&app.filter_text, Style::default().fg(Color::White)),
            Span::styled(format!("  [Error: {error_msg}]"), Style::default().fg(Color::Red)),
        ]);
        Paragraph::new(err_line)
    } else {
        Paragraph::new(line)
    };

    f.render_widget(para, area);
}
