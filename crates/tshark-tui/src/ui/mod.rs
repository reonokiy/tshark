pub mod colors;
pub mod filter_bar;
pub mod hex_dump;
pub mod packet_detail;
pub mod packet_list;
pub mod status_bar;

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout};

use crate::app::App;

pub fn draw(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),  // filter bar
            Constraint::Min(5),    // main content
            Constraint::Length(1), // status bar
        ])
        .split(f.area());

    filter_bar::draw(f, app, chunks[0]);

    // Split main content: packet list (40%), detail (35%), hex dump (25%)
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(40),
            Constraint::Percentage(35),
            Constraint::Percentage(25),
        ])
        .split(chunks[1]);

    packet_list::draw(f, app, main_chunks[0]);
    packet_detail::draw(f, app, main_chunks[1]);
    hex_dump::draw(f, app, main_chunks[2]);

    status_bar::draw(f, app, chunks[2]);

    // Set cursor position when editing filter
    if app.mode == crate::app::AppMode::FilterEdit {
        let cursor_x = chunks[0].x + 8 + app.filter_text_editing.len() as u16;
        let cursor_y = chunks[0].y;
        f.set_cursor_position((cursor_x, cursor_y));
    }
}
