mod app;
mod ui;

use std::io;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use crossbeam_channel::{bounded, unbounded};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

use tshark_capture::{CaptureConfig, LiveCapture};

use crate::app::{App, AppMode, Pane};

#[derive(Parser)]
#[command(name = "tshark-tui", about = "Network protocol analyzer (TUI)", version)]
struct Cli {
    /// Read packets from a pcap file
    #[arg(short = 'f', long = "file")]
    file: Option<PathBuf>,

    /// Capture from a network interface
    #[arg(short, long)]
    interface: Option<String>,

    /// BPF capture filter
    #[arg(long)]
    capture_filter: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut app = App::new();

    // Load packets from file or start live capture
    if let Some(ref path) = cli.file {
        let (tx, rx) = unbounded();
        tshark_capture::file::read_pcap(path, tx)?;
        for raw in rx {
            let idx = app.packets.len() + 1;
            let dissected = app.registry.dissect_packet(&raw, idx);
            app.filtered_indices.push(app.packets.len());
            app.packets.push(dissected);
            app.packets_received += 1;
        }
        // Expand first layer by default
        if !app.packets.is_empty() {
            app.detail_expanded.insert(0);
        }
    } else if let Some(ref iface) = cli.interface {
        let config = CaptureConfig {
            interface: iface.clone(),
            bpf_filter: cli.capture_filter.clone(),
            ..Default::default()
        };
        let capture = LiveCapture::new(config);
        let (tx, rx) = bounded(4096);
        capture.start(tx)?;
        app.capture_rx = Some(rx);
    }

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run_event_loop(&mut terminal, &mut app);

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

fn run_event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> Result<()> {
    let tick_rate = Duration::from_millis(50);

    loop {
        // Drain capture channel
        app.drain_capture_channel();

        // Render
        terminal.draw(|f| ui::draw(f, app))?;

        // Poll for input
        if event::poll(tick_rate)? {
            if let Event::Key(key) = event::read()? {
                handle_key(app, key);
            }
        }

        if !app.running {
            break;
        }
    }

    Ok(())
}

fn handle_key(app: &mut App, key: KeyEvent) {
    // Ctrl-C always quits
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        app.running = false;
        return;
    }

    match app.mode {
        AppMode::FilterEdit => handle_filter_key(app, key),
        AppMode::Normal => handle_normal_key(app, key),
    }
}

fn handle_filter_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Enter => {
            app.filter_text = app.filter_text_editing.clone();
            app.mode = AppMode::Normal;
            app.apply_filter();
        }
        KeyCode::Esc => {
            app.filter_text_editing = app.filter_text.clone();
            app.mode = AppMode::Normal;
        }
        KeyCode::Backspace => {
            app.filter_text_editing.pop();
        }
        KeyCode::Char(c) => {
            app.filter_text_editing.push(c);
        }
        _ => {}
    }
}

fn handle_normal_key(app: &mut App, key: KeyEvent) {
    match app.active_pane {
        Pane::PacketList => handle_list_key(app, key),
        Pane::PacketDetail => handle_detail_key(app, key),
        Pane::HexDump => handle_hex_key(app, key),
    }
}

fn handle_list_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Char('q') => app.running = false,
        KeyCode::Char('j') | KeyCode::Down => app.select_next(),
        KeyCode::Char('k') | KeyCode::Up => app.select_prev(),
        KeyCode::Char('g') | KeyCode::Home => app.select_first(),
        KeyCode::Char('G') | KeyCode::End => app.select_last(),
        KeyCode::Char('/') => {
            app.mode = AppMode::FilterEdit;
            app.filter_text_editing = app.filter_text.clone();
        }
        KeyCode::Tab => app.cycle_pane(),
        KeyCode::Char('f') => app.toggle_auto_scroll(),
        KeyCode::Enter => {
            // Expand all layers of selected packet for quick view
            if let Some(pkt) = app.selected_packet() {
                let layer_count = pkt.layers.len();
                for i in 0..layer_count {
                    app.detail_expanded.insert(i);
                }
            }
        }
        _ => {}
    }
}

fn handle_detail_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Char('q') => app.running = false,
        KeyCode::Char('j') | KeyCode::Down => app.detail_cursor_down(),
        KeyCode::Char('k') | KeyCode::Up => app.detail_cursor_up(),
        KeyCode::Enter | KeyCode::Char(' ') => app.toggle_detail_expand(),
        KeyCode::Tab => app.cycle_pane(),
        KeyCode::Char('/') => {
            app.mode = AppMode::FilterEdit;
            app.filter_text_editing = app.filter_text.clone();
        }
        _ => {}
    }
}

fn handle_hex_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Char('q') => app.running = false,
        KeyCode::Char('j') | KeyCode::Down => {
            app.hex_scroll = app.hex_scroll.saturating_add(1);
        }
        KeyCode::Char('k') | KeyCode::Up => {
            app.hex_scroll = app.hex_scroll.saturating_sub(1);
        }
        KeyCode::Tab => app.cycle_pane(),
        KeyCode::Char('/') => {
            app.mode = AppMode::FilterEdit;
            app.filter_text_editing = app.filter_text.clone();
        }
        _ => {}
    }
}
