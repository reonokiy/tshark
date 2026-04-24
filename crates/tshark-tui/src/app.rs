use std::collections::HashSet;

use crossbeam_channel::Receiver;

use tshark_core::{DissectedPacket, RawPacket};
use tshark_dissect::DissectorRegistry;
use tshark_filter::{evaluate, parse_filter, FilterExpr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppMode {
    Normal,
    FilterEdit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pane {
    PacketList,
    PacketDetail,
    HexDump,
}

pub struct App {
    pub packets: Vec<DissectedPacket>,
    pub filtered_indices: Vec<usize>,
    pub selected_index: usize,
    pub filter_text: String,
    pub filter_text_editing: String,
    pub compiled_filter: Option<FilterExpr>,
    pub filter_error: Option<String>,
    pub mode: AppMode,
    pub active_pane: Pane,
    pub detail_scroll: usize,
    pub hex_scroll: usize,
    pub detail_expanded: HashSet<usize>,
    pub packets_received: u64,
    pub running: bool,
    pub auto_scroll: bool,
    pub registry: DissectorRegistry,
    pub capture_rx: Option<Receiver<RawPacket>>,
    // For field highlighting in hex dump
    pub selected_field_range: Option<std::ops::Range<usize>>,
    pub detail_cursor: usize,
}

impl App {
    pub fn new() -> Self {
        Self {
            packets: Vec::new(),
            filtered_indices: Vec::new(),
            selected_index: 0,
            filter_text: String::new(),
            filter_text_editing: String::new(),
            compiled_filter: None,
            filter_error: None,
            mode: AppMode::Normal,
            active_pane: Pane::PacketList,
            detail_scroll: 0,
            hex_scroll: 0,
            detail_expanded: HashSet::new(),
            packets_received: 0,
            running: true,
            auto_scroll: true,
            registry: DissectorRegistry::default_registry(),
            capture_rx: None,
            selected_field_range: None,
            detail_cursor: 0,
        }
    }

    pub fn selected_packet(&self) -> Option<&DissectedPacket> {
        self.filtered_indices
            .get(self.selected_index)
            .and_then(|&idx| self.packets.get(idx))
    }

    pub fn apply_filter(&mut self) {
        self.filter_error = None;
        if self.filter_text.trim().is_empty() {
            self.compiled_filter = None;
            self.refilter();
            return;
        }
        match parse_filter(&self.filter_text) {
            Ok(expr) => {
                self.compiled_filter = Some(expr);
                self.refilter();
            }
            Err(e) => {
                self.filter_error = Some(e.to_string());
            }
        }
    }

    fn refilter(&mut self) {
        self.filtered_indices.clear();
        for (i, pkt) in self.packets.iter().enumerate() {
            let pass = self
                .compiled_filter
                .as_ref()
                .map(|f| evaluate(f, pkt))
                .unwrap_or(true);
            if pass {
                self.filtered_indices.push(i);
            }
        }
        if self.selected_index >= self.filtered_indices.len() && !self.filtered_indices.is_empty() {
            self.selected_index = self.filtered_indices.len() - 1;
        }
    }

    pub fn drain_capture_channel(&mut self) {
        let rx = match self.capture_rx.as_ref() {
            Some(rx) => rx,
            None => return,
        };

        // Drain up to 256 packets per tick to stay responsive
        for _ in 0..256 {
            match rx.try_recv() {
                Ok(raw) => {
                    self.packets_received += 1;
                    let idx = self.packets.len();
                    let pkt_index = idx + 1;
                    let dissected = self.registry.dissect_packet(&raw, pkt_index);
                    let passes = self
                        .compiled_filter
                        .as_ref()
                        .map(|f| evaluate(f, &dissected))
                        .unwrap_or(true);
                    self.packets.push(dissected);
                    if passes {
                        self.filtered_indices.push(idx);
                    }
                }
                Err(_) => break,
            }
        }

        // Auto-scroll to bottom
        if self.auto_scroll && !self.filtered_indices.is_empty() {
            self.selected_index = self.filtered_indices.len() - 1;
        }
    }

    pub fn select_next(&mut self) {
        if self.selected_index + 1 < self.filtered_indices.len() {
            self.selected_index += 1;
            self.auto_scroll = false;
            self.detail_scroll = 0;
            self.detail_cursor = 0;
            self.selected_field_range = None;
        }
    }

    pub fn select_prev(&mut self) {
        if self.selected_index > 0 {
            self.selected_index -= 1;
            self.auto_scroll = false;
            self.detail_scroll = 0;
            self.detail_cursor = 0;
            self.selected_field_range = None;
        }
    }

    pub fn select_first(&mut self) {
        self.selected_index = 0;
        self.auto_scroll = false;
        self.detail_scroll = 0;
        self.detail_cursor = 0;
    }

    pub fn select_last(&mut self) {
        if !self.filtered_indices.is_empty() {
            self.selected_index = self.filtered_indices.len() - 1;
        }
    }

    pub fn cycle_pane(&mut self) {
        self.active_pane = match self.active_pane {
            Pane::PacketList => Pane::PacketDetail,
            Pane::PacketDetail => Pane::HexDump,
            Pane::HexDump => Pane::PacketList,
        };
    }

    pub fn toggle_auto_scroll(&mut self) {
        self.auto_scroll = !self.auto_scroll;
    }

    /// Get all detail lines for the selected packet (for rendering + navigation)
    pub fn detail_lines(&self) -> Vec<DetailLine> {
        let pkt = match self.selected_packet() {
            Some(p) => p,
            None => return Vec::new(),
        };

        let mut lines = Vec::new();
        for (layer_idx, layer) in pkt.layers.iter().enumerate() {
            let expanded = self.detail_expanded.contains(&layer_idx);
            let arrow = if expanded { "v" } else { ">" };
            lines.push(DetailLine::Layer {
                layer_idx,
                text: format!("{arrow} {}, {}", layer.name, layer.summary),
                expanded,
            });
            if expanded {
                for field in &layer.fields {
                    lines.push(DetailLine::Field {
                        text: format!("    {}: {}", field.display_name, field.value),
                        byte_range: field.byte_range.clone(),
                    });
                }
            }
        }
        lines
    }

    pub fn toggle_detail_expand(&mut self) {
        let lines = self.detail_lines();
        if let Some(line) = lines.get(self.detail_cursor) {
            if let DetailLine::Layer { layer_idx, expanded, .. } = line {
                if *expanded {
                    self.detail_expanded.remove(layer_idx);
                } else {
                    self.detail_expanded.insert(*layer_idx);
                }
            }
        }
    }

    pub fn detail_cursor_down(&mut self) {
        let max = self.detail_lines().len();
        if max > 0 && self.detail_cursor + 1 < max {
            self.detail_cursor += 1;
        }
        self.update_selected_field();
    }

    pub fn detail_cursor_up(&mut self) {
        if self.detail_cursor > 0 {
            self.detail_cursor -= 1;
        }
        self.update_selected_field();
    }

    fn update_selected_field(&mut self) {
        let lines = self.detail_lines();
        self.selected_field_range = lines
            .get(self.detail_cursor)
            .and_then(|l| match l {
                DetailLine::Field { byte_range, .. } => Some(byte_range.clone()),
                _ => None,
            });
    }
}

pub enum DetailLine {
    Layer {
        layer_idx: usize,
        text: String,
        expanded: bool,
    },
    Field {
        text: String,
        byte_range: std::ops::Range<usize>,
    },
}
