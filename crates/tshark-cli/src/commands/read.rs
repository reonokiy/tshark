use std::path::Path;

use anyhow::Result;
use crossbeam_channel::unbounded;

use tshark_dissect::DissectorRegistry;
use tshark_filter::{evaluate, parse_filter, FilterExpr};

use crate::output;

pub fn run(
    file: &Path,
    display_filter: Option<&str>,
    verbose: bool,
    hex_dump: bool,
    format: Option<&str>,
) -> Result<()> {
    let filter = parse_display_filter(display_filter)?;
    let registry = DissectorRegistry::default_registry();
    let (tx, rx) = unbounded();

    tshark_capture::file::read_pcap(file, tx)?;

    let mut pkt_index = 0usize;
    let mut first_ts = None;

    for raw in rx {
        pkt_index += 1;
        let dissected = registry.dissect_packet(&raw, pkt_index);

        if let Some(ref f) = filter {
            if !evaluate(f, &dissected) {
                continue;
            }
        }

        if first_ts.is_none() {
            first_ts = Some(dissected.raw.timestamp);
        }
        let relative_ts = dissected
            .raw
            .timestamp
            .signed_duration_since(first_ts.unwrap());
        let ts_secs = relative_ts.num_microseconds().unwrap_or(0) as f64 / 1_000_000.0;

        match format {
            Some("json") => output::json::print_packet(&dissected),
            _ => {
                output::summary::print_packet(&dissected, ts_secs);
                if verbose {
                    output::verbose::print_packet(&dissected);
                }
                if hex_dump {
                    output::hex::print_packet(&dissected);
                }
            }
        }
    }

    Ok(())
}

fn parse_display_filter(filter: Option<&str>) -> Result<Option<FilterExpr>> {
    match filter {
        Some(f) => Ok(Some(parse_filter(f)?)),
        None => Ok(None),
    }
}
