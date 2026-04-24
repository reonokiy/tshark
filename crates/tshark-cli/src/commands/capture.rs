use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use crossbeam_channel::bounded;

use tshark_capture::{CaptureConfig, LiveCapture};
use tshark_dissect::DissectorRegistry;
use tshark_filter::{evaluate, parse_filter, FilterExpr};

use crate::output;

pub fn run(
    interface: &str,
    capture_filter: Option<&str>,
    display_filter: Option<&str>,
    count: Option<usize>,
    verbose: bool,
    hex_dump: bool,
    format: Option<&str>,
) -> Result<()> {
    let filter = parse_display_filter(display_filter)?;
    let registry = DissectorRegistry::default_registry();

    let config = CaptureConfig {
        interface: interface.to_string(),
        bpf_filter: capture_filter.map(String::from),
        ..Default::default()
    };

    let capture = LiveCapture::new(config);
    let (tx, rx) = bounded(4096);

    let handle = capture.start(tx)?;

    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_clone = stop_flag.clone();
    ctrlc::set_handler(move || {
        stop_clone.store(true, Ordering::Relaxed);
    })?;

    let mut pkt_index = 0usize;
    let mut displayed = 0usize;
    let mut first_ts = None;

    eprintln!("Capturing on interface '{interface}' ...");

    loop {
        if stop_flag.load(Ordering::Relaxed) {
            capture.stop();
            break;
        }

        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(raw) => {
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
                let ts_secs =
                    relative_ts.num_microseconds().unwrap_or(0) as f64 / 1_000_000.0;

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

                displayed += 1;
                if let Some(max) = count {
                    if displayed >= max {
                        capture.stop();
                        break;
                    }
                }
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
        }
    }

    if let Ok(result) = handle.join() {
        match result {
            Ok(stats) => {
                eprintln!(
                    "\n{} packets captured, {} dropped",
                    stats.packets_received, stats.packets_dropped
                );
            }
            Err(e) => eprintln!("\nCapture error: {e}"),
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
