use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Instant;

use bytes::Bytes;
use chrono::{DateTime, TimeZone, Utc};
use crossbeam_channel::Sender;

use tshark_core::{LinkType, RawPacket, TsharkError};

/// Configuration for a live packet capture session.
#[derive(Debug, Clone)]
pub struct CaptureConfig {
    /// Network interface name (e.g. "eth0", "lo").
    pub interface: String,
    /// Whether to enable promiscuous mode.
    pub promiscuous: bool,
    /// Maximum number of bytes to capture per packet.
    pub snaplen: i32,
    /// Read timeout in milliseconds.
    pub timeout_ms: i32,
    /// BPF capture filter expression (e.g. "tcp port 80").
    pub bpf_filter: Option<String>,
    /// Kernel buffer size in bytes.
    pub buffer_size: i32,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            interface: String::new(),
            promiscuous: true,
            snaplen: 65535,
            timeout_ms: 100,
            bpf_filter: None,
            buffer_size: 1_048_576, // 1 MB
        }
    }
}

/// Statistics from a completed capture session.
#[derive(Debug, Clone, Default)]
pub struct CaptureStats {
    pub packets_received: u64,
    pub packets_dropped: u64,
    pub duration: std::time::Duration,
}

/// A live packet capture handle.
pub struct LiveCapture {
    config: CaptureConfig,
    stop: Arc<AtomicBool>,
}

impl LiveCapture {
    pub fn new(config: CaptureConfig) -> Self {
        Self {
            config,
            stop: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Start capturing packets. Sends `RawPacket` values on the channel until
    /// `stop()` is called or an error occurs. Runs in a dedicated thread.
    pub fn start(
        &self,
        sender: Sender<RawPacket>,
    ) -> Result<JoinHandle<Result<CaptureStats, TsharkError>>, TsharkError> {
        let config = self.config.clone();
        let stop = self.stop.clone();

        let mut cap = pcap::Capture::from_device(config.interface.as_str())
            .map_err(|e| TsharkError::Capture(format!("Failed to open device: {e}")))?
            .promisc(config.promiscuous)
            .snaplen(config.snaplen)
            .timeout(config.timeout_ms)
            .buffer_size(config.buffer_size)
            .open()
            .map_err(|e| TsharkError::Capture(format!("Failed to activate capture: {e}")))?;

        if let Some(ref filter) = config.bpf_filter {
            cap.filter(filter, true)
                .map_err(|e| TsharkError::Capture(format!("Invalid BPF filter: {e}")))?;
        }

        let link_type = convert_link_type(cap.get_datalink());

        let handle = thread::spawn(move || {
            let start = Instant::now();
            let mut packets_received: u64 = 0;

            while !stop.load(Ordering::Relaxed) {
                match cap.next_packet() {
                    Ok(packet) => {
                        let timestamp = pcap_ts_to_datetime(packet.header.ts);
                        let raw = RawPacket {
                            timestamp,
                            capture_length: packet.header.caplen,
                            original_length: packet.header.len,
                            data: Bytes::copy_from_slice(packet.data),
                            link_type,
                        };
                        packets_received += 1;
                        if sender.send(raw).is_err() {
                            // Receiver dropped, stop capturing
                            break;
                        }
                    }
                    Err(pcap::Error::TimeoutExpired) => {
                        // Normal for non-blocking reads, just loop
                        continue;
                    }
                    Err(e) => {
                        return Err(TsharkError::Capture(format!("Capture error: {e}")));
                    }
                }
            }

            let pcap_stats = cap
                .stats()
                .map_err(|e| TsharkError::Capture(format!("Failed to get stats: {e}")))?;

            Ok(CaptureStats {
                packets_received,
                packets_dropped: pcap_stats.dropped as u64,
                duration: start.elapsed(),
            })
        });

        Ok(handle)
    }

    /// Signal the capture thread to stop.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    /// Returns whether a stop has been requested.
    pub fn is_stopped(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }
}

fn convert_link_type(datalink: pcap::Linktype) -> LinkType {
    match datalink {
        pcap::Linktype::ETHERNET => LinkType::Ethernet,
        pcap::Linktype(12) => LinkType::RawIp, // DLT_RAW
        pcap::Linktype(113) => LinkType::LinuxSll, // DLT_LINUX_SLL
        _ => LinkType::Ethernet, // Fallback
    }
}

fn pcap_ts_to_datetime(ts: libc::timeval) -> DateTime<Utc> {
    Utc.timestamp_opt(ts.tv_sec as i64, (ts.tv_usec as u32) * 1000)
        .single()
        .unwrap_or_else(Utc::now)
}
