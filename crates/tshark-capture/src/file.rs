use std::path::Path;

use bytes::Bytes;
use chrono::{TimeZone, Utc};
use crossbeam_channel::Sender;

use tshark_core::{LinkType, RawPacket, TsharkError};

use crate::live::CaptureStats;

/// Read all packets from a pcap file and send them through the channel.
pub fn read_pcap(
    path: &Path,
    sender: Sender<RawPacket>,
) -> Result<CaptureStats, TsharkError> {
    let mut cap = pcap::Capture::from_file(path)
        .map_err(|e| TsharkError::Capture(format!("Failed to open pcap file: {e}")))?;

    let link_type = convert_link_type(cap.get_datalink());
    let mut packets_received: u64 = 0;

    loop {
        match cap.next_packet() {
            Ok(packet) => {
                let timestamp = Utc
                    .timestamp_opt(
                        packet.header.ts.tv_sec as i64,
                        (packet.header.ts.tv_usec as u32) * 1000,
                    )
                    .single()
                    .unwrap_or_else(Utc::now);

                let raw = RawPacket {
                    timestamp,
                    capture_length: packet.header.caplen,
                    original_length: packet.header.len,
                    data: Bytes::copy_from_slice(packet.data),
                    link_type,
                };

                packets_received += 1;
                if sender.send(raw).is_err() {
                    break;
                }
            }
            Err(pcap::Error::NoMorePackets) => break,
            Err(e) => {
                return Err(TsharkError::Capture(format!("Error reading pcap: {e}")));
            }
        }
    }

    Ok(CaptureStats {
        packets_received,
        packets_dropped: 0,
        duration: std::time::Duration::ZERO,
    })
}

fn convert_link_type(datalink: pcap::Linktype) -> LinkType {
    match datalink {
        pcap::Linktype::ETHERNET => LinkType::Ethernet,
        pcap::Linktype(12) => LinkType::RawIp,
        pcap::Linktype(113) => LinkType::LinuxSll,
        _ => LinkType::Ethernet,
    }
}
