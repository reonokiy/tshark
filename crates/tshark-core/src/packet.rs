use bytes::Bytes;
use chrono::{DateTime, Utc};

/// The link-layer type of a captured packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    Ethernet,
    RawIp,
    LinuxSll,
}

/// A raw packet as received from the capture engine, before any dissection.
#[derive(Debug, Clone)]
pub struct RawPacket {
    /// When this packet was captured.
    pub timestamp: DateTime<Utc>,
    /// Number of bytes actually captured (may be less than original_length).
    pub capture_length: u32,
    /// Original length of the packet on the wire.
    pub original_length: u32,
    /// The raw packet bytes. Uses `bytes::Bytes` for zero-copy slicing.
    pub data: Bytes,
    /// Link-layer type, determines the first dissector to use.
    pub link_type: LinkType,
}
