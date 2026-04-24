use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::Range;

use serde::Serialize;

use crate::protocol::ProtocolId;

/// One dissected protocol layer within a packet (e.g. the IPv4 header).
#[derive(Debug, Clone, Serialize)]
pub struct Layer {
    /// Which protocol this layer represents.
    pub protocol: ProtocolId,
    /// Full human-readable name, e.g. "Internet Protocol Version 4".
    pub name: String,
    /// One-line summary, e.g. "192.168.1.1 -> 10.0.0.1".
    pub summary: String,
    /// Byte range of this layer's header within the original packet.
    pub header_range: Range<usize>,
    /// Parsed fields within this layer.
    pub fields: Vec<Field>,
}

/// A single parsed field within a protocol layer.
#[derive(Debug, Clone, Serialize)]
pub struct Field {
    /// Dotted filter name, e.g. "ip.src".
    pub name: String,
    /// Human-readable display name, e.g. "Source Address".
    pub display_name: String,
    /// The parsed value.
    pub value: FieldValue,
    /// Byte range in the original packet that this field occupies.
    /// Used by the TUI to highlight corresponding bytes in the hex dump.
    pub byte_range: Range<usize>,
}

/// The value of a parsed protocol field.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum FieldValue {
    Unsigned(u64),
    Signed(i64),
    Bool(bool),
    Bytes(Vec<u8>),
    String(String),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    MacAddress([u8; 6]),
}

impl fmt::Display for FieldValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsigned(v) => write!(f, "{v}"),
            Self::Signed(v) => write!(f, "{v}"),
            Self::Bool(v) => write!(f, "{v}"),
            Self::Bytes(v) => {
                for (i, b) in v.iter().enumerate() {
                    if i > 0 {
                        write!(f, " ")?;
                    }
                    write!(f, "{b:02x}")?;
                }
                Ok(())
            }
            Self::String(v) => write!(f, "{v}"),
            Self::Ipv4(v) => write!(f, "{v}"),
            Self::Ipv6(v) => write!(f, "{v}"),
            Self::MacAddress(v) => write!(
                f,
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                v[0], v[1], v[2], v[3], v[4], v[5]
            ),
        }
    }
}

impl FieldValue {
    /// Try to interpret this value as an unsigned integer for comparisons.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Unsigned(v) => Some(*v),
            Self::Signed(v) if *v >= 0 => Some(*v as u64),
            Self::Bool(v) => Some(*v as u64),
            _ => None,
        }
    }

    /// Try to interpret this value as a string for comparisons.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(v) => Some(v),
            _ => None,
        }
    }
}
