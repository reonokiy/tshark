use crate::layer::{Field, Layer};
use crate::packet::RawPacket;
use crate::protocol::ProtocolId;

/// A fully dissected packet: the raw bytes plus all parsed protocol layers.
#[derive(Debug, Clone)]
pub struct DissectedPacket {
    /// 1-based packet number within the capture.
    pub index: usize,
    /// The original raw packet data.
    pub raw: RawPacket,
    /// Protocol layers, ordered from lowest (Ethernet) to highest (e.g. HTTP).
    pub layers: Vec<Layer>,
}

/// Well-known field aliases that map to multiple underlying fields.
/// For example, "tcp.port" should match either "tcp.srcport" or "tcp.dstport".
const FIELD_ALIASES: &[(&str, &[&str])] = &[
    ("tcp.port", &["tcp.srcport", "tcp.dstport"]),
    ("udp.port", &["udp.srcport", "udp.dstport"]),
    ("ip.addr", &["ip.src", "ip.dst"]),
    ("ipv6.addr", &["ipv6.src", "ipv6.dst"]),
    ("eth.addr", &["eth.src", "eth.dst"]),
];

impl DissectedPacket {
    /// Look up a field by its dotted name (e.g. "ip.src").
    /// Also supports virtual aliases like "tcp.port" which matches either src or dst.
    pub fn field(&self, name: &str) -> Option<&Field> {
        // First try direct lookup
        for layer in &self.layers {
            for field in &layer.fields {
                if field.name == name {
                    return Some(field);
                }
            }
        }

        // Then try aliases
        for &(alias, expansions) in FIELD_ALIASES {
            if name == alias {
                for expansion in expansions {
                    if let Some(f) = self.field(expansion) {
                        return Some(f);
                    }
                }
            }
        }

        None
    }

    /// Get all fields matching a name, including alias expansion.
    /// For example, "tcp.port" returns both "tcp.srcport" and "tcp.dstport" fields.
    pub fn fields_all(&self, name: &str) -> Vec<&Field> {
        // First try direct lookup
        let mut results: Vec<&Field> = self.layers
            .iter()
            .flat_map(|l| l.fields.iter())
            .filter(|f| f.name == name)
            .collect();

        if !results.is_empty() {
            return results;
        }

        // Then try aliases
        for &(alias, expansions) in FIELD_ALIASES {
            if name == alias {
                for expansion in expansions {
                    results.extend(self.fields_all(expansion));
                }
            }
        }

        results
    }

    /// Get all field names present in this packet.
    pub fn field_names(&self) -> Vec<&str> {
        self.layers
            .iter()
            .flat_map(|l| l.fields.iter().map(|f| f.name.as_str()))
            .collect()
    }

    /// One-line summary string for the CLI/TUI packet list view.
    /// Uses the highest-layer summary if available.
    pub fn summary(&self) -> String {
        self.layers
            .last()
            .map(|l| l.summary.clone())
            .unwrap_or_default()
    }

    /// Get the highest-level (most specific) protocol in this packet.
    pub fn top_protocol(&self) -> ProtocolId {
        self.layers
            .last()
            .map(|l| l.protocol)
            .unwrap_or(ProtocolId::Unknown(0))
    }

    /// Get source address string (from IP or Ethernet layer).
    pub fn source_addr(&self) -> String {
        // Try IPv4 first, then IPv6, then Ethernet
        if let Some(f) = self.field("ip.src") {
            return f.value.to_string();
        }
        if let Some(f) = self.field("ipv6.src") {
            return f.value.to_string();
        }
        if let Some(f) = self.field("eth.src") {
            return f.value.to_string();
        }
        String::new()
    }

    /// Get destination address string (from IP or Ethernet layer).
    pub fn dest_addr(&self) -> String {
        if let Some(f) = self.field("ip.dst") {
            return f.value.to_string();
        }
        if let Some(f) = self.field("ipv6.dst") {
            return f.value.to_string();
        }
        if let Some(f) = self.field("eth.dst") {
            return f.value.to_string();
        }
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::{FieldValue, Layer, Field};
    use crate::packet::LinkType;
    use bytes::Bytes;
    use chrono::Utc;
    use std::net::Ipv4Addr;

    fn make_test_packet() -> DissectedPacket {
        DissectedPacket {
            index: 1,
            raw: RawPacket {
                timestamp: Utc::now(),
                capture_length: 66,
                original_length: 66,
                data: Bytes::from_static(&[0u8; 66]),
                link_type: LinkType::Ethernet,
            },
            layers: vec![
                Layer {
                    protocol: ProtocolId::Ethernet,
                    name: "Ethernet II".into(),
                    summary: "00:11:22:33:44:55 -> aa:bb:cc:dd:ee:ff".into(),
                    header_range: 0..14,
                    fields: vec![
                        Field {
                            name: "eth.src".into(),
                            display_name: "Source".into(),
                            value: FieldValue::MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
                            byte_range: 6..12,
                        },
                        Field {
                            name: "eth.dst".into(),
                            display_name: "Destination".into(),
                            value: FieldValue::MacAddress([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
                            byte_range: 0..6,
                        },
                    ],
                },
                Layer {
                    protocol: ProtocolId::Ipv4,
                    name: "Internet Protocol Version 4".into(),
                    summary: "192.168.1.1 -> 10.0.0.1".into(),
                    header_range: 14..34,
                    fields: vec![
                        Field {
                            name: "ip.src".into(),
                            display_name: "Source Address".into(),
                            value: FieldValue::Ipv4(Ipv4Addr::new(192, 168, 1, 1)),
                            byte_range: 26..30,
                        },
                        Field {
                            name: "ip.dst".into(),
                            display_name: "Destination Address".into(),
                            value: FieldValue::Ipv4(Ipv4Addr::new(10, 0, 0, 1)),
                            byte_range: 30..34,
                        },
                    ],
                },
                Layer {
                    protocol: ProtocolId::Tcp,
                    name: "Transmission Control Protocol".into(),
                    summary: "54321 -> 80 [SYN]".into(),
                    header_range: 34..54,
                    fields: vec![
                        Field {
                            name: "tcp.srcport".into(),
                            display_name: "Source Port".into(),
                            value: FieldValue::Unsigned(54321),
                            byte_range: 34..36,
                        },
                        Field {
                            name: "tcp.dstport".into(),
                            display_name: "Destination Port".into(),
                            value: FieldValue::Unsigned(80),
                            byte_range: 36..38,
                        },
                    ],
                },
            ],
        }
    }

    #[test]
    fn test_field_lookup() {
        let pkt = make_test_packet();
        let f = pkt.field("ip.src").unwrap();
        assert_eq!(f.value, FieldValue::Ipv4(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn test_field_alias_tcp_port() {
        let pkt = make_test_packet();
        // tcp.port should resolve to tcp.srcport (first match)
        let f = pkt.field("tcp.port").unwrap();
        assert_eq!(f.value, FieldValue::Unsigned(54321));
    }

    #[test]
    fn test_field_not_found() {
        let pkt = make_test_packet();
        assert!(pkt.field("dns.qry.name").is_none());
    }

    #[test]
    fn test_top_protocol() {
        let pkt = make_test_packet();
        assert_eq!(pkt.top_protocol(), ProtocolId::Tcp);
    }

    #[test]
    fn test_source_dest_addr() {
        let pkt = make_test_packet();
        assert_eq!(pkt.source_addr(), "192.168.1.1");
        assert_eq!(pkt.dest_addr(), "10.0.0.1");
    }

    #[test]
    fn test_field_names() {
        let pkt = make_test_packet();
        let names = pkt.field_names();
        assert!(names.contains(&"ip.src"));
        assert!(names.contains(&"tcp.dstport"));
        assert_eq!(names.len(), 6);
    }
}
