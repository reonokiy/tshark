
use tshark_core::{DissectedPacket, FieldValue, ProtocolId};

use crate::ast::{CompareOp, FilterExpr, FilterValue};

/// Evaluate a filter expression against a dissected packet.
pub fn evaluate(expr: &FilterExpr, packet: &DissectedPacket) -> bool {
    match expr {
        FilterExpr::And(a, b) => evaluate(a, packet) && evaluate(b, packet),
        FilterExpr::Or(a, b) => evaluate(a, packet) || evaluate(b, packet),
        FilterExpr::Not(e) => !evaluate(e, packet),
        FilterExpr::Exists(field) => field_exists(field, packet),
        FilterExpr::Comparison { field, op, value } => {
            eval_comparison(field, *op, value, packet)
        }
    }
}

/// Check if a field or protocol exists in the packet.
fn field_exists(name: &str, packet: &DissectedPacket) -> bool {
    // Check as a field name first
    if packet.field(name).is_some() {
        return true;
    }

    // Check as a protocol short name (e.g. "tcp", "dns")
    let proto = match name {
        "eth" | "ethernet" => Some(ProtocolId::Ethernet),
        "arp" => Some(ProtocolId::Arp),
        "ip" | "ipv4" => Some(ProtocolId::Ipv4),
        "ipv6" => Some(ProtocolId::Ipv6),
        "icmp" => Some(ProtocolId::Icmp),
        "icmpv6" => Some(ProtocolId::Icmpv6),
        "tcp" => Some(ProtocolId::Tcp),
        "udp" => Some(ProtocolId::Udp),
        "dns" => Some(ProtocolId::Dns),
        "http" => Some(ProtocolId::Http),
        "tls" | "ssl" => Some(ProtocolId::Tls),
        "vlan" => Some(ProtocolId::Vlan),
        _ => None,
    };

    if let Some(proto_id) = proto {
        return packet.layers.iter().any(|l| l.protocol == proto_id);
    }

    false
}

fn eval_comparison(field: &str, op: CompareOp, value: &FilterValue, packet: &DissectedPacket) -> bool {
    // For alias fields like tcp.port, check all matching fields (both srcport and dstport)
    let fields = packet.fields_all(field);
    if fields.is_empty() {
        return false;
    }
    fields.iter().any(|f| compare(&f.value, op, value))
}

fn compare(field_val: &FieldValue, op: CompareOp, filter_val: &FilterValue) -> bool {
    match op {
        CompareOp::Contains => compare_contains(field_val, filter_val),
        _ => compare_ordered(field_val, op, filter_val),
    }
}

fn compare_contains(field_val: &FieldValue, filter_val: &FilterValue) -> bool {
    match (field_val, filter_val) {
        (FieldValue::String(s), FilterValue::Str(pattern)) => s.contains(pattern.as_str()),
        (FieldValue::Bytes(b), FilterValue::Str(pattern)) => {
            let field_str = String::from_utf8_lossy(b);
            field_str.contains(pattern.as_str())
        }
        _ => false,
    }
}

fn compare_ordered(field_val: &FieldValue, op: CompareOp, filter_val: &FilterValue) -> bool {
    // Try numeric comparison first
    if let (Some(a), Some(b)) = (field_as_u64(field_val), filter_as_u64(filter_val)) {
        return match op {
            CompareOp::Eq => a == b,
            CompareOp::Ne => a != b,
            CompareOp::Gt => a > b,
            CompareOp::Ge => a >= b,
            CompareOp::Lt => a < b,
            CompareOp::Le => a <= b,
            CompareOp::Contains => false,
        };
    }

    // Try string comparison
    if let (Some(a), Some(b)) = (field_as_str(field_val), filter_as_str(filter_val)) {
        return match op {
            CompareOp::Eq => a == b,
            CompareOp::Ne => a != b,
            _ => false,
        };
    }

    // IPv4 comparison
    if let (FieldValue::Ipv4(a), FilterValue::Ipv4(b)) = (field_val, filter_val) {
        return match op {
            CompareOp::Eq => a == b,
            CompareOp::Ne => a != b,
            _ => false,
        };
    }

    // IPv6 comparison
    if let (FieldValue::Ipv6(a), FilterValue::Ipv6(b)) = (field_val, filter_val) {
        return match op {
            CompareOp::Eq => a == b,
            CompareOp::Ne => a != b,
            _ => false,
        };
    }

    // MAC comparison
    if let (FieldValue::MacAddress(a), FilterValue::Mac(b)) = (field_val, filter_val) {
        return match op {
            CompareOp::Eq => a == b,
            CompareOp::Ne => a != b,
            _ => false,
        };
    }

    // Bool comparison
    if let (FieldValue::Bool(a), FilterValue::Bool(b)) = (field_val, filter_val) {
        return match op {
            CompareOp::Eq => a == b,
            CompareOp::Ne => a != b,
            _ => false,
        };
    }

    // Incompatible types
    matches!(op, CompareOp::Ne)
}

fn field_as_u64(v: &FieldValue) -> Option<u64> {
    match v {
        FieldValue::Unsigned(n) => Some(*n),
        FieldValue::Signed(n) if *n >= 0 => Some(*n as u64),
        FieldValue::Bool(b) => Some(*b as u64),
        _ => None,
    }
}

fn filter_as_u64(v: &FilterValue) -> Option<u64> {
    match v {
        FilterValue::Integer(n) if *n >= 0 => Some(*n as u64),
        FilterValue::Bool(b) => Some(*b as u64),
        _ => None,
    }
}

fn field_as_str(v: &FieldValue) -> Option<&str> {
    match v {
        FieldValue::String(s) => Some(s),
        _ => None,
    }
}

fn filter_as_str(v: &FilterValue) -> Option<&str> {
    match v {
        FilterValue::Str(s) => Some(s),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_filter;
    use tshark_core::*;
    use bytes::Bytes;
    use chrono::Utc;
    use std::net::Ipv4Addr;

    fn make_tcp_packet() -> DissectedPacket {
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
                    summary: String::new(),
                    header_range: 0..14,
                    fields: vec![
                        Field {
                            name: "eth.src".into(),
                            display_name: "Source".into(),
                            value: FieldValue::MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
                            byte_range: 6..12,
                        },
                    ],
                },
                Layer {
                    protocol: ProtocolId::Ipv4,
                    name: "IPv4".into(),
                    summary: String::new(),
                    header_range: 14..34,
                    fields: vec![
                        Field {
                            name: "ip.src".into(),
                            display_name: "Source".into(),
                            value: FieldValue::Ipv4(Ipv4Addr::new(192, 168, 1, 100)),
                            byte_range: 26..30,
                        },
                        Field {
                            name: "ip.dst".into(),
                            display_name: "Destination".into(),
                            value: FieldValue::Ipv4(Ipv4Addr::new(10, 0, 0, 1)),
                            byte_range: 30..34,
                        },
                    ],
                },
                Layer {
                    protocol: ProtocolId::Tcp,
                    name: "TCP".into(),
                    summary: String::new(),
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
                        Field {
                            name: "tcp.flags.syn".into(),
                            display_name: "SYN".into(),
                            value: FieldValue::Bool(true),
                            byte_range: 47..48,
                        },
                    ],
                },
            ],
        }
    }

    #[test]
    fn test_ip_comparison() {
        let pkt = make_tcp_packet();
        let expr = parse_filter("ip.src == 192.168.1.100").unwrap();
        assert!(evaluate(&expr, &pkt));

        let expr = parse_filter("ip.src == 10.0.0.1").unwrap();
        assert!(!evaluate(&expr, &pkt));
    }

    #[test]
    fn test_port_comparison() {
        let pkt = make_tcp_packet();
        let expr = parse_filter("tcp.dstport == 80").unwrap();
        assert!(evaluate(&expr, &pkt));

        let expr = parse_filter("tcp.port == 80").unwrap();
        assert!(evaluate(&expr, &pkt));

        let expr = parse_filter("tcp.port == 443").unwrap();
        assert!(!evaluate(&expr, &pkt));
    }

    #[test]
    fn test_protocol_existence() {
        let pkt = make_tcp_packet();
        assert!(evaluate(&parse_filter("tcp").unwrap(), &pkt));
        assert!(evaluate(&parse_filter("ip").unwrap(), &pkt));
        assert!(!evaluate(&parse_filter("udp").unwrap(), &pkt));
        assert!(!evaluate(&parse_filter("dns").unwrap(), &pkt));
    }

    #[test]
    fn test_negation() {
        let pkt = make_tcp_packet();
        assert!(evaluate(&parse_filter("!udp").unwrap(), &pkt));
        assert!(!evaluate(&parse_filter("!tcp").unwrap(), &pkt));
    }

    #[test]
    fn test_and() {
        let pkt = make_tcp_packet();
        assert!(evaluate(&parse_filter("tcp && ip.src == 192.168.1.100").unwrap(), &pkt));
        assert!(!evaluate(&parse_filter("udp && ip.src == 192.168.1.100").unwrap(), &pkt));
    }

    #[test]
    fn test_or() {
        let pkt = make_tcp_packet();
        assert!(evaluate(&parse_filter("tcp || udp").unwrap(), &pkt));
        assert!(!evaluate(&parse_filter("udp || dns").unwrap(), &pkt));
    }

    #[test]
    fn test_complex_expression() {
        let pkt = make_tcp_packet();
        let expr = parse_filter("(tcp || udp) && ip.src == 192.168.1.100 && tcp.dstport == 80").unwrap();
        assert!(evaluate(&expr, &pkt));
    }

    #[test]
    fn test_boolean_field() {
        let pkt = make_tcp_packet();
        assert!(evaluate(&parse_filter("tcp.flags.syn == true").unwrap(), &pkt));
        assert!(evaluate(&parse_filter("tcp.flags.syn").unwrap(), &pkt));
    }

    #[test]
    fn test_mac_comparison() {
        let pkt = make_tcp_packet();
        let expr = parse_filter("eth.src == 00:11:22:33:44:55").unwrap();
        assert!(evaluate(&expr, &pkt));
    }

    #[test]
    fn test_numeric_inequality() {
        let pkt = make_tcp_packet();
        assert!(evaluate(&parse_filter("tcp.dstport > 79").unwrap(), &pkt));
        assert!(evaluate(&parse_filter("tcp.dstport >= 80").unwrap(), &pkt));
        assert!(evaluate(&parse_filter("tcp.dstport < 81").unwrap(), &pkt));
        assert!(!evaluate(&parse_filter("tcp.dstport > 80").unwrap(), &pkt));
    }
}
