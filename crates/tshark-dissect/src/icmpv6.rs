use tshark_core::{Field, FieldValue, Layer, ProtocolId, TsharkError};

use crate::dissector::{DissectResult, Dissector};

pub struct Icmpv6Dissector;

impl Dissector for Icmpv6Dissector {
    fn protocol_id(&self) -> ProtocolId {
        ProtocolId::Icmpv6
    }

    fn name(&self) -> &'static str {
        "Internet Control Message Protocol v6"
    }

    fn dissect(&self, data: &[u8], offset: usize) -> Result<DissectResult, TsharkError> {
        if data.len() < 4 {
            return Err(TsharkError::InsufficientData {
                need: 4,
                have: data.len(),
            });
        }

        let icmp_type = data[0];
        let code = data[1];
        let checksum = u16::from_be_bytes([data[2], data[3]]);

        let mut fields = vec![
            Field {
                name: "icmpv6.type".into(),
                display_name: "Type".into(),
                value: FieldValue::Unsigned(icmp_type as u64),
                byte_range: offset..offset + 1,
            },
            Field {
                name: "icmpv6.code".into(),
                display_name: "Code".into(),
                value: FieldValue::Unsigned(code as u64),
                byte_range: offset + 1..offset + 2,
            },
            Field {
                name: "icmpv6.checksum".into(),
                display_name: "Checksum".into(),
                value: FieldValue::Unsigned(checksum as u64),
                byte_range: offset + 2..offset + 4,
            },
        ];

        let type_name = match icmp_type {
            1 => "Destination Unreachable",
            2 => "Packet Too Big",
            3 => "Time Exceeded",
            128 => "Echo Request",
            129 => "Echo Reply",
            133 => "Router Solicitation",
            134 => "Router Advertisement",
            135 => "Neighbor Solicitation",
            136 => "Neighbor Advertisement",
            _ => "Unknown",
        };

        // Parse echo request/reply
        if (icmp_type == 128 || icmp_type == 129) && data.len() >= 8 {
            let ident = u16::from_be_bytes([data[4], data[5]]);
            let seq = u16::from_be_bytes([data[6], data[7]]);
            fields.push(Field {
                name: "icmpv6.ident".into(),
                display_name: "Identifier".into(),
                value: FieldValue::Unsigned(ident as u64),
                byte_range: offset + 4..offset + 6,
            });
            fields.push(Field {
                name: "icmpv6.seq".into(),
                display_name: "Sequence Number".into(),
                value: FieldValue::Unsigned(seq as u64),
                byte_range: offset + 6..offset + 8,
            });
        }

        let summary = if icmp_type == 128 || icmp_type == 129 {
            if data.len() >= 8 {
                let ident = u16::from_be_bytes([data[4], data[5]]);
                let seq = u16::from_be_bytes([data[6], data[7]]);
                format!("{type_name} id=0x{ident:04x} seq={seq}")
            } else {
                type_name.to_string()
            }
        } else {
            format!("{type_name} (type={icmp_type}, code={code})")
        };

        Ok(DissectResult {
            layer: Layer {
                protocol: ProtocolId::Icmpv6,
                name: "Internet Control Message Protocol v6".into(),
                summary,
                header_range: offset..offset + data.len(),
                fields,
            },
            bytes_consumed: data.len(),
            next_protocol: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_icmpv6_echo_request() {
        let data = hex!("80 00 ab cd 00 01 00 05 DE AD");
        let result = Icmpv6Dissector.dissect(&data, 0).unwrap();
        assert!(result.layer.summary.contains("Echo Request"));
        assert!(result.layer.summary.contains("seq=5"));
    }

    #[test]
    fn test_icmpv6_neighbor_solicitation() {
        let data = hex!("87 00 ab cd 00 00 00 00");
        let result = Icmpv6Dissector.dissect(&data, 0).unwrap();
        assert!(result.layer.summary.contains("Neighbor Solicitation"));
    }

    #[test]
    fn test_icmpv6_truncated() {
        let data = hex!("80 00");
        assert!(Icmpv6Dissector.dissect(&data, 0).is_err());
    }
}
