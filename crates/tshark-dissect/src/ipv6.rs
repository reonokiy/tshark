use std::net::Ipv6Addr;

use tshark_core::{Field, FieldValue, Layer, ProtocolId, TsharkError};

use crate::dissector::{DissectResult, Dissector, HintTable, ProtocolHint};

pub struct Ipv6Dissector;

const IPV6_HEADER_LEN: usize = 40;

impl Dissector for Ipv6Dissector {
    fn protocol_id(&self) -> ProtocolId {
        ProtocolId::Ipv6
    }

    fn name(&self) -> &'static str {
        "Internet Protocol Version 6"
    }

    fn dissect(&self, data: &[u8], offset: usize) -> Result<DissectResult, TsharkError> {
        if data.len() < IPV6_HEADER_LEN {
            return Err(TsharkError::InsufficientData {
                need: IPV6_HEADER_LEN,
                have: data.len(),
            });
        }

        let first_word = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let version = (first_word >> 28) & 0x0F;
        let traffic_class = ((first_word >> 20) & 0xFF) as u8;
        let flow_label = first_word & 0x000F_FFFF;
        let payload_length = u16::from_be_bytes([data[4], data[5]]);
        let next_header = data[6];
        let hop_limit = data[7];

        let src_bytes: [u8; 16] = data[8..24].try_into().unwrap();
        let dst_bytes: [u8; 16] = data[24..40].try_into().unwrap();
        let src_ip = Ipv6Addr::from(src_bytes);
        let dst_ip = Ipv6Addr::from(dst_bytes);

        let fields = vec![
            Field {
                name: "ipv6.version".into(),
                display_name: "Version".into(),
                value: FieldValue::Unsigned(version as u64),
                byte_range: offset..offset + 4,
            },
            Field {
                name: "ipv6.traffic_class".into(),
                display_name: "Traffic Class".into(),
                value: FieldValue::Unsigned(traffic_class as u64),
                byte_range: offset..offset + 4,
            },
            Field {
                name: "ipv6.flow_label".into(),
                display_name: "Flow Label".into(),
                value: FieldValue::Unsigned(flow_label as u64),
                byte_range: offset..offset + 4,
            },
            Field {
                name: "ipv6.plen".into(),
                display_name: "Payload Length".into(),
                value: FieldValue::Unsigned(payload_length as u64),
                byte_range: offset + 4..offset + 6,
            },
            Field {
                name: "ipv6.nxt".into(),
                display_name: "Next Header".into(),
                value: FieldValue::Unsigned(next_header as u64),
                byte_range: offset + 6..offset + 7,
            },
            Field {
                name: "ipv6.hlim".into(),
                display_name: "Hop Limit".into(),
                value: FieldValue::Unsigned(hop_limit as u64),
                byte_range: offset + 7..offset + 8,
            },
            Field {
                name: "ipv6.src".into(),
                display_name: "Source Address".into(),
                value: FieldValue::Ipv6(src_ip),
                byte_range: offset + 8..offset + 24,
            },
            Field {
                name: "ipv6.dst".into(),
                display_name: "Destination Address".into(),
                value: FieldValue::Ipv6(dst_ip),
                byte_range: offset + 24..offset + 40,
            },
        ];

        Ok(DissectResult {
            layer: Layer {
                protocol: ProtocolId::Ipv6,
                name: "Internet Protocol Version 6".into(),
                summary: format!("{src_ip} -> {dst_ip}"),
                header_range: offset..offset + IPV6_HEADER_LEN,
                fields,
            },
            bytes_consumed: IPV6_HEADER_LEN,
            next_protocol: Some(ProtocolHint::ByNumber {
                table: HintTable::IpProtocol,
                value: next_header as u16,
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_ipv6_normal() {
        let data = hex!(
            "60 00 00 00"  // ver=6, tc=0, flow=0
            "00 18 06 40"  // plen=24, nxt=TCP(6), hlim=64
            "20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 01"  // src
            "20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 02"  // dst
        );
        let result = Ipv6Dissector.dissect(&data, 14).unwrap();
        assert_eq!(result.bytes_consumed, 40);

        let src = result.layer.fields.iter().find(|f| f.name == "ipv6.src").unwrap();
        assert_eq!(src.value, FieldValue::Ipv6("2001:db8::1".parse().unwrap()));

        match &result.next_protocol {
            Some(ProtocolHint::ByNumber { value, .. }) => assert_eq!(*value, 6),
            _ => panic!("Expected IpProtocol hint"),
        }
    }

    #[test]
    fn test_ipv6_truncated() {
        let data = hex!("60 00 00 00 00 18 06 40");
        assert!(Ipv6Dissector.dissect(&data, 0).is_err());
    }
}
