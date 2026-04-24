use tshark_core::{Field, FieldValue, Layer, ProtocolId, TsharkError};

use crate::dissector::{DissectResult, Dissector, ProtocolHint};

pub struct UdpDissector;

const UDP_HEADER_LEN: usize = 8;

impl Dissector for UdpDissector {
    fn protocol_id(&self) -> ProtocolId {
        ProtocolId::Udp
    }

    fn name(&self) -> &'static str {
        "User Datagram Protocol"
    }

    fn dissect(&self, data: &[u8], offset: usize) -> Result<DissectResult, TsharkError> {
        if data.len() < UDP_HEADER_LEN {
            return Err(TsharkError::InsufficientData {
                need: UDP_HEADER_LEN,
                have: data.len(),
            });
        }

        let src_port = u16::from_be_bytes([data[0], data[1]]);
        let dst_port = u16::from_be_bytes([data[2], data[3]]);
        let length = u16::from_be_bytes([data[4], data[5]]);
        let checksum = u16::from_be_bytes([data[6], data[7]]);

        let fields = vec![
            Field {
                name: "udp.srcport".into(),
                display_name: "Source Port".into(),
                value: FieldValue::Unsigned(src_port as u64),
                byte_range: offset..offset + 2,
            },
            Field {
                name: "udp.dstport".into(),
                display_name: "Destination Port".into(),
                value: FieldValue::Unsigned(dst_port as u64),
                byte_range: offset + 2..offset + 4,
            },
            Field {
                name: "udp.length".into(),
                display_name: "Length".into(),
                value: FieldValue::Unsigned(length as u64),
                byte_range: offset + 4..offset + 6,
            },
            Field {
                name: "udp.checksum".into(),
                display_name: "Checksum".into(),
                value: FieldValue::Unsigned(checksum as u64),
                byte_range: offset + 6..offset + 8,
            },
        ];

        Ok(DissectResult {
            layer: Layer {
                protocol: ProtocolId::Udp,
                name: "User Datagram Protocol".into(),
                summary: format!("{src_port} -> {dst_port} Len={length}"),
                header_range: offset..offset + UDP_HEADER_LEN,
                fields,
            },
            bytes_consumed: UDP_HEADER_LEN,
            next_protocol: Some(ProtocolHint::ByPort {
                src: src_port,
                dst: dst_port,
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_udp_normal() {
        let data = hex!(
            "30 39 00 35"  // src=12345, dst=53
            "00 1c 00 00"  // len=28, checksum=0
            "AB CD"        // payload
        );
        let result = UdpDissector.dissect(&data, 34).unwrap();
        assert_eq!(result.bytes_consumed, 8);
        assert!(result.layer.summary.contains("12345 -> 53"));

        match &result.next_protocol {
            Some(ProtocolHint::ByPort { src, dst }) => {
                assert_eq!(*src, 12345);
                assert_eq!(*dst, 53);
            }
            _ => panic!("Expected ByPort hint"),
        }
    }

    #[test]
    fn test_udp_truncated() {
        let data = hex!("30 39 00 35 00 1c");
        assert!(UdpDissector.dissect(&data, 0).is_err());
    }
}
