use std::net::Ipv4Addr;

use tshark_core::{Field, FieldValue, Layer, ProtocolId, TsharkError};

use crate::dissector::{DissectResult, Dissector};

pub struct ArpDissector;

impl Dissector for ArpDissector {
    fn protocol_id(&self) -> ProtocolId {
        ProtocolId::Arp
    }

    fn name(&self) -> &'static str {
        "Address Resolution Protocol"
    }

    fn dissect(&self, data: &[u8], offset: usize) -> Result<DissectResult, TsharkError> {
        if data.len() < 8 {
            return Err(TsharkError::InsufficientData {
                need: 8,
                have: data.len(),
            });
        }

        let hw_type = u16::from_be_bytes([data[0], data[1]]);
        let proto_type = u16::from_be_bytes([data[2], data[3]]);
        let hw_len = data[4] as usize;
        let proto_len = data[5] as usize;
        let operation = u16::from_be_bytes([data[6], data[7]]);

        let total_len = 8 + 2 * hw_len + 2 * proto_len;
        if data.len() < total_len {
            return Err(TsharkError::InsufficientData {
                need: total_len,
                have: data.len(),
            });
        }

        let mut fields = vec![
            Field {
                name: "arp.hw.type".into(),
                display_name: "Hardware Type".into(),
                value: FieldValue::Unsigned(hw_type as u64),
                byte_range: offset..offset + 2,
            },
            Field {
                name: "arp.proto.type".into(),
                display_name: "Protocol Type".into(),
                value: FieldValue::Unsigned(proto_type as u64),
                byte_range: offset + 2..offset + 4,
            },
            Field {
                name: "arp.opcode".into(),
                display_name: "Opcode".into(),
                value: FieldValue::Unsigned(operation as u64),
                byte_range: offset + 6..offset + 8,
            },
        ];

        let op_name = match operation {
            1 => "request",
            2 => "reply",
            _ => "unknown",
        };

        // Parse sender/target for Ethernet+IPv4 (hw_len=6, proto_len=4)
        let mut summary = format!("ARP {op_name}");
        if hw_len == 6 && proto_len == 4 {
            let sender_mac: [u8; 6] = data[8..14].try_into().unwrap();
            let sender_ip = Ipv4Addr::new(data[14], data[15], data[16], data[17]);
            let target_mac: [u8; 6] = data[18..24].try_into().unwrap();
            let target_ip = Ipv4Addr::new(data[24], data[25], data[26], data[27]);

            fields.extend([
                Field {
                    name: "arp.src.hw_mac".into(),
                    display_name: "Sender MAC Address".into(),
                    value: FieldValue::MacAddress(sender_mac),
                    byte_range: offset + 8..offset + 14,
                },
                Field {
                    name: "arp.src.proto_ipv4".into(),
                    display_name: "Sender IP Address".into(),
                    value: FieldValue::Ipv4(sender_ip),
                    byte_range: offset + 14..offset + 18,
                },
                Field {
                    name: "arp.dst.hw_mac".into(),
                    display_name: "Target MAC Address".into(),
                    value: FieldValue::MacAddress(target_mac),
                    byte_range: offset + 18..offset + 24,
                },
                Field {
                    name: "arp.dst.proto_ipv4".into(),
                    display_name: "Target IP Address".into(),
                    value: FieldValue::Ipv4(target_ip),
                    byte_range: offset + 24..offset + 28,
                },
            ]);

            summary = if operation == 1 {
                format!("Who has {target_ip}? Tell {sender_ip}")
            } else {
                format!("{sender_ip} is at {}", FieldValue::MacAddress(sender_mac))
            };
        }

        Ok(DissectResult {
            layer: Layer {
                protocol: ProtocolId::Arp,
                name: "Address Resolution Protocol".into(),
                summary,
                header_range: offset..offset + total_len,
                fields,
            },
            bytes_consumed: total_len,
            next_protocol: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_arp_request() {
        let data = hex!(
            "00 01 08 00 06 04 00 01"  // hw=1, proto=0x0800, hwlen=6, protolen=4, op=request
            "00 11 22 33 44 55"        // sender MAC
            "0a 00 00 02"              // sender IP: 10.0.0.2
            "00 00 00 00 00 00"        // target MAC
            "0a 00 00 01"              // target IP: 10.0.0.1
        );
        let result = ArpDissector.dissect(&data, 14).unwrap();
        assert_eq!(result.bytes_consumed, 28);
        assert!(result.layer.summary.contains("10.0.0.1"));
        assert!(result.layer.summary.contains("10.0.0.2"));
        assert!(result.next_protocol.is_none());
    }

    #[test]
    fn test_arp_reply() {
        let data = hex!(
            "00 01 08 00 06 04 00 02"
            "aa bb cc dd ee ff"
            "0a 00 00 01"
            "00 11 22 33 44 55"
            "0a 00 00 02"
        );
        let result = ArpDissector.dissect(&data, 0).unwrap();
        assert!(result.layer.summary.contains("10.0.0.1 is at"));
    }

    #[test]
    fn test_arp_truncated() {
        let data = hex!("00 01 08 00 06 04");
        assert!(ArpDissector.dissect(&data, 0).is_err());
    }
}
