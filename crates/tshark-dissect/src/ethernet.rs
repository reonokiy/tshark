use tshark_core::{Field, FieldValue, Layer, ProtocolId, TsharkError};

use crate::dissector::{DissectResult, Dissector, HintTable, ProtocolHint};

pub struct EthernetDissector;

const ETHERNET_HEADER_LEN: usize = 14;

impl Dissector for EthernetDissector {
    fn protocol_id(&self) -> ProtocolId {
        ProtocolId::Ethernet
    }

    fn name(&self) -> &'static str {
        "Ethernet II"
    }

    fn dissect(&self, data: &[u8], offset: usize) -> Result<DissectResult, TsharkError> {
        if data.len() < ETHERNET_HEADER_LEN {
            return Err(TsharkError::InsufficientData {
                need: ETHERNET_HEADER_LEN,
                have: data.len(),
            });
        }

        let dst_mac: [u8; 6] = data[0..6].try_into().unwrap();
        let src_mac: [u8; 6] = data[6..12].try_into().unwrap();
        let ethertype = u16::from_be_bytes([data[12], data[13]]);

        let fields = vec![
            Field {
                name: "eth.dst".into(),
                display_name: "Destination".into(),
                value: FieldValue::MacAddress(dst_mac),
                byte_range: offset..offset + 6,
            },
            Field {
                name: "eth.src".into(),
                display_name: "Source".into(),
                value: FieldValue::MacAddress(src_mac),
                byte_range: offset + 6..offset + 12,
            },
            Field {
                name: "eth.type".into(),
                display_name: "Type".into(),
                value: FieldValue::Unsigned(ethertype as u64),
                byte_range: offset + 12..offset + 14,
            },
        ];

        let summary = format!(
            "{} -> {}",
            FieldValue::MacAddress(src_mac),
            FieldValue::MacAddress(dst_mac)
        );

        Ok(DissectResult {
            layer: Layer {
                protocol: ProtocolId::Ethernet,
                name: "Ethernet II".into(),
                summary,
                header_range: offset..offset + ETHERNET_HEADER_LEN,
                fields,
            },
            bytes_consumed: ETHERNET_HEADER_LEN,
            next_protocol: Some(ProtocolHint::ByNumber {
                table: HintTable::EtherType,
                value: ethertype,
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_ethernet_normal() {
        let data = hex!("ff ff ff ff ff ff 00 11 22 33 44 55 08 00 DE AD");
        let result = EthernetDissector.dissect(&data, 0).unwrap();
        assert_eq!(result.layer.protocol, ProtocolId::Ethernet);
        assert_eq!(result.bytes_consumed, 14);
        assert_eq!(result.layer.fields.len(), 3);

        // Check ethertype field
        let etype = &result.layer.fields[2];
        assert_eq!(etype.value, FieldValue::Unsigned(0x0800));

        // Check next protocol hint
        match &result.next_protocol {
            Some(ProtocolHint::ByNumber { table, value }) => {
                assert_eq!(*table, HintTable::EtherType);
                assert_eq!(*value, 0x0800);
            }
            _ => panic!("Expected ByNumber hint"),
        }
    }

    #[test]
    fn test_ethernet_minimum_size() {
        let data = hex!("ff ff ff ff ff ff 00 11 22 33 44 55 08 06");
        let result = EthernetDissector.dissect(&data, 0).unwrap();
        assert_eq!(result.bytes_consumed, 14);
    }

    #[test]
    fn test_ethernet_truncated() {
        let data = hex!("ff ff ff ff ff ff 00 11 22 33");
        let result = EthernetDissector.dissect(&data, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_ethernet_with_offset() {
        let data = hex!("ff ff ff ff ff ff 00 11 22 33 44 55 08 00");
        let result = EthernetDissector.dissect(&data, 100).unwrap();
        assert_eq!(result.layer.header_range, 100..114);
        assert_eq!(result.layer.fields[0].byte_range, 100..106);
    }
}
