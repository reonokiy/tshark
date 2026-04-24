use tshark_core::{Field, FieldValue, Layer, ProtocolId, TsharkError};

use crate::dissector::{DissectResult, Dissector, HintTable, ProtocolHint};

pub struct VlanDissector;

const VLAN_HEADER_LEN: usize = 4;

impl Dissector for VlanDissector {
    fn protocol_id(&self) -> ProtocolId {
        ProtocolId::Vlan
    }

    fn name(&self) -> &'static str {
        "802.1Q Virtual LAN"
    }

    fn dissect(&self, data: &[u8], offset: usize) -> Result<DissectResult, TsharkError> {
        if data.len() < VLAN_HEADER_LEN {
            return Err(TsharkError::InsufficientData {
                need: VLAN_HEADER_LEN,
                have: data.len(),
            });
        }

        let tci = u16::from_be_bytes([data[0], data[1]]);
        let priority = (tci >> 13) & 0x07;
        let dei = (tci >> 12) & 0x01;
        let vlan_id = tci & 0x0FFF;
        let inner_ethertype = u16::from_be_bytes([data[2], data[3]]);

        let fields = vec![
            Field {
                name: "vlan.id".into(),
                display_name: "VLAN ID".into(),
                value: FieldValue::Unsigned(vlan_id as u64),
                byte_range: offset..offset + 2,
            },
            Field {
                name: "vlan.priority".into(),
                display_name: "Priority".into(),
                value: FieldValue::Unsigned(priority as u64),
                byte_range: offset..offset + 2,
            },
            Field {
                name: "vlan.dei".into(),
                display_name: "DEI".into(),
                value: FieldValue::Bool(dei != 0),
                byte_range: offset..offset + 2,
            },
            Field {
                name: "vlan.etype".into(),
                display_name: "Type".into(),
                value: FieldValue::Unsigned(inner_ethertype as u64),
                byte_range: offset + 2..offset + 4,
            },
        ];

        Ok(DissectResult {
            layer: Layer {
                protocol: ProtocolId::Vlan,
                name: "802.1Q Virtual LAN".into(),
                summary: format!("VLAN {vlan_id}"),
                header_range: offset..offset + VLAN_HEADER_LEN,
                fields,
            },
            bytes_consumed: VLAN_HEADER_LEN,
            next_protocol: Some(ProtocolHint::ByNumber {
                table: HintTable::EtherType,
                value: inner_ethertype,
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_vlan_normal() {
        // Priority=3, DEI=0, VLAN ID=100, inner EtherType=IPv4
        let data = hex!("60 64 08 00");
        let result = VlanDissector.dissect(&data, 14).unwrap();
        assert_eq!(result.bytes_consumed, 4);

        let id_field = &result.layer.fields[0];
        assert_eq!(id_field.value, FieldValue::Unsigned(100));

        let prio_field = &result.layer.fields[1];
        assert_eq!(prio_field.value, FieldValue::Unsigned(3));
    }

    #[test]
    fn test_vlan_truncated() {
        let data = hex!("60 64");
        assert!(VlanDissector.dissect(&data, 0).is_err());
    }
}
