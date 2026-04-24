use tshark_core::{Field, FieldValue, Layer, ProtocolId, TsharkError};

use crate::dissector::{DissectResult, Dissector};

pub struct IcmpDissector;

const ICMP_MIN_LEN: usize = 8;

impl Dissector for IcmpDissector {
    fn protocol_id(&self) -> ProtocolId {
        ProtocolId::Icmp
    }

    fn name(&self) -> &'static str {
        "Internet Control Message Protocol"
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
                name: "icmp.type".into(),
                display_name: "Type".into(),
                value: FieldValue::Unsigned(icmp_type as u64),
                byte_range: offset..offset + 1,
            },
            Field {
                name: "icmp.code".into(),
                display_name: "Code".into(),
                value: FieldValue::Unsigned(code as u64),
                byte_range: offset + 1..offset + 2,
            },
            Field {
                name: "icmp.checksum".into(),
                display_name: "Checksum".into(),
                value: FieldValue::Unsigned(checksum as u64),
                byte_range: offset + 2..offset + 4,
            },
        ];

        let type_name = match icmp_type {
            0 => "Echo Reply",
            3 => "Destination Unreachable",
            5 => "Redirect",
            8 => "Echo Request",
            11 => "Time Exceeded",
            _ => "Unknown",
        };

        // Parse echo request/reply extra fields
        let consumed = if (icmp_type == 0 || icmp_type == 8) && data.len() >= ICMP_MIN_LEN {
            let ident = u16::from_be_bytes([data[4], data[5]]);
            let seq = u16::from_be_bytes([data[6], data[7]]);
            fields.push(Field {
                name: "icmp.ident".into(),
                display_name: "Identifier".into(),
                value: FieldValue::Unsigned(ident as u64),
                byte_range: offset + 4..offset + 6,
            });
            fields.push(Field {
                name: "icmp.seq".into(),
                display_name: "Sequence Number".into(),
                value: FieldValue::Unsigned(seq as u64),
                byte_range: offset + 6..offset + 8,
            });
            data.len() // consume all remaining data
        } else {
            data.len()
        };

        let summary = if icmp_type == 0 || icmp_type == 8 {
            if data.len() >= ICMP_MIN_LEN {
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
                protocol: ProtocolId::Icmp,
                name: "Internet Control Message Protocol".into(),
                summary,
                header_range: offset..offset + consumed,
                fields,
            },
            bytes_consumed: consumed,
            next_protocol: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_icmp_echo_request() {
        let data = hex!(
            "08 00 4d 56"  // type=8(echo request), code=0, checksum
            "12 34 00 01"  // ident=0x1234, seq=1
            "DE AD BE EF"  // payload
        );
        let result = IcmpDissector.dissect(&data, 34).unwrap();
        assert!(result.layer.summary.contains("Echo Request"));
        assert!(result.layer.summary.contains("0x1234"));
        assert!(result.layer.summary.contains("seq=1"));
        assert!(result.next_protocol.is_none());
    }

    #[test]
    fn test_icmp_dest_unreachable() {
        let data = hex!("03 01 00 00 00 00 00 00");
        let result = IcmpDissector.dissect(&data, 0).unwrap();
        assert!(result.layer.summary.contains("Destination Unreachable"));
    }

    #[test]
    fn test_icmp_truncated() {
        let data = hex!("08 00");
        assert!(IcmpDissector.dissect(&data, 0).is_err());
    }
}
