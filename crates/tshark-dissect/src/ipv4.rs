use std::net::Ipv4Addr;

use tshark_core::{Field, FieldValue, Layer, ProtocolId, TsharkError};

use crate::dissector::{DissectResult, Dissector, HintTable, ProtocolHint};

pub struct Ipv4Dissector;

const IPV4_MIN_HEADER_LEN: usize = 20;

impl Dissector for Ipv4Dissector {
    fn protocol_id(&self) -> ProtocolId {
        ProtocolId::Ipv4
    }

    fn name(&self) -> &'static str {
        "Internet Protocol Version 4"
    }

    fn dissect(&self, data: &[u8], offset: usize) -> Result<DissectResult, TsharkError> {
        if data.len() < IPV4_MIN_HEADER_LEN {
            return Err(TsharkError::InsufficientData {
                need: IPV4_MIN_HEADER_LEN,
                have: data.len(),
            });
        }

        let version = (data[0] >> 4) & 0x0F;
        let ihl = (data[0] & 0x0F) as usize;
        let header_len = ihl * 4;

        if header_len < IPV4_MIN_HEADER_LEN || data.len() < header_len {
            return Err(TsharkError::Dissect {
                offset,
                message: format!("Invalid IHL: {ihl} (header_len={header_len})"),
            });
        }

        let dscp = (data[1] >> 2) & 0x3F;
        let ecn = data[1] & 0x03;
        let total_length = u16::from_be_bytes([data[2], data[3]]);
        let identification = u16::from_be_bytes([data[4], data[5]]);
        let flags_frag = u16::from_be_bytes([data[6], data[7]]);
        let df = (flags_frag >> 14) & 1;
        let mf = (flags_frag >> 13) & 1;
        let frag_offset = flags_frag & 0x1FFF;
        let ttl = data[8];
        let protocol = data[9];
        let checksum = u16::from_be_bytes([data[10], data[11]]);
        let src_ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let dst_ip = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

        let fields = vec![
            Field {
                name: "ip.version".into(),
                display_name: "Version".into(),
                value: FieldValue::Unsigned(version as u64),
                byte_range: offset..offset + 1,
            },
            Field {
                name: "ip.hdr_len".into(),
                display_name: "Header Length".into(),
                value: FieldValue::Unsigned(header_len as u64),
                byte_range: offset..offset + 1,
            },
            Field {
                name: "ip.dscp".into(),
                display_name: "DSCP".into(),
                value: FieldValue::Unsigned(dscp as u64),
                byte_range: offset + 1..offset + 2,
            },
            Field {
                name: "ip.ecn".into(),
                display_name: "ECN".into(),
                value: FieldValue::Unsigned(ecn as u64),
                byte_range: offset + 1..offset + 2,
            },
            Field {
                name: "ip.len".into(),
                display_name: "Total Length".into(),
                value: FieldValue::Unsigned(total_length as u64),
                byte_range: offset + 2..offset + 4,
            },
            Field {
                name: "ip.id".into(),
                display_name: "Identification".into(),
                value: FieldValue::Unsigned(identification as u64),
                byte_range: offset + 4..offset + 6,
            },
            Field {
                name: "ip.flags.df".into(),
                display_name: "Don't Fragment".into(),
                value: FieldValue::Bool(df != 0),
                byte_range: offset + 6..offset + 8,
            },
            Field {
                name: "ip.flags.mf".into(),
                display_name: "More Fragments".into(),
                value: FieldValue::Bool(mf != 0),
                byte_range: offset + 6..offset + 8,
            },
            Field {
                name: "ip.frag_offset".into(),
                display_name: "Fragment Offset".into(),
                value: FieldValue::Unsigned(frag_offset as u64),
                byte_range: offset + 6..offset + 8,
            },
            Field {
                name: "ip.ttl".into(),
                display_name: "Time to Live".into(),
                value: FieldValue::Unsigned(ttl as u64),
                byte_range: offset + 8..offset + 9,
            },
            Field {
                name: "ip.proto".into(),
                display_name: "Protocol".into(),
                value: FieldValue::Unsigned(protocol as u64),
                byte_range: offset + 9..offset + 10,
            },
            Field {
                name: "ip.checksum".into(),
                display_name: "Header Checksum".into(),
                value: FieldValue::Unsigned(checksum as u64),
                byte_range: offset + 10..offset + 12,
            },
            Field {
                name: "ip.src".into(),
                display_name: "Source Address".into(),
                value: FieldValue::Ipv4(src_ip),
                byte_range: offset + 12..offset + 16,
            },
            Field {
                name: "ip.dst".into(),
                display_name: "Destination Address".into(),
                value: FieldValue::Ipv4(dst_ip),
                byte_range: offset + 16..offset + 20,
            },
        ];

        let mut summary = format!("{src_ip} -> {dst_ip}");
        if mf != 0 || frag_offset != 0 {
            summary.push_str(" [Fragment]");
        }

        Ok(DissectResult {
            layer: Layer {
                protocol: ProtocolId::Ipv4,
                name: "Internet Protocol Version 4".into(),
                summary,
                header_range: offset..offset + header_len,
                fields,
            },
            bytes_consumed: header_len,
            next_protocol: Some(ProtocolHint::ByNumber {
                table: HintTable::IpProtocol,
                value: protocol as u16,
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_ipv4_normal() {
        let data = hex!(
            "45 00 00 28"  // ver=4, ihl=5, len=40
            "12 34 40 00"  // id=0x1234, DF=1
            "40 06 00 00"  // ttl=64, proto=TCP(6)
            "c0 a8 01 64"  // src=192.168.1.100
            "5d b8 d8 22"  // dst=93.184.216.34
        );
        let result = Ipv4Dissector.dissect(&data, 14).unwrap();
        assert_eq!(result.bytes_consumed, 20);

        let src = result.layer.fields.iter().find(|f| f.name == "ip.src").unwrap();
        assert_eq!(src.value, FieldValue::Ipv4(Ipv4Addr::new(192, 168, 1, 100)));

        let dst = result.layer.fields.iter().find(|f| f.name == "ip.dst").unwrap();
        assert_eq!(dst.value, FieldValue::Ipv4(Ipv4Addr::new(93, 184, 216, 34)));

        match &result.next_protocol {
            Some(ProtocolHint::ByNumber { value, .. }) => assert_eq!(*value, 6),
            _ => panic!("Expected IpProtocol hint"),
        }
    }

    #[test]
    fn test_ipv4_with_options() {
        // IHL=6 (24 bytes header)
        let mut data = hex!(
            "46 00 00 1c"
            "12 34 40 00"
            "40 06 00 00"
            "c0 a8 01 01"
            "c0 a8 01 02"
            "01 01 01 00"  // 4 bytes of options
        ).to_vec();
        let result = Ipv4Dissector.dissect(&data, 0).unwrap();
        assert_eq!(result.bytes_consumed, 24);
    }

    #[test]
    fn test_ipv4_truncated() {
        let data = hex!("45 00 00 28 12 34");
        assert!(Ipv4Dissector.dissect(&data, 0).is_err());
    }

    #[test]
    fn test_ipv4_fragment() {
        let data = hex!(
            "45 00 00 28"
            "12 34 20 80"  // MF=1, offset=128
            "40 06 00 00"
            "c0 a8 01 01"
            "c0 a8 01 02"
        );
        let result = Ipv4Dissector.dissect(&data, 0).unwrap();
        assert!(result.layer.summary.contains("[Fragment]"));
    }
}
