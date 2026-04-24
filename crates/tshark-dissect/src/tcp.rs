use tshark_core::{Field, FieldValue, Layer, ProtocolId, TsharkError};

use crate::dissector::{DissectResult, Dissector, ProtocolHint};

pub struct TcpDissector;

const TCP_MIN_HEADER_LEN: usize = 20;

impl Dissector for TcpDissector {
    fn protocol_id(&self) -> ProtocolId {
        ProtocolId::Tcp
    }

    fn name(&self) -> &'static str {
        "Transmission Control Protocol"
    }

    fn dissect(&self, data: &[u8], offset: usize) -> Result<DissectResult, TsharkError> {
        if data.len() < TCP_MIN_HEADER_LEN {
            return Err(TsharkError::InsufficientData {
                need: TCP_MIN_HEADER_LEN,
                have: data.len(),
            });
        }

        let src_port = u16::from_be_bytes([data[0], data[1]]);
        let dst_port = u16::from_be_bytes([data[2], data[3]]);
        let seq = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let ack = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let data_offset = ((data[12] >> 4) & 0x0F) as usize;
        let header_len = data_offset * 4;
        let flags = data[13];
        let window = u16::from_be_bytes([data[14], data[15]]);
        let checksum = u16::from_be_bytes([data[16], data[17]]);
        let urgent = u16::from_be_bytes([data[18], data[19]]);

        if header_len < TCP_MIN_HEADER_LEN || data.len() < header_len {
            return Err(TsharkError::Dissect {
                offset,
                message: format!(
                    "Invalid TCP data offset: {data_offset} (header_len={header_len})"
                ),
            });
        }

        // Decode flags
        let fin = flags & 0x01 != 0;
        let syn = flags & 0x02 != 0;
        let rst = flags & 0x04 != 0;
        let psh = flags & 0x08 != 0;
        let ack_flag = flags & 0x10 != 0;
        let urg = flags & 0x20 != 0;
        let ece = flags & 0x40 != 0;
        let cwr = flags & 0x80 != 0;

        let mut fields = vec![
            Field {
                name: "tcp.srcport".into(),
                display_name: "Source Port".into(),
                value: FieldValue::Unsigned(src_port as u64),
                byte_range: offset..offset + 2,
            },
            Field {
                name: "tcp.dstport".into(),
                display_name: "Destination Port".into(),
                value: FieldValue::Unsigned(dst_port as u64),
                byte_range: offset + 2..offset + 4,
            },
            Field {
                name: "tcp.seq".into(),
                display_name: "Sequence Number".into(),
                value: FieldValue::Unsigned(seq as u64),
                byte_range: offset + 4..offset + 8,
            },
            Field {
                name: "tcp.ack".into(),
                display_name: "Acknowledgment Number".into(),
                value: FieldValue::Unsigned(ack as u64),
                byte_range: offset + 8..offset + 12,
            },
            Field {
                name: "tcp.hdr_len".into(),
                display_name: "Header Length".into(),
                value: FieldValue::Unsigned(header_len as u64),
                byte_range: offset + 12..offset + 13,
            },
            Field {
                name: "tcp.flags.fin".into(),
                display_name: "FIN".into(),
                value: FieldValue::Bool(fin),
                byte_range: offset + 13..offset + 14,
            },
            Field {
                name: "tcp.flags.syn".into(),
                display_name: "SYN".into(),
                value: FieldValue::Bool(syn),
                byte_range: offset + 13..offset + 14,
            },
            Field {
                name: "tcp.flags.rst".into(),
                display_name: "RST".into(),
                value: FieldValue::Bool(rst),
                byte_range: offset + 13..offset + 14,
            },
            Field {
                name: "tcp.flags.psh".into(),
                display_name: "PSH".into(),
                value: FieldValue::Bool(psh),
                byte_range: offset + 13..offset + 14,
            },
            Field {
                name: "tcp.flags.ack".into(),
                display_name: "ACK".into(),
                value: FieldValue::Bool(ack_flag),
                byte_range: offset + 13..offset + 14,
            },
            Field {
                name: "tcp.flags.urg".into(),
                display_name: "URG".into(),
                value: FieldValue::Bool(urg),
                byte_range: offset + 13..offset + 14,
            },
            Field {
                name: "tcp.window".into(),
                display_name: "Window Size".into(),
                value: FieldValue::Unsigned(window as u64),
                byte_range: offset + 14..offset + 16,
            },
            Field {
                name: "tcp.checksum".into(),
                display_name: "Checksum".into(),
                value: FieldValue::Unsigned(checksum as u64),
                byte_range: offset + 16..offset + 18,
            },
            Field {
                name: "tcp.urgent".into(),
                display_name: "Urgent Pointer".into(),
                value: FieldValue::Unsigned(urgent as u64),
                byte_range: offset + 18..offset + 20,
            },
        ];

        // Parse TCP options if header > 20 bytes
        if header_len > TCP_MIN_HEADER_LEN {
            parse_tcp_options(&data[20..header_len], offset + 20, &mut fields);
        }

        // Build flags string
        let mut flag_names = Vec::new();
        if syn { flag_names.push("SYN"); }
        if ack_flag { flag_names.push("ACK"); }
        if fin { flag_names.push("FIN"); }
        if rst { flag_names.push("RST"); }
        if psh { flag_names.push("PSH"); }
        if urg { flag_names.push("URG"); }
        if ece { flag_names.push("ECE"); }
        if cwr { flag_names.push("CWR"); }

        let flags_str = format!("[{}]", flag_names.join(", "));
        let summary = format!(
            "{src_port} -> {dst_port} {flags_str} Seq={seq} Ack={ack} Win={window}"
        );

        // Only hint at upper-layer protocol if there's payload data
        let has_payload = data.len() > header_len;
        let next_protocol = if has_payload {
            Some(ProtocolHint::ByPort {
                src: src_port,
                dst: dst_port,
            })
        } else {
            None
        };

        Ok(DissectResult {
            layer: Layer {
                protocol: ProtocolId::Tcp,
                name: "Transmission Control Protocol".into(),
                summary,
                header_range: offset..offset + header_len,
                fields,
            },
            bytes_consumed: header_len,
            next_protocol,
        })
    }
}

fn parse_tcp_options(data: &[u8], base_offset: usize, fields: &mut Vec<Field>) {
    let mut pos = 0;
    while pos < data.len() {
        let kind = data[pos];
        match kind {
            0 => break, // End of options
            1 => {
                pos += 1; // NOP
            }
            _ => {
                if pos + 1 >= data.len() {
                    break;
                }
                let len = data[pos + 1] as usize;
                if len < 2 || pos + len > data.len() {
                    break;
                }
                let opt_data = &data[pos..pos + len];
                let opt_offset = base_offset + pos;

                match kind {
                    2 if len == 4 => {
                        // MSS
                        let mss = u16::from_be_bytes([opt_data[2], opt_data[3]]);
                        fields.push(Field {
                            name: "tcp.options.mss".into(),
                            display_name: "Maximum Segment Size".into(),
                            value: FieldValue::Unsigned(mss as u64),
                            byte_range: opt_offset..opt_offset + len,
                        });
                    }
                    3 if len == 3 => {
                        // Window Scale
                        let scale = opt_data[2];
                        fields.push(Field {
                            name: "tcp.options.wscale".into(),
                            display_name: "Window Scale".into(),
                            value: FieldValue::Unsigned(scale as u64),
                            byte_range: opt_offset..opt_offset + len,
                        });
                    }
                    8 if len == 10 => {
                        // Timestamps
                        let tsval = u32::from_be_bytes([
                            opt_data[2], opt_data[3], opt_data[4], opt_data[5],
                        ]);
                        let tsecr = u32::from_be_bytes([
                            opt_data[6], opt_data[7], opt_data[8], opt_data[9],
                        ]);
                        fields.push(Field {
                            name: "tcp.options.timestamp.tsval".into(),
                            display_name: "Timestamp Value".into(),
                            value: FieldValue::Unsigned(tsval as u64),
                            byte_range: opt_offset + 2..opt_offset + 6,
                        });
                        fields.push(Field {
                            name: "tcp.options.timestamp.tsecr".into(),
                            display_name: "Timestamp Echo Reply".into(),
                            value: FieldValue::Unsigned(tsecr as u64),
                            byte_range: opt_offset + 6..opt_offset + 10,
                        });
                    }
                    4 if len == 2 => {
                        // SACK Permitted
                        fields.push(Field {
                            name: "tcp.options.sack_perm".into(),
                            display_name: "SACK Permitted".into(),
                            value: FieldValue::Bool(true),
                            byte_range: opt_offset..opt_offset + len,
                        });
                    }
                    _ => {} // Skip unknown options
                }

                pos += len;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_tcp_syn() {
        let data = hex!(
            "d4 31 00 50"  // src=54321, dst=80
            "00 00 03 e8"  // seq=1000
            "00 00 00 00"  // ack=0
            "50 02 ff ff"  // offset=5(20 bytes), SYN, win=65535
            "00 00 00 00"  // checksum, urgent
        );
        let result = TcpDissector.dissect(&data, 34).unwrap();
        assert_eq!(result.bytes_consumed, 20);
        assert!(result.layer.summary.contains("[SYN]"));
        assert!(result.layer.summary.contains("54321 -> 80"));

        let syn = result.layer.fields.iter().find(|f| f.name == "tcp.flags.syn").unwrap();
        assert_eq!(syn.value, FieldValue::Bool(true));

        // No payload, so no next protocol
        assert!(result.next_protocol.is_none());
    }

    #[test]
    fn test_tcp_syn_ack() {
        let data = hex!(
            "00 50 d4 31"
            "00 00 00 01"
            "00 00 03 e9"
            "50 12 ff ff"  // SYN+ACK
            "00 00 00 00"
        );
        let result = TcpDissector.dissect(&data, 0).unwrap();
        assert!(result.layer.summary.contains("[SYN, ACK]"));
    }

    #[test]
    fn test_tcp_with_payload() {
        let data = hex!(
            "d4 31 00 50"
            "00 00 03 e9"
            "00 00 00 01"
            "50 18 ff ff"  // PSH+ACK
            "00 00 00 00"
            "48 45 4c 4c 4f"  // "HELLO" payload
        );
        let result = TcpDissector.dissect(&data, 0).unwrap();
        assert!(result.layer.summary.contains("[ACK, PSH]"));
        assert!(result.next_protocol.is_some()); // has payload
    }

    #[test]
    fn test_tcp_with_options() {
        let data = hex!(
            "d4 31 00 50"
            "00 00 03 e8"
            "00 00 00 00"
            "80 02 ff ff"  // offset=8(32 bytes), SYN
            "00 00 00 00"
            // Options (12 bytes)
            "02 04 05 b4"  // MSS=1460
            "01"           // NOP
            "03 03 07"     // Window Scale=7
            "04 02"        // SACK Permitted
            "01 01"        // NOP NOP
        );
        let result = TcpDissector.dissect(&data, 0).unwrap();
        assert_eq!(result.bytes_consumed, 32);

        let mss = result.layer.fields.iter().find(|f| f.name == "tcp.options.mss").unwrap();
        assert_eq!(mss.value, FieldValue::Unsigned(1460));

        let ws = result.layer.fields.iter().find(|f| f.name == "tcp.options.wscale").unwrap();
        assert_eq!(ws.value, FieldValue::Unsigned(7));
    }

    #[test]
    fn test_tcp_truncated() {
        let data = hex!("d4 31 00 50 00 00 03 e8");
        assert!(TcpDissector.dissect(&data, 0).is_err());
    }
}
