use std::net::{Ipv4Addr, Ipv6Addr};

use tshark_core::{Field, FieldValue, Layer, ProtocolId, TsharkError};

use crate::dissector::{DissectResult, Dissector};

pub struct DnsDissector;

const DNS_HEADER_LEN: usize = 12;
const MAX_NAME_RECURSION: usize = 10;

impl Dissector for DnsDissector {
    fn protocol_id(&self) -> ProtocolId {
        ProtocolId::Dns
    }

    fn name(&self) -> &'static str {
        "Domain Name System"
    }

    fn dissect(&self, data: &[u8], offset: usize) -> Result<DissectResult, TsharkError> {
        if data.len() < DNS_HEADER_LEN {
            return Err(TsharkError::InsufficientData {
                need: DNS_HEADER_LEN,
                have: data.len(),
            });
        }

        let txn_id = u16::from_be_bytes([data[0], data[1]]);
        let flags = u16::from_be_bytes([data[2], data[3]]);
        let is_response = (flags >> 15) & 1 != 0;
        let opcode = (flags >> 11) & 0x0F;
        let rcode = flags & 0x0F;
        let qdcount = u16::from_be_bytes([data[4], data[5]]);
        let ancount = u16::from_be_bytes([data[6], data[7]]);
        let _nscount = u16::from_be_bytes([data[8], data[9]]);
        let _arcount = u16::from_be_bytes([data[10], data[11]]);

        let mut fields = vec![
            Field {
                name: "dns.id".into(),
                display_name: "Transaction ID".into(),
                value: FieldValue::Unsigned(txn_id as u64),
                byte_range: offset..offset + 2,
            },
            Field {
                name: "dns.flags.response".into(),
                display_name: "Response".into(),
                value: FieldValue::Bool(is_response),
                byte_range: offset + 2..offset + 4,
            },
            Field {
                name: "dns.flags.opcode".into(),
                display_name: "Opcode".into(),
                value: FieldValue::Unsigned(opcode as u64),
                byte_range: offset + 2..offset + 4,
            },
            Field {
                name: "dns.flags.rcode".into(),
                display_name: "Reply Code".into(),
                value: FieldValue::Unsigned(rcode as u64),
                byte_range: offset + 2..offset + 4,
            },
        ];

        let mut pos = DNS_HEADER_LEN;
        let mut query_names = Vec::new();
        let mut answer_strs = Vec::new();

        // Parse questions
        for _ in 0..qdcount {
            if pos >= data.len() {
                break;
            }
            let (name, new_pos) = decode_dns_name(data, pos)?;
            pos = new_pos;
            if pos + 4 > data.len() {
                break;
            }
            let qtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let _qclass = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
            pos += 4;

            fields.push(Field {
                name: "dns.qry.name".into(),
                display_name: "Query Name".into(),
                value: FieldValue::String(name.clone()),
                byte_range: offset + DNS_HEADER_LEN..offset + pos,
            });
            fields.push(Field {
                name: "dns.qry.type".into(),
                display_name: "Query Type".into(),
                value: FieldValue::Unsigned(qtype as u64),
                byte_range: offset + pos - 4..offset + pos - 2,
            });

            query_names.push(format!("{} {}", dns_type_name(qtype), name));
        }

        // Parse answers
        for _ in 0..ancount {
            if pos >= data.len() {
                break;
            }
            let (name, new_pos) = decode_dns_name(data, pos)?;
            pos = new_pos;
            if pos + 10 > data.len() {
                break;
            }
            let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let _rclass = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
            let ttl = u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);
            let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
            pos += 10;

            if pos + rdlength > data.len() {
                break;
            }

            fields.push(Field {
                name: "dns.resp.name".into(),
                display_name: "Response Name".into(),
                value: FieldValue::String(name.clone()),
                byte_range: offset + pos - 10..offset + pos,
            });
            fields.push(Field {
                name: "dns.resp.type".into(),
                display_name: "Response Type".into(),
                value: FieldValue::Unsigned(rtype as u64),
                byte_range: offset + pos - 10..offset + pos - 8,
            });
            fields.push(Field {
                name: "dns.resp.ttl".into(),
                display_name: "TTL".into(),
                value: FieldValue::Unsigned(ttl as u64),
                byte_range: offset + pos - 6..offset + pos - 2,
            });

            let rdata = &data[pos..pos + rdlength];
            match rtype {
                1 if rdlength == 4 => {
                    // A record
                    let ip = Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]);
                    fields.push(Field {
                        name: "dns.a".into(),
                        display_name: "A".into(),
                        value: FieldValue::Ipv4(ip),
                        byte_range: offset + pos..offset + pos + rdlength,
                    });
                    answer_strs.push(format!("{name} A {ip}"));
                }
                28 if rdlength == 16 => {
                    // AAAA record
                    let bytes: [u8; 16] = rdata.try_into().unwrap();
                    let ip = Ipv6Addr::from(bytes);
                    fields.push(Field {
                        name: "dns.aaaa".into(),
                        display_name: "AAAA".into(),
                        value: FieldValue::Ipv6(ip),
                        byte_range: offset + pos..offset + pos + rdlength,
                    });
                    answer_strs.push(format!("{name} AAAA {ip}"));
                }
                5 => {
                    // CNAME
                    if let Ok((cname, _)) = decode_dns_name(data, pos) {
                        fields.push(Field {
                            name: "dns.cname".into(),
                            display_name: "CNAME".into(),
                            value: FieldValue::String(cname.clone()),
                            byte_range: offset + pos..offset + pos + rdlength,
                        });
                        answer_strs.push(format!("{name} CNAME {cname}"));
                    }
                }
                _ => {
                    answer_strs.push(format!("{name} type={rtype}"));
                }
            }

            pos += rdlength;
        }

        let summary = if is_response {
            if answer_strs.is_empty() {
                format!("DNS response 0x{txn_id:04x} rcode={rcode}")
            } else {
                format!("DNS response: {}", answer_strs.join(", "))
            }
        } else {
            format!("DNS query: {}", query_names.join(", "))
        };

        Ok(DissectResult {
            layer: Layer {
                protocol: ProtocolId::Dns,
                name: "Domain Name System".into(),
                summary,
                header_range: offset..offset + data.len(),
                fields,
            },
            bytes_consumed: data.len(),
            next_protocol: None,
        })
    }
}

/// Decode a DNS domain name with compression pointer support.
fn decode_dns_name(data: &[u8], start: usize) -> Result<(String, usize), TsharkError> {
    let mut labels = Vec::new();
    let mut pos = start;
    let mut jumped = false;
    let mut end_pos = 0;
    let mut depth = 0;

    loop {
        if depth > MAX_NAME_RECURSION {
            return Err(TsharkError::Dissect {
                offset: start,
                message: "DNS name compression recursion limit exceeded".into(),
            });
        }
        if pos >= data.len() {
            return Err(TsharkError::InsufficientData {
                need: pos + 1,
                have: data.len(),
            });
        }

        let len_byte = data[pos];

        if len_byte == 0 {
            if !jumped {
                end_pos = pos + 1;
            }
            break;
        }

        if (len_byte & 0xC0) == 0xC0 {
            // Compression pointer
            if pos + 1 >= data.len() {
                return Err(TsharkError::InsufficientData {
                    need: pos + 2,
                    have: data.len(),
                });
            }
            let pointer = ((len_byte as usize & 0x3F) << 8) | data[pos + 1] as usize;
            if !jumped {
                end_pos = pos + 2;
            }
            pos = pointer;
            jumped = true;
            depth += 1;
        } else {
            // Regular label
            let label_len = len_byte as usize;
            pos += 1;
            if pos + label_len > data.len() {
                return Err(TsharkError::InsufficientData {
                    need: pos + label_len,
                    have: data.len(),
                });
            }
            let label = String::from_utf8_lossy(&data[pos..pos + label_len]).to_string();
            labels.push(label);
            pos += label_len;
            if !jumped {
                end_pos = pos;
            }
        }
    }

    let name = if labels.is_empty() {
        ".".to_string()
    } else {
        labels.join(".")
    };

    Ok((name, end_pos))
}

fn dns_type_name(qtype: u16) -> &'static str {
    match qtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        255 => "ANY",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_dns_query() {
        let data = hex!(
            "ab cd 01 00"  // id=0xabcd, flags=standard query
            "00 01 00 00"  // qdcount=1
            "00 00 00 00"
            // Query: example.com, type=A, class=IN
            "07 65 78 61 6d 70 6c 65"  // "example"
            "03 63 6f 6d"              // "com"
            "00"                       // end
            "00 01 00 01"              // type=A, class=IN
        );
        let result = DnsDissector.dissect(&data, 42).unwrap();
        assert!(result.layer.summary.contains("DNS query"));
        assert!(result.layer.summary.contains("example.com"));

        let qname = result.layer.fields.iter().find(|f| f.name == "dns.qry.name").unwrap();
        assert_eq!(qname.value, FieldValue::String("example.com".into()));
    }

    #[test]
    fn test_dns_response_with_a_record() {
        let data = hex!(
            "ab cd 81 80"  // id=0xabcd, flags=response
            "00 01 00 01"  // qdcount=1, ancount=1
            "00 00 00 00"
            // Query
            "07 65 78 61 6d 70 6c 65 03 63 6f 6d 00"
            "00 01 00 01"
            // Answer: pointer to query name, type=A, class=IN, ttl=300, rdlen=4
            "c0 0c"        // name pointer to offset 12
            "00 01 00 01"  // type=A, class=IN
            "00 00 01 2c"  // ttl=300
            "00 04"        // rdlength=4
            "5d b8 d8 22"  // 93.184.216.34
        );
        let result = DnsDissector.dissect(&data, 0).unwrap();
        assert!(result.layer.summary.contains("DNS response"));

        let a = result.layer.fields.iter().find(|f| f.name == "dns.a").unwrap();
        assert_eq!(a.value, FieldValue::Ipv4(Ipv4Addr::new(93, 184, 216, 34)));
    }

    #[test]
    fn test_dns_truncated() {
        let data = hex!("ab cd 01 00 00 01");
        assert!(DnsDissector.dissect(&data, 0).is_err());
    }

    #[test]
    fn test_dns_name_decompression() {
        // Simulates a packet with compression pointer
        let data = hex!(
            "00 00 00 00 00 00 00 00 00 00 00 00"  // DNS header (12 bytes)
            "03 66 6f 6f"  // "foo" at offset 12
            "03 62 61 72"  // "bar"
            "00"           // end -> "foo.bar" at offsets 12..20
        );
        let (name, end) = decode_dns_name(&data, 12).unwrap();
        assert_eq!(name, "foo.bar");
        assert_eq!(end, 21);
    }
}
