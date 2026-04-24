use tshark_core::{Field, FieldValue, Layer, ProtocolId, TsharkError};

use crate::dissector::{DissectResult, Dissector};

pub struct TlsDissector;

const TLS_RECORD_HEADER_LEN: usize = 5;

impl Dissector for TlsDissector {
    fn protocol_id(&self) -> ProtocolId {
        ProtocolId::Tls
    }

    fn name(&self) -> &'static str {
        "Transport Layer Security"
    }

    fn dissect(&self, data: &[u8], offset: usize) -> Result<DissectResult, TsharkError> {
        if data.len() < TLS_RECORD_HEADER_LEN {
            return Err(TsharkError::InsufficientData {
                need: TLS_RECORD_HEADER_LEN,
                have: data.len(),
            });
        }

        let content_type = data[0];
        let version_major = data[1];
        let version_minor = data[2];
        let record_length = u16::from_be_bytes([data[3], data[4]]) as usize;

        // Validate this looks like TLS
        if content_type < 20 || content_type > 25 {
            return Err(TsharkError::Dissect {
                offset,
                message: format!("Invalid TLS content type: {content_type}"),
            });
        }

        let content_type_name = match content_type {
            20 => "Change Cipher Spec",
            21 => "Alert",
            22 => "Handshake",
            23 => "Application Data",
            _ => "Unknown",
        };

        let version_str = match (version_major, version_minor) {
            (3, 0) => "SSL 3.0",
            (3, 1) => "TLS 1.0",
            (3, 2) => "TLS 1.1",
            (3, 3) => "TLS 1.2",
            (3, 4) => "TLS 1.3",
            _ => "Unknown",
        };

        let mut fields = vec![
            Field {
                name: "tls.record.content_type".into(),
                display_name: "Content Type".into(),
                value: FieldValue::Unsigned(content_type as u64),
                byte_range: offset..offset + 1,
            },
            Field {
                name: "tls.record.version".into(),
                display_name: "Version".into(),
                value: FieldValue::String(version_str.into()),
                byte_range: offset + 1..offset + 3,
            },
            Field {
                name: "tls.record.length".into(),
                display_name: "Length".into(),
                value: FieldValue::Unsigned(record_length as u64),
                byte_range: offset + 3..offset + 5,
            },
        ];

        let mut summary = format!("{version_str} {content_type_name}");

        // Parse handshake messages
        if content_type == 22 && data.len() > TLS_RECORD_HEADER_LEN {
            let hs_data = &data[TLS_RECORD_HEADER_LEN..];
            if let Some((hs_fields, hs_summary)) = parse_handshake(hs_data, offset + TLS_RECORD_HEADER_LEN) {
                fields.extend(hs_fields);
                summary = format!("{version_str} {hs_summary}");
            }
        }

        let consumed = std::cmp::min(TLS_RECORD_HEADER_LEN + record_length, data.len());

        Ok(DissectResult {
            layer: Layer {
                protocol: ProtocolId::Tls,
                name: "Transport Layer Security".into(),
                summary,
                header_range: offset..offset + consumed,
                fields,
            },
            bytes_consumed: consumed,
            next_protocol: None,
        })
    }
}

fn parse_handshake(data: &[u8], offset: usize) -> Option<(Vec<Field>, String)> {
    if data.len() < 4 {
        return None;
    }

    let hs_type = data[0];
    let hs_length = ((data[1] as u32) << 16) | ((data[2] as u32) << 8) | (data[3] as u32);

    let hs_type_name = match hs_type {
        0 => "HelloRequest",
        1 => "ClientHello",
        2 => "ServerHello",
        11 => "Certificate",
        12 => "ServerKeyExchange",
        13 => "CertificateRequest",
        14 => "ServerHelloDone",
        15 => "CertificateVerify",
        16 => "ClientKeyExchange",
        20 => "Finished",
        _ => "Unknown",
    };

    let mut fields = vec![
        Field {
            name: "tls.handshake.type".into(),
            display_name: "Handshake Type".into(),
            value: FieldValue::Unsigned(hs_type as u64),
            byte_range: offset..offset + 1,
        },
        Field {
            name: "tls.handshake.length".into(),
            display_name: "Handshake Length".into(),
            value: FieldValue::Unsigned(hs_length as u64),
            byte_range: offset + 1..offset + 4,
        },
    ];

    let mut summary = hs_type_name.to_string();

    // Parse ClientHello / ServerHello
    if (hs_type == 1 || hs_type == 2) && data.len() > 6 {
        let hs_version_major = data[4];
        let hs_version_minor = data[5];
        let hs_version = match (hs_version_major, hs_version_minor) {
            (3, 1) => "TLS 1.0",
            (3, 2) => "TLS 1.1",
            (3, 3) => "TLS 1.2",
            (3, 4) => "TLS 1.3",
            _ => "Unknown",
        };

        fields.push(Field {
            name: "tls.handshake.version".into(),
            display_name: "Handshake Version".into(),
            value: FieldValue::String(hs_version.into()),
            byte_range: offset + 4..offset + 6,
        });

        // Try to extract SNI from ClientHello
        if hs_type == 1 {
            if let Some(sni) = extract_sni(data) {
                fields.push(Field {
                    name: "tls.handshake.extensions.sni".into(),
                    display_name: "Server Name".into(),
                    value: FieldValue::String(sni.clone()),
                    byte_range: offset..offset + data.len(),
                });
                summary = format!("ClientHello (SNI: {sni})");
            } else {
                summary = "ClientHello".into();
            }
        } else {
            summary = "ServerHello".into();
        }
    }

    Some((fields, summary))
}

/// Extract the SNI hostname from a ClientHello message.
fn extract_sni(data: &[u8]) -> Option<String> {
    // ClientHello structure after handshake header:
    // [4] handshake header (type + length)
    // [2] version
    // [32] random
    // [1+N] session id
    // [2+N] cipher suites
    // [1+N] compression methods
    // [2+N] extensions

    if data.len() < 4 + 2 + 32 + 1 {
        return None;
    }

    let mut pos = 4 + 2 + 32; // Skip header, version, random

    // Skip session ID
    if pos >= data.len() {
        return None;
    }
    let session_id_len = data[pos] as usize;
    pos += 1 + session_id_len;

    // Skip cipher suites
    if pos + 2 > data.len() {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;

    // Skip compression methods
    if pos >= data.len() {
        return None;
    }
    let comp_methods_len = data[pos] as usize;
    pos += 1 + comp_methods_len;

    // Extensions
    if pos + 2 > data.len() {
        return None;
    }
    let extensions_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;

    let ext_end = pos + extensions_len;
    while pos + 4 <= ext_end && pos + 4 <= data.len() {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0 {
            // SNI extension
            // [2] server name list length
            // [1] server name type (0 = hostname)
            // [2] server name length
            // [N] server name
            if ext_len >= 5 && pos + ext_len <= data.len() {
                let name_type = data[pos + 2];
                if name_type == 0 {
                    let name_len = u16::from_be_bytes([data[pos + 3], data[pos + 4]]) as usize;
                    if pos + 5 + name_len <= data.len() {
                        return String::from_utf8(data[pos + 5..pos + 5 + name_len].to_vec()).ok();
                    }
                }
            }
            return None;
        }

        pos += ext_len;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_tls_handshake_record() {
        let data = hex!(
            "16 03 01 00 05"  // Handshake, TLS 1.0, length=5
            "01 00 00 01 03"  // ClientHello stub
        );
        let result = TlsDissector.dissect(&data, 0).unwrap();
        assert_eq!(result.layer.protocol, ProtocolId::Tls);

        let ct = result.layer.fields.iter().find(|f| f.name == "tls.record.content_type").unwrap();
        assert_eq!(ct.value, FieldValue::Unsigned(22));
    }

    #[test]
    fn test_tls_application_data() {
        let data = hex!(
            "17 03 03 00 04"  // Application Data, TLS 1.2, length=4
            "DE AD BE EF"
        );
        let result = TlsDissector.dissect(&data, 0).unwrap();
        assert!(result.layer.summary.contains("Application Data"));
    }

    #[test]
    fn test_tls_not_tls() {
        let data = hex!("47 45 54 20 2f"); // "GET /"
        assert!(TlsDissector.dissect(&data, 0).is_err());
    }

    #[test]
    fn test_tls_truncated() {
        let data = hex!("16 03");
        assert!(TlsDissector.dissect(&data, 0).is_err());
    }
}
