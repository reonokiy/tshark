use tshark_core::{Field, FieldValue, Layer, ProtocolId, TsharkError};

use crate::dissector::{DissectResult, Dissector};

pub struct HttpDissector;

const HTTP_METHODS: &[&str] = &[
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE",
];

impl Dissector for HttpDissector {
    fn protocol_id(&self) -> ProtocolId {
        ProtocolId::Http
    }

    fn name(&self) -> &'static str {
        "Hypertext Transfer Protocol"
    }

    fn dissect(&self, data: &[u8], offset: usize) -> Result<DissectResult, TsharkError> {
        if data.len() < 4 {
            return Err(TsharkError::InsufficientData {
                need: 4,
                have: data.len(),
            });
        }

        // Try to interpret as UTF-8 text
        let text = match std::str::from_utf8(data) {
            Ok(t) => t,
            Err(_) => {
                return Err(TsharkError::Dissect {
                    offset,
                    message: "HTTP data is not valid UTF-8".into(),
                });
            }
        };

        let mut fields = Vec::new();
        let summary;

        // Check if this is a request or response
        if text.starts_with("HTTP/") {
            // Response
            let first_line = text.lines().next().unwrap_or("");
            let parts: Vec<&str> = first_line.splitn(3, ' ').collect();

            let version = parts.first().copied().unwrap_or("HTTP/1.1");
            let status_code = parts.get(1).and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
            let reason = parts.get(2).copied().unwrap_or("");

            fields.push(Field {
                name: "http.response.version".into(),
                display_name: "Version".into(),
                value: FieldValue::String(version.into()),
                byte_range: offset..offset + version.len(),
            });
            fields.push(Field {
                name: "http.response.code".into(),
                display_name: "Status Code".into(),
                value: FieldValue::Unsigned(status_code as u64),
                byte_range: offset..offset + first_line.len(),
            });
            fields.push(Field {
                name: "http.response.phrase".into(),
                display_name: "Reason Phrase".into(),
                value: FieldValue::String(reason.into()),
                byte_range: offset..offset + first_line.len(),
            });

            summary = format!("HTTP/{} {status_code} {reason}", version.trim_start_matches("HTTP/"));
        } else if HTTP_METHODS.iter().any(|m| text.starts_with(m)) {
            // Request
            let first_line = text.lines().next().unwrap_or("");
            let parts: Vec<&str> = first_line.splitn(3, ' ').collect();

            let method = parts.first().copied().unwrap_or("");
            let uri = parts.get(1).copied().unwrap_or("");
            let version = parts.get(2).copied().unwrap_or("HTTP/1.1");

            fields.push(Field {
                name: "http.request.method".into(),
                display_name: "Method".into(),
                value: FieldValue::String(method.into()),
                byte_range: offset..offset + method.len(),
            });
            fields.push(Field {
                name: "http.request.uri".into(),
                display_name: "URI".into(),
                value: FieldValue::String(uri.into()),
                byte_range: offset..offset + first_line.len(),
            });
            fields.push(Field {
                name: "http.request.version".into(),
                display_name: "Version".into(),
                value: FieldValue::String(version.into()),
                byte_range: offset..offset + first_line.len(),
            });

            summary = format!("{method} {uri} {version}");
        } else {
            return Err(TsharkError::Dissect {
                offset,
                message: "Not an HTTP message".into(),
            });
        }

        // Parse headers
        let _header_end = text.find("\r\n\r\n").or_else(|| text.find("\n\n"));
        for line in text.lines().skip(1) {
            if line.is_empty() {
                break;
            }
            if let Some((key, value)) = line.split_once(':') {
                let key = key.trim();
                let value = value.trim();
                let field_name = match key.to_lowercase().as_str() {
                    "host" => "http.host",
                    "content-type" => "http.content_type",
                    "content-length" => "http.content_length",
                    "user-agent" => "http.user_agent",
                    "server" => "http.server",
                    _ => continue, // Skip unknown headers to avoid field bloat
                };
                fields.push(Field {
                    name: field_name.into(),
                    display_name: key.into(),
                    value: FieldValue::String(value.into()),
                    byte_range: offset..offset + data.len(),
                });
            }
        }

        Ok(DissectResult {
            layer: Layer {
                protocol: ProtocolId::Http,
                name: "Hypertext Transfer Protocol".into(),
                summary,
                header_range: offset..offset + data.len(),
                fields,
            },
            bytes_consumed: data.len(),
            next_protocol: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_get_request() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test/1.0\r\n\r\n";
        let result = HttpDissector.dissect(data, 54).unwrap();
        assert!(result.layer.summary.contains("GET / HTTP/1.1"));

        let method = result.layer.fields.iter().find(|f| f.name == "http.request.method").unwrap();
        assert_eq!(method.value, FieldValue::String("GET".into()));

        let host = result.layer.fields.iter().find(|f| f.name == "http.host").unwrap();
        assert_eq!(host.value, FieldValue::String("example.com".into()));
    }

    #[test]
    fn test_http_response() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nHello";
        let result = HttpDissector.dissect(data, 0).unwrap();
        assert!(result.layer.summary.contains("200 OK"));

        let code = result.layer.fields.iter().find(|f| f.name == "http.response.code").unwrap();
        assert_eq!(code.value, FieldValue::Unsigned(200));
    }

    #[test]
    fn test_http_not_http() {
        let data = b"\x16\x03\x01\x00\x05"; // TLS record header
        assert!(HttpDissector.dissect(data, 0).is_err());
    }

    #[test]
    fn test_http_truncated() {
        let data = b"GE";
        assert!(HttpDissector.dissect(data, 0).is_err());
    }
}
