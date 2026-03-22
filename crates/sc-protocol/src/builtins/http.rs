use crate::dissector::*;
use crate::model::*;
use sc_core::Protocol;

/// Native HTTP/1.x dissector.
pub struct HttpDissector;

fn is_http_method(s: &[u8]) -> bool {
    matches!(
        s,
        b"GET"
            | b"POST"
            | b"PUT"
            | b"DELETE"
            | b"HEAD"
            | b"OPTIONS"
            | b"PATCH"
            | b"CONNECT"
            | b"TRACE"
    )
}

fn status_category(code: u16) -> &'static str {
    match code {
        100..=199 => "Informational",
        200..=299 => "Success",
        300..=399 => "Redirection",
        400..=499 => "Client Error",
        500..=599 => "Server Error",
        _ => "Unknown",
    }
}

fn content_type_label(ct: &str) -> &'static str {
    let ct_lower = ct.to_ascii_lowercase();
    if ct_lower.contains("json") {
        "JSON"
    } else if ct_lower.contains("html") {
        "HTML"
    } else if ct_lower.contains("xml") {
        "XML"
    } else if ct_lower.contains("javascript") {
        "JavaScript"
    } else if ct_lower.contains("css") {
        "CSS"
    } else if ct_lower.contains("image") {
        "Image"
    } else if ct_lower.contains("octet-stream") {
        "Binary"
    } else if ct_lower.contains("text") {
        "Text"
    } else {
        "Other"
    }
}

/// Try to find end of HTTP headers (double CRLF).
fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
}

/// Parse header lines from header block.
fn parse_headers(header_block: &[u8]) -> Vec<(&str, &str)> {
    let text = match std::str::from_utf8(header_block) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let mut headers = Vec::new();
    for line in text.split("\r\n") {
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim(), value.trim()));
        }
    }
    headers
}

impl Dissector for HttpDissector {
    fn id(&self) -> DissectorId {
        DissectorId("http".into())
    }

    fn name(&self) -> &str {
        "HTTP"
    }

    fn can_dissect(&self, data: &[u8], context: &DissectionContext) -> Confidence {
        if context.next_protocol_hint == Some(Protocol::Http) && data.len() >= 16 {
            return Confidence::Exact;
        }
        // Port heuristic
        let http_port = matches!(
            context.src_port,
            Some(80) | Some(8080) | Some(8000) | Some(8888) | Some(3000)
        ) || matches!(
            context.dst_port,
            Some(80) | Some(8080) | Some(8000) | Some(8888) | Some(3000)
        );

        if !http_port || data.len() < 16 {
            return Confidence::None;
        }

        // Quick check: starts with an HTTP method or "HTTP/"
        if data.starts_with(b"HTTP/") {
            return Confidence::High;
        }
        // Check if first word (up to space) is a known method
        if let Some(sp) = data.iter().position(|&b| b == b' ') {
            if sp <= 7 && is_http_method(&data[..sp]) {
                return Confidence::High;
            }
        }
        Confidence::Low
    }

    fn dissect<'a>(
        &self,
        data: &'a [u8],
        _context: &mut DissectionContext,
    ) -> sc_core::Result<DissectedLayer<'a>> {
        let header_end = find_header_end(data).unwrap_or(data.len());
        let header_block = &data[..header_end];
        let text = std::str::from_utf8(header_block).map_err(|_| sc_core::ShadowError::Parse {
            message: "HTTP: invalid UTF-8 in headers".into(),
        })?;

        // First line
        let first_line_end = text.find("\r\n").unwrap_or(text.len());
        let first_line = &text[..first_line_end];

        let mut fields = vec![Field {
            name: "Request/Status Line".into(),
            display_value: first_line.to_string(),
            byte_range: 0..first_line_end,
            field_type: FieldType::String,
        }];

        let summary = if first_line.starts_with("HTTP/") {
            // Response: HTTP/1.1 200 OK
            let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
            let version = parts.first().unwrap_or(&"HTTP/?");
            let status_code: u16 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
            let reason = parts.get(2).unwrap_or(&"");

            fields.push(Field {
                name: "Version".into(),
                display_value: version.to_string(),
                byte_range: 0..version.len(),
                field_type: FieldType::String,
            });
            fields.push(Field {
                name: "Status Code".into(),
                display_value: format!("{status_code} ({})", status_category(status_code)),
                byte_range: 0..first_line_end,
                field_type: FieldType::UInt16,
            });

            format!("HTTP {version} {status_code} {reason}")
        } else {
            // Request: GET /path HTTP/1.1
            let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
            let method = parts.first().unwrap_or(&"?");
            let uri = parts.get(1).unwrap_or(&"/");
            let version = parts.get(2).unwrap_or(&"HTTP/?");

            fields.push(Field {
                name: "Method".into(),
                display_value: method.to_string(),
                byte_range: 0..method.len(),
                field_type: FieldType::String,
            });
            fields.push(Field {
                name: "URI".into(),
                display_value: uri.to_string(),
                byte_range: 0..first_line_end,
                field_type: FieldType::String,
            });
            fields.push(Field {
                name: "Version".into(),
                display_value: version.to_string(),
                byte_range: 0..first_line_end,
                field_type: FieldType::String,
            });

            format!("HTTP {method} {uri} {version}")
        };

        // Parse headers
        let header_start = first_line_end + 2; // skip \r\n
        if header_start < header_end {
            let headers = parse_headers(&data[header_start..header_end - 2]); // trim trailing \r\n
            let header_count = headers.len();

            for (name, value) in &headers {
                let display = format!("{name}: {value}");
                fields.push(Field {
                    name: format!("Header: {name}"),
                    display_value: display,
                    byte_range: header_start..header_end,
                    field_type: FieldType::String,
                });
            }

            // Extract useful metadata
            if let Some((_, ct)) = headers
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case("Content-Type"))
            {
                fields.push(Field {
                    name: "Content-Type Category".into(),
                    display_value: content_type_label(ct).to_string(),
                    byte_range: header_start..header_end,
                    field_type: FieldType::String,
                });
            }

            if let Some((_, cl)) = headers
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case("Content-Length"))
            {
                fields.push(Field {
                    name: "Content-Length".into(),
                    display_value: cl.to_string(),
                    byte_range: header_start..header_end,
                    field_type: FieldType::String,
                });
            }

            fields.push(Field {
                name: "Header Count".into(),
                display_value: format!("{header_count}"),
                byte_range: header_start..header_end,
                field_type: FieldType::UInt16,
            });
        }

        let body = &data[header_end..];

        let node = ProtocolNode {
            protocol: "HTTP".into(),
            byte_range: 0..header_end,
            fields,
            summary,
        };

        Ok(DissectedLayer {
            node,
            remaining: body,
            next_protocol: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_request() {
        let data =
            b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nAccept: text/html\r\n\r\nbody";

        let mut ctx = DissectionContext::new(16);
        ctx.dst_port = Some(80);

        let conf = HttpDissector.can_dissect(data, &ctx);
        assert!(conf >= Confidence::High);

        let layer = HttpDissector.dissect(data, &mut ctx).unwrap();
        assert_eq!(layer.node.protocol, "HTTP");
        assert!(layer.node.summary.contains("GET"));
        assert!(layer.node.summary.contains("/index.html"));
        assert_eq!(layer.remaining, b"body");

        // Check Host header
        let host = layer.node.fields.iter().find(|f| f.name == "Header: Host");
        assert!(host.is_some());
    }

    #[test]
    fn test_http_response() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n{\"status\":\"ok\"}";

        let mut ctx = DissectionContext::new(16);
        ctx.src_port = Some(80);

        let layer = HttpDissector.dissect(data, &mut ctx).unwrap();
        assert!(layer.node.summary.contains("200"));
        assert!(layer.node.summary.contains("OK"));

        let ct_cat = layer
            .node
            .fields
            .iter()
            .find(|f| f.name == "Content-Type Category");
        assert!(ct_cat.is_some());
        assert_eq!(ct_cat.unwrap().display_value, "JSON");
    }

    #[test]
    fn test_http_no_match_wrong_port() {
        let data = b"GET /foo HTTP/1.1\r\nHost: x\r\n\r\n";
        let ctx = DissectionContext::new(16);
        let conf = HttpDissector.can_dissect(data, &ctx);
        assert_eq!(conf, Confidence::None);
    }
}
