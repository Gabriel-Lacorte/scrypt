use aho_corasick::AhoCorasick;

/// A byte-level pattern for protocol identification.
#[derive(Debug, Clone)]
pub struct Pattern {
    /// Pattern identifier
    pub name: String,
    /// Byte sequence to match
    pub bytes: Vec<u8>,
    /// Offset from the start of data where to look
    pub offset: Option<usize>,
    /// Optional mask to apply before matching
    pub mask: Option<Vec<u8>>,
}

/// Multi-pattern matcher using Aho-Corasick for high-performance protocol identification.
pub struct PatternMatcher {
    automaton: AhoCorasick,
    patterns: Vec<Pattern>,
}

impl PatternMatcher {
    /// Build a new pattern matcher from a list of patterns.
    pub fn new(patterns: Vec<Pattern>) -> Result<Self, aho_corasick::BuildError> {
        let byte_patterns: Vec<&[u8]> = patterns.iter().map(|p| p.bytes.as_slice()).collect();
        let automaton = AhoCorasick::new(&byte_patterns)?;
        Ok(Self { automaton, patterns })
    }

    /// Find all matching patterns in the data, returning their names.
    pub fn find_matches(&self, data: &[u8]) -> Vec<&str> {
        let mut matches = Vec::new();
        for mat in self.automaton.find_iter(data) {
            let pattern = &self.patterns[mat.pattern().as_usize()];

            // If an offset constraint exists, check it
            if let Some(expected_offset) = pattern.offset {
                if mat.start() != expected_offset {
                    continue;
                }
            }

            matches.push(pattern.name.as_str());
        }
        matches
    }

    /// Check if any pattern matches.
    pub fn has_match(&self, data: &[u8]) -> bool {
        self.automaton.is_match(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_matching() {
        let patterns = vec![
            Pattern {
                name: "HTTP".into(),
                bytes: b"HTTP/1.".to_vec(),
                offset: None,
                mask: None,
            },
            Pattern {
                name: "TLS_HANDSHAKE".into(),
                bytes: vec![0x16, 0x03],
                offset: Some(0),
                mask: None,
            },
        ];

        let matcher = PatternMatcher::new(patterns).unwrap();

        let http_data = b"GET / HTTP/1.1\r\n";
        let matches = matcher.find_matches(http_data);
        assert!(matches.contains(&"HTTP"));

        let tls_data = vec![0x16, 0x03, 0x03, 0x00, 0x05];
        let matches = matcher.find_matches(&tls_data);
        assert!(matches.contains(&"TLS_HANDSHAKE"));
    }
}
