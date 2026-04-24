use std::net::{Ipv4Addr, Ipv6Addr};

use tshark_core::TsharkError;

/// Token produced by the lexer.
#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    /// Dotted field name, e.g. "ip.src", "tcp.flags.syn"
    FieldName(String),
    /// String literal
    StringLit(String),
    /// Integer literal (decimal or hex)
    IntLit(i64),
    /// IPv4 address literal
    Ipv4Lit(Ipv4Addr),
    /// IPv6 address literal
    Ipv6Lit(Ipv6Addr),
    /// MAC address literal
    MacLit([u8; 6]),
    /// Boolean literal
    BoolLit(bool),

    // Operators
    Eq,       // ==
    Ne,       // !=
    Gt,       // >
    Ge,       // >=
    Lt,       // <
    Le,       // <=
    And,      // &&
    Or,       // ||
    Not,      // !
    Contains, // contains

    // Grouping
    LParen,
    RParen,

    Eof,
}

pub struct Lexer<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> Lexer<'a> {
    pub fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    pub fn tokenize(&mut self) -> Result<Vec<Token>, TsharkError> {
        let mut tokens = Vec::new();
        loop {
            self.skip_whitespace();
            if self.pos >= self.input.len() {
                tokens.push(Token::Eof);
                break;
            }
            tokens.push(self.next_token()?);
        }
        Ok(tokens)
    }

    fn skip_whitespace(&mut self) {
        while self.pos < self.input.len() && self.input.as_bytes()[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.as_bytes().get(self.pos).copied()
    }

    fn advance(&mut self) -> u8 {
        let b = self.input.as_bytes()[self.pos];
        self.pos += 1;
        b
    }

    fn next_token(&mut self) -> Result<Token, TsharkError> {
        let start = self.pos;
        let ch = self.peek().unwrap();

        match ch {
            b'(' => { self.advance(); Ok(Token::LParen) }
            b')' => { self.advance(); Ok(Token::RParen) }
            b'!' => {
                self.advance();
                if self.peek() == Some(b'=') {
                    self.advance();
                    Ok(Token::Ne)
                } else {
                    Ok(Token::Not)
                }
            }
            b'=' => {
                self.advance();
                if self.peek() == Some(b'=') {
                    self.advance();
                    Ok(Token::Eq)
                } else {
                    Err(self.error(start, "Expected '==' but got single '='"))
                }
            }
            b'>' => {
                self.advance();
                if self.peek() == Some(b'=') {
                    self.advance();
                    Ok(Token::Ge)
                } else {
                    Ok(Token::Gt)
                }
            }
            b'<' => {
                self.advance();
                if self.peek() == Some(b'=') {
                    self.advance();
                    Ok(Token::Le)
                } else {
                    Ok(Token::Lt)
                }
            }
            b'&' => {
                self.advance();
                if self.peek() == Some(b'&') {
                    self.advance();
                    Ok(Token::And)
                } else {
                    Err(self.error(start, "Expected '&&' but got single '&'"))
                }
            }
            b'|' => {
                self.advance();
                if self.peek() == Some(b'|') {
                    self.advance();
                    Ok(Token::Or)
                } else {
                    Err(self.error(start, "Expected '||' but got single '|'"))
                }
            }
            b'"' => self.read_string(),
            _ if ch.is_ascii_digit() => self.read_number_or_addr(),
            _ if ch.is_ascii_alphabetic() || ch == b'_' => self.read_ident_or_addr(),
            _ => Err(self.error(start, &format!("Unexpected character: '{}'", ch as char))),
        }
    }

    fn read_string(&mut self) -> Result<Token, TsharkError> {
        let start = self.pos;
        self.advance(); // skip opening quote
        let str_start = self.pos;
        while self.pos < self.input.len() && self.input.as_bytes()[self.pos] != b'"' {
            self.pos += 1;
        }
        if self.pos >= self.input.len() {
            return Err(self.error(start, "Unterminated string literal"));
        }
        let s = self.input[str_start..self.pos].to_string();
        self.advance(); // skip closing quote
        Ok(Token::StringLit(s))
    }

    fn read_number_or_addr(&mut self) -> Result<Token, TsharkError> {
        let start = self.pos;

        // Check for hex: 0x...
        if self.remaining().starts_with("0x") || self.remaining().starts_with("0X") {
            self.pos += 2;
            let hex_start = self.pos;
            while self.pos < self.input.len() && self.input.as_bytes()[self.pos].is_ascii_hexdigit() {
                self.pos += 1;
            }
            let hex_str = &self.input[hex_start..self.pos];
            let val = i64::from_str_radix(hex_str, 16)
                .map_err(|_| self.error(start, "Invalid hex literal"))?;
            return Ok(Token::IntLit(val));
        }

        // Read digits
        while self.pos < self.input.len() && self.input.as_bytes()[self.pos].is_ascii_digit() {
            self.pos += 1;
        }

        // Check if this is an IPv4 address (digits followed by dots and more digits)
        if self.peek() == Some(b'.') {
            let saved = self.pos;
            // Try to parse as IPv4
            if let Some(ip) = self.try_read_ipv4(start) {
                return Ok(Token::Ipv4Lit(ip));
            }
            self.pos = saved;
        }

        // Check if this could be a MAC address (2 hex digits followed by colon)
        let token_so_far = &self.input[start..self.pos];
        if self.peek() == Some(b':') && token_so_far.len() == 2 {
            let saved_pos = self.pos;
            if let Some(mac) = self.try_read_mac(start) {
                return Ok(Token::MacLit(mac));
            }
            self.pos = saved_pos;
        }

        // Plain integer
        let num_str = &self.input[start..self.pos];
        let val = num_str.parse::<i64>()
            .map_err(|_| self.error(start, "Invalid integer literal"))?;
        Ok(Token::IntLit(val))
    }

    fn try_read_ipv4(&mut self, start: usize) -> Option<Ipv4Addr> {
        // We already read the first octet's digits. Now read .X.X.X
        let mut end = self.pos;
        for _ in 0..3 {
            if end >= self.input.len() || self.input.as_bytes()[end] != b'.' {
                return None;
            }
            end += 1;
            let digit_start = end;
            while end < self.input.len() && self.input.as_bytes()[end].is_ascii_digit() {
                end += 1;
            }
            if end == digit_start {
                return None; // No digits after dot
            }
        }
        // Make sure we don't have another dot (would mean it's a field name like 1.2.3.4.5)
        if end < self.input.len() && self.input.as_bytes()[end] == b'.' {
            return None;
        }

        let ip_str = &self.input[start..end];
        if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
            self.pos = end;
            Some(ip)
        } else {
            None
        }
    }

    fn try_read_mac(&mut self, start: usize) -> Option<[u8; 6]> {
        // Try to read aa:bb:cc:dd:ee:ff pattern
        let mut end = self.pos;
        for _i in 0..5 {
            if end >= self.input.len() || self.input.as_bytes()[end] != b':' {
                return None;
            }
            end += 1;
            let hex_start = end;
            while end < self.input.len() && self.input.as_bytes()[end].is_ascii_hexdigit() {
                end += 1;
            }
            if end - hex_start != 2 {
                return None;
            }
        }

        let mac_str = &self.input[start..end];
        let parts: Vec<&str> = mac_str.split(':').collect();
        if parts.len() != 6 {
            return None;
        }
        let mut mac = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            mac[i] = u8::from_str_radix(part, 16).ok()?;
        }
        self.pos = end;
        Some(mac)
    }

    fn read_ident_or_addr(&mut self) -> Result<Token, TsharkError> {
        let start = self.pos;

        // Read identifier characters: alphanumeric, underscore, dot
        while self.pos < self.input.len() {
            let ch = self.input.as_bytes()[self.pos];
            if ch.is_ascii_alphanumeric() || ch == b'_' || ch == b'.' {
                self.pos += 1;
            } else {
                break;
            }
        }

        let word = &self.input[start..self.pos];

        // Check for keywords
        match word {
            "true" => Ok(Token::BoolLit(true)),
            "false" => Ok(Token::BoolLit(false)),
            "contains" => Ok(Token::Contains),
            "and" => Ok(Token::And),
            "or" => Ok(Token::Or),
            "not" => Ok(Token::Not),
            _ => {
                // Try as IPv6 address (contains colons after the initial part)
                // For now, treat as field name. IPv6 in filters is rare.
                Ok(Token::FieldName(word.to_string()))
            }
        }
    }

    fn remaining(&self) -> &str {
        &self.input[self.pos..]
    }

    fn error(&self, pos: usize, message: &str) -> TsharkError {
        TsharkError::FilterParse {
            pos,
            message: message.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokenize(input: &str) -> Vec<Token> {
        Lexer::new(input).tokenize().unwrap()
    }

    #[test]
    fn test_simple_comparison() {
        let tokens = tokenize("ip.src == 192.168.1.1");
        assert_eq!(tokens, vec![
            Token::FieldName("ip.src".into()),
            Token::Eq,
            Token::Ipv4Lit(Ipv4Addr::new(192, 168, 1, 1)),
            Token::Eof,
        ]);
    }

    #[test]
    fn test_complex_expression() {
        let tokens = tokenize("tcp.port == 80 && ip.src != 10.0.0.1");
        assert_eq!(tokens, vec![
            Token::FieldName("tcp.port".into()),
            Token::Eq,
            Token::IntLit(80),
            Token::And,
            Token::FieldName("ip.src".into()),
            Token::Ne,
            Token::Ipv4Lit(Ipv4Addr::new(10, 0, 0, 1)),
            Token::Eof,
        ]);
    }

    #[test]
    fn test_string_literal() {
        let tokens = tokenize("http.host contains \"example\"");
        assert_eq!(tokens, vec![
            Token::FieldName("http.host".into()),
            Token::Contains,
            Token::StringLit("example".into()),
            Token::Eof,
        ]);
    }

    #[test]
    fn test_boolean_and_negation() {
        let tokens = tokenize("!tcp.flags.syn");
        assert_eq!(tokens, vec![
            Token::Not,
            Token::FieldName("tcp.flags.syn".into()),
            Token::Eof,
        ]);
    }

    #[test]
    fn test_parentheses() {
        let tokens = tokenize("(tcp || udp) && ip.src == 10.0.0.1");
        assert_eq!(tokens, vec![
            Token::LParen,
            Token::FieldName("tcp".into()),
            Token::Or,
            Token::FieldName("udp".into()),
            Token::RParen,
            Token::And,
            Token::FieldName("ip.src".into()),
            Token::Eq,
            Token::Ipv4Lit(Ipv4Addr::new(10, 0, 0, 1)),
            Token::Eof,
        ]);
    }

    #[test]
    fn test_hex_literal() {
        let tokens = tokenize("eth.type == 0x0800");
        assert_eq!(tokens, vec![
            Token::FieldName("eth.type".into()),
            Token::Eq,
            Token::IntLit(0x0800),
            Token::Eof,
        ]);
    }

    #[test]
    fn test_mac_address() {
        let tokens = tokenize("eth.src == 00:11:22:33:44:55");
        assert_eq!(tokens, vec![
            Token::FieldName("eth.src".into()),
            Token::Eq,
            Token::MacLit([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            Token::Eof,
        ]);
    }

    #[test]
    fn test_word_operators() {
        let tokens = tokenize("tcp and not udp or icmp");
        assert_eq!(tokens, vec![
            Token::FieldName("tcp".into()),
            Token::And,
            Token::Not,
            Token::FieldName("udp".into()),
            Token::Or,
            Token::FieldName("icmp".into()),
            Token::Eof,
        ]);
    }

    #[test]
    fn test_empty_input() {
        let tokens = tokenize("");
        assert_eq!(tokens, vec![Token::Eof]);
    }
}
