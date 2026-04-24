use tshark_core::TsharkError;

use crate::ast::{CompareOp, FilterExpr, FilterValue};
use crate::lexer::Token;

/// Pratt parser for filter expressions.
pub struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    pub fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, pos: 0 }
    }

    pub fn parse(&mut self) -> Result<FilterExpr, TsharkError> {
        let expr = self.parse_expr(0)?;
        if !self.at_end() {
            return Err(self.error("Unexpected token after expression"));
        }
        Ok(expr)
    }

    fn parse_expr(&mut self, min_bp: u8) -> Result<FilterExpr, TsharkError> {
        let mut lhs = self.parse_prefix()?;

        loop {
            let (op_bp, is_right_assoc) = match self.peek() {
                Token::Or => (1, false),
                Token::And => (2, false),
                _ => break,
            };

            if op_bp < min_bp {
                break;
            }

            let op_token = self.advance();
            let next_bp = if is_right_assoc { op_bp } else { op_bp + 1 };
            let rhs = self.parse_expr(next_bp)?;

            lhs = match op_token {
                Token::Or => FilterExpr::Or(Box::new(lhs), Box::new(rhs)),
                Token::And => FilterExpr::And(Box::new(lhs), Box::new(rhs)),
                _ => unreachable!(),
            };
        }

        Ok(lhs)
    }

    fn parse_prefix(&mut self) -> Result<FilterExpr, TsharkError> {
        match self.peek().clone() {
            Token::Not => {
                self.advance();
                let expr = self.parse_prefix()?;
                Ok(FilterExpr::Not(Box::new(expr)))
            }
            Token::LParen => {
                self.advance();
                let expr = self.parse_expr(0)?;
                self.expect(Token::RParen)?;
                Ok(expr)
            }
            Token::FieldName(name) => {
                self.advance();
                // Check if followed by a comparison operator
                match self.peek() {
                    Token::Eq | Token::Ne | Token::Gt | Token::Ge |
                    Token::Lt | Token::Le | Token::Contains => {
                        let op = self.parse_compare_op()?;
                        let value = self.parse_value()?;
                        Ok(FilterExpr::Comparison { field: name, op, value })
                    }
                    _ => {
                        // Field existence check
                        Ok(FilterExpr::Exists(name))
                    }
                }
            }
            _ => Err(self.error("Expected field name, '!', or '('")),
        }
    }

    fn parse_compare_op(&mut self) -> Result<CompareOp, TsharkError> {
        let tok = self.advance();
        match tok {
            Token::Eq => Ok(CompareOp::Eq),
            Token::Ne => Ok(CompareOp::Ne),
            Token::Gt => Ok(CompareOp::Gt),
            Token::Ge => Ok(CompareOp::Ge),
            Token::Lt => Ok(CompareOp::Lt),
            Token::Le => Ok(CompareOp::Le),
            Token::Contains => Ok(CompareOp::Contains),
            _ => Err(self.error("Expected comparison operator")),
        }
    }

    fn parse_value(&mut self) -> Result<FilterValue, TsharkError> {
        let tok = self.advance();
        match tok {
            Token::IntLit(v) => Ok(FilterValue::Integer(v)),
            Token::StringLit(s) => Ok(FilterValue::Str(s)),
            Token::Ipv4Lit(ip) => Ok(FilterValue::Ipv4(ip)),
            Token::Ipv6Lit(ip) => Ok(FilterValue::Ipv6(ip)),
            Token::MacLit(mac) => Ok(FilterValue::Mac(mac)),
            Token::BoolLit(b) => Ok(FilterValue::Bool(b)),
            _ => Err(self.error("Expected a value (number, string, IP address, MAC address, or bool)")),
        }
    }

    fn peek(&self) -> &Token {
        self.tokens.get(self.pos).unwrap_or(&Token::Eof)
    }

    fn advance(&mut self) -> Token {
        let tok = self.tokens.get(self.pos).cloned().unwrap_or(Token::Eof);
        self.pos += 1;
        tok
    }

    fn expect(&mut self, expected: Token) -> Result<(), TsharkError> {
        let tok = self.advance();
        if std::mem::discriminant(&tok) == std::mem::discriminant(&expected) {
            Ok(())
        } else {
            Err(self.error(&format!("Expected {:?}, got {:?}", expected, tok)))
        }
    }

    fn at_end(&self) -> bool {
        matches!(self.peek(), Token::Eof)
    }

    fn error(&self, message: &str) -> TsharkError {
        TsharkError::FilterParse {
            pos: self.pos,
            message: message.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::Lexer;
    use std::net::Ipv4Addr;

    fn parse(input: &str) -> FilterExpr {
        let tokens = Lexer::new(input).tokenize().unwrap();
        Parser::new(tokens).parse().unwrap()
    }

    #[test]
    fn test_simple_comparison() {
        let expr = parse("ip.src == 192.168.1.1");
        assert_eq!(expr, FilterExpr::Comparison {
            field: "ip.src".into(),
            op: CompareOp::Eq,
            value: FilterValue::Ipv4(Ipv4Addr::new(192, 168, 1, 1)),
        });
    }

    #[test]
    fn test_field_existence() {
        let expr = parse("tcp");
        assert_eq!(expr, FilterExpr::Exists("tcp".into()));
    }

    #[test]
    fn test_not() {
        let expr = parse("!tcp");
        assert_eq!(expr, FilterExpr::Not(Box::new(FilterExpr::Exists("tcp".into()))));
    }

    #[test]
    fn test_and() {
        let expr = parse("tcp && ip.src == 10.0.0.1");
        match expr {
            FilterExpr::And(lhs, rhs) => {
                assert_eq!(*lhs, FilterExpr::Exists("tcp".into()));
                assert!(matches!(*rhs, FilterExpr::Comparison { .. }));
            }
            _ => panic!("Expected And"),
        }
    }

    #[test]
    fn test_or_and_precedence() {
        // a || b && c  should parse as  a || (b && c)
        let expr = parse("tcp || udp && dns");
        match expr {
            FilterExpr::Or(lhs, rhs) => {
                assert_eq!(*lhs, FilterExpr::Exists("tcp".into()));
                match *rhs {
                    FilterExpr::And(a, b) => {
                        assert_eq!(*a, FilterExpr::Exists("udp".into()));
                        assert_eq!(*b, FilterExpr::Exists("dns".into()));
                    }
                    _ => panic!("Expected And on right side"),
                }
            }
            _ => panic!("Expected Or"),
        }
    }

    #[test]
    fn test_parentheses() {
        // (a || b) && c
        let expr = parse("(tcp || udp) && dns");
        match expr {
            FilterExpr::And(lhs, rhs) => {
                assert!(matches!(*lhs, FilterExpr::Or(..)));
                assert_eq!(*rhs, FilterExpr::Exists("dns".into()));
            }
            _ => panic!("Expected And"),
        }
    }

    #[test]
    fn test_contains() {
        let expr = parse("http.host contains \"example\"");
        assert_eq!(expr, FilterExpr::Comparison {
            field: "http.host".into(),
            op: CompareOp::Contains,
            value: FilterValue::Str("example".into()),
        });
    }

    #[test]
    fn test_nested_not() {
        let expr = parse("!!tcp");
        assert_eq!(expr, FilterExpr::Not(Box::new(
            FilterExpr::Not(Box::new(FilterExpr::Exists("tcp".into())))
        )));
    }
}
