pub mod ast;
pub mod lexer;
pub mod parser;
pub mod eval;

pub use ast::{FilterExpr, CompareOp, FilterValue};
pub use eval::evaluate;

use tshark_core::TsharkError;

/// Convenience function: parse a filter expression from a string.
pub fn parse_filter(input: &str) -> Result<FilterExpr, TsharkError> {
    if input.trim().is_empty() {
        // Empty filter matches everything; represent as a special case
        // We return an Exists that always matches... but actually the caller
        // should treat None filter as "accept all". So we return an error-free
        // tautology. Let's use a pragmatic approach:
        return Err(TsharkError::FilterParse {
            pos: 0,
            message: "Empty filter expression".into(),
        });
    }
    let tokens = lexer::Lexer::new(input).tokenize()?;
    parser::Parser::new(tokens).parse()
}
