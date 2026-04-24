use std::net::{Ipv4Addr, Ipv6Addr};

/// A filter expression AST node.
#[derive(Debug, Clone, PartialEq)]
pub enum FilterExpr {
    And(Box<FilterExpr>, Box<FilterExpr>),
    Or(Box<FilterExpr>, Box<FilterExpr>),
    Not(Box<FilterExpr>),
    Comparison {
        field: String,
        op: CompareOp,
        value: FilterValue,
    },
    /// Field existence check: true if the field is present in the packet.
    Exists(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareOp {
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
    Contains,
}

/// A literal value in a filter expression.
#[derive(Debug, Clone, PartialEq)]
pub enum FilterValue {
    Integer(i64),
    Str(String),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Mac([u8; 6]),
    Bool(bool),
}
