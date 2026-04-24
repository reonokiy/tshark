#[derive(Debug, thiserror::Error)]
pub enum TsharkError {
    #[error("Capture error: {0}")]
    Capture(String),

    #[error("Dissection error at offset {offset}: {message}")]
    Dissect { offset: usize, message: String },

    #[error("Filter parse error at position {pos}: {message}")]
    FilterParse { pos: usize, message: String },

    #[error("Insufficient data: need {need} bytes, have {have}")]
    InsufficientData { need: usize, have: usize },

    #[error("Unknown protocol: {0}")]
    UnknownProtocol(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Convenience type alias for Results using TsharkError.
pub type Result<T> = std::result::Result<T, TsharkError>;
