use tshark_core::{Layer, ProtocolId, TsharkError};

/// The result of dissecting one protocol layer.
pub struct DissectResult {
    /// The parsed layer with all its fields.
    pub layer: Layer,
    /// Number of bytes this layer's header consumed from the input.
    pub bytes_consumed: usize,
    /// Hint for the registry about what protocol comes next.
    pub next_protocol: Option<ProtocolHint>,
}

/// How a dissector tells the registry what protocol to try next.
#[derive(Debug, Clone)]
pub enum ProtocolHint {
    /// A known protocol ID.
    ById(ProtocolId),
    /// Look up by port numbers (e.g. TCP/UDP port-based detection).
    ByPort { src: u16, dst: u16 },
    /// Look up by a table value (e.g. EtherType, IP protocol number).
    ByNumber { table: HintTable, value: u16 },
}

/// Which routing table to look up for next-protocol resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HintTable {
    EtherType,
    IpProtocol,
    TcpPort,
    UdpPort,
}

/// Trait implemented by all protocol dissectors.
pub trait Dissector: Send + Sync {
    /// Which protocol this dissector handles.
    fn protocol_id(&self) -> ProtocolId;

    /// Human-readable protocol name.
    fn name(&self) -> &'static str;

    /// Dissect the given bytes starting at `offset` within the original packet.
    ///
    /// `data` is a slice starting at this layer's header.
    /// `offset` is the absolute byte position in the original packet (for `byte_range` fields).
    fn dissect(&self, data: &[u8], offset: usize) -> Result<DissectResult, TsharkError>;
}
