use serde::Serialize;

/// Identifies a network protocol. Used as the routing key in the dissector registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum ProtocolId {
    Ethernet,
    Vlan,
    Arp,
    Ipv4,
    Ipv6,
    Icmp,
    Icmpv6,
    Tcp,
    Udp,
    Dns,
    Http,
    Tls,
    /// Unrecognized protocol identified by its numeric value (EtherType or IP protocol number).
    Unknown(u16),
}

impl ProtocolId {
    /// Human-readable short name for display.
    pub fn short_name(&self) -> &'static str {
        match self {
            Self::Ethernet => "ETH",
            Self::Vlan => "VLAN",
            Self::Arp => "ARP",
            Self::Ipv4 => "IPv4",
            Self::Ipv6 => "IPv6",
            Self::Icmp => "ICMP",
            Self::Icmpv6 => "ICMPv6",
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
            Self::Dns => "DNS",
            Self::Http => "HTTP",
            Self::Tls => "TLS",
            Self::Unknown(_) => "???",
        }
    }
}

impl std::fmt::Display for ProtocolId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown(v) => write!(f, "Unknown(0x{v:04x})"),
            other => write!(f, "{}", other.short_name()),
        }
    }
}
