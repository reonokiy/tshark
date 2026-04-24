use ratatui::style::Color;
use tshark_core::ProtocolId;

pub fn protocol_fg(proto: ProtocolId) -> Color {
    match proto {
        ProtocolId::Tcp => Color::LightMagenta,
        ProtocolId::Udp => Color::LightCyan,
        ProtocolId::Dns => Color::LightCyan,
        ProtocolId::Http => Color::LightGreen,
        ProtocolId::Tls => Color::LightRed,
        ProtocolId::Arp => Color::Yellow,
        ProtocolId::Icmp | ProtocolId::Icmpv6 => Color::Magenta,
        ProtocolId::Ipv4 | ProtocolId::Ipv6 => Color::White,
        ProtocolId::Ethernet => Color::DarkGray,
        _ => Color::White,
    }
}
