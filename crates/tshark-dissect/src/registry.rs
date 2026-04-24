use std::collections::HashMap;

use tshark_core::{DissectedPacket, Layer, LinkType, ProtocolId, RawPacket};

use crate::dissector::{Dissector, HintTable, ProtocolHint};

struct PortRoute {
    _table: HintTable,
    port: u16,
    protocol: ProtocolId,
}

/// Registry that holds all dissectors and routes packets through the protocol stack.
pub struct DissectorRegistry {
    by_id: HashMap<ProtocolId, Box<dyn Dissector>>,
    table_routes: HashMap<(HintTable, u16), ProtocolId>,
    port_routes: Vec<PortRoute>,
}

impl DissectorRegistry {
    pub fn new() -> Self {
        Self {
            by_id: HashMap::new(),
            table_routes: HashMap::new(),
            port_routes: Vec::new(),
        }
    }

    /// Register a dissector.
    pub fn register(&mut self, dissector: Box<dyn Dissector>) {
        let id = dissector.protocol_id();
        self.by_id.insert(id, dissector);
    }

    /// Register a table-based route (e.g. EtherType 0x0800 -> IPv4).
    pub fn register_table_route(&mut self, table: HintTable, value: u16, protocol: ProtocolId) {
        self.table_routes.insert((table, value), protocol);
    }

    /// Register a port-based route (e.g. TCP port 80 -> HTTP).
    pub fn register_port_route(&mut self, table: HintTable, port: u16, protocol: ProtocolId) {
        self.port_routes.push(PortRoute {
            _table: table,
            port,
            protocol,
        });
    }

    /// Resolve a protocol hint to a protocol ID.
    fn resolve_hint(&self, hint: &ProtocolHint) -> Option<ProtocolId> {
        match hint {
            ProtocolHint::ById(id) => Some(*id),
            ProtocolHint::ByNumber { table, value } => {
                self.table_routes.get(&(*table, *value)).copied()
            }
            ProtocolHint::ByPort { src, dst } => {
                // Check destination port first (more likely to be the well-known port),
                // then source port.
                for route in &self.port_routes {
                    if route.port == *dst {
                        return Some(route.protocol);
                    }
                }
                for route in &self.port_routes {
                    if route.port == *src {
                        return Some(route.protocol);
                    }
                }
                None
            }
        }
    }

    /// Dissect a complete packet from the link layer up.
    pub fn dissect_packet(&self, raw: &RawPacket, index: usize) -> DissectedPacket {
        let mut layers: Vec<Layer> = Vec::new();
        let data = &raw.data[..];

        // Determine the starting protocol from the link type
        let start_protocol = match raw.link_type {
            LinkType::Ethernet => ProtocolId::Ethernet,
            LinkType::RawIp => {
                // Peek at version nibble to determine IPv4 vs IPv6
                if !data.is_empty() && (data[0] >> 4) == 6 {
                    ProtocolId::Ipv6
                } else {
                    ProtocolId::Ipv4
                }
            }
            LinkType::LinuxSll => ProtocolId::Ethernet, // Simplified
        };

        let mut current_protocol = Some(start_protocol);
        let mut offset: usize = 0;

        while let Some(proto_id) = current_protocol {
            let remaining = &data[offset..];
            if remaining.is_empty() {
                break;
            }

            let dissector = match self.by_id.get(&proto_id) {
                Some(d) => d,
                None => break, // No dissector registered for this protocol
            };

            match dissector.dissect(remaining, offset) {
                Ok(result) => {
                    offset += result.bytes_consumed;
                    let next_hint = result.next_protocol.clone();
                    layers.push(result.layer);

                    current_protocol = next_hint.and_then(|h| self.resolve_hint(&h));
                }
                Err(_e) => {
                    // Malformed data at this layer; stop dissection
                    layers.push(Layer {
                        protocol: proto_id,
                        name: format!("[Malformed {}]", proto_id),
                        summary: "Malformed packet data".into(),
                        header_range: offset..data.len(),
                        fields: Vec::new(),
                    });
                    break;
                }
            }
        }

        DissectedPacket {
            index,
            raw: raw.clone(),
            layers,
        }
    }

    /// Create a registry with all built-in dissectors pre-registered.
    pub fn default_registry() -> Self {
        let mut reg = Self::new();

        // Register all dissectors
        reg.register(Box::new(crate::ethernet::EthernetDissector));
        reg.register(Box::new(crate::vlan::VlanDissector));
        reg.register(Box::new(crate::arp::ArpDissector));
        reg.register(Box::new(crate::ipv4::Ipv4Dissector));
        reg.register(Box::new(crate::ipv6::Ipv6Dissector));
        reg.register(Box::new(crate::icmp::IcmpDissector));
        reg.register(Box::new(crate::icmpv6::Icmpv6Dissector));
        reg.register(Box::new(crate::udp::UdpDissector));
        reg.register(Box::new(crate::tcp::TcpDissector));
        reg.register(Box::new(crate::dns::DnsDissector));
        reg.register(Box::new(crate::http::HttpDissector));
        reg.register(Box::new(crate::tls::TlsDissector));

        // EtherType routing
        reg.register_table_route(HintTable::EtherType, 0x0800, ProtocolId::Ipv4);
        reg.register_table_route(HintTable::EtherType, 0x86DD, ProtocolId::Ipv6);
        reg.register_table_route(HintTable::EtherType, 0x0806, ProtocolId::Arp);
        reg.register_table_route(HintTable::EtherType, 0x8100, ProtocolId::Vlan);

        // IP protocol routing
        reg.register_table_route(HintTable::IpProtocol, 1, ProtocolId::Icmp);
        reg.register_table_route(HintTable::IpProtocol, 6, ProtocolId::Tcp);
        reg.register_table_route(HintTable::IpProtocol, 17, ProtocolId::Udp);
        reg.register_table_route(HintTable::IpProtocol, 58, ProtocolId::Icmpv6);

        // Well-known port routes
        reg.register_port_route(HintTable::UdpPort, 53, ProtocolId::Dns);
        reg.register_port_route(HintTable::TcpPort, 53, ProtocolId::Dns);
        reg.register_port_route(HintTable::TcpPort, 80, ProtocolId::Http);
        reg.register_port_route(HintTable::TcpPort, 8080, ProtocolId::Http);
        reg.register_port_route(HintTable::TcpPort, 443, ProtocolId::Tls);

        reg
    }
}
