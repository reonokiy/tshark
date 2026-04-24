use std::net::IpAddr;
use tshark_core::TsharkError;

/// Information about a network interface available for capture.
#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    pub name: String,
    pub description: Option<String>,
    pub addresses: Vec<IpAddr>,
    pub is_up: bool,
    pub is_loopback: bool,
}

/// List all network interfaces available for packet capture.
pub fn list_interfaces() -> Result<Vec<InterfaceInfo>, TsharkError> {
    let devices = pcap::Device::list()
        .map_err(|e| TsharkError::Capture(format!("Failed to list interfaces: {e}")))?;

    let interfaces = devices
        .into_iter()
        .map(|dev| {
            let addresses = dev
                .addresses
                .iter()
                .filter_map(|a| match a.addr {
                    std::net::IpAddr::V4(v4) => Some(IpAddr::V4(v4)),
                    std::net::IpAddr::V6(v6) => Some(IpAddr::V6(v6)),
                })
                .collect();

            let is_loopback = dev.flags.is_loopback();
            let is_up = dev.flags.is_up();

            InterfaceInfo {
                name: dev.name,
                description: dev.desc,
                addresses,
                is_up,
                is_loopback,
            }
        })
        .collect();

    Ok(interfaces)
}
