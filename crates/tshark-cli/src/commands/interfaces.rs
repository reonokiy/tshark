use anyhow::Result;
use tshark_capture::list_interfaces;

pub fn run() -> Result<()> {
    let interfaces = list_interfaces()?;

    println!("{:<4} {:<16} {:<6} {}", "No.", "Name", "Status", "Addresses");
    println!("{}", "-".repeat(60));

    for (i, iface) in interfaces.iter().enumerate() {
        let status = if iface.is_up { "Up" } else { "Down" };
        let addrs: Vec<String> = iface.addresses.iter().map(|a| a.to_string()).collect();
        let addr_str = if addrs.is_empty() {
            "(none)".to_string()
        } else {
            addrs.join(", ")
        };

        let suffix = if iface.is_loopback { " (loopback)" } else { "" };

        println!(
            "{:<4} {:<16} {:<6} {}{}",
            i + 1,
            iface.name,
            status,
            addr_str,
            suffix
        );
    }

    Ok(())
}
