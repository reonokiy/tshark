use tshark_core::DissectedPacket;

/// Print a one-line summary of a packet.
/// Format: `index  timestamp  source -> dest  protocol  length  info`
pub fn print_packet(packet: &DissectedPacket, relative_ts: f64) {
    let src = packet.source_addr();
    let dst = packet.dest_addr();
    let proto = packet.top_protocol().short_name();
    let length = packet.raw.original_length;
    let info = packet.summary();

    println!(
        "{:>5}  {:<12.6}  {:<15} -> {:<15}  {:<6}  {:>5}  {}",
        packet.index, relative_ts, src, dst, proto, length, info
    );
}
