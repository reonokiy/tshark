use tshark_core::DissectedPacket;

/// Print verbose dissection output showing all protocol layers and fields.
pub fn print_packet(packet: &DissectedPacket) {
    println!(
        "Frame {}: {} bytes on wire, {} bytes captured",
        packet.index, packet.raw.original_length, packet.raw.capture_length
    );

    for layer in &packet.layers {
        println!("{}, {}", layer.name, layer.summary);
        for field in &layer.fields {
            println!("    {}: {}", field.display_name, field.value);
        }
    }

    println!();
}
