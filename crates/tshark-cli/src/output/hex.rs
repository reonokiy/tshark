use tshark_core::DissectedPacket;

/// Print a hex dump of the raw packet data.
pub fn print_packet(packet: &DissectedPacket) {
    let data = &packet.raw.data;

    for offset in (0..data.len()).step_by(16) {
        // Offset
        print!("{:04x}   ", offset);

        // Hex bytes
        for i in 0..16 {
            if offset + i < data.len() {
                print!("{:02x} ", data[offset + i]);
            } else {
                print!("   ");
            }
            if i == 7 {
                print!(" ");
            }
        }

        print!("  ");

        // ASCII representation
        for i in 0..16 {
            if offset + i < data.len() {
                let b = data[offset + i];
                if b.is_ascii_graphic() || b == b' ' {
                    print!("{}", b as char);
                } else {
                    print!(".");
                }
            }
        }

        println!();
    }

    println!();
}
