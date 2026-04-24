use std::path::Path;
use crossbeam_channel::unbounded;
use tshark_core::LinkType;

#[test]
fn test_read_simple_pcap() {
    let (tx, rx) = unbounded();
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent().unwrap()
        .parent().unwrap()
        .join("testdata/simple.pcap");

    let stats = tshark_capture::file::read_pcap(&path, tx).unwrap();
    assert_eq!(stats.packets_received, 4);

    let packets: Vec<_> = rx.try_iter().collect();
    assert_eq!(packets.len(), 4);

    // All should be Ethernet link type
    for pkt in &packets {
        assert_eq!(pkt.link_type, LinkType::Ethernet);
        assert!(pkt.data.len() > 0);
        assert_eq!(pkt.capture_length, pkt.data.len() as u32);
    }

    // First packet is ARP (42 bytes)
    assert_eq!(packets[0].data.len(), 42);
    // Second is TCP SYN (54 bytes)
    assert_eq!(packets[1].data.len(), 54);
}

#[test]
fn test_read_arp_pcap() {
    let (tx, rx) = unbounded();
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent().unwrap()
        .parent().unwrap()
        .join("testdata/arp.pcap");

    let stats = tshark_capture::file::read_pcap(&path, tx).unwrap();
    assert_eq!(stats.packets_received, 1);

    let pkt = rx.try_recv().unwrap();
    // Check EtherType is ARP (0x0806) at bytes 12-13
    assert_eq!(pkt.data[12], 0x08);
    assert_eq!(pkt.data[13], 0x06);
}

#[test]
fn test_read_nonexistent_file() {
    let (tx, _rx) = unbounded();
    let result = tshark_capture::file::read_pcap(Path::new("/nonexistent.pcap"), tx);
    assert!(result.is_err());
}

#[test]
fn test_list_interfaces() {
    let interfaces = tshark_capture::list_interfaces().unwrap();
    // Should have at least one interface (loopback)
    assert!(!interfaces.is_empty());
    // Should have a loopback interface
    assert!(interfaces.iter().any(|i| i.is_loopback || i.name == "lo"));
}
