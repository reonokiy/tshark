use tshark_core::DissectedPacket;

/// Print a packet as a JSON object.
pub fn print_packet(packet: &DissectedPacket) {
    let mut obj = serde_json::Map::new();
    obj.insert("index".into(), serde_json::Value::from(packet.index as u64));
    obj.insert(
        "timestamp".into(),
        serde_json::Value::from(packet.raw.timestamp.to_rfc3339()),
    );
    obj.insert(
        "length".into(),
        serde_json::Value::from(packet.raw.original_length),
    );

    let mut layers = serde_json::Map::new();
    for layer in &packet.layers {
        let mut fields = serde_json::Map::new();
        for field in &layer.fields {
            fields.insert(field.name.clone(), serde_json::Value::from(field.value.to_string()));
        }
        // Use protocol short name as key (lowercase)
        let key = layer.protocol.short_name().to_lowercase();
        fields.insert("_summary".into(), serde_json::Value::from(layer.summary.clone()));
        layers.insert(key, serde_json::Value::Object(fields));
    }

    obj.insert("layers".into(), serde_json::Value::Object(layers));

    println!("{}", serde_json::Value::Object(obj));
}
