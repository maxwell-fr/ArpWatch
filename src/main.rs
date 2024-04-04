use pcap::Device;

fn main() {
    let devs = Device::list().unwrap();

    // output a list of interface devices
    for d in &devs {
        println!("Device:{:?}", d);
    }

    // pick a device that starts with a real subnet -- more likely to be activity
    let dev = devs.iter().find(|s| s.addresses.iter().any(|a| a.addr.to_string().starts_with("192.168."))).unwrap();
    println!("Device autoselected: {:?}", dev.name);
    let mut cap = dev.clone().open().unwrap();

    while let Ok(packet) = cap.next_packet() {
        // output arp packet details, or a dot for anything else
        if packet.data[12..14] == [0x08, 0x06] {
            println!("\narp: {:?}", packet);
        }
        else {
            print!(".");
        }
    }
}
