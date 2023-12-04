pub mod sniffer{
    use pnet::datalink::{self};
    use pnet::datalink::Channel::Ethernet;
    use pnet::packet::ethernet::{EthernetPacket};
    use pnet::packet::ipv4::Ipv4Packet;
    use pnet::packet::Packet;
    use pnet::packet::udp::UdpPacket;
    use pnet::packet::ip::{IpNextHeaderProtocol};
    use pnet::packet::tcp::TcpPacket;

    use crate::ip::ip::IP;
    pub const MAX_PORT: i32 = 65536;
    pub const IPPROTO_TCP: u16 = 6;
    pub const IPPROTO_UDP: u16 = 17;

    pub struct Sniffer{
        port: u16,
        ip : IP,
        packets: Vec<Vec<u8>> //each packet is Vec<u8>
    }

    impl Sniffer{
        pub fn new(ip: IP, port: u16) -> Result<Sniffer, String> {
            return match i32::from(port).is_negative() || i32::from(port) > MAX_PORT {
                true => Ok(Sniffer { port, ip, packets: Vec::new() }),
                false => Err("Invalid port number!".to_string())
            }
        }
        pub fn get_ip(&self) -> IP {
            return IP::copy(&self.ip);
        }
        pub fn get_port(&self) -> u16 {
            return self.port;
        }
        pub fn sniff(&mut self, max_amount_packets: i32) -> String{
            //Getting the interface to sniff from
            let interfaces = datalink::interfaces();
            let interface = &interfaces[0];

            // Create a channel to receive packets
            let mut rx = match datalink::channel(&interface, Default::default()) {
                Ok(Ethernet(tx, rx)) =>  rx,
                Ok(_) => panic!("Unknown channel type"),
                Err(e) => panic!("Error opening network channel: {}", e),
            };
            println!("Listening for packets to IP address {}: {}", IP::get_ip(&self.ip), interface.name);

            while self.packets.len() < max_amount_packets as usize {
                let is_property_packet;
                let the_packet = rx.next();
                match the_packet {
                    Ok(packet) => is_property_packet = check_packet_propriety(packet.to_vec(), self.ip.copy(), self.port),
                    Err(e) => return e.to_string()
                }

                if is_property_packet{
                    println!("Received packet to IP address {}", IP::get_ip(&self.ip));
                    self.packets.push(the_packet.unwrap().to_vec());
                }
            }
            return "".to_string(); //default value
        }
    }

    fn check_packet_propriety(packet: Vec<u8>, ip: IP, port: u16) -> bool{
        if let Some(ethernet) = EthernetPacket::new(&packet) {
            // Extract the IPv4 packet
            if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                // Check if the packet is destined for the target IP address
                if ipv4.get_destination().to_string() == IP::get_ip(&ip).to_string() {
                    // Check if the packet is a UDP packet
                    if ipv4.get_next_level_protocol() == IpNextHeaderProtocol(IPPROTO_UDP as u8) {
                        //Extracting the port from the UDP packet
                        if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                            if udp.get_destination() == port{
                                return true;
                            }
                        }
                    }
                    // Check if the packet is a TCP packet
                    else if ipv4.get_next_level_protocol() == IpNextHeaderProtocol(IPPROTO_TCP as u8) {
                        //Extracting the port from the TCP packet
                        if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                            if tcp.get_destination() == port{
                                return true;
                            }
                        }
                    }
                }
            }
        }
        return false;
    }
}