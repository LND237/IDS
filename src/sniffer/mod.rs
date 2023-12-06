pub mod sniffer{
    use pnet::datalink::{self, Channel::Ethernet};
    use pnet::packet;
    use pnet::packet::{Packet,
                       ethernet::EthernetPacket,
                       ipv4::Ipv4Packet,
                       tcp::TcpPacket,
                       udp::UdpPacket};

    type SinglePacket = Vec<u8>;

    use crate::ip::ip::IP;
    pub const MAX_PORT: u16 = 65535;

    pub struct Sniffer{
        port: u16,
        ip : IP,
        packets: Vec<SinglePacket> //each packet is Vec<u8>
    }

    impl Sniffer{
        ///Constructor of struct Sniffer.
        /// Input: An IP struct- the destination ip to sniff and an
        /// u16 variable- the source port to sniff.
        /// Output: An "object" of struct Sniffer.
        pub fn new(ip: IP, port: u16) -> Result<Sniffer, String> {
            return match true {
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

        ///The function sniffs the network transport according
        /// to the fields in the Sniffer struct.
        /// Input: self(Sniffer) and an i32 variable- the limit amount of packets to sniff.
        /// Output: A vector of SinglePacket- the packets which the sniffer sniffed.
        pub fn sniff(&mut self, max_amount_packets: i32) -> Vec<SinglePacket>{
            //Getting the wifi interface to sniff
            let interfaces = datalink::interfaces();
            let interface = &interfaces[1]; //index wifi interface

            println!("Found interface with name {}", interface.name);

            // Create a channel to receive packets
            let mut rx = match datalink::channel(&interface, Default::default()) {
                Ok(Ethernet(tx, rx)) =>  rx,
                Ok(_) => panic!("Unknown channel type"),
                Err(e) => panic!("Error opening network channel: {}", e),
            };
            println!("Listening for packets to IP address {} in port {}", IP::get_ip(&self.ip), self.port);

            //Waiting until there are enough packets which the sniffer sniffed
            while self.packets.len() < max_amount_packets as usize {
                let the_packet = rx.next(); //getting the next packet
                match the_packet {
                    Ok(packet) => {
                        //The packet has the right port and ip
                        if check_packet_propriety(packet.to_vec(), self.ip.copy(), self.port){
                            self.packets.push(packet.to_vec());
                        }
                    },
                    Err(e) => panic!("{}", e)
                }

            }
            return self.packets.clone();
        }

    }

    ///The function extracts from the packet its header data.
    /// Input: a SinglePacket- the packet with the data.
    /// Output: a String value- the string with the data about the packet.
    pub fn get_string_packet(the_packet: &SinglePacket) -> String{
        let mut packet_str = String::new();
        // Parse Ethernet header
        if let Some(ethernet_packet) = EthernetPacket::new(the_packet) {
            //Source MAC address
            packet_str.push_str("Source MAC: ");
            packet_str.push_str(&ethernet_packet.get_source().to_string());

            //Destination MAC address
            packet_str.push_str("\nDestination MAC: ");
            packet_str.push_str(&ethernet_packet.get_destination().to_string());
            if let Some(ipv4_packet) = Ipv4Packet::new(ethernet_packet.payload()) {
                //Source IP address
                packet_str.push_str("\nSource IP: ");
                packet_str.push_str(&ipv4_packet.get_source().to_string());

                //Destination IP address
                packet_str.push_str("\nDestination IP: ");
                packet_str.push_str(&ipv4_packet.get_destination().to_string());

                // Check if it's a TCP(/UDP) packet
                if ipv4_packet.get_next_level_protocol() == packet::ip::IpNextHeaderProtocols::Tcp {
                    if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {
                        //Source port
                        packet_str.push_str("\nSource Port: ");
                        packet_str.push_str(&tcp_packet.get_source().to_string());

                        //Destination port
                        packet_str.push_str("\nDestination Port: ");
                        packet_str.push_str(&tcp_packet.get_destination().to_string());

                        //Payload
                        packet_str.push_str("\nPayload: ");
                        packet_str.push_str(&String::from_utf8_lossy(tcp_packet.payload()));
                    }
                }
            }
        }
        return packet_str;
    }

    //private function
    ///The function checks if the packet contains the right
    /// destination IP and source port.
    /// Input: a SinglePacket variable- the packet to examine,
    /// an IP struct- the destination IP and an u16 variable- the port.
    /// Output: a bool value- if the packet is proper or not.
    fn check_packet_propriety(packet: SinglePacket, ip: IP, port: u16) -> bool{
        if let Some(ethernet) = EthernetPacket::new(&packet) {
            // Extract the IPv4 packet
            if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                // Check if the packet is destined for the target IP address
                if ipv4.get_destination().to_string() == IP::get_ip(&ip).to_string() {
                    // Check if the packet is a UDP packet
                    if ipv4.get_next_level_protocol() == packet::ip::IpNextHeaderProtocols::Udp {
                        //Extracting the port from the UDP packet
                        if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                            if udp.get_source() == port{
                                return true;
                            }
                        }
                    }
                    // Check if the packet is a TCP packet
                    else if ipv4.get_next_level_protocol() == packet::ip::IpNextHeaderProtocols::Tcp {
                        //Extracting the port from the TCP packet
                        if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                            if tcp.get_source() == port{
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