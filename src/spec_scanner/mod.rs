pub mod spec_scanner{
    use tokio::runtime::Runtime;
    use crate::scanner::scanner::{Scanner, ScannerFunctions};
    use crate::ip::ip::IP;
    use crate::server::server::{Server};
    use crate::sniffer::sniffer::{SinglePacket, extract_ip_src_from_packet};

    const SPEC_ATTACK_NAME: &str = "REPEAT_ATTACK";

    #[derive(Clone)]
    pub struct SpecScanner{
        base: Scanner,
        spec_ip: IP
    }

    impl SpecScanner{
        ///Constructor of struct SpecScanner.
        /// Input: 2 IP variables- the ips of the client to
        /// defend and the attacker to block.
        pub fn new(ip_client: IP, ip_attacker: IP) -> Self {
            return Self{base: Scanner::new(ip_client.copy(), SPEC_ATTACK_NAME.to_string()), spec_ip: ip_attacker.copy()};
        }

        ///The function gets the ip to defend from.
        /// Input: None.
        /// Output: an IP value- a copy of the ip to block.
        pub fn get_spec_ip(&self) -> IP{
            return self.spec_ip.copy();
        }

        ///The function checks the packets which was sniffed before
        /// and decides if there was an attack from the specific
        /// attacker or not.
        /// Input: A self reference(SpecScanner) and a vector of SinglePackets- the packets to check.
        /// Output: An IP value- the IP who did the attack(if
        /// there is no attack-returning default IP Broadcast)
        fn check_packets(&self, packets: Vec<SinglePacket>) -> Option<IP> {
            //Going over the packets
            for packet in packets{
                let ip_src_packet = extract_ip_src_from_packet(packet);
                //If the packet is from an attacker
                if ip_src_packet.copy().get_ip() == self.get_spec_ip().get_ip(){
                    return Some(ip_src_packet.copy());
                }
            }
            return Some(IP::new_default());
        }
    }

    impl ScannerFunctions for SpecScanner{
        ///The function scans the network and checks if there is
        /// a Specific Attack or not and handles the result.
        /// Input: self reference(SpecScanner) and a Vec<SinglePacket>- the
        /// packets to check.
        /// Output: None.
        fn scan(&self, packets: Vec<SinglePacket>){
            let result = self.check_packets(packets);
            let rt = Runtime::new().unwrap();
            rt.block_on(Server::handle_result(self.base.get_ip(), self.base.get_name(), result))
        }

        ///The function gets the base data of it.
        /// Input: None.
        /// Output: a Scanner value- the base data.
        fn get_base_data(&self) -> Scanner {
            return self.base.copy();
        }
    }

}